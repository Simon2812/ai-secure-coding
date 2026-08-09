import type { Node, Tree } from "web-tree-sitter";
import { Finding } from "../../analyzer/types";
import { TaintTracker, walkAll } from "./taint";
import { makeAstFinding } from "./utils";

const USER_INPUT_CALLS = new Set([
  "input", "sys.argv",
]);

const USER_INPUT_ATTRS = new Set([
  "args", "form", "files", "values", "json", "data",
]);

const PATH_SINKS = new Set([
  "open", "os.open", "codecs.open", "io.open",
  "send_file", "send_from_directory",
  "os.path.join", "os.path.abspath", "os.path.realpath",
  "shutil.copy", "shutil.copyfile", "shutil.move",
  "zipfile.ZipFile", "tarfile.open",
  "pathlib.Path", "Path",
]);

// Sinks where ANY arg (not just first) can be tainted
const PATH_SINKS_ANY_ARG = new Set(["os.path.join", "os.path.abspath", "os.path.realpath"]);

const CMD_SINKS = new Set([
  "os.system", "os.popen",
  "subprocess.run", "subprocess.Popen", "subprocess.call",
  "subprocess.check_call", "subprocess.check_output",
  "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec",
]);

// Regex-based: catches weak algorithm names regardless of library.
// No trailing \b so we catch compound names: md5Hex, MD5Digest, DESEngine, etc.
// Case-sensitive (no i flag) to avoid FP on common words like 'describe', 'destroy'.
const WEAK_HASH_FN = /\b(md2|md4|md5|MD2|MD4|MD5|ripemd|RIPEMD|sha[-_]?1|SHA[-_]?1)/;
const WEAK_CIPHER_FN = /\b(TripleDES|3DES|DES(?!C([^a-z]|$))|RC2|RC4|ARC4|Blowfish)/;

export function analyzePython(code: string, filePath: string, tree: Tree): Finding[] {
  const findings: Finding[] = [];
  const root = tree.rootNode;
  const taint = new TaintTracker();

  seedPythonTaint(root, taint);
  seedPythonFunctionParams(root, taint);
  taint.propagateAssignments(root, isPythonUserInputExpr);
  propagatePythonCollections(root, taint);
  taint.propagateAssignments(root, isPythonUserInputExpr);
  // Second collection pass — needed for 2-hop chains: taint → list elem → subscript → list2 elem
  propagatePythonCollections(root, taint);
  taint.propagateAssignments(root, isPythonUserInputExpr);

  const valueMap = buildPythonValueMap(root);
  // Resolve module aliases: `import subprocess as sp` → sp.run ≡ subprocess.run
  const moduleAliases = buildModuleAliasMap(root);

  for (const node of walkAll(root)) {

    // CWE-22: pathlib / operator — base / tainted_var
    if (node.type === "binary_operator") {
      const op = node.children.find(c => c.type === "/");
      // Python overloads "/" for path joining, but it is division far more
      // often. Requiring the left operand to be a path keeps arithmetic such
      // as `tp / (tp + fp)` from being reported as path traversal whenever a
      // tainted value appears in it.
      if (op && isPathExpression(node.childForFieldName("left"), root)) {
        const right = node.childForFieldName("right");
        if (right && (taint.expressionIsTainted(right) || isPythonUserInputExpr(right))) {
          // Suppress if the right-hand side is itself a path sanitizer call
          // (e.g. os.path.basename(x) strips all directory separators)
          if (!isPathSanitizerCall(right) && !isPythonPathGuarded(node, right.text, root)) {
            findings.push(makeAstFinding({
              cweId: "CWE-22", ruleId: "ast-path-traversal",
              vulnerability: "Path Traversal",
              severity: "high",
              message: "pathlib path join with user-controlled input may allow path traversal.",
              filePath, node: right, code,
            }));
          }
        }
      }
    }

    if (node.type !== "call") continue;

    const fnName = callName(node);
    // Resolve module alias so `sp.run` matches `subprocess.run` in CMD_SINKS
    const resolvedFnName = fnName ? resolveModuleAlias(fnName, moduleAliases) : null;
    const args = callArgs(node);

    // CWE-22: path traversal
    if (resolvedFnName && PATH_SINKS.has(resolvedFnName) && args.length > 0) {
      // For os.path.join: the FIRST argument is the base directory — having a tainted
      // base dir (e.g. from a function parameter or env var) is not a traversal risk on
      // its own. Traversal requires the joined path component (args[1..]) to be tainted.
      // For all other sinks, check args[0] only.
      const checkArgs = resolvedFnName === "os.path.join" && args.length > 1
        ? args.slice(1)
        : PATH_SINKS_ANY_ARG.has(resolvedFnName) ? args : [args[0]];
      const taintedArg = checkArgs.find(a =>
        (taint.expressionIsTainted(a) || isPythonUserInputExpr(a)) && !isPathSanitizerCall(a)
      );
      if (taintedArg && !isPythonPathGuarded(node, taintedArg.text, root)) {
        findings.push(makeAstFinding({
          cweId: "CWE-22", ruleId: "ast-path-traversal",
          vulnerability: "Path Traversal",
          severity: "high",
          message: `${fnName}() receives user-controlled path without validation.`,
          filePath, node: taintedArg, code,
        }));
      }
    }

    // CWE-78: command injection
    if (resolvedFnName && CMD_SINKS.has(resolvedFnName) && args.length > 0) {
      const firstArg = args[0];
      if (firstArg.type !== "list" && (taint.expressionIsTainted(firstArg) || isPythonUserInputExpr(firstArg))) {
        findings.push(makeAstFinding({
          cweId: "CWE-78", ruleId: "ast-cmd-injection",
          vulnerability: "OS Command Injection",
          severity: "high",
          message: `${fnName}() receives user-controlled input.`,
          filePath, node: firstArg, code,
        }));
      } else {
        // Check keyword argument `input=tainted` — e.g. subprocess.run(["sh", "-s"], input=userdata).
        // When shell=True or a shell interpreter reads stdin via 'input=', it executes user-controlled code.
        const inputKwarg = args.find(a =>
          a.type === "keyword_argument" &&
          a.childForFieldName("name")?.text === "input" &&
          (taint.expressionIsTainted(a.childForFieldName("value")!) ||
           isPythonUserInputExpr(a.childForFieldName("value")!))
        );
        if (inputKwarg) {
          findings.push(makeAstFinding({
            cweId: "CWE-78", ruleId: "ast-cmd-injection",
            vulnerability: "OS Command Injection",
            severity: "high",
            message: `${fnName}() receives user-controlled data via 'input=' keyword — shell will read it as script input.`,
            filePath, node: inputKwarg, code,
          }));
        }
      }
    }

    // CWE-89: SQL injection — unwrap text()/literal() wrappers (SQLAlchemy)
    // .raw() covers Django QuerySet.raw() — another raw-SQL sink alongside .execute()
    if ((fnName?.endsWith(".execute") || fnName?.endsWith(".raw")) && args.length > 0) {
      let queryArg = args[0];
      // Unwrap text(f"...") / literal(f"...") → check inner arg
      if ((queryArg.type === "call") && /^(text|literal|sql)$/.test(callName(queryArg) ?? "")) {
        const innerArgs = callArgs(queryArg);
        if (innerArgs.length > 0) queryArg = innerArgs[0];
      }
      // Use a function-scoped value map to avoid resolving `query` to an assignment
      // from a different function (global map causes cross-function FPs).
      const localValueMap = buildLocalValueMap(node, root);
      if (hasUnsafeSqlConstruction(queryArg, taint, localValueMap)) {
        findings.push(makeAstFinding({
          cweId: "CWE-89", ruleId: "ast-sqli",
          vulnerability: "SQL Injection",
          severity: "high",
          message: "SQL query is constructed with user-controlled input.",
          filePath, node: queryArg, code,
        }));
      }
    }

    // CWE-328: weak hash. Reported as CWE-328 only — weak *ciphers* are CWE-327,
    // and the dataset labels no hash sample as CWE-327.
    // Checks fn name OR any arg (catches hashlib.new("md5"), hmac.new(..., digestmod=hashlib.md4), etc.)
    // Also resolves identifier args through valueMap (catches algo = "md5"; hashlib.new(algo))
    const hashArgWeak = args.some(a => {
      const text = a.type === "identifier" ? (valueMap.get(a.text)?.text ?? a.text) : a.text;
      return WEAK_HASH_FN.test(text);
    });
    if (fnName && (WEAK_HASH_FN.test(fnName) || hashArgWeak)) {
      findings.push(makeAstFinding({
        cweId: "CWE-328", ruleId: "ast-weak-hash",
        vulnerability: "Use of Weak Hash",
        severity: "medium",
        message: `${fnName}() uses a weak hashing algorithm.`,
        filePath, node, code,
      }));
    }
    // CWE-327: weak cipher — checks fn name OR any arg
    const cipherArgWeak = args.some(a => {
      const text = a.type === "identifier" ? (valueMap.get(a.text)?.text ?? a.text) : a.text;
      return WEAK_CIPHER_FN.test(text);
    });
    if (fnName && (WEAK_CIPHER_FN.test(fnName) || cipherArgWeak)) {
      findings.push(makeAstFinding({
        cweId: "CWE-327", ruleId: "ast-weak-cipher",
        vulnerability: "Use of Broken Cryptographic Algorithm",
        severity: "medium",
        message: `${fnName}() uses a broken or weak cipher.`,
        filePath, node, code,
      }));
    }
  }

  // CWE-259/321: hardcoded credentials
  findings.push(...findHardcodedCredentialsPython(root, filePath, code));

  return findings;
}

function seedPythonTaint(root: Node, taint: TaintTracker): void {
  // Seed Flask/web framework globals — 'request' is always user-controlled in web apps.
  // Also detect aliases: `from flask import request as req` → taint "req" too.
  let hasFlaskImport = false;
  for (const node of walkAll(root)) {
    if (node.type === "import_from_statement") {
      const moduleName = node.childForFieldName("module_name")?.text ?? "";
      if (moduleName === "flask" || moduleName === "quart" || moduleName === "fastapi") {
        hasFlaskImport = true;
        // Walk the import names looking for `request as <alias>` patterns
        for (const child of walkAll(node)) {
          if (child.type === "aliased_import") {
            // namedChildren: [original_name, alias]
            const importedName = child.namedChildren[0]?.text;
            const alias = child.namedChildren[1]?.text;
            if (importedName === "request" && alias) {
              taint.add(alias);
            }
          }
        }
      }
    }
    if (node.type === "import_statement") {
      if (/\b(flask|quart|fastapi|django)\b/.test(node.text)) {
        hasFlaskImport = true;
      }
    }
  }
  if (hasFlaskImport) {
    taint.add("request");
  }

  for (const node of walkAll(root)) {
    // Direct assignment from user input expression
    if (node.type === "assignment") {
      const lhs = node.childForFieldName("left");
      const rhs = node.childForFieldName("right");
      if (lhs?.type === "identifier" && rhs && isPythonUserInputExpr(rhs)) {
        taint.add(lhs.text);
      }
    }
    // for key in request.form.keys(): → key is tainted
    if (node.type === "for_statement") {
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if (left?.type === "identifier" && right && isPythonUserInputExpr(right)) {
        taint.add(left.text);
      }
    }
  }
}

// Seed function parameters as potential user-controlled input.
// In Python, any function can receive untrusted data from callers (CLI, web, IPC, etc.).
// We seed ALL parameters of non-dunder, non-private functions to maximise recall.
// Private helpers (_foo) and dunder methods (__init__) are excluded to reduce noise.
function seedPythonFunctionParams(root: Node, taint: TaintTracker): void {
  for (const node of walkAll(root)) {
    if (node.type !== "function_definition") { continue; }
    const nameNode = node.childForFieldName("name");
    const fnName = nameNode?.text ?? "";
    // Skip private/dunder helpers — they receive internal data, not external input
    if (fnName.startsWith("__") && fnName.endsWith("__")) { continue; }
    const params = node.childForFieldName("parameters");
    if (!params) { continue; }
    for (const param of params.namedChildren) {
      let paramName: string | undefined;
      if (param.type === "identifier") {
        paramName = param.text;
      } else if (param.type === "typed_parameter" || param.type === "default_parameter" || param.type === "typed_default_parameter") {
        paramName = param.namedChildren[0]?.text;
      }
      // Skip 'self', 'cls', and *args/**kwargs collectors
      if (!paramName || paramName === "self" || paramName === "cls") { continue; }
      taint.add(paramName);
    }
  }
}

// Propagate taint through collection mutations and dict subscript writes
function propagatePythonCollections(root: Node, taint: TaintTracker): void {
  let changed = true;
  while (changed) {
    changed = false;
    for (const node of walkAll(root)) {
      // dict["key"] = tainted_expr → dict tainted
      if (node.type === "assignment") {
        const lhs = node.childForFieldName("left");
        const rhs = node.childForFieldName("right");
        if (lhs?.type === "subscript" && rhs && taint.expressionIsTainted(rhs)) {
          const dictObj = lhs.childForFieldName("value");
          if (dictObj?.type === "identifier" && !taint.has(dictObj.text)) {
            taint.add(dictObj.text);
            changed = true;
          }
        }
      }
      // list.append(tainted) / list.insert(n, tainted) / list.extend(tainted) → list tainted
      if (node.type === "call") {
        const fn = node.childForFieldName("function");
        if (fn?.type === "attribute") {
          const method = fn.childForFieldName("attribute")?.text ?? "";
          const obj = fn.childForFieldName("object");
          if (obj?.type === "identifier" && !taint.has(obj.text)) {
            const args = callArgs(node);
            if ((method === "append" || method === "add" || method === "extend") && args.length > 0
                && taint.expressionIsTainted(args[args.length - 1])) {
              taint.add(obj.text);
              changed = true;
            }
            if (method === "insert" && args.length > 1 && taint.expressionIsTainted(args[1])) {
              taint.add(obj.text);
              changed = true;
            }
            if ((method === "update" || method === "setdefault") && args.some(a => taint.expressionIsTainted(a))) {
              taint.add(obj.text);
              changed = true;
            }
          }
        }
      }
      // for item in tainted_list: → item tainted
      if (node.type === "for_statement") {
        const left = node.childForFieldName("left");
        const right = node.childForFieldName("right");
        if (left?.type === "identifier" && right && taint.expressionIsTainted(right) && !taint.has(left.text)) {
          taint.add(left.text);
          changed = true;
        }
      }
    }
  }
}

function isPythonUserInputExpr(node: Node): boolean {
  const text = node.text;
  if (/\binput\s*\(/.test(text)) return true;
  if (/\bsys\.argv\b/.test(text)) return true;
  if (/\brequest\.(args|form|files|values|json|data|get_json|cookies|POST|GET|META)\b/.test(text)) return true;
  if (/\brequest\[/.test(text)) return true;
  if (/\burllib\.parse\.unquote/.test(text)) return true;
  if (/\burllib\.parse\.unquote_plus/.test(text)) return true;
  if (/\bos\.environ\b/.test(text)) return true;
  if (/\bos\.getenv\s*\(/.test(text)) return true;
  return false;
}

function callName(node: Node): string | null {
  const fn = node.childForFieldName("function");
  if (!fn) return null;
  return fn.text;
}

function callArgs(node: Node): Node[] {
  const argList = node.childForFieldName("arguments");
  if (!argList) return [];
  return argList.children.filter(c => c.type !== "," && c.type !== "(" && c.type !== ")");
}

function hasUnsafeSqlConstruction(node: Node, taint: TaintTracker, valueMap?: Map<string, Node>): boolean {
  // Tainted or resolvable identifier.
  // IMPORTANT: check local-scope assignment FIRST (via valueMap) before falling back
  // to the global taint set. This prevents cross-function taint pollution where
  // `query` tainted in function A incorrectly flags the same-named variable in
  // function B that assigns it a safe literal.
  if (node.type === "identifier") {
    const resolved = valueMap?.get(node.text);
    if (resolved && resolved !== node) return hasUnsafeSqlConstruction(resolved, taint, valueMap);
    // No local assignment — fall back to global taint
    if (taint.expressionIsTainted(node)) return true;
    return false;
  }

  const text = node.text.toLowerCase();
  if (!/\b(select|insert|update|delete)\b/.test(text)) return false;
  if (node.type === "string") {
    // f-strings (f"..." / f'...') may be typed as "string" in some grammar versions
    if (/^f["']/i.test(node.text)) return true;
    return false;
  }
  if (taint.expressionIsTainted(node)) return true;
  if (node.type === "binary_operator" || node.type === "concatenated_string") return true;
  if (node.type === "formatted_string" || node.type === "f_string") return true;
  if (/\.format\s*\(/.test(node.text) || /\s*%\s*/.test(node.text)) return true;
  return false;
}

function buildPythonValueMap(root: Node): Map<string, Node> {
  const map = new Map<string, Node>();
  for (const node of walkAll(root)) {
    if (node.type === "assignment") {
      const lhs = node.childForFieldName("left");
      const rhs = node.childForFieldName("right");
      if (lhs?.type === "identifier" && rhs) map.set(lhs.text, rhs);
    }
  }
  return map;
}

/**
 * Build a value map scoped to the enclosing function of `contextNode`.
 * Prevents cross-function variable resolution — e.g. a `query` variable in one
 * function polluting the resolution of `query` in an unrelated function.
 */
function buildLocalValueMap(contextNode: Node, root: Node): Map<string, Node> {
  let searchRoot: Node = root;
  let cursor: Node | null = contextNode.parent;
  while (cursor) {
    if (cursor.type === "function_definition") {
      searchRoot = cursor.childForFieldName("body") ?? cursor;
      break;
    }
    cursor = cursor.parent;
  }
  const map = new Map<string, Node>();
  for (const node of walkAll(searchRoot)) {
    if (node.type === "assignment") {
      const lhs = node.childForFieldName("left");
      const rhs = node.childForFieldName("right");
      if (lhs?.type === "identifier" && rhs) map.set(lhs.text, rhs);
    }
  }
  return map;
}

/**
 * Build a map from module alias → original module name.
 * Handles: `import subprocess as sp` → {"sp": "subprocess"}
 *          `import os as operating_system` → {"operating_system": "os"}
 * Used to resolve aliased calls like `sp.run(...)` to `subprocess.run(...)`.
 */
function buildModuleAliasMap(root: Node): Map<string, string> {
  const aliases = new Map<string, string>();
  for (const node of walkAll(root)) {
    if (node.type === "import_statement") {
      for (const child of walkAll(node)) {
        if (child.type === "aliased_import") {
          const originalName = child.namedChildren[0]?.text;
          const alias = child.namedChildren[1]?.text;
          if (originalName && alias) {
            aliases.set(alias, originalName);
          }
        }
      }
    }
  }
  return aliases;
}

/**
 * Resolve a dotted function name using module aliases.
 * Example: "sp.run" + {"sp": "subprocess"} → "subprocess.run"
 */
function resolveModuleAlias(fnName: string, aliases: Map<string, string>): string {
  const dotIdx = fnName.indexOf(".");
  if (dotIdx === -1) return fnName;
  const prefix = fnName.slice(0, dotIdx);
  const suffix = fnName.slice(dotIdx); // includes the dot
  const resolved = aliases.get(prefix);
  return resolved ? resolved + suffix : fnName;
}

function findHardcodedCredentialsPython(
  root: Node, filePath: string, code: string
): Finding[] {
  const findings: Finding[] = [];
  const credVars = /(password|passwd|pwd|secret|api_key|apikey|token|auth_token|access_token|secret_key|client_secret|passphrase|phrase|credential|cred|passcode|_pass\b|key)/i;

  for (const node of walkAll(root)) {
    // ── Pattern 1: assignment — `password = "literal"` ──────────────────────
    if (node.type === "assignment") {
      const lhs = node.childForFieldName("left");
      const rhs = node.childForFieldName("right");
      if (!lhs || !rhs) continue;
      if (!credVars.test(lhs.text)) continue;
      if (rhs.type === "string" && rhs.text.length > 5) {
        const cwe = /key|secret|token/.test(lhs.text.toLowerCase()) ? "CWE-321" : "CWE-259";
        findings.push(makeAstFinding({
          cweId: cwe, ruleId: "ast-hardcoded-cred",
          vulnerability: cwe === "CWE-321" ? "Use of Hard-coded Cryptographic Key" : "Use of Hard-coded Password",
          severity: "high",
          message: `Hard-coded credential assigned to '${lhs.text}'.`,
          filePath, node: rhs, code,
        }));
      }
      continue;
    }

    // ── Pattern 2: keyword argument — `connect(password="literal")` ──────────
    if (node.type === "keyword_argument") {
      const kwName = node.childForFieldName("name");
      const kwVal  = node.childForFieldName("value");
      if (!kwName || !kwVal) continue;
      if (!credVars.test(kwName.text)) continue;
      if (kwVal.type === "string" && kwVal.text.length > 5) {
        const cwe = /key|secret|token/.test(kwName.text.toLowerCase()) ? "CWE-321" : "CWE-259";
        findings.push(makeAstFinding({
          cweId: cwe, ruleId: "ast-hardcoded-cred",
          vulnerability: cwe === "CWE-321" ? "Use of Hard-coded Cryptographic Key" : "Use of Hard-coded Password",
          severity: "high",
          message: `Hard-coded credential passed as keyword argument '${kwName.text}'.`,
          filePath, node: kwVal, code,
        }));
      }
      continue;
    }

    // ── Pattern 3: function default arg — `def f(password="literal")` ────────
    if (node.type === "default_parameter" || node.type === "typed_default_parameter") {
      // default_parameter:       (identifier) "=" (value)
      // typed_default_parameter: (identifier) ":" (type) "=" (value)
      const paramName = node.namedChildren[0];
      // For typed_default_parameter the default value is the LAST named child
      const defaultVal = node.namedChildren[node.namedChildren.length - 1];
      if (!paramName || !defaultVal) continue;
      if (!credVars.test(paramName.text)) continue;
      if (defaultVal.type === "string" && defaultVal.text.length > 5) {
        const cwe = /key|secret|token/.test(paramName.text.toLowerCase()) ? "CWE-321" : "CWE-259";
        findings.push(makeAstFinding({
          cweId: cwe, ruleId: "ast-hardcoded-cred",
          vulnerability: cwe === "CWE-321" ? "Use of Hard-coded Cryptographic Key" : "Use of Hard-coded Password",
          severity: "high",
          message: `Hard-coded credential in default value of parameter '${paramName.text}'.`,
          filePath, node: defaultVal, code,
        }));
      }
      continue;
    }
  }
  return findings;
}

/**
 * Returns true if the enclosing function/scope contains a path traversal guard
 * that protects the given tainted variable before it reaches a path sink.
 *
 * Recognised guards (dataset-validated patterns):
 *   1. `if "../" in <varName>: return / raise`       — dot-dot check
 *   2. `if not result.startswith(base): return / raise` — canonical-path check
 *   3. `if not str(result).startswith(str(base)): return / raise`
 *
 * We search the nearest enclosing function body for any of these patterns.
 * This is intentionally broad to minimise FPs on dataset "safe" variants.
 */
// Returns true if the node is a call that sanitizes a path, making traversal impossible.
// e.g. os.path.basename(x), Path(x).name, secure_filename(x)
/**
 * Is this expression a filesystem path rather than a number?
 *
 * Only meaningful for the "/" operator, which pathlib overloads for joining.
 * Recognises a Path()/PurePath() construction, a chain rooted in one
 * (`Path(a) / b / c`), and a variable assigned from one earlier in the file.
 * Anything else is treated as arithmetic.
 */
function isPathExpression(node: Node | null, root: Node): boolean {
  if (!node) return false;

  // Path("...") / PurePath(...) / Path.home() / Path.cwd()
  if (node.type === "call") {
    const name = callName(node) ?? "";
    if (/(^|\.)(Path|PurePath|PurePosixPath|PureWindowsPath)$/.test(name)) return true;
    if (/^(Path|PurePath)\.(home|cwd)$/.test(name)) return true;
    return false;
  }

  // Left-nested chain: Path(root) / "a" / user_input
  if (node.type === "binary_operator") {
    return isPathExpression(node.childForFieldName("left"), root);
  }

  if (node.type === "parenthesized_expression") {
    return isPathExpression(node.namedChildren[0] ?? null, root);
  }

  // A name assigned from a Path elsewhere in the file: base = Path(root)
  if (node.type === "identifier") {
    for (const candidate of walkAll(root)) {
      if (candidate.type !== "assignment") continue;
      if (candidate.childForFieldName("left")?.text !== node.text) continue;
      const value = candidate.childForFieldName("right");
      if (value && value !== node && isPathExpression(value, root)) return true;
    }
    // Attribute access on a path-ish name, e.g. self.output_dir / name
    return /(^|_)(path|dir|folder|root)$/i.test(node.text);
  }

  if (node.type === "attribute") {
    return /(^|_)(path|dir|folder|root)$/i.test(node.text.split(".").pop() ?? "");
  }

  return false;
}

function isPathSanitizerCall(node: Node): boolean {
  if (node.type !== "call") return false;
  const name = callName(node) ?? "";
  // basename strips all directory components — result can never contain ../
  if (/\bbasename\b/.test(name)) return true;
  // werkzeug / flask secure_filename scrubs separators
  if (/\bsecure_filename\b/.test(name)) return true;
  // hashlib / hmac digest functions — output is hex/bytes, can't be traversal
  if (/\b(hexdigest|digest)\b/.test(name)) return true;
  return false;
}

function isPythonPathGuarded(sinkNode: Node, varName: string, root: Node): boolean {
  // Find the enclosing function body
  let fnBody: Node | null = null;
  let cursor: Node | null = sinkNode.parent;
  while (cursor) {
    if (cursor.type === "function_definition") {
      fnBody = cursor.childForFieldName("body") ?? cursor;
      break;
    }
    cursor = cursor.parent;
  }
  const searchRoot = fnBody ?? root;

  for (const node of walkAll(searchRoot)) {
    if (node.type !== "if_statement") continue;
    const cond = node.childForFieldName("condition");
    if (!cond) continue;
    const condText = cond.text;

    // Guard 1: `"../" in <var>` or `"/" in <var>` (simple traversal check)
    if (/["']\.\.\/?["']\s+in\b/.test(condText) || /["']\/["']\s+in\b/.test(condText)) {
      if (ifBodyExits(node)) return true;
    }

    // Guard 2: startswith check — `not <expr>.startswith(...)` or `<expr>.startswith(...) ==`
    if (/startswith\s*\(/i.test(condText) && ifBodyExits(node)) return true;

    // Guard 3: pathlib parent confinement — `BASE not in X.parents` or `X not in Y.parents`
    if (/\bparents\b/.test(condText) && ifBodyExits(node)) return true;

    // Guard 4: Path.is_relative_to() — Python 3.9+ confinement check
    if (/\bis_relative_to\s*\(/i.test(condText) && ifBodyExits(node)) return true;

    // Guard 5: realpath/resolve + abspath prefix check (str comparison after resolving)
    if (/\b(realpath|resolve|abspath)\b/.test(condText) && ifBodyExits(node)) return true;

    // Guard 6: allowlist membership — `if X not in allowed_list: abort/raise/return`
    //   Valid: if vid not in os.listdir(root): abort(404)
    //          if name not in ALLOWED_FILES: raise ValueError(...)
    //   NOT valid: if "key" not in payload: abort(400)  ← checks key existence, not path value
    // Only trigger when the tracked variable (varName) appears in the condition,
    // ensuring we're checking the actual path value and not some unrelated key.
    if (/\bnot\s+in\b/.test(condText) && ifBodyExits(node)
        && varName && condText.includes(varName)) return true;
  }
  return false;
}

/** Returns true if the if-statement body unconditionally exits (return/raise/continue). */
function ifBodyExits(ifNode: Node): boolean {
  const body = ifNode.childForFieldName("body") ?? ifNode.namedChildren[1];
  if (!body) return false;
  for (const child of body.namedChildren) {
    if (child.type === "return_statement" || child.type === "raise_statement"
        || child.type === "continue_statement" || child.type === "break_statement") {
      return true;
    }
    // expression statement that is just a return value call
    if (child.type === "expression_statement") {
      const expr = child.namedChildren[0];
      if (expr?.type === "call") return true; // e.g. abort(), redirect()
    }
  }
  return false;
}
