import type { Node, Tree } from "web-tree-sitter";
import { Finding } from "../../analyzer/types";
import { TaintTracker, walkAll } from "./taint";
import { makeAstFinding } from "./utils";

const PATH_SINK_TYPES = new Set([
  "File", "FileInputStream", "FileOutputStream",
  "FileReader", "FileWriter", "RandomAccessFile", "ZipFile",
]);

const PATH_SINK_CALLS = new Set([
  "Paths.get", "Path.of",
  "Files.newBufferedReader", "Files.newBufferedWriter",
  "Files.newInputStream", "Files.newOutputStream",
  "Files.readAllBytes", "Files.readAllLines", "Files.readString",
  "Files.write", "Files.writeString",
]);

const CMD_SINK_TYPES = new Set(["ProcessBuilder"]);
const CMD_SINK_CALLS = new Set(["Runtime.getRuntime().exec", "Runtime.exec"]);

const SQL_EXECUTE = new Set(["execute", "executeQuery", "executeUpdate", "executeBatch", "addBatch"]);
const SQL_PREPARE = new Set(["prepareStatement", "prepareCall"]);

// Matches string argument in getInstance("MD5"), getInstance("DES/ECB/...")
const WEAK_HASH_ALGOS = /^"(MD2|MD4|MD5|RIPEMD-?160|SHA|SHA-?1|SHA-224)"$/i;
const WEAK_CIPHER_ALGOS = /^"(DES|RC2|RC4|Blowfish|TripleDES|3DES)(\/[^"]+)?"$/i;
// Regex-based: catches weak algorithm names in method/type names regardless of library.
// No trailing \b so we catch compound names: md5Hex, MD5Digest, DESEngine, etc.
// Case-sensitive (no i flag) to avoid FP on common words like 'describe', 'destroy'.
const WEAK_HASH_NAME = /\b(md2|md4|md5|MD2|MD4|MD5|ripemd|RIPEMD|sha[-_]?1|SHA[-_]?1)/;
const WEAK_CIPHER_NAME = /\b(DES|TripleDES|3DES|RC2|RC4|ARC4|Blowfish)/;

export function analyzeJava(code: string, filePath: string, tree: Tree): Finding[] {
  const findings: Finding[] = [];
  const root = tree.rootNode;
  const taint = new TaintTracker();

  seedJavaTaint(root, taint);
  seedJavaMethodParams(root, taint);
  // Remove formal parameters that are validated by a guard (matches/contains + throw).
  // Must run BEFORE propagateAssignments so the sanitized params don't spread their taint.
  applyJavaValidationGuards(root, taint);
  taint.propagateAssignments(root, isJavaUserInputExpr);
  propagateJavaCollections(root, taint);
  taint.propagateAssignments(root, isJavaUserInputExpr);

  const valueMap = buildJavaValueMap(root);

  for (const node of walkAll(root)) {

    // object_creation_expression: new File(...), new ProcessBuilder(...)
    if (node.type === "object_creation_expression") {
      const typeNode = node.childForFieldName("type");
      const argsNode = node.childForFieldName("arguments");
      const typeName = typeNode?.text ?? "";

      if (PATH_SINK_TYPES.has(typeName) && argsNode) {
        const args = getJavaArgs(argsNode);
        const taintedArg = args.find(a => taint.expressionIsTainted(a) || isJavaUserInputExpr(a));
        if (taintedArg && !isJavaPathGuarded(node, code)) {
          findings.push(makeAstFinding({
            cweId: "CWE-22", ruleId: "ast-path-traversal",
            vulnerability: "Path Traversal",
            severity: "high",
            message: `new ${typeName}() receives user-controlled path.`,
            filePath, node: taintedArg, code,
          }));
        }
      }

      // CWE-327/328: weak hash/cipher in type name (new MD5Digest(), new DESEngine(), etc.)
      if (WEAK_HASH_NAME.test(typeName)) {
        for (const cweId of ["CWE-327", "CWE-328"] as const) {
          findings.push(makeAstFinding({
            cweId, ruleId: "ast-weak-hash",
            vulnerability: cweId === "CWE-328" ? "Use of Weak Hash" : "Use of Broken Cryptographic Algorithm",
            severity: "medium",
            message: `new ${typeName}() uses a weak hashing algorithm (MD5/SHA1).`,
            filePath, node, code,
          }));
        }
      }
      if (WEAK_CIPHER_NAME.test(typeName) && !PATH_SINK_TYPES.has(typeName)) {
        findings.push(makeAstFinding({
          cweId: "CWE-327", ruleId: "ast-weak-cipher",
          vulnerability: "Use of Broken Cryptographic Algorithm",
          severity: "medium",
          message: `new ${typeName}() uses a broken or weak cipher.`,
          filePath, node, code,
        }));
      }

      if (CMD_SINK_TYPES.has(typeName) && argsNode) {
        const args = getJavaArgs(argsNode);
        // ProcessBuilder(cmd, arg1, arg2, ...) — flag when:
        //   1. The program (args[0]) itself is user-controlled, OR
        //   2. Single-string command — entire arg is user-controlled, OR
        //   3. Shell interpreter + "-c"/"/c" + tainted shell command string:
        //      new ProcessBuilder("sh", "-c", userCmd) — userCmd is interpreted by shell.
        const cmdArg = args[0];
        const isSingleStringCmd = args.length === 1;

        // Pattern 3: ProcessBuilder("sh"|"bash"|"cmd.exe", "-c"|"/c", taintedCmd)
        const SHELL_INTERPRETERS = new Set(["sh", "bash", "zsh", "ksh", "cmd.exe", "cmd", "/bin/sh", "/bin/bash"]);
        const SHELL_C_FLAGS = new Set(["-c", "/c"]);
        const isShellShellC = args.length >= 3
          && cmdArg?.type === "string_literal" && SHELL_INTERPRETERS.has(cmdArg.text.replace(/['"]/g, ""))
          && args[1]?.type === "string_literal" && SHELL_C_FLAGS.has(args[1].text.replace(/['"]/g, ""));

        if (cmdArg && (taint.expressionIsTainted(cmdArg) || isJavaUserInputExpr(cmdArg))) {
          findings.push(makeAstFinding({
            cweId: "CWE-78", ruleId: "ast-cmd-injection",
            vulnerability: "OS Command Injection",
            severity: "high",
            message: `new ${typeName}() receives user-controlled command.`,
            filePath, node, code,
          }));
        } else if (isSingleStringCmd && cmdArg &&
                   args.some(a => taint.expressionIsTainted(a) || isJavaUserInputExpr(a))) {
          findings.push(makeAstFinding({
            cweId: "CWE-78", ruleId: "ast-cmd-injection",
            vulnerability: "OS Command Injection",
            severity: "high",
            message: `new ${typeName}() receives user-controlled input.`,
            filePath, node, code,
          }));
        } else if (isShellShellC && args[2] &&
                   (taint.expressionIsTainted(args[2]) || isJavaUserInputExpr(args[2]))) {
          // ProcessBuilder("sh", "-c", taintedShellCmd) — the 3rd arg is the shell command string.
          // Only args[2] is the shell command; any further args are positional ($0,$1,...) and
          // not directly shell-interpreted, so we check only the command-string position.
          findings.push(makeAstFinding({
            cweId: "CWE-78", ruleId: "ast-cmd-injection",
            vulnerability: "OS Command Injection",
            severity: "high",
            message: `new ${typeName}("${cmdArg?.text?.replace(/['"]/g, "")}", "-c", …) receives user-controlled shell command.`,
            filePath, node, code,
          }));
        }
      }
    }

    // method_invocation
    if (node.type === "method_invocation") {
      const methodName = node.childForFieldName("name")?.text ?? "";
      const argsNode = node.childForFieldName("arguments");
      const obj = node.childForFieldName("object");
      const fullName = obj ? `${obj.text}.${methodName}` : methodName;

      // Path sinks: Paths.get(), Path.of(), Files.readString(), Files.readAllLines(), etc.
      if (PATH_SINK_CALLS.has(fullName) && argsNode) {
        const args = getJavaArgs(argsNode);
        if (args.some(a => taint.expressionIsTainted(a) || isJavaUserInputExpr(a))
            && !isCallResultSanitized(node)
            && !isJavaPathGuarded(node, code)) {
          findings.push(makeAstFinding({
            cweId: "CWE-22", ruleId: "ast-path-traversal",
            vulnerability: "Path Traversal",
            severity: "high",
            message: `${fullName}() receives user-controlled path.`,
            filePath, node, code,
          }));
        }
      }

      // Path.resolve(tainted) — called on any Path variable.
      // Skip if the receiver is `new SomeClass()` — that's a user-defined method,
      // not java.nio.file.Path.resolve().
      if (methodName === "resolve" && argsNode
          && obj?.type !== "object_creation_expression") {
        const args = getJavaArgs(argsNode);
        if (args.some(a => taint.expressionIsTainted(a) || isJavaUserInputExpr(a))
            && !isJavaPathGuarded(node, code)) {
          findings.push(makeAstFinding({
            cweId: "CWE-22", ruleId: "ast-path-traversal",
            vulnerability: "Path Traversal",
            severity: "high",
            message: "Path.resolve() receives user-controlled input.",
            filePath, node, code,
          }));
        }
      }

      // SQL sinks: execute / executeQuery / executeUpdate / addBatch
      if (SQL_EXECUTE.has(methodName) && argsNode) {
        const args = getJavaArgs(argsNode);
        if (args.length > 0 && hasUnsafeSqlConstruction(args[0], taint, valueMap)) {
          findings.push(makeAstFinding({
            cweId: "CWE-89", ruleId: "ast-sqli",
            vulnerability: "SQL Injection",
            severity: "high",
            message: "SQL query constructed with user-controlled input.",
            filePath, node: args[0], code,
          }));
        }
      }

      // SQL sinks: prepareStatement / prepareCall with unsafe query
      if (SQL_PREPARE.has(methodName) && argsNode) {
        const args = getJavaArgs(argsNode);
        if (args.length > 0 && hasUnsafeSqlConstruction(args[0], taint, valueMap)) {
          findings.push(makeAstFinding({
            cweId: "CWE-89", ruleId: "ast-sqli",
            vulnerability: "SQL Injection",
            severity: "high",
            message: `${methodName}() called with user-controlled SQL query.`,
            filePath, node: args[0], code,
          }));
        }
      }

      // Weak crypto: MessageDigest.getInstance("MD5")
      if (methodName === "getInstance" && argsNode) {
        const args = getJavaArgs(argsNode);
        if (args.length > 0 && WEAK_HASH_ALGOS.test(args[0].text)) {
          for (const cweId of ["CWE-327", "CWE-328"] as const) {
            findings.push(makeAstFinding({
              cweId, ruleId: "ast-weak-hash",
              vulnerability: cweId === "CWE-328" ? "Use of Weak Hash" : "Use of Broken Cryptographic Algorithm",
              severity: "medium",
              message: `getInstance(${args[0].text}) uses a weak hash algorithm (MD5/SHA-1).`,
              filePath, node, code,
            }));
          }
        }
        if (args.length > 0 && WEAK_CIPHER_ALGOS.test(args[0].text)) {
          findings.push(makeAstFinding({
            cweId: "CWE-327", ruleId: "ast-weak-cipher",
            vulnerability: "Use of Broken Cryptographic Algorithm",
            severity: "medium",
            message: `getInstance(${args[0].text}) uses a broken or weak cipher.`,
            filePath, node, code,
          }));
        }
      }

      // CWE-327/328: weak hash in method/full name (DigestUtils.md5Hex, Hashing.md5, etc.)
      if (WEAK_HASH_NAME.test(fullName) && methodName !== "getInstance") {
        for (const cweId of ["CWE-327", "CWE-328"] as const) {
          findings.push(makeAstFinding({
            cweId, ruleId: "ast-weak-hash",
            vulnerability: cweId === "CWE-328" ? "Use of Weak Hash" : "Use of Broken Cryptographic Algorithm",
            severity: "medium",
            message: `${fullName}() uses a weak hashing algorithm (MD5/SHA1).`,
            filePath, node, code,
          }));
        }
      }
      // CWE-327: weak cipher in method/full name
      if (WEAK_CIPHER_NAME.test(fullName) && methodName !== "getInstance") {
        findings.push(makeAstFinding({
          cweId: "CWE-327", ruleId: "ast-weak-cipher",
          vulnerability: "Use of Broken Cryptographic Algorithm",
          severity: "medium",
          message: `${fullName}() uses a broken or weak cipher.`,
          filePath, node, code,
        }));
      }

      // Command injection via Runtime.exec
      if ((methodName === "exec") && argsNode) {
        const args = getJavaArgs(argsNode);
        if (args.some(a => taint.expressionIsTainted(a) || isJavaUserInputExpr(a))) {
          findings.push(makeAstFinding({
            cweId: "CWE-78", ruleId: "ast-cmd-injection",
            vulnerability: "OS Command Injection",
            severity: "high",
            message: "Runtime.exec() receives user-controlled input.",
            filePath, node, code,
          }));
        }
      }

      // Command injection via ProcessBuilder.command(args) — called after `new ProcessBuilder()`
      // e.g.: builder.command(args);  or  pb.command(List.of("sh", "-c", userInput))
      if (methodName === "command" && argsNode && obj) {
        const args = getJavaArgs(argsNode);
        const anyTainted = args.some(a => taint.expressionIsTainted(a) || isJavaUserInputExpr(a));
        if (anyTainted) {
          // Only flag if the receiver is a known ProcessBuilder variable (not an arbitrary .command())
          // We detect this by checking if the receiver was assigned from new ProcessBuilder().
          if (isProcessBuilderVar(obj, root)) {
            findings.push(makeAstFinding({
              cweId: "CWE-78", ruleId: "ast-cmd-injection",
              vulnerability: "OS Command Injection",
              severity: "high",
              message: "ProcessBuilder.command() receives user-controlled input.",
              filePath, node, code,
            }));
          }
        }
      }
    }
  }

  findings.push(...findHardcodedCredentialsJava(root, filePath, code));

  return findings;
}

/** Returns true if `node` (identifier used as receiver of .command()) refers to a
 *  ProcessBuilder variable — i.e., was declared/assigned as `new ProcessBuilder(...)`.
 */
function isProcessBuilderVar(node: Node, root: Node): boolean {
  const name = node.text;
  for (const n of walkAll(root)) {
    // ProcessBuilder pb = new ProcessBuilder(...);
    if (n.type === "local_variable_declaration") {
      const typeNode = n.childForFieldName("type");
      if (typeNode?.text === "ProcessBuilder") {
        const decl = n.children.find(c => c.type === "variable_declarator");
        if (decl?.childForFieldName("name")?.text === name) return true;
      }
    }
    // pb = new ProcessBuilder(...);
    if (n.type === "assignment_expression") {
      const left = n.childForFieldName("left");
      const right = n.childForFieldName("right");
      if (left?.text === name && right?.type === "object_creation_expression") {
        if (right.childForFieldName("type")?.text === "ProcessBuilder") return true;
      }
    }
  }
  return false;
}

function seedJavaTaint(root: Node, taint: TaintTracker): void {
  for (const node of walkAll(root)) {
    // local_variable_declaration: Type name = expr;
    if (node.type === "local_variable_declaration") {
      const declarator = node.children.find(c => c.type === "variable_declarator");
      if (!declarator) continue;
      const nameNode = declarator.childForFieldName("name");
      const valueNode = declarator.childForFieldName("value");
      if (!nameNode || !valueNode) continue;
      if (isJavaUserInputExpr(valueNode)) {
        taint.add(nameNode.text);
      }
      continue;
    }
    // assignment_expression: name = expr (inside loops, if-blocks, etc.)
    if (node.type === "assignment_expression") {
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if (!left || !right || left.type !== "identifier") continue;
      if (isJavaUserInputExpr(right)) {
        taint.add(left.text);
      }
    }
  }
}

function isJavaUserInputExpr(node: Node): boolean {
  const text = node.text;
  if (/\bgetParameter\s*\(/.test(text)) return true;
  if (/\bgetHeaders?\s*\(/.test(text)) return true;
  if (/\bgetHeaderNames\s*\(/.test(text)) return true;
  if (/\bgetQueryString\s*\(/.test(text)) return true;
  if (/\bgetPathInfo\s*\(/.test(text)) return true;
  if (/\bgetParts?\s*\(/.test(text)) return true;
  if (/\bgetCookies\s*\(/.test(text)) return true;
  if (/\bgetParameterMap\s*\(/.test(text)) return true;
  if (/\bgetParameterValues\s*\(/.test(text)) return true;
  if (/\bgetParameterNames\s*\(/.test(text)) return true;
  if (/\.getValue\s*\(/.test(text)) return true;
  if (/\.nextElement\s*\(/.test(text)) return true;
  if (/\.nextLine\s*\(/.test(text)) return true;
  if (/\.readLine\s*\(/.test(text)) return true;
  if (/\bargs\s*\[/.test(text)) return true;
  if (/\bURLDecoder\.decode\s*\(/.test(text)) return true;
  if (/\bSystem\.getenv\s*\(/.test(text)) return true;
  if (/\bSystem\.getProperty\s*\(/.test(text)) return true;
  // Properties.getProperty() — config files and property maps are often externally controlled.
  // Exclude System.getProperty() (already handled above; that returns JVM internals, not user data).
  if (/\.getProperty\s*\(/.test(text) && !/\bSystem\.getProperty\s*\(/.test(text)) return true;
  return false;
}

function getJavaArgs(argsNode: Node): Node[] {
  return argsNode.children.filter(c => c.type !== "," && c.type !== "(" && c.type !== ")");
}

function hasUnsafeSqlConstruction(node: Node, taint: TaintTracker, valueMap?: Map<string, Node>): boolean {
  // Tainted identifier passed directly to SQL sink
  if (node.type === "identifier") {
    if (taint.expressionIsTainted(node)) return true;
    // Resolve to assigned value and check that
    const resolved = valueMap?.get(node.text);
    if (resolved && resolved !== node) return hasUnsafeSqlConstruction(resolved, taint, valueMap);
    return false;
  }

  const text = node.text.toLowerCase();
  if (!/\b(select|insert|update|delete)\b/.test(text)) return false;
  if (node.type === "string_literal") return false;
  if (taint.expressionIsTainted(node)) return true;
  if (node.type === "binary_expression" && node.text.includes("+")) return true;
  if (/String\.format\s*\(/.test(node.text)) return true;
  return false;
}

// Seed String/Object formal parameters of methods as tainted (catches param-as-input patterns)
function seedJavaMethodParams(root: Node, taint: TaintTracker): void {
  for (const node of walkAll(root)) {
    if (node.type !== "method_declaration" && node.type !== "constructor_declaration") continue;
    const params = node.childForFieldName("parameters");
    if (!params) continue;
    for (const param of params.children) {
      if (param.type !== "formal_parameter") continue;
      const type = param.childForFieldName("type")?.text ?? "";
      const name = param.childForFieldName("name")?.text ?? "";
      if (/^(String|Object|CharSequence|StringBuilder|StringBuffer)$/.test(type) && name) {
        taint.add(name);
      }
    }
  }
}

// Propagate taint through collection mutations: list.add(tainted) → list tainted
const COLLECTION_ADD_METHODS = new Set(["add", "addAll", "offer", "push", "put", "putAll", "set", "insert"]);

function propagateJavaCollections(root: Node, taint: TaintTracker): void {
  let changed = true;
  while (changed) {
    changed = false;
    for (const node of walkAll(root)) {
      // collection.add(tainted) → collection tainted
      if (node.type === "method_invocation") {
        const methodName = node.childForFieldName("name")?.text ?? "";
        if (!COLLECTION_ADD_METHODS.has(methodName)) continue;
        const obj = node.childForFieldName("object");
        if (!obj || obj.type !== "identifier") continue;
        if (taint.has(obj.text)) continue;
        const argsNode = node.childForFieldName("arguments");
        if (!argsNode) continue;
        const args = getJavaArgs(argsNode);
        if (args.some(a => taint.expressionIsTainted(a) || isJavaUserInputExpr(a))) {
          taint.add(obj.text);
          changed = true;
        }
      }
      // arr[i] = tainted → arr tainted (array element assignment)
      if (node.type === "assignment_expression") {
        const left = node.childForFieldName("left");
        const right = node.childForFieldName("right");
        if (left?.type !== "array_access" || !right) continue;
        // array_access: array child is the array expression, index is the subscript
        const arrNode = left.childForFieldName("array") ?? left.namedChildren[0];
        if (!arrNode || arrNode.type !== "identifier") continue;
        if (taint.has(arrNode.text)) continue;
        if (taint.expressionIsTainted(right) || isJavaUserInputExpr(right)) {
          taint.add(arrNode.text);
          changed = true;
        }
      }
    }
  }
}

/**
 * Java method names whose output is sanitized regardless of their input.
 * Used in the sink-level check: if a path-construction call (Path.of, Paths.get)
 * is immediately chained through one of these methods, it is NOT a sink.
 */
const JAVA_RESULT_SANITIZING_METHODS = new Set([
  "getFileName",  // Path.getFileName() — strips directory components, safe filename only
]);

/**
 * Returns true if the result of `callNode` passes through a sanitizing method
 * before being used elsewhere.
 *
 * Walks up the parent method_invocation chain from `callNode`.
 * Example (returns true):
 *   Path.of(userInput).getFileName()          ← callNode = Path.of(...), parent = getFileName()
 *   Path.of(userInput).getFileName().toString()← callNode = Path.of(...), parent = getFileName()
 */
function isCallResultSanitized(callNode: Node): boolean {
  let cur: Node | null = callNode.parent;
  while (cur && cur.type === "method_invocation") {
    const name = cur.childForFieldName("name")?.text;
    if (name && JAVA_RESULT_SANITIZING_METHODS.has(name)) return true;
    cur = cur.parent;
  }
  return false;
}

/**
 * Removes formally-validated parameters from the taint set before propagation.
 *
 * Detects two validation-guard patterns used in Java security code:
 *
 * Pattern 1 — Regex whitelist (matches):
 *   if (!var.matches("[A-Za-z0-9_-]+")) { throw new IOException(...); }
 *   → var is guaranteed to contain only safe characters → remove from taint.
 *
 * Pattern 2 — Path traversal blacklist (contains):
 *   if (var.contains("..") || var.contains("/") || var.contains("\\")) { throw ... }
 *   → var cannot contain path traversal sequences → remove from taint.
 *
 * Both patterns require that the if-body unconditionally throws (or returns),
 * ensuring no tainted value can reach the code after the guard.
 *
 * Called BEFORE propagateAssignments so that sanitized parameters do not
 * spread their taint to derived variables.
 */
function applyJavaValidationGuards(root: Node, taint: TaintTracker): void {
  for (const node of walkAll(root)) {
    if (node.type !== "if_statement") continue;

    const condNode  = node.childForFieldName("condition");
    const bodyNode  = node.childForFieldName("consequence");
    if (!condNode || !bodyNode) continue;

    // Body must unconditionally throw (or return early) to act as a guard.
    if (!blockContainsThrowOrReturn(bodyNode)) continue;

    // Extract the variable protected by the guard condition.
    const guardedVar = extractGuardedVar(condNode);
    if (guardedVar && taint.has(guardedVar)) {
      taint.remove(guardedVar);
    }
  }
}

/**
 * Returns true when the block unconditionally throws or returns — meaning
 * any code after the if statement is only reached when the condition was false.
 */
function blockContainsThrowOrReturn(block: Node): boolean {
  for (const child of walkAll(block)) {
    if (child.type === "throw_statement" || child.type === "return_statement") {
      return true;
    }
  }
  return false;
}

/**
 * Extracts the name of the variable being validated by the guard condition.
 *
 * Handles:
 *   !var.matches(regex)              → "var"
 *   var.contains("..") || …         → "var"  (only when arg looks like a path sep)
 *
 * Returns null when the condition doesn't match a known validation pattern.
 */
function extractGuardedVar(condition: Node): string | null {
  // Unwrap Java if-condition parentheses: if (expr) → condition field = parenthesized
  let cond: Node = condition;
  while (cond.type === "parenthesized_expression" && cond.namedChildren.length > 0) {
    cond = cond.namedChildren[0];
  }

  // Pattern 1: !var.matches(regex)
  // AST: unary_expression [ "!" method_invocation { object=identifier, name="matches" } ]
  if (cond.type === "unary_expression") {
    const operand = cond.namedChildren[0];
    if (operand?.type === "method_invocation") {
      const methodName = operand.childForFieldName("name")?.text;
      if (methodName === "matches") {
        const obj = operand.childForFieldName("object");
        if (obj?.type === "identifier") return obj.text;
      }
    }
  }

  // Pattern 2: var.contains("..") || var.contains("/") ...
  // Walk all method_invocations in the condition; the first one whose arg is a
  // path-traversal indicator string identifies the variable being checked.
  for (const child of walkAll(cond)) {
    if (child.type !== "method_invocation") continue;
    const methodName = child.childForFieldName("name")?.text;
    if (methodName !== "contains") continue;
    const argsNode = child.childForFieldName("arguments");
    if (!argsNode) continue;
    // Only treat as a path-traversal guard when the checked string is a
    // well-known dangerous path component: "..", "/", or "\"
    const argText = argsNode.text;
    if (!argText.includes("..") && !argText.includes("/") && !argText.includes("\\\\")) {
      continue;
    }
    const obj = child.childForFieldName("object");
    if (obj?.type === "identifier") return obj.text;
  }

  return null;
}

function buildJavaValueMap(root: Node): Map<string, Node> {
  const map = new Map<string, Node>();
  for (const node of walkAll(root)) {
    if (node.type === "init_declarator") {
      const decl = node.childForFieldName("declarator");
      const val = node.childForFieldName("value");
      if (decl?.type === "identifier" && val) map.set(decl.text, val);
    }
    if (node.type === "assignment_expression") {
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if (left?.type === "identifier" && right) map.set(left.text, right);
    }
  }
  return map;
}

// Sinks that indicate a string literal is used as a credential/key
const CRED_SINK_METHODS = new Set(["getConnection", "connect", "login", "authenticate"]);
const KEY_SINK_TYPES = new Set(["SecretKeySpec", "PBEKeySpec", "SecretKey", "KerberosKey", "PasswordAuthentication"]);
const KEY_SINK_METHODS = new Set(["doFinal", "init", "encrypt", "decrypt", "sign", "verify"]);

function findHardcodedCredentialsJava(
  root: Node, filePath: string, code: string
): Finding[] {
  const findings: Finding[] = [];
  const credVars = /(password|passwd|pwd|secret|apiKey|api_key|token|authToken|accessToken|secretKey|clientSecret|passphrase|phrase|credential|cred|passcode|_pass\b|material|fallback|keyBytes|keyData|keyValue|crypto|cipher)/i;

  // Track string literals assigned to any variable, then check if used in credential sinks
  const literalVars = new Map<string, Node>(); // varName → string/array literal node

  for (const node of walkAll(root)) {
    // Collect all string-literal variable assignments (incl. "str".getBytes())
    if (node.type === "variable_declarator") {
      const nameNode = node.childForFieldName("name");
      const valueNode = node.childForFieldName("value");
      if (nameNode && valueNode) {
        if (valueNode.type === "string_literal" && valueNode.text.length > 5) {
          literalVars.set(nameNode.text, valueNode);
        } else if (valueNode.type === "method_invocation") {
          const obj = valueNode.childForFieldName("object");
          const method = valueNode.childForFieldName("name")?.text;
          if ((method === "getBytes" || method === "toCharArray") && obj?.type === "string_literal" && obj.text.length > 5) {
            literalVars.set(nameNode.text, obj);
          }
        } else if (valueNode.type === "array_initializer" && isHardcodedByteArray(valueNode)) {
          // byte[] SECRET_KEY = {0x41, 0x42, ...} — hardcoded byte array key material
          literalVars.set(nameNode.text, valueNode);
        }
      }
    }

    // Also catch assignment_expression: var = "literal"
    if (node.type === "assignment_expression") {
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if (left?.type === "identifier" && right?.type === "string_literal" && right.text.length > 5) {
        literalVars.set(left.text, right);
      }
    }
  }

  for (const node of walkAll(root)) {
    // Pattern 1: variable name matches credential pattern → string literal value
    if (node.type === "variable_declarator") {
      const nameNode = node.childForFieldName("name");
      const valueNode = node.childForFieldName("value");
      if (!nameNode || !valueNode) continue;
      if (!credVars.test(nameNode.text)) continue;
      const resolvedLit =
        valueNode.type === "string_literal" ? valueNode :
        (valueNode.type === "method_invocation" && (valueNode.childForFieldName("name")?.text === "getBytes" || valueNode.childForFieldName("name")?.text === "toCharArray"))
          ? valueNode.childForFieldName("object") : null;
      if (resolvedLit?.type === "string_literal" && resolvedLit.text.length > 5) {
        const cwe = /key|secret|token/i.test(nameNode.text) ? "CWE-321" : "CWE-259";
        findings.push(makeAstFinding({
          cweId: cwe, ruleId: "ast-hardcoded-cred",
          vulnerability: cwe === "CWE-321" ? "Use of Hard-coded Cryptographic Key" : "Use of Hard-coded Password",
          severity: "high",
          message: `Hard-coded credential assigned to '${nameNode.text}'.`,
          filePath, node: valueNode, code,
        }));
      }
    }

    // Pattern 2: string literal passed directly to credential/key sink methods
    if (node.type === "method_invocation") {
      const methodName = node.childForFieldName("name")?.text ?? "";
      const argsNode = node.childForFieldName("arguments");
      if (!argsNode) continue;
      const args = getJavaArgs(argsNode);

      if (CRED_SINK_METHODS.has(methodName)) {
        // Last arg of getConnection/connect is typically the password
        const lastArg = args[args.length - 1];
        if (lastArg && isHardcodedString(lastArg, literalVars)) {
          findings.push(makeAstFinding({
            cweId: "CWE-259", ruleId: "ast-hardcoded-cred",
            vulnerability: "Use of Hard-coded Password",
            severity: "high",
            message: `Hard-coded password passed to ${methodName}().`,
            filePath, node: lastArg, code,
          }));
        }
      }

      // Pattern 2b: map.put("credential-key", stringLiteral) — hardcoded value in a map
      if (methodName === "put" && args.length >= 2) {
        const keyArg = args[0];
        const valArg = args[1];
        if (keyArg.type === "string_literal" && credVars.test(keyArg.text)
            && isHardcodedString(valArg, literalVars)) {
          const cwe = /key|secret|token|material|cipher|crypto/i.test(keyArg.text) ? "CWE-321" : "CWE-259";
          findings.push(makeAstFinding({
            cweId: cwe, ruleId: "ast-hardcoded-cred",
            vulnerability: cwe === "CWE-321" ? "Use of Hard-coded Cryptographic Key" : "Use of Hard-coded Password",
            severity: "high",
            message: `Hard-coded credential value stored under key ${keyArg.text}.`,
            filePath, node: valArg, code,
          }));
        }
      }
    }

    // Pattern 3: string literal used to construct SecretKeySpec / PBEKeySpec
    if (node.type === "object_creation_expression") {
      const typeNode = node.childForFieldName("type");
      const argsNode = node.childForFieldName("arguments");
      if (!typeNode || !argsNode) continue;
      if (!KEY_SINK_TYPES.has(typeNode.text)) continue;
      const args = getJavaArgs(argsNode);
      // Check all args — password/key may be at any position (e.g. PasswordAuthentication index 1)
      if (args.some(a => isHardcodedKeyMaterial(a, literalVars))) {
        findings.push(makeAstFinding({
          cweId: "CWE-321", ruleId: "ast-hardcoded-cred",
          vulnerability: "Use of Hard-coded Cryptographic Key",
          severity: "high",
          message: `Hard-coded key material passed to ${typeNode.text}.`,
          filePath, node: args[0], code,
        }));
      }
    }
  }
  return findings;
}

function isHardcodedString(node: Node, literalVars: Map<string, Node>): boolean {
  if (node.type === "string_literal") return node.text.length > 5;
  if (node.type === "identifier") return literalVars.has(node.text);
  return false;
}

/**
 * Returns true if the node is a byte array initializer where every element
 * is a compile-time integer/hex literal — i.e. a hardcoded key in byte form.
 * Examples: {0x41, 0x42, 0x43}  or  {65, 66, 67}
 */
function isHardcodedByteArray(node: Node): boolean {
  if (node.type !== "array_initializer") return false;
  const elements = node.namedChildren;
  if (elements.length === 0) return false;
  return elements.every(c =>
    c.type === "decimal_integer_literal" ||
    c.type === "hex_integer_literal" ||
    c.type === "integer_literal" ||
    /^-?0[xX][0-9a-fA-F]+$/.test(c.text) ||
    /^-?\d+$/.test(c.text)
  );
}

function isHardcodedKeyMaterial(node: Node, literalVars: Map<string, Node>): boolean {
  // getBytes() / toCharArray() call on a string literal or literal variable
  if (node.type === "method_invocation") {
    const obj = node.childForFieldName("object");
    const method = node.childForFieldName("name")?.text;
    if ((method === "getBytes" || method === "toCharArray") && obj) {
      return isHardcodedString(obj, literalVars);
    }
  }
  // Inline byte array literal: new SecretKeySpec(new byte[]{0x41, ...}, "AES")
  if (node.type === "array_creation_expression") {
    const init = node.namedChildren.find(c => c.type === "array_initializer");
    if (init && isHardcodedByteArray(init)) return true;
  }
  if (node.type === "array_initializer" && isHardcodedByteArray(node)) return true;
  return isHardcodedString(node, literalVars);
}

/**
 * Returns true if the method containing `sinkNode` has a `startsWith`-based
 * path guard — i.e. validates the resolved path stays inside the base directory.
 *
 * Recognised patterns (dataset-validated):
 *   if (!target.startsWith(base)) throw / return
 *   if (target.startsWith(base) == false) throw / return
 *
 * We scan the raw code text of the enclosing method for the presence of
 * `.startsWith(` after a `.resolve(` call, combined with an early exit.
 * A text scan is sufficient here because the pattern is highly distinctive.
 */
function isJavaPathGuarded(sinkNode: Node, code: string): boolean {
  // Walk up to the enclosing method/constructor declaration
  let cursor: import("web-tree-sitter").Node | null = sinkNode.parent;
  while (cursor) {
    if (cursor.type === "method_declaration" || cursor.type === "constructor_declaration"
        || cursor.type === "lambda_expression") {
      const methodText = code.slice(cursor.startIndex, cursor.endIndex);

      // Guard 1: resolve + startsWith confinement check (canonical Java pattern)
      //   Path target = base.resolve(input).normalize();
      //   if (!target.startsWith(base)) throw ...
      if (/\.startsWith\s*\(/.test(methodText)) return true;

      // Guard 2: string sanitization — replace("..", "") / replace("/", "") / replace("\\", "")
      //   Strips traversal sequences before use
      if (/\.replace\s*\(\s*["'`]\.\.["'`]/.test(methodText)) return true;

      // Guard 3: matches() whitelist — already handled by removeValidatedParams,
      //   but also catch it here for methods that don't call removeValidatedParams
      if (/\.matches\s*\(/.test(methodText)
          && /throw|return\s+null|return\s+""|response\.send|abort/.test(methodText)) return true;

      // Guard 4: contains("..") / contains("/") traversal check
      if (/\.contains\s*\(\s*["']\.\.["']/.test(methodText)
          && /throw|return/.test(methodText)) return true;

      break;
    }
    cursor = cursor.parent;
  }
  return false;
}
