import type { Node, Tree } from "web-tree-sitter";
import { Finding } from "../../analyzer/types";
import { TaintTracker, walkAll } from "./taint";
import { makeAstFinding } from "./utils";

const OOB_WRITE_FUNCS = new Set(["gets", "strcpy", "strcat", "sprintf", "vsprintf"]);
const OVERFLOW_ALLOC_FUNCS = new Set(["malloc", "realloc", "calloc"]);
const OVERFLOW_MEM_FUNCS = new Set(["memcpy", "memmove", "memset"]);
const CMD_FUNCS = new Set([
  // Standard POSIX exec/spawn
  "system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve", "execvpe",
  // Uppercase macro variants (common in Juliet / NIST test suites)
  "SYSTEM", "POPEN", "EXECL", "EXECLP", "EXECLE", "EXECV", "EXECVP", "EXECVE",
  // Windows spawn family
  "_spawnl", "_spawnlp", "_spawnle", "_spawnlpe",
  "_spawnv", "_spawnvp", "_spawnve", "_spawnvpe",
  "posix_spawn", "posix_spawnp",
  // Uppercase spawn macros
  "SPAWNL", "SPAWNV", "SPAWNVP",
]);
// Regex-based: catches MD5/SHA1 regardless of OpenSSL step function variant
// (MD5, MD5_Init, MD5_Update, MD5_Final, EVP_md5, SHA1, SHA1_Init, EVP_sha1, etc.)
const WEAK_HASH_FN = /^(MD[245]|EVP_md[245]|SHA1?|EVP_sha1?)(_Init|_Update|_Final)?$/i;
const CRED_MACROS = /(PASSWORD|PASSWD|PWD|SECRET|API_KEY|APIKEY|TOKEN|AUTH_TOKEN|ACCESS_TOKEN|SECRET_KEY|CLIENT_SECRET|FALLBACK|KEY|PHRASE|PASSPHRASE|MATERIAL)/i;

// Windows Crypto API weak algorithm constants
const WEAK_CALG_CIPHER = new Set(["CALG_3DES", "CALG_3DES_112", "CALG_DES", "CALG_RC2", "CALG_RC4", "CALG_RC5"]);
const WEAK_CALG_HASH = new Set(["CALG_MD5", "CALG_MD4", "CALG_MD2", "CALG_SHA", "CALG_SHA1"]);

// OpenSSL and common C crypto API functions that receive a key as their first argument
const CRYPTO_KEY_SETUP_FUNCS = new Set([
  "AES_set_encrypt_key", "AES_set_decrypt_key",
  "EVP_CipherInit_ex", "EVP_EncryptInit_ex", "EVP_DecryptInit_ex",
  "EVP_CipherInit", "EVP_EncryptInit", "EVP_DecryptInit",
  "DES_set_key", "DES_set_key_checked", "DES_set_key_unchecked",
  "RC4_set_key", "Blowfish_set_key", "BF_set_key",
]);

export function analyzeC(code: string, filePath: string, tree: Tree): Finding[] {
  const findings: Finding[] = [];
  const root = tree.rootNode;
  const freedPointers = new Map<string, Node>();

  // CWE-190 / CWE-787: taint-based integer / OOB detection
  const intTaint = new TaintTracker();
  seedCIntegerSources(root, intTaint);
  seedCIntParamSources(root, intTaint);        // treat int params as potential user input
  intTaint.propagateAssignments(root, isCIntegerSourceExpr);

  // CWE-78: string taint — track char* variables from user-controlled string sources.
  // strTaint: direct user-input vars (fgets, getenv, argv, char* params).
  // snprintfTainted: vars filled by snprintf/sprintf from tainted format args.
  //   Kept separate because system()/popen() detection uses strTaint as a "known" set
  //   (flag if NOT in strTaint and not a literal), while exec() detection needs explicit
  //   taint marking. Merging them would cause safe_allowlist patterns to be falsely flagged.
  const strTaint = new TaintTracker();
  seedCStringSources(root, strTaint);
  seedCStringParamSources(root, strTaint);     // char* params are potential user input
  strTaint.propagateAssignments(root, isCStringSourceExpr);
  const snprintfTainted = buildSnprintfTaintedSet(root, strTaint); // snprintf(buf,..,tainted)→buf

  for (const node of walkAll(root)) {
    // CWE-190: arithmetic on user-controlled integer
    if (node.type === "init_declarator" || node.type === "assignment_expression") {
      const valueNode = node.type === "init_declarator"
        ? node.childForFieldName("value")
        : node.childForFieldName("right");
      if (valueNode && containsArithmetic(valueNode) && intTaint.expressionIsTainted(valueNode)
          && !isProtectedByBoundsCheck(node, valueNode)) {
        findings.push(makeAstFinding({
          cweId: "CWE-190", ruleId: "ast-integer-overflow",
          vulnerability: "Integer Overflow",
          severity: "medium",
          message: "Arithmetic on user-controlled integer may overflow.",
          filePath, node: valueNode, code,
        }));
      }
    }

    // CWE-190: x++ / x-- on tainted integer (update_expression)
    if (node.type === "update_expression") {
      const arg = node.children.find(c => c.type === "identifier");
      if (arg && intTaint.has(arg.text) && !isProtectedByBoundsCheck(node, arg)) {
        findings.push(makeAstFinding({
          cweId: "CWE-190", ruleId: "ast-integer-overflow",
          vulnerability: "Integer Overflow",
          severity: "medium",
          message: `Increment/decrement of user-controlled integer '${arg.text}' may overflow.`,
          filePath, node, code,
        }));
      }
    }

    // CWE-190: x += n / x -= n / x *= n (augmented_assignment on tainted var)
    if (node.type === "augmented_assignment_expression") {
      const left = node.childForFieldName("left");
      if (left?.type === "identifier" && intTaint.has(left.text) && !isProtectedByBoundsCheck(node, left)) {
        findings.push(makeAstFinding({
          cweId: "CWE-190", ruleId: "ast-integer-overflow",
          vulnerability: "Integer Overflow",
          severity: "medium",
          message: `Augmented arithmetic on user-controlled integer '${left.text}' may overflow.`,
          filePath, node, code,
        }));
      }
    }
  }

  for (const node of walkAll(root)) {

    if (node.type === "call_expression") {
      const fnNode = node.childForFieldName("function");
      const argsNode = node.childForFieldName("arguments");
      const fnName = fnNode?.text ?? "";

      // CWE-787: out-of-bounds write
      // For strcpy/strcat: only flag if the source (2nd arg) is non-literal (tainted or identifier)
      // gets/sprintf/vsprintf are always unsafe regardless of args
      if (OOB_WRITE_FUNCS.has(fnName)) {
        const alwaysUnsafe = fnName === "gets" || fnName === "sprintf" || fnName === "vsprintf";
        const srcArg = argsNode ? getArgs(argsNode)[1] : undefined;
        const srcIsLiteral = srcArg ? isStringLiteral(srcArg) : false;
        if (alwaysUnsafe || !srcIsLiteral) {
          findings.push(makeAstFinding({
            cweId: "CWE-787", ruleId: "ast-oob-write",
            vulnerability: "Out-of-bounds Write",
            severity: "high",
            message: `${fnName}() does not perform bounds checking and may write past a buffer.`,
            filePath, node, code,
          }));
        }
      }

      // Also catch scanf with %s
      if ((fnName === "scanf" || fnName === "fscanf" || fnName === "sscanf") && argsNode) {
        const args = getArgs(argsNode);
        const fmt = args.find(a => a.text.includes("%s"));
        if (fmt) {
          findings.push(makeAstFinding({
            cweId: "CWE-787", ruleId: "ast-oob-write",
            vulnerability: "Out-of-bounds Write",
            severity: "high",
            message: `${fnName}() with %s format specifier may write past buffer bounds.`,
            filePath, node, code,
          }));
        }
      }

      // CWE-787: strncpy/strncat(dest, src, strlen(src)) — size arg is source length,
      // not remaining space in destination. Both functions have this classic misuse pattern.
      if ((fnName === "strncpy" || fnName === "strncat") && argsNode) {
        const args = getArgs(argsNode);
        if (args.length >= 3 && args[2].type === "call_expression") {
          const sizeCallFn = args[2].childForFieldName("function")?.text ?? "";
          if (sizeCallFn === "strlen") {
            findings.push(makeAstFinding({
              cweId: "CWE-787", ruleId: "ast-oob-write",
              vulnerability: "Out-of-bounds Write",
              severity: "high",
              message: `${fnName}() with strlen() as size uses source length, not destination capacity.`,
              filePath, node, code,
            }));
          }
        }
      }

      // CWE-78: command injection
      if (CMD_FUNCS.has(fnName) && argsNode) {
        const args = getArgs(argsNode);
        if (args.length > 0) {
          // For system/popen: the entire first arg is the shell command — flag if:
          //   (a) non-literal AND not a directly-tracked user-input var (unknown provenance), OR
          //   (b) built by snprintf from tainted format args (explicit taint chain)
          const isShellFunc = fnName.toLowerCase() === "system" || fnName.toLowerCase() === "popen";
          if (isShellFunc) {
            const argText = args[0]?.text ?? "";
            const isSnprintfDerived = snprintfTainted.has(argText);
            const isUnknown = !isStringLiteral(args[0]) && !isNullOrConstant(args[0]) && !strTaint.has(argText);
            if (isSnprintfDerived || isUnknown) {
              findings.push(makeAstFinding({
                cweId: "CWE-78", ruleId: "ast-cmd-injection",
                vulnerability: "OS Command Injection",
                severity: "high",
                message: `${fnName}() receives a non-literal command argument.`,
                filePath, node, code,
              }));
            }
          } else {
            // For exec/spawn family: flag if any arg is directly tainted (strTaint/intTaint)
            // OR was built by snprintf from tainted input (snprintfTainted).
            const pathArgIdx = fnName.startsWith("_spawn") ? 1 : 0; // _spawnX has mode as arg[0]
            const pathArg = args[pathArgIdx];
            const anyTainted = args.some(a =>
              strTaint.expressionIsTainted(a) || intTaint.expressionIsTainted(a) ||
              snprintfTainted.has(a.text ?? "")
            );
            if (anyTainted || (pathArg && !isStringLiteral(pathArg) && !isNullOrConstant(pathArg))) {
              findings.push(makeAstFinding({
                cweId: "CWE-78", ruleId: "ast-cmd-injection",
                vulnerability: "OS Command Injection",
                severity: "high",
                message: `${fnName}() receives user-controlled argument.`,
                filePath, node, code,
              }));
            }
          }
        }
      }

      // CWE-190: integer overflow in allocation/memory functions.
      // Flag when the size argument contains arithmetic that is not purely compile-time constant.
      // Pure constant arithmetic (e.g. 5 * sizeof(char), 44 * sizeof(int)) cannot overflow at
      // runtime, so skip those to avoid FPs. Non-constant operands (identifiers, calls, field
      // expressions) indicate runtime values that can carry an overflowed quantity.
      if (OVERFLOW_ALLOC_FUNCS.has(fnName) && argsNode) {
        const args = getArgs(argsNode);
        const sizeArg = fnName === "realloc" ? args[1] : args[0];
        if (sizeArg && containsArithmetic(sizeArg) && !isConstantSizeExpr(sizeArg)
            && !isProtectedByBoundsCheck(node, sizeArg)) {
          findings.push(makeAstFinding({
            cweId: "CWE-190", ruleId: "ast-integer-overflow",
            vulnerability: "Integer Overflow",
            severity: "medium",
            message: `${fnName}() size argument contains arithmetic that may overflow.`,
            filePath, node: sizeArg, code,
          }));
        }
      }

      if (OVERFLOW_MEM_FUNCS.has(fnName) && argsNode) {
        const args = getArgs(argsNode);
        const sizeArg = args[2];
        if (sizeArg && containsArithmetic(sizeArg) && !isConstantSizeExpr(sizeArg)
            && !isProtectedByBoundsCheck(node, sizeArg)) {
          findings.push(makeAstFinding({
            cweId: "CWE-190", ruleId: "ast-integer-overflow",
            vulnerability: "Integer Overflow",
            severity: "medium",
            message: `${fnName}() size argument contains arithmetic that may overflow.`,
            filePath, node: sizeArg, code,
          }));
        }
        // CWE-787: tainted offset in destination pointer — memcpy(buf + user_offset, src, n)
        const destArg = args[0];
        if (destArg && destArg.type === "binary_expression"
            && intTaint.expressionIsTainted(destArg)
            && !isProtectedByBoundsCheck(node, destArg)) {
          findings.push(makeAstFinding({
            cweId: "CWE-787", ruleId: "ast-oob-write",
            vulnerability: "Out-of-bounds Write",
            severity: "high",
            message: `${fnName}() destination pointer uses user-controlled offset without bounds check.`,
            filePath, node: destArg, code,
          }));
        }
      }

      // CWE-416: use-after-free — track free() calls
      if (fnName === "free" && argsNode) {
        const args = getArgs(argsNode);
        if (args.length > 0 && args[0].type === "identifier") {
          freedPointers.set(args[0].text, node);
        }
      }

      // CWE-328: weak hash — hashes are CWE-328 only; weak ciphers are CWE-327.
      if (WEAK_HASH_FN.test(fnName)) {
        findings.push(makeAstFinding({
          cweId: "CWE-328", ruleId: "ast-weak-hash",
          vulnerability: "Use of Weak Hash",
          severity: "medium",
          message: `${fnName}() uses a weak hashing algorithm (MD5/SHA1).`,
          filePath, node, code,
        }));
      }

      // CWE-327: Windows Crypto API — CryptDeriveKey/CryptEncrypt with weak cipher
      if ((fnName === "CryptDeriveKey" || fnName === "CryptEncrypt" || fnName === "CryptDecrypt") && argsNode) {
        const args = getArgs(argsNode);
        const algoArg = args[1]; // second arg is the algorithm constant
        if (algoArg && WEAK_CALG_CIPHER.has(algoArg.text)) {
          findings.push(makeAstFinding({
            cweId: "CWE-327", ruleId: "ast-weak-wincrypt-cipher",
            vulnerability: "Use of Broken Cryptographic Algorithm",
            severity: "medium",
            message: `${fnName}() uses ${algoArg.text}, a weak or broken cipher.`,
            filePath, node: algoArg, code,
          }));
        }
      }

      // CWE-328: Windows Crypto API — CryptCreateHash with a weak hash algorithm.
      if (fnName === "CryptCreateHash" && argsNode) {
        const args = getArgs(argsNode);
        const algoArg = args[1]; // second arg is the algorithm constant
        if (algoArg && WEAK_CALG_HASH.has(algoArg.text)) {
          findings.push(makeAstFinding({
            cweId: "CWE-328", ruleId: "ast-weak-wincrypt-hash",
            vulnerability: "Use of Weak Hash",
            severity: "medium",
            message: `CryptCreateHash() uses ${algoArg.text}, a weak hashing algorithm.`,
            filePath, node: algoArg, code,
          }));
        }
      }
    }

    // CWE-787: array subscript write with tainted index — arr[user_input] = val
    if (node.type === "assignment_expression") {
      const left = node.childForFieldName("left");
      if (left?.type === "subscript_expression") {
        const index = left.childForFieldName("index");
        if (index && intTaint.expressionIsTainted(index) && !isProtectedByBoundsCheck(node, index)) {
          findings.push(makeAstFinding({
            cweId: "CWE-787", ruleId: "ast-oob-write",
            vulnerability: "Out-of-bounds Write",
            severity: "high",
            message: "Array write uses user-controlled index without bounds check.",
            filePath, node: index, code,
          }));
        }
      }
      // CWE-787: pointer arithmetic write — *(ptr + user_input) = val
      if (left?.type === "pointer_expression" || left?.type === "unary_expression") {
        const arg = left.children.find(c => c.type !== "*" && c.type !== "(" && c.type !== ")");
        if (arg && intTaint.expressionIsTainted(arg) && !isProtectedByBoundsCheck(node, arg)) {
          findings.push(makeAstFinding({
            cweId: "CWE-787", ruleId: "ast-oob-write",
            vulnerability: "Out-of-bounds Write",
            severity: "high",
            message: "Pointer write uses user-controlled offset without bounds check.",
            filePath, node: arg, code,
          }));
        }
      }
    }

    // CWE-787: loop writes to array with user-controlled access
    // Two cases:
    //   (1) the array index itself is tainted (direct control)
    //   (2) the loop condition contains a tainted bound (e.g. i < user_n)
    //       catches the common pattern where i is an untainted counter
    // In both cases: skip if the index is protected by a visible bounds check
    // (e.g. while (write_head < sizeof(buf)) correctly bounds the write).
    if (node.type === "for_statement" || node.type === "while_statement") {
      const condition = node.childForFieldName("condition");
      const conditionTainted = condition != null && intTaint.expressionIsTainted(condition);
      const body = node.childForFieldName("body");
      if (body) {
        for (const inner of walkAll(body)) {
          if (inner.type === "assignment_expression") {
            const left = inner.childForFieldName("left");
            if (left?.type === "subscript_expression") {
              const index = left.childForFieldName("index");
              if (!index) continue;
              const indexTainted = intTaint.expressionIsTainted(index);
              if ((indexTainted || conditionTainted)
                  && !isProtectedByBoundsCheck(inner, index)) {
                findings.push(makeAstFinding({
                  cweId: "CWE-787", ruleId: "ast-oob-write",
                  vulnerability: "Out-of-bounds Write",
                  severity: "high",
                  message: "Loop writes to array using a user-controlled bound or index without bounds check.",
                  filePath, node: index, code,
                }));
                break;
              }
            }
          }
        }
      }
    }

    // CWE-416: C++ delete — track delete p and delete[] p expressions.
    // tree-sitter-c parses these as declaration/subscript_expression (see isInsideDeleteStatement).
    if (node.type === "declaration") {
      const first = node.children[0];
      if (first?.type === "type_identifier" && first.text === "delete") {
        const ident = node.children.find(c => c.type === "identifier");
        if (ident) freedPointers.set(ident.text, node);
      }
    }
    if (node.type === "expression_statement") {
      const inner = node.namedChildren[0];
      if (inner?.type === "subscript_expression") {
        const firstNamed = inner.namedChildren[0];
        if (firstNamed?.type === "identifier" && firstNamed.text === "delete") {
          const ptrIdent = inner.namedChildren.find((c, i) => i > 0 && c.type === "identifier");
          if (ptrIdent) freedPointers.set(ptrIdent.text, node);
        }
      }
    }

    // CWE-416: use-after-free — detect use of freed pointer
    if (node.type === "identifier" && freedPointers.has(node.text)) {
      const parent = node.parent;
      if (parent && !isInsideFreeCall(node) && !isInsideDeleteStatement(node) && !isAssignmentTarget(parent, node)) {
        const freeNode = freedPointers.get(node.text)!;
        if (node.startIndex > freeNode.startIndex) {
          findings.push(makeAstFinding({
            cweId: "CWE-416", ruleId: "ast-use-after-free",
            vulnerability: "Use After Free",
            severity: "high",
            message: `Pointer '${node.text}' is used after being freed.`,
            filePath, node, code,
          }));
          freedPointers.delete(node.text);
        }
      }
    }

    // Reset freed pointer if reassigned
    if (node.type === "assignment_expression") {
      const left = node.childForFieldName("left");
      if (left && freedPointers.has(left.text)) {
        freedPointers.delete(left.text);
      }
    }

    // CWE-259/321: hardcoded credentials in #define macros
    if (node.type === "preproc_def") {
      const nameNode = node.childForFieldName("name");
      const valueNode = node.childForFieldName("value");
      if (nameNode && valueNode && CRED_MACROS.test(nameNode.text)) {
        const val = valueNode.text.trim();
        if ((val.startsWith('"') || val.startsWith('L"') || val.startsWith('u"') || val.startsWith('U"')) && val.length > 5) {
          const cwe = /KEY|SECRET|TOKEN/i.test(nameNode.text) ? "CWE-321" : "CWE-259";
          findings.push(makeAstFinding({
            cweId: cwe, ruleId: "ast-hardcoded-cred",
            vulnerability: cwe === "CWE-321" ? "Use of Hard-coded Cryptographic Key" : "Use of Hard-coded Password",
            severity: "high",
            message: `Hard-coded credential in macro '${nameNode.text}'.`,
            filePath, node: valueNode, code,
          }));
        }
      }
    }

    // CWE-321: hardcoded crypto key in variable declaration
    //   const unsigned char AES_KEY[] = "0123456789abcdef";
    //   static char key[16] = "hardcoded_secret";
    // Only fires on const/static declarations — mutable locals can be overwritten at runtime
    // and are rarely actual hardcoded crypto keys.
    if (node.type === "declaration") {
      const declText = node.text;
      const isConstOrStatic = /\b(const|static)\b/.test(declText);
      if (!isConstOrStatic) continue;

      for (const child of walkAll(node)) {
        if (child.type !== "init_declarator") continue;
        const declNode = child.childForFieldName("declarator");
        const valueNode = child.childForFieldName("value");
        if (!declNode || !valueNode) continue;
        if (!isStringLiteral(valueNode) || valueNode.text.length <= 5) continue;
        // Extract the variable name (may be wrapped in array_declarator)
        const nameText = declNode.type === "array_declarator"
          ? (declNode.childForFieldName("declarator") ?? declNode.namedChildren[0])?.text
          : declNode.type === "identifier" ? declNode.text : undefined;
        if (!nameText || !CRED_MACROS.test(nameText)) continue;
        findings.push(makeAstFinding({
          cweId: "CWE-321", ruleId: "ast-hardcoded-cred",
          vulnerability: "Use of Hard-coded Cryptographic Key",
          severity: "high",
          message: `Hard-coded key material in variable '${nameText}'.`,
          filePath, node: valueNode, code,
        }));
      }
    }

    // CWE-321: string literal or key-named variable passed to crypto key setup function
    //   AES_set_encrypt_key("hardcoded", 128, &key);
    //   AES_set_encrypt_key(AES_KEY_BYTES, 128, &key);
    if (node.type === "call_expression") {
      const fnName = node.childForFieldName("function")?.text ?? "";
      if (CRYPTO_KEY_SETUP_FUNCS.has(fnName)) {
        const argsNode = node.childForFieldName("arguments");
        if (argsNode) {
          const args = getArgs(argsNode);
          const keyArg = args[0]; // first arg is always the key
          // Only flag: direct string literals, or ALL_CAPS identifiers (static const / #define constants).
          // Skip lowercase/camelCase locals like `key` — those are typically runtime-generated.
          const isHardcodedKeyArg = keyArg && (
            isStringLiteral(keyArg) ||
            (keyArg.type === "identifier" && /^[A-Z][A-Z0-9_]{3,}$/.test(keyArg.text) && CRED_MACROS.test(keyArg.text))
          );
          if (isHardcodedKeyArg) {
            findings.push(makeAstFinding({
              cweId: "CWE-321", ruleId: "ast-hardcoded-cred",
              vulnerability: "Use of Hard-coded Cryptographic Key",
              severity: "high",
              message: `Hard-coded key material passed to ${fnName}().`,
              filePath, node: keyArg, code,
            }));
          }
        }
      }
    }
  }

  // CWE-190: constant overflow (CHAR_MAX/INT_MAX arithmetic, no user input needed)
  findings.push(...findConstantOverflows(root, filePath, code));

  // CWE-787: constant-based OOB patterns (no taint needed)
  findings.push(...findConstantOobWrites(root, filePath, code));

  return findings;
}

function getArgs(argsNode: Node): Node[] {
  return argsNode.children.filter(c => c.type !== "," && c.type !== "(" && c.type !== ")");
}

function isStringLiteral(node: Node): boolean {
  return node.type === "string_literal" || node.type === "concatenated_string";
}

// NULL pointer, numeric literals, or ALL_CAPS constants (macro-defined path/flag constants)
function isNullOrConstant(node: Node): boolean {
  if (node.type === "null" || node.text === "NULL") return true;
  if (node.type === "number_literal") return true;
  // ALL_CAPS identifiers are typically #define constants (e.g. CMD_PATH, _P_WAIT)
  if (node.type === "identifier" && /^[A-Z_][A-Z0-9_]*$/.test(node.text)) return true;
  return false;
}

function containsArithmetic(node: Node): boolean {
  if (node.type === "binary_expression") {
    const op = node.children.find(c => c.type === "+" || c.type === "*" || c.type === "-");
    if (op) return true;
  }
  if (node.type === "update_expression") return true;
  return node.children.some(c => containsArithmetic(c));
}

/** Returns true iff every operand in the size expression is a compile-time constant:
 *  number literals, sizeof(...), casts of constants, or constant arithmetic.
 *  Identifiers, field expressions, and call expressions make it non-constant.
 *  Examples that ARE constant:  5 * sizeof(char),  (size_t)44 * sizeof(int)
 *  Examples that are NOT constant:  amount * sizeof(int),  strlen(val) + 1
 */
function isConstantSizeExpr(node: Node): boolean {
  switch (node.type) {
    case "number_literal":
      return true;
    case "sizeof_expression":
      return true;
    case "parenthesized_expression": {
      const inner = node.namedChildren[0];
      return inner ? isConstantSizeExpr(inner) : true;
    }
    case "cast_expression":
    case "binary_expression":
      return node.namedChildren.every(c => isConstantSizeExpr(c));
    case "primitive_type":
    case "type_identifier":
      return true; // type children inside cast_expression or sizeof
    default:
      return false; // identifiers, field_expressions, call_expressions → not constant
  }
}

function isProtectedByBoundsCheck(callNode: Node, sizeArg: Node): boolean {
  const vars = collectIdentifiers(sizeArg);
  if (vars.size === 0) return false;

  let cursor: Node | null = callNode.parent;
  let depth = 0;
  while (cursor && depth < 15) {
    if (cursor.type === "if_statement" || cursor.type === "for_statement" || cursor.type === "while_statement") {
      const condition = cursor.childForFieldName("condition");
      if (condition) {
        const ctext = condition.text;
        // In loop conditions (for/while), a numeric literal bound (e.g. pos < 10) controls
        // iteration COUNT, not byte capacity — do NOT treat it as a bounds protection.
        // Only sizeof(...) is byte-accurate and safe to trust in loop conditions.
        // In if_statement conditions, numeric literal bounds are fine (e.g. if (n < 100)).
        const isLoop = cursor.type === "for_statement" || cursor.type === "while_statement";
        for (const v of vars) {
          if (!new RegExp(`\\b${v}\\b`).test(ctext)) continue;
          // Boundary constant check (INT_MAX / UINT_MAX / SIZE_MAX) — always valid
          if (/INT_MAX|UINT_MAX|INT_MIN|SIZE_MAX/.test(ctext)) return true;
          // sizeof(...) as upper bound — always valid (byte-accurate).
          // Allow optional cast expression between operator and sizeof:
          //   v < sizeof(buf)          → direct comparison
          //   v < (int)sizeof(buf)     → cast before sizeof
          //   v < (size_t)sizeof(buf)  → cast before sizeof
          if (new RegExp(`\\b${v}\\s*<=?\\s*(?:\\([^)]*\\)\\s*)?sizeof\\s*\\(`).test(ctext)) return true;
          if (new RegExp(`sizeof\\s*\\([^)]*\\)\\s*(?:\\([^)]*\\)\\s*)?>=?\\s*\\b${v}\\b`).test(ctext)) return true;
          // Numeric literal bounds: only trust in if_statement (not loop conditions)
          if (!isLoop) {
            if (new RegExp(`\\b${v}\\s*<=?\\s*\\d+`).test(ctext)) return true;
            if (new RegExp(`\\d+\\s*>=?\\s*\\b${v}\\b`).test(ctext)) return true;
          }
        }
      }
    }
    cursor = cursor.parent;
    depth++;
  }
  return false;
}

function collectIdentifiers(node: Node): Set<string> {
  const ids = new Set<string>();
  for (const n of walkAll(node)) {
    if (n.type === "identifier") ids.add(n.text);
  }
  return ids;
}

function seedCIntegerSources(root: Node, taint: TaintTracker): void {
  for (const node of walkAll(root)) {
    if (node.type !== "call_expression") continue;
    const fn = node.childForFieldName("function")?.text ?? "";
    const argsNode = node.childForFieldName("arguments");
    if (!argsNode) continue;
    if (fn === "scanf" || fn === "fscanf" || fn === "sscanf") {
      for (const m of argsNode.text.matchAll(/&([a-zA-Z_][a-zA-Z0-9_]*)/g)) {
        taint.add(m[1]);
      }
    }
  }
}

// Seed integer-typed formal parameters as potentially user-controlled
const C_INT_TYPES = /^(int|size_t|ssize_t|long|unsigned|uint32_t|uint64_t|int32_t|int64_t|ptrdiff_t)$/;

function seedCIntParamSources(root: Node, taint: TaintTracker): void {
  for (const node of walkAll(root)) {
    if (node.type !== "function_definition") continue;
    const declarator = node.childForFieldName("declarator");
    if (!declarator) continue;
    // Find the parameter_list inside the declarator
    for (const child of walkAll(declarator)) {
      if (child.type !== "parameter_declaration") continue;
      const type = child.childForFieldName("type")?.text ?? "";
      if (!C_INT_TYPES.test(type.trim())) continue;
      // The parameter name is the last identifier child
      const decl = child.childForFieldName("declarator");
      const name = decl?.type === "identifier" ? decl.text : decl?.children.find(c => c.type === "identifier")?.text;
      if (name) taint.add(name);
    }
  }
}

function isCIntegerSourceExpr(node: Node): boolean {
  const text = node.text;
  return /\batoi\s*\(/.test(text) ||
         /\bstrtol\s*\(/.test(text) ||
         /\bstrtoul\s*\(/.test(text) ||
         /\batol\s*\(/.test(text) ||
         /\bstrtoll\s*\(/.test(text) ||
         /\bstrtoull\s*\(/.test(text) ||
         /\bgetenv\s*\(/.test(text) ||
         /\brand\s*\(/.test(text) ||
         /\brand_r\s*\(/.test(text) ||
         /\brecv\s*\(/.test(text) ||
         /\bread\s*\(/.test(text) ||
         /\bfread\s*\(/.test(text) ||
         /\bfgets\s*\(/.test(text) ||
         /\bgetchar\s*\(/.test(text) ||
         /\bgetc\s*\(/.test(text);
}

// ─── Sizeof table (approximate 64-bit LP64 sizes) ────────────────────────────
const SIZEOF_BYTES = new Map<string, number>([
  ["char", 1], ["unsigned char", 1], ["signed char", 1],
  ["short", 2], ["unsigned short", 2], ["short int", 2], ["unsigned short int", 2],
  ["int", 4], ["unsigned int", 4], ["signed int", 4], ["unsigned", 4],
  ["long", 8], ["unsigned long", 8], ["long int", 8], ["unsigned long int", 8],
  ["long long", 8], ["long long int", 8], ["unsigned long long", 8], ["unsigned long long int", 8],
  ["int8_t", 1],  ["uint8_t", 1],
  ["int16_t", 2], ["uint16_t", 2],
  ["int32_t", 4], ["uint32_t", 4],
  ["int64_t", 8], ["uint64_t", 8],
  ["float", 4], ["double", 8], ["long double", 16],
  ["wchar_t", 4], ["size_t", 8], ["ptrdiff_t", 8], ["ssize_t", 8],
]);

/**
 * Evaluate a C size expression to a number of bytes.
 * Returns null if the expression is not a compile-time constant or uses unknown types.
 * Handles: literals, sizeof(T), casts, binary arithmetic (+,-,*,/), identifiers in constMap.
 */
function evaluateSizeBytes(node: Node, constMap: Map<string, number>): number | null {
  if (!node) return null;
  switch (node.type) {
    case "number_literal": {
      const val = parseInt(node.text.replace(/[uUlLfF]+$/, ""), 10);
      return isNaN(val) ? null : val;
    }
    case "sizeof_expression": {
      const typeNode = node.childForFieldName("type") ?? node.namedChildren[0];
      if (!typeNode) return null;
      const typeName = typeNode.text.trim().replace(/\s+/g, " ").replace(/\s*\*\s*/g, "");
      return SIZEOF_BYTES.get(typeName) ?? null;
    }
    case "parenthesized_expression": {
      const inner = node.namedChildren[node.namedChildren.length - 1];
      return inner ? evaluateSizeBytes(inner, constMap) : null;
    }
    case "cast_expression": {
      // (T)expr — evaluate the value being cast (last named child)
      const val = node.namedChildren[node.namedChildren.length - 1];
      return val ? evaluateSizeBytes(val, constMap) : null;
    }
    case "binary_expression": {
      const op = node.children.find(c => !c.isNamed)?.type;
      const named = node.namedChildren;
      if (named.length < 2 || !op) return null;
      const lv = evaluateSizeBytes(named[0], constMap);
      const rv = evaluateSizeBytes(named[named.length - 1], constMap);
      if (lv === null || rv === null) return null;
      switch (op) {
        case "*": return lv * rv;
        case "+": return lv + rv;
        case "-": return lv - rv;
        case "/": return rv !== 0 ? Math.trunc(lv / rv) : null;
        default:  return null;
      }
    }
    case "unary_expression": {
      const op = node.children.find(c => !c.isNamed)?.type;
      if (op === "-") {
        const inner = node.namedChildren[0];
        const val = inner ? evaluateSizeBytes(inner, constMap) : null;
        return val !== null ? -val : null;
      }
      return null;
    }
    case "identifier":
      return constMap.get(node.text) ?? null;
    default:
      return null;
  }
}

/**
 * Build a map of variable name → bytes allocated, from malloc/alloca/calloc calls
 * and stack array declarations.
 * Only records entries where the size is fully compile-time constant.
 */
function buildAllocSizeMap(root: Node, constMap: Map<string, number>): Map<string, number> {
  const map = new Map<string, number>();

  for (const node of walkAll(root)) {
    // init_declarator: T *ptr = malloc(N)  /  T *ptr = (T*)malloc(N)
    if (node.type === "init_declarator") {
      const name = getInnermostIdentifier(node.childForFieldName("declarator"));
      const valueNode = node.childForFieldName("value");
      if (!name || !valueNode) continue;

      const call = stripCastExpr(valueNode);
      if (call?.type === "call_expression") {
        const fn = call.childForFieldName("function")?.text ?? "";
        const argsNode = call.childForFieldName("arguments");
        if (!argsNode) continue;
        const args = getArgs(argsNode);
        if (fn === "malloc" || fn === "alloca") {
          const bytes = args[0] ? evaluateSizeBytes(args[0], constMap) : null;
          if (bytes !== null && bytes > 0) map.set(name, bytes);
        } else if (fn === "calloc" && args.length >= 2) {
          const count = evaluateSizeBytes(args[0], constMap);
          const size  = evaluateSizeBytes(args[1], constMap);
          if (count !== null && size !== null) map.set(name, count * size);
        }
      }
    }

    // assignment_expression: ptr = malloc(N)
    if (node.type === "assignment_expression") {
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if (left?.type !== "identifier" || !right) continue;
      const call = stripCastExpr(right);
      if (call?.type !== "call_expression") continue;
      const fn = call.childForFieldName("function")?.text ?? "";
      const argsNode = call.childForFieldName("arguments");
      if (!argsNode) continue;
      const args = getArgs(argsNode);
      if (fn === "malloc" || fn === "alloca") {
        const bytes = args[0] ? evaluateSizeBytes(args[0], constMap) : null;
        if (bytes !== null && bytes > 0) map.set(left.text, bytes);
      } else if (fn === "calloc" && args.length >= 2) {
        const count = evaluateSizeBytes(args[0], constMap);
        const size  = evaluateSizeBytes(args[1], constMap);
        if (count !== null && size !== null) map.set(left.text, count * size);
      }
    }
  }
  return map;
}

/** Strip cast/parenthesis wrappers to reach the underlying expression. */
function stripCastExpr(node: Node): Node | null {
  if (!node) return null;
  if (node.type === "cast_expression" || node.type === "parenthesized_expression") {
    const inner = node.namedChildren[node.namedChildren.length - 1];
    return inner ? stripCastExpr(inner) : null;
  }
  return node;
}

/** Walk declarator children to find the innermost identifier. */
function getInnermostIdentifier(node: Node | null | undefined): string | null {
  if (!node) return null;
  if (node.type === "identifier") return node.text;
  for (const child of node.namedChildren) {
    const name = getInnermostIdentifier(child);
    if (name) return name;
  }
  return null;
}

/**
 * Build a simple compile-time integer constant map for C.
 * Handles: int x = N (literal), int x = -N (negation), int x = A * B (binary).
 */
function buildCConstMap(root: Node): Map<string, number> {
  const map = new Map<string, number>();
  let changed = true;
  while (changed) {
    changed = false;
    for (const node of walkAll(root)) {
      if (node.type !== "init_declarator" && node.type !== "assignment_expression") continue;
      const name = node.type === "init_declarator"
        ? getInnermostIdentifier(node.childForFieldName("declarator"))
        : node.childForFieldName("left")?.type === "identifier"
          ? node.childForFieldName("left")?.text ?? null
          : null;
      const rhs = node.type === "init_declarator"
        ? node.childForFieldName("value")
        : node.childForFieldName("right");
      if (!name || !rhs || map.has(name)) continue;
      const val = evaluateSizeBytes(rhs, map);
      if (val !== null) { map.set(name, val); changed = true; }
    }
  }
  return map;
}

/**
 * Detect three classes of constant-derivable OOB writes that don't require taint:
 *
 * A. memcpy/memmove where copy_bytes > alloc_bytes of destination.
 *    e.g. malloc(120) then memcpy(ptr, src, 120 * sizeof(int)) [480 > 120]
 *
 * B. Pointer underflow: ptr = base - POSITIVE_CONST, then any write via ptr.
 *    e.g. ptr = buffer - 8; ptr[i] = ...  — writes before the allocated buffer.
 *
 * C. Negative constant array index: arr[ind] = val where ind is a known negative constant.
 *    e.g. int ind = -5; arr[ind] = 1  — always writes before the array.
 */
function findConstantOobWrites(root: Node, filePath: string, code: string): Finding[] {
  const findings: Finding[] = [];
  const constMap = buildCConstMap(root);
  const allocMap = buildAllocSizeMap(root, constMap);

  // ── B: build underflow pointer set ──────────────────────────────────────────
  // Track pointers set to (something - positive_constant), i.e. ptr = base - N (N > 0).
  // Any subsequent write through such a pointer is an OOB write before the buffer.
  const underflowPtrs = new Set<string>();
  for (const node of walkAll(root)) {
    const rhs = node.type === "init_declarator" ? node.childForFieldName("value")
              : node.type === "assignment_expression" ? node.childForFieldName("right")
              : null;
    const lhsName = node.type === "init_declarator"
      ? getInnermostIdentifier(node.childForFieldName("declarator"))
      : node.childForFieldName("left")?.type === "identifier"
        ? node.childForFieldName("left")?.text ?? null
        : null;
    if (!rhs || !lhsName) continue;

    // RHS is a binary_expression with operator '-' and a positive constant right operand
    if (rhs.type === "binary_expression") {
      const op = rhs.children.find(c => !c.isNamed)?.type;
      if (op === "-") {
        const rightOperand = rhs.namedChildren[rhs.namedChildren.length - 1];
        const val = rightOperand ? evaluateSizeBytes(rightOperand, constMap) : null;
        if (val !== null && val > 0) {
          underflowPtrs.add(lhsName);
        }
      }
    }
  }

  for (const node of walkAll(root)) {

    // ── A: memcpy/memmove copy_bytes > alloc_bytes ───────────────────────────
    if (node.type === "call_expression") {
      const fnName = node.childForFieldName("function")?.text ?? "";
      const argsNode = node.childForFieldName("arguments");
      if ((fnName === "memcpy" || fnName === "memmove") && argsNode) {
        const args = getArgs(argsNode);
        if (args.length >= 3) {
          const destName = getInnermostIdentifier(args[0]) ?? args[0].text;
          const allocBytes = allocMap.get(destName) ?? null;
          const copyBytes  = evaluateSizeBytes(args[2], constMap);
          if (allocBytes !== null && copyBytes !== null && copyBytes > allocBytes) {
            findings.push(makeAstFinding({
              cweId: "CWE-787", ruleId: "ast-oob-write",
              vulnerability: "Out-of-bounds Write",
              severity: "high",
              message: `${fnName}() copies ${copyBytes} bytes into a ${allocBytes}-byte buffer.`,
              filePath, node, code,
            }));
          }
        }
      }

      // ── B: write via underflow pointer (memcpy/memmove/strncpy destination) ─
      if ((fnName === "memcpy" || fnName === "memmove" || fnName === "strncpy"
           || fnName === "wmemmove" || fnName === "wmemcpy") && argsNode) {
        const args = getArgs(argsNode);
        const destName = args[0] ? getInnermostIdentifier(args[0]) ?? args[0].text : null;
        if (destName && underflowPtrs.has(destName)) {
          findings.push(makeAstFinding({
            cweId: "CWE-787", ruleId: "ast-oob-write",
            vulnerability: "Out-of-bounds Write",
            severity: "high",
            message: `${fnName}() destination pointer is set before its buffer (pointer underflow).`,
            filePath, node, code,
          }));
        }
      }
    }

    // ── B: write via underflow pointer (subscript write: ptr[i] = val) ───────
    if (node.type === "assignment_expression") {
      const left = node.childForFieldName("left");
      if (left?.type === "subscript_expression") {
        const obj = left.childForFieldName("argument") ?? left.namedChildren[0];
        const objName = obj?.type === "identifier" ? obj.text : null;
        if (objName && underflowPtrs.has(objName)) {
          findings.push(makeAstFinding({
            cweId: "CWE-787", ruleId: "ast-oob-write",
            vulnerability: "Out-of-bounds Write",
            severity: "high",
            message: `Write via '${objName}' which points before its buffer (pointer underflow).`,
            filePath, node, code,
          }));
        }
      }

      // ── C: negative constant array index ──────────────────────────────────
      if (left?.type === "subscript_expression") {
        const index = left.childForFieldName("index");
        if (index) {
          const idxVal = evaluateSizeBytes(index, constMap)
            ?? (index.type === "identifier" ? constMap.get(index.text) ?? null : null);
          if (idxVal !== null && idxVal < 0) {
            findings.push(makeAstFinding({
              cweId: "CWE-787", ruleId: "ast-oob-write",
              vulnerability: "Out-of-bounds Write",
              severity: "high",
              message: `Array write with constant negative index (${idxVal}) — always out of bounds.`,
              filePath, node, code,
            }));
          }
        }
      }
    }

    // ── B: loop writes via underflow pointer ──────────────────────────────────
    if (node.type === "for_statement" || node.type === "while_statement") {
      const body = node.childForFieldName("body");
      if (!body) continue;
      for (const inner of walkAll(body)) {
        if (inner.type === "assignment_expression") {
          const left = inner.childForFieldName("left");
          if (left?.type === "subscript_expression") {
            const obj = left.childForFieldName("argument") ?? left.namedChildren[0];
            const objName = obj?.type === "identifier" ? obj.text : null;
            if (objName && underflowPtrs.has(objName)) {
              findings.push(makeAstFinding({
                cweId: "CWE-787", ruleId: "ast-oob-write",
                vulnerability: "Out-of-bounds Write",
                severity: "high",
                message: `Loop writes via '${objName}' which points before its buffer (pointer underflow).`,
                filePath, node, code,
              }));
              break;
            }
          }
        }
      }
    }
  }
  return findings;
}

// CWE-190: constant overflow detection — track variables assigned MAX/boundary constants
const OVERFLOW_CONST_PATTERN = /\b(CHAR_MAX|SCHAR_MAX|UCHAR_MAX|SHRT_MAX|USHRT_MAX|INT_MAX|UINT_MAX|LONG_MAX|ULONG_MAX|LLONG_MAX|ULLONG_MAX|INT8_MAX|INT16_MAX|INT32_MAX|INT64_MAX|UINT8_MAX|UINT16_MAX|UINT32_MAX|UINT64_MAX|SIZE_MAX)\b/;

function findConstantOverflows(root: Node, filePath: string, code: string): Finding[] {
  const findings: Finding[] = [];
  // Map variable name → node where it was assigned a MAX constant
  const maxVars = new Map<string, Node>();

  for (const node of walkAll(root)) {
    // Seed: variable assigned to MAX constant directly (int x = INT_MAX or x = CHAR_MAX)
    if (node.type === "init_declarator" || node.type === "assignment_expression") {
      const lhs = node.type === "init_declarator"
        ? (() => { const d = node.childForFieldName("declarator"); return d?.type === "identifier" ? d : null; })()
        : node.childForFieldName("left");
      const rhs = node.type === "init_declarator"
        ? node.childForFieldName("value")
        : node.childForFieldName("right");
      if (lhs?.type === "identifier" && rhs && OVERFLOW_CONST_PATTERN.test(rhs.text)) {
        maxVars.set(lhs.text, rhs);
      }
    }
  }

  if (maxVars.size === 0) return findings;

  for (const node of walkAll(root)) {
    if (node.type !== "init_declarator" && node.type !== "assignment_expression") continue;
    const valueNode = node.type === "init_declarator"
      ? node.childForFieldName("value")
      : node.childForFieldName("right");
    if (!valueNode) continue;
    if (!containsArithmetic(valueNode)) continue;
    // Check if any MAX variable is referenced in this arithmetic expression
    const ids = collectIdentifiers(valueNode);
    for (const id of ids) {
      if (maxVars.has(id)) {
        findings.push(makeAstFinding({
          cweId: "CWE-190", ruleId: "ast-integer-overflow",
          vulnerability: "Integer Overflow",
          severity: "medium",
          message: `Arithmetic on '${id}' (assigned a boundary constant) may overflow.`,
          filePath, node: valueNode, code,
        }));
        break;
      }
    }
  }
  return findings;
}

function seedCStringSources(root: Node, taint: TaintTracker): void {
  for (const node of walkAll(root)) {
    if (node.type !== "call_expression") continue;
    const fn = node.childForFieldName("function")?.text ?? "";
    const argsNode = node.childForFieldName("arguments");
    if (!argsNode) continue;

    // fgets(buf, size, stream) / gets(buf) — first arg is the destination buffer
    if (fn === "fgets" || fn === "gets") {
      const args = getArgs(argsNode);
      if (args.length > 0 && args[0].type === "identifier") {
        taint.add(args[0].text);
      }
    }
    // scanf/fscanf/sscanf — address-of args are destination buffers
    if (fn === "scanf" || fn === "fscanf" || fn === "sscanf") {
      for (const m of argsNode.text.matchAll(/&([a-zA-Z_][a-zA-Z0-9_]*)/g)) {
        taint.add(m[1]);
      }
    }
    // recv(sock, buf, ...) — second arg is the buffer
    if (fn === "recv" || fn === "read") {
      const args = getArgs(argsNode);
      if (args.length >= 2 && args[1].type === "identifier") {
        taint.add(args[1].text);
      }
    }
    // getenv returns a char* from environment — assign target is tainted
  }
  // getenv: the return value is tainted — caught via propagateAssignments with isCStringSourceExpr
}

function isCStringSourceExpr(node: Node): boolean {
  const text = node.text;
  return /\bgetenv\s*\(/.test(text) ||
         /\bgetlogin\s*\(/.test(text) ||
         /\bcuserid\s*\(/.test(text) ||
         /\bgetcwd\s*\(/.test(text);
}

// Seed char* / const char* function parameters (including argv) as potential user input.
// Analogous to seedCIntParamSources for integer parameters. This covers patterns where
// user-controlled strings arrive via function parameters (e.g. argv[1], helper functions).
const C_STRING_PTR_TYPES = /^(const\s+)?((unsigned\s+)?char|wchar_t)\s*\*/;

// Walk down nested pointer_declarator / abstract_pointer_declarator nodes to find the
// innermost identifier — handles char* param, char** argv, const char* const* ppargv, etc.
function findInnermostIdentifier(node: Node): string | undefined {
  if (node.type === "identifier") return node.text;
  for (const child of node.children) {
    const found = findInnermostIdentifier(child);
    if (found) return found;
  }
  return undefined;
}

function seedCStringParamSources(root: Node, taint: TaintTracker): void {
  for (const node of walkAll(root)) {
    if (node.type !== "function_definition") continue;
    const declarator = node.childForFieldName("declarator");
    if (!declarator) continue;
    for (const child of walkAll(declarator)) {
      if (child.type !== "parameter_declaration") continue;
      const typeNode = child.childForFieldName("type");
      const declNode = child.childForFieldName("declarator");
      if (!typeNode || !declNode) continue;
      const typeText = child.text.replace(/\s+/g, " ").trim();
      // Match char*, const char*, wchar_t*, and pointer-to-pointer like char**
      if (!C_STRING_PTR_TYPES.test(typeText) && !/\bchar\s*\*/.test(typeText)) continue;
      // Recursively extract the parameter name from arbitrarily nested pointer declarators
      const name = findInnermostIdentifier(declNode);
      if (name) taint.add(name);
    }
  }
}

// Build the set of variables whose value was written by snprintf/sprintf_s/vsnprintf
// where at least one format argument is tainted or a user-input expression.
//
//   snprintf(buf, size, fmt, arg1, arg2, ...) with any tainted argN → buf ∈ result
//
// Kept separate from strTaint so the system()/popen() detection can use its own
// heuristic (flag unknowns) while exec() detection uses explicit taint membership.
const SNPRINTF_FUNCS = new Set(["snprintf", "sprintf_s", "vsnprintf", "vsprintf", "_snprintf", "_snprintf_s"]);

function buildSnprintfTaintedSet(root: Node, taint: TaintTracker): Set<string> {
  const result = new Set<string>();
  let changed = true;
  while (changed) {
    changed = false;
    for (const node of walkAll(root)) {
      if (node.type !== "call_expression") continue;
      const fn = node.childForFieldName("function")?.text ?? "";
      if (!SNPRINTF_FUNCS.has(fn)) continue;
      const argsNode = node.childForFieldName("arguments");
      if (!argsNode) continue;
      const args = getArgs(argsNode);
      if (args.length < 3) continue;
      const dest = args[0];
      if (dest.type !== "identifier") continue;
      if (result.has(dest.text)) continue;
      // Format arguments start at index 2 (after dest and size/format)
      const formatArgs = args.slice(2);
      const anyTainted = formatArgs.some(a =>
        taint.expressionIsTainted(a) || isCStringSourceExpr(a) || result.has(a.text ?? "")
      );
      if (anyTainted) {
        result.add(dest.text);
        changed = true;
      }
    }
  }
  return result;
}

// Walk up ancestors to check if this identifier is an argument of free()
// (immediate parent is argument_list, not call_expression, so we climb one more level)
function isInsideFreeCall(node: Node): boolean {
  let cursor: Node | null = node.parent;
  while (cursor) {
    if (cursor.type === "call_expression") {
      return cursor.childForFieldName("function")?.text === "free";
    }
    if (cursor.type === "expression_statement" || cursor.type === "compound_statement") break;
    cursor = cursor.parent;
  }
  return false;
}

// Walk up ancestors to check if this identifier is the operand of a C++ delete expression.
// tree-sitter-c parses:
//   delete p;      → declaration { type_identifier:"delete", identifier:"p" }
//   delete [] p;   → expression_statement { subscript_expression { identifier:"delete", ... identifier:"p" } }
function isInsideDeleteStatement(node: Node): boolean {
  let cursor: Node | null = node.parent;
  while (cursor) {
    if (cursor.type === "declaration") {
      const first = cursor.children[0];
      if (first?.type === "type_identifier" && first.text === "delete") return true;
    }
    if (cursor.type === "subscript_expression") {
      const first = cursor.namedChildren[0];
      if (first?.type === "identifier" && first.text === "delete") return true;
    }
    if (cursor.type === "expression_statement" || cursor.type === "translation_unit") break;
    cursor = cursor.parent;
  }
  return false;
}

function isAssignmentTarget(parent: Node, node: Node): boolean {
  if (parent.type === "assignment_expression") {
    const left = parent.childForFieldName("left");
    return left === node;
  }
  return false;
}
