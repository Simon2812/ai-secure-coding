import type { Node } from "web-tree-sitter";

export class TaintTracker {
  private tainted = new Set<string>();

  add(varName: string): void {
    this.tainted.add(varName);
  }

  remove(varName: string): void {
    this.tainted.delete(varName);
  }

  has(varName: string): boolean {
    return this.tainted.has(varName);
  }

  size(): number {
    return this.tainted.size;
  }

  expressionIsTainted(node: Node): boolean {
    return this.nodeContainsTaintedIdentifier(node);
  }

  private nodeContainsTaintedIdentifier(node: Node): boolean {
    if (node.type === "identifier" && this.tainted.has(node.text)) {
      return true;
    }
    for (const child of node.children) {
      if (this.nodeContainsTaintedIdentifier(child)) return true;
    }
    return false;
  }

  propagateAssignments(root: Node, isSourceExpr: (node: Node) => boolean): void {
    // Build a map of variables assigned to compile-time constant integers.
    // Used to evaluate ternary/conditional guards like `7 * 18 + marker > 200`.
    const constMap = buildConstIntMap(root);

    // Pre-index all method/function definitions by name for O(1) lookup.
    // Used by inter-procedural return-value analysis below.
    const methodDeclMap = buildMethodDeclMap(root);

    let changed = true;
    while (changed) {
      changed = false;
      for (const node of walkAll(root)) {
        const lhs = getAssignmentLhs(node);
        const rhs = getAssignmentRhs(node);
        if (!lhs || !rhs) continue;
        if (this.tainted.has(lhs)) continue;

        // Dead-branch suppression: if this assignment is inside an if/else branch
        // whose condition is a compile-time constant, skip it if we're in the
        // not-taken branch.
        // Example: if (7*42 - marker > 200) { selected = "safe.txt"; }
        //          else { selected = userInput; }  ← this else is never reached
        if (isInsideDeadBranch(node, constMap)) continue;

        let rhsTainted: boolean;

        if (isTernaryOrConditional(rhs)) {
          // Constant-expression ternary guard:
          // If the condition evaluates to a compile-time constant, only the
          // actually-taken branch can taint the result.
          // Example (OWASP Benchmark dead-code pattern):
          //   selected = (7 * 18) + marker > 200 ? "safe.txt" : userInput
          //   → condition is always true → result is "safe.txt" → NOT tainted
          rhsTainted = this.ternaryIsTainted(rhs, constMap, isSourceExpr);
        } else if (isSubscriptAccess(rhs)) {
          // Subscript/index access (dict[key], arr[idx]):
          // Only propagate taint if the COLLECTION OBJECT itself is tainted.
          // Prevents constant-dict lookups like CATALOG[tainted_key] from
          // tainting the result — the value comes from the safe dict, not the key.
          rhsTainted = this.collectionObjectIsTainted(rhs);
        } else if (rhs.type === "method_invocation") {
          // Java method call: use return-value analysis instead of checking
          // all argument identifiers. This prevents laundering FPs where a helper
          // receives tainted input but ignores it (dead branch) and returns a constant.
          //
          // Example (OWASP Benchmark pattern):
          //   resolvedName = selectEntry(clientValue)
          //   → selectEntry uses a dead-branch to always return "report.log"
          //   → clientValue being tainted does NOT taint resolvedName
          //
          // Scoped to Java method_invocation only (not Python call / C call_expression)
          // because Java's seedJavaMethodParams seeds formal parameters as tainted,
          // making methodBodyReturnsTainted correct. Python has no param seeding, so
          // applying this there would create false negatives.
          //
          // Exceptions:
          //   1. callee is a known taint source → always propagate
          //   2. receiver/object is tainted → conservatively propagate
          //   3. callee not defined in this file → fall back to arg check
          if (isSourceExpr(rhs)) {
            rhsTainted = true;
          } else if (isSanitizingCallChain(rhs)) {
            // The call (or its receiver chain) passes through a sanitizing method
            // such as Path.getFileName(), which strips directory traversal components.
            // Even if arguments/receiver are tainted, the output is safe.
            // Example: safeId = Path.of(profileId).getFileName().toString()
            rhsTainted = false;
          } else {
            const receiver = getCallReceiver(rhs);
            const callee = getCallMethodName(rhs);

            // Map.get(key): value comes from the map (the receiver), not the key (args).
            // If the receiver (the map/collection object) is NOT tainted, the result is
            // clean regardless of whether the key argument is tainted.
            // Example: String path = WHITELIST_MAP.get(userKey) → not tainted (map is constant)
            // Guard: only when there IS an explicit receiver; local get() calls fall through.
            if (callee === "get" && receiver && !this.expressionIsTainted(receiver)) {
              rhsTainted = false;
            } else if (receiver && this.expressionIsTainted(receiver)) {
              // e.g. taintedStr.toLowerCase() → result is still tainted
              rhsTainted = true;
            } else {
              const calleeDecl = callee ? methodDeclMap.get(callee) : undefined;
              if (calleeDecl) {
                // Callee is defined in this file: check whether its return value
                // is tainted under the current taint state. The outer fixed-point
                // loop ensures this converges correctly even when the callee body
                // is not yet fully processed on the first iteration.
                rhsTainted = this.methodBodyReturnsTainted(calleeDecl, isSourceExpr);
              } else {
                // Callee not in this file (stdlib, external): conservative fallback.
                rhsTainted = this.expressionIsTainted(rhs);
              }
            }
          }
        } else {
          rhsTainted = isSourceExpr(rhs) || this.expressionIsTainted(rhs);
        }

        if (rhsTainted) {
          this.tainted.add(lhs);
          changed = true;
        }
      }
    }
  }

  /**
   * Returns true if any return statement in the given method/function body
   * returns a tainted expression under the current taint state.
   *
   * Used for inter-procedural return-value analysis:
   * if the callee always returns a non-tainted value (e.g. because its
   * "tainted" branch is dead), the caller's result should not be tainted.
   */
  private methodBodyReturnsTainted(
    methodNode: Node,
    isSourceExpr: (node: Node) => boolean,
  ): boolean {
    for (const child of walkAll(methodNode)) {
      if (child.type === "return_statement") {
        // Return value is the first named child in Java/Python/C
        const retVal = child.namedChildren[0];
        if (retVal && (isSourceExpr(retVal) || this.expressionIsTainted(retVal))) {
          return true;
        }
      }
    }
    return false; // all return paths are clean
  }

  private ternaryIsTainted(
    ternary: Node,
    constMap: Map<string, number>,
    isSourceExpr: (node: Node) => boolean,
  ): boolean {
    const parts = getTernaryParts(ternary);
    if (!parts) {
      // Can't parse → conservative
      return isSourceExpr(ternary) || this.expressionIsTainted(ternary);
    }

    const { condition, consequence, alternative } = parts;
    const condVal = evaluateConstantInt(condition, constMap);

    const checkNode = (n: Node) => isSourceExpr(n) || this.expressionIsTainted(n);

    if (condVal !== null) {
      // Condition is a compile-time constant.
      return condVal !== 0 ? checkNode(consequence) : checkNode(alternative);
    }

    // Unknown condition → conservative: either branch could taint
    return checkNode(consequence) || checkNode(alternative);
  }

  private collectionObjectIsTainted(node: Node): boolean {
    // Get the collection/array object (the part before the bracket).
    // Field name varies by language:
    //   Python subscript: "value" field
    //   Java array_access: "array" field
    //   C subscript_expression: first named child
    const obj = node.childForFieldName("value")
      ?? node.childForFieldName("array")
      ?? node.namedChildren[0];
    return obj ? this.expressionIsTainted(obj) : false;
  }
}

function getAssignmentLhs(node: Node): string | null {
  // Python: assignment, augmented_assignment
  // Java/C: assignment_expression
  if (node.type === "assignment" || node.type === "assignment_expression" || node.type === "augmented_assignment") {
    const left = node.childForFieldName("left");
    if (left?.type === "identifier") return left.text;
  }
  // Java: local_variable_declaration wraps variable_declarator
  if (node.type === "local_variable_declaration" || node.type === "variable_declarator") {
    const name = node.childForFieldName("name") ?? node.children.find(c => c.type === "identifier");
    if (name) return name.text;
  }
  // C: init_declarator (int x = expr)
  if (node.type === "init_declarator") {
    const decl = node.childForFieldName("declarator");
    if (decl?.type === "identifier") return decl.text;
  }
  return null;
}

function getAssignmentRhs(node: Node): Node | null {
  if (node.type === "assignment" || node.type === "assignment_expression" || node.type === "augmented_assignment") {
    return node.childForFieldName("right") ?? null;
  }
  if (node.type === "variable_declarator") {
    return node.childForFieldName("value") ?? null;
  }
  // C: init_declarator
  if (node.type === "init_declarator") {
    return node.childForFieldName("value") ?? null;
  }
  return null;
}

export function* walkAll(node: Node): Generator<Node> {
  yield node;
  for (const child of node.children) {
    yield* walkAll(child);
  }
}

/**
 * Returns true if the node is a ternary/conditional expression.
 * Node types by language:
 *   Python: "conditional_expression"  (A if COND else B — no named fields)
 *   Java:   "ternary_expression"       (COND ? A : B — named fields)
 *   C:      "conditional_expression"   (COND ? A : B — named fields)
 */
function isTernaryOrConditional(node: Node): boolean {
  return node.type === "ternary_expression"     // Java
    || node.type === "conditional_expression";  // Python and C
}

/**
 * Extract condition, consequence, alternative from a ternary/conditional node.
 * Returns null if the structure cannot be determined.
 *
 * Java ternary_expression:   COND ? A : B  (named fields: condition, consequence, alternative)
 * C conditional_expression:  COND ? A : B  (named fields: condition, consequence, alternative)
 * Python conditional_expression: A if COND else B  (no named fields; namedChildren=[A, COND, B])
 */
function getTernaryParts(node: Node): {
  condition: Node;
  consequence: Node;
  alternative: Node;
} | null {
  // Java and C use named fields
  const condition = node.childForFieldName("condition");
  const consequence = node.childForFieldName("consequence");
  const alternative = node.childForFieldName("alternative");

  if (condition && consequence && alternative) {
    return { condition, consequence, alternative };
  }

  // Python conditional_expression: A if COND else B  (no named fields)
  // namedChildren order: [consequence(A), condition(COND), alternative(B)]
  if (node.type === "conditional_expression") {
    const named = node.namedChildren;
    if (named.length >= 3) {
      return {
        consequence: named[0],
        condition:   named[1],
        alternative: named[2],
      };
    }
  }

  return null;
}

/**
 * Build a map of variable names to their compile-time constant integer values.
 * Iterates until a fixed point, handling chains like:
 *   base = 106            → {base: 106}
 *   total = 7 * 18 + base → {base: 106, total: 232}
 */
function buildConstIntMap(root: Node): Map<string, number> {
  const map = new Map<string, number>();
  let changed = true;

  while (changed) {
    changed = false;
    for (const node of walkAll(root)) {
      const lhs = getAssignmentLhs(node);
      const rhs = getAssignmentRhs(node);
      if (!lhs || !rhs || map.has(lhs)) continue;

      const val = evaluateConstantInt(rhs, map);
      if (val !== null) {
        map.set(lhs, val);
        changed = true;
      }
    }
  }

  return map;
}

/**
 * Evaluate a node as a compile-time constant integer.
 * Returns the integer value, or null if the expression is not fully constant.
 *
 * Handles:
 *   - Integer literals (all languages)
 *   - Identifiers with known constant values (from constMap)
 *   - Parenthesized expressions
 *   - Binary arithmetic (+, -, *, /) and comparisons (>, <, >=, <=, ==, !=)
 */
function evaluateConstantInt(node: Node, constMap: Map<string, number>): number | null {
  switch (node.type) {
    // Integer literals
    case "integer":                    // Python
    case "decimal_integer_literal":    // Java
    case "number_literal": {           // C
      // Remove underscores (Java/Python numeric separators), take decimal part only
      const text = node.text.replace(/_/g, "").split(".")[0];
      const val = parseInt(text, 10);
      return isNaN(val) ? null : val;
    }

    // Identifier: look up in constant map
    case "identifier":
      return constMap.has(node.text) ? constMap.get(node.text)! : null;

    // Parenthesized expression: unwrap and evaluate inner
    case "parenthesized_expression": {
      const inner = node.namedChildren[0];
      return inner ? evaluateConstantInt(inner, constMap) : null;
    }

    // Binary expression: arithmetic and comparisons
    case "binary_expression":    // Java and C (all operators)
    case "comparison_operator":  // Python: A > B, A < B, A == B, etc.
    case "binary_operator": {    // Python: A + B, A * B, A - B, etc.
      const named = node.namedChildren;
      if (named.length < 2) return null;

      const left = named[0];
      const right = named[named.length - 1];

      const leftVal = evaluateConstantInt(left, constMap);
      const rightVal = evaluateConstantInt(right, constMap);
      if (leftVal === null || rightVal === null) return null;

      // The operator is among the unnamed (non-field) children
      const opNode = node.children.find(c => !c.isNamed);
      if (!opNode) return null;

      switch (opNode.type) {
        case "+":  return leftVal + rightVal;
        case "-":  return leftVal - rightVal;
        case "*":  return leftVal * rightVal;
        case "/":  return rightVal !== 0 ? Math.trunc(leftVal / rightVal) : null;
        case "%":  return rightVal !== 0 ? leftVal % rightVal : null;
        case ">":  return leftVal > rightVal  ? 1 : 0;
        case "<":  return leftVal < rightVal  ? 1 : 0;
        case ">=": return leftVal >= rightVal ? 1 : 0;
        case "<=": return leftVal <= rightVal ? 1 : 0;
        case "==": return leftVal === rightVal ? 1 : 0;
        case "!=": return leftVal !== rightVal ? 1 : 0;
        default:   return null;
      }
    }

    default:
      return null;
  }
}

/**
 * Returns true if the node is inside an if-else branch that is provably never
 * executed because the condition is a compile-time constant.
 *
 * Example (OWASP Benchmark dead-else pattern):
 *   int marker = 86;
 *   if ((7 * 42) - marker > 200) { selected = "safe.txt"; }
 *   else { selected = userInput; }   ← this else is never executed
 *
 * Walking up the ancestor tree: if we find an if_statement where
 *   - the condition evaluates to a constant
 *   - the current node is in the NOT-taken branch (else when true, then when false)
 * we return true (suppress this assignment).
 */
function isInsideDeadBranch(node: Node, constMap: Map<string, number>): boolean {
  let cursor: Node | null = node.parent;
  while (cursor) {
    if (cursor.type === "if_statement") {
      const conditionNode = cursor.childForFieldName("condition");
      if (conditionNode) {
        const condVal = evaluateConstantInt(conditionNode, constMap);
        if (condVal !== null) {
          const consequence = cursor.childForFieldName("consequence");
          const alternative = cursor.childForFieldName("alternative");

          if (condVal !== 0) {
            // Condition always true → else branch (alternative) is dead
            if (alternative && isDescendant(node, alternative)) return true;
          } else {
            // Condition always false → then branch (consequence) is dead
            if (consequence && isDescendant(node, consequence)) return true;
          }
        }
      }
    }
    cursor = cursor.parent;
  }
  return false;
}

function isDescendant(node: Node, ancestor: Node): boolean {
  // NOTE: web-tree-sitter creates a new JS wrapper object for every node access,
  // so === reference equality always fails. Compare by byte range instead.
  const aStart = ancestor.startIndex;
  const aEnd   = ancestor.endIndex;
  let cursor: Node | null = node;
  while (cursor) {
    if (cursor.startIndex === aStart && cursor.endIndex === aEnd) return true;
    cursor = cursor.parent;
  }
  return false;
}

/**
 * Returns true if the node is a subscript/index access expression.
 * These are handled specially in taint propagation:
 *   dict[key], arr[idx] — value comes from the collection, not the key.
 * Grammar node types by language:
 *   Python: "subscript"
 *   Java:   "array_access"
 *   C:      "subscript_expression"
 */
function isSubscriptAccess(node: Node): boolean {
  return node.type === "subscript"             // Python: dict[key], list[i]
    || node.type === "subscript_expression"    // C:      arr[i]
    || node.type === "array_access";           // Java:   arr[i]
}

// ─── Inter-procedural helpers ────────────────────────────────────────────────

/**
 * Returns true if the node is any kind of function/method call expression.
 * Node types by language:
 *   Java:   "method_invocation"
 *   Python: "call"
 *   C:      "call_expression"
 */
function isCallExpr(node: Node): boolean {
  return node.type === "method_invocation"
    || node.type === "call"
    || node.type === "call_expression";
}

/**
 * Extract the receiver/object of a call (the value the method is called on).
 * Returns null for top-level function calls with no receiver.
 *
 *   Java:   obj.method(args)  → "object" field
 *   Python: obj.method(args)  → attribute_expression "object" or "value" field
 *   C:      no receiver concept (all calls are top-level)
 */
function getCallReceiver(node: Node): Node | null {
  if (node.type === "method_invocation") {
    return node.childForFieldName("object") ?? null;
  }
  if (node.type === "call") {
    const func = node.childForFieldName("function");
    if (!func) return null;
    // Python attribute call: obj.method(args) → func is attribute node
    // The object is the "value" field of the attribute (or first named child)
    if (func.type === "attribute") {
      return func.childForFieldName("value") ?? func.namedChildren[0] ?? null;
    }
    return null; // plain function call, no receiver
  }
  // C call_expression: function pointer calls rarely have an object
  return null;
}

/**
 * Extract the callee name from a call expression.
 * Returns null if the name cannot be statically determined.
 *
 *   Java:   obj.method(args)   → "method"
 *   Java:   staticMethod(args) → "staticMethod"
 *   Python: func(args)         → "func"
 *   Python: obj.method(args)   → "method"
 *   C:      func(args)         → "func"
 */
function getCallMethodName(node: Node): string | null {
  if (node.type === "method_invocation") {
    return node.childForFieldName("name")?.text ?? null;
  }
  if (node.type === "call") {
    const func = node.childForFieldName("function");
    if (!func) return null;
    if (func.type === "identifier") return func.text;
    // obj.method(args) → attribute node → attribute field holds the method name
    if (func.type === "attribute") {
      return func.childForFieldName("attribute")?.text ?? null;
    }
    return null;
  }
  if (node.type === "call_expression") {
    const func = node.childForFieldName("function");
    if (!func) return null;
    if (func.type === "identifier") return func.text;
    // field_expression: obj->method or obj.method in C
    if (func.type === "field_expression") {
      return func.childForFieldName("field")?.text ?? null;
    }
    return null;
  }
  return null;
}

/**
 * Pre-index all method/function definitions by name for O(1) lookup.
 * Handles Java method_declaration and Python/C function_definition.
 * When multiple definitions share a name (overloads), the last one wins
 * (conservative: we return tainted if any overload returns tainted).
 */
function buildMethodDeclMap(root: Node): Map<string, Node> {
  const map = new Map<string, Node>();
  for (const node of walkAll(root)) {
    if (node.type === "method_declaration" || node.type === "function_definition") {
      const nameNode = node.childForFieldName("name");
      if (nameNode?.text) map.set(nameNode.text, node);
    }
  }
  return map;
}

// ─── Sanitizing method detection ─────────────────────────────────────────────

/**
 * Java method calls that sanitize their input regardless of receiver taint.
 *
 * Path.getFileName():
 *   Strips all directory components, returning only the final filename.
 *   Even if the receiver path was built from user input, the filename
 *   portion cannot contain path traversal sequences like "../".
 */
const JAVA_SANITIZING_METHODS = new Set([
  "getFileName",  // java.nio.file.Path.getFileName() — strips directory traversal
]);

/**
 * Returns true if the node is a method_invocation that passes through (or IS)
 * a known sanitizing call, walking up the receiver chain.
 *
 * Examples:
 *   Path.of(userInput).getFileName()           → true  (getFileName found)
 *   Path.of(userInput).getFileName().toString() → true  (getFileName in receiver chain)
 *   Path.of(userInput).normalize()             → false (normalize is NOT sanitizing)
 *
 * Only handles Java method_invocation nodes (Python/C use different node types).
 */
function isSanitizingCallChain(node: Node): boolean {
  if (node.type !== "method_invocation") return false;
  const name = node.childForFieldName("name")?.text;
  // Direct sanitizing call
  if (name && JAVA_SANITIZING_METHODS.has(name)) return true;
  // Check whether the receiver is itself a sanitizing call chain.
  // This handles wrappers like .toString() called on .getFileName() result.
  const receiver = node.childForFieldName("object");
  if (receiver && receiver.type === "method_invocation") {
    return isSanitizingCallChain(receiver);
  }
  return false;
}
