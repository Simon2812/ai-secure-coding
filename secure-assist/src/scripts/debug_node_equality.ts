import { initAstAnalyzer } from './ast/astAnalyzer';
import { walkAll } from './ast/taint';
import { initTreeSitter, JavaLang, newParser } from './ast/init';
import type { Node } from 'web-tree-sitter';
import * as fs from 'fs';

function evaluateConstantInt(node: Node, constMap: Map<string, number>): number | null {
  switch (node.type) {
    case "integer":
    case "decimal_integer_literal":
    case "number_literal": {
      const text = node.text.replace(/_/g, "").split(".")[0];
      const val = parseInt(text, 10);
      return isNaN(val) ? null : val;
    }
    case "identifier":
      return constMap.has(node.text) ? constMap.get(node.text)! : null;
    case "parenthesized_expression": {
      const inner = node.namedChildren[0];
      return inner ? evaluateConstantInt(inner, constMap) : null;
    }
    case "binary_expression":
    case "comparison_operator":
    case "binary_operator": {
      const named = node.namedChildren;
      if (named.length < 2) return null;
      const left = named[0];
      const right = named[named.length - 1];
      const leftVal = evaluateConstantInt(left, constMap);
      const rightVal = evaluateConstantInt(right, constMap);
      if (leftVal === null || rightVal === null) {
        console.log(`  evaluateConstantInt(${node.type} "${node.text.substring(0,30)}"): left=${leftVal}, right=${rightVal} → null`);
        return null;
      }
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

async function main() {
  await initTreeSitter();
  const parser = newParser();
  parser.setLanguage(JavaLang);

  const code = fs.readFileSync('C:/Users/drozh/asc-main-dataset/dataset/normalized/CWE-22/java/CWE-22-java-64.java', 'utf-8');
  const tree = parser.parse(code)!;
  const root = tree.rootNode;

  // Build constMap
  const constMap = new Map<string, number>();
  for (const node of walkAll(root)) {
    if (node.type === 'variable_declarator') {
      const name = node.childForFieldName('name');
      const val = node.childForFieldName('value');
      if (name && val) {
        const v = evaluateConstantInt(val, constMap);
        if (v !== null) {
          console.log(`constMap: ${name.text} = ${v}`);
          constMap.set(name.text, v);
        }
      }
    }
  }

  console.log('\nConstMap:', Object.fromEntries(constMap));

  // Find the if_statement
  let ifNode: Node | null = null;
  for (const node of walkAll(root)) {
    if (node.type === 'if_statement') {
      const cond = node.childForFieldName('condition');
      if (cond && cond.text.includes('marker')) {
        ifNode = node;
        break;
      }
    }
  }

  if (!ifNode) { console.log('No if_statement with marker found!'); return; }

  const condNode = ifNode.childForFieldName('condition');
  const altNode = ifNode.childForFieldName('alternative');
  const consNode = ifNode.childForFieldName('consequence');

  console.log('\nif_statement condition:', condNode?.text);
  console.log('condNode type:', condNode?.type);
  const condVal = condNode ? evaluateConstantInt(condNode, constMap) : null;
  console.log('condVal:', condVal);
  console.log('alternative:', altNode?.type, altNode?.startIndex, '-', altNode?.endIndex);
  console.log('consequence:', consNode?.type, consNode?.startIndex, '-', consNode?.endIndex);

  // Find the assignment "selected = userInput" in the else branch
  let assignNode: Node | null = null;
  for (const node of walkAll(root)) {
    if (node.type === 'assignment_expression') {
      const left = node.childForFieldName('left');
      const right = node.childForFieldName('right');
      if (left?.text === 'selected' && right?.text === 'userInput') {
        assignNode = node;
        break;
      }
    }
  }

  if (!assignNode) { console.log('No assignment "selected = userInput" found!'); return; }
  console.log('\nassignNode:', assignNode.type, assignNode.startIndex, '-', assignNode.endIndex);

  // Test isDescendant with reference
  console.log('\n--- isDescendant by reference ---');
  let cursor: Node | null = assignNode;
  let depth = 0;
  while (cursor && depth < 15) {
    const sameRef = cursor === altNode;
    const samePos = altNode && cursor.startIndex === altNode.startIndex && cursor.endIndex === altNode.endIndex;
    console.log(`  [${depth}] ${cursor.type} (${cursor.startIndex}-${cursor.endIndex}) ref=${sameRef} pos=${samePos}`);
    if (sameRef || samePos) { console.log('  ^ FOUND!'); break; }
    cursor = cursor.parent;
    depth++;
  }

  // Also check if altNode2 from re-fetch equals altNode
  const altNode2 = ifNode.childForFieldName('alternative');
  console.log('\naltNode same ref on re-fetch:', altNode === altNode2);
  console.log('altNode same pos on re-fetch:', altNode?.startIndex === altNode2?.startIndex && altNode?.endIndex === altNode2?.endIndex);
}

main().catch(console.error);
