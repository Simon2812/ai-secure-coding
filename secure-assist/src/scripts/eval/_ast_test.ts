import { initTreeSitter, CLang, newParser } from '../../analyzer/ast/init';

async function main() {
  await initTreeSitter();
  const parser = newParser();
  parser.setLanguage(CLang);
  // Test delete[] with more complex use pattern (like file 08/09)
  const code = "Pair *records = 0;\nrecords = new Pair[48];\ndelete [] records;\nlog_pair(records[0]);";
  const tree = parser.parse(code);
  function walk(n: any, depth: number): void {
    const pad = '  '.repeat(depth);
    const snippet = JSON.stringify((n.text || '').slice(0, 30));
    console.log(pad + n.type + ': ' + snippet);
    for (const c of n.children) { walk(c, depth + 1); }
  }
  walk(tree!.rootNode, 0);
}
main().catch(console.error);