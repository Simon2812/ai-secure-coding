import { buildTree, collapseSingleChildFolders, FolderNode } from '../report/tree';

// Minimal stand-ins: buildTree only reads path/score/findings.
const files: any[] = [
  { path: 'scan-demo/backend/app.py',        score: 5,   findings: [1, 2, 3, 4, 5] },
  { path: 'scan-demo/backend/UserDao.java',  score: 40,  findings: [1, 2, 3] },
  { path: 'scan-demo/backend/safe_db.py',    score: 100, findings: [] },
  { path: 'scan-demo/native/parser.c',       score: 40,  findings: [1, 2, 3] },
  { path: 'scan-demo/native/buffer.c',       score: 90,  findings: [1] },
  { path: 'README.md.py',                    score: 100, findings: [] },
];

function print(node: FolderNode, indent = ''): void {
  if (node.path !== '') {
    console.log(`${indent}[DIR] ${node.name.padEnd(24)} score=${String(node.score).padEnd(4)} files=${node.fileCount} findings=${node.findingCount}`);
  }
  const next = node.path === '' ? indent : indent + '   ';
  node.folders.forEach(f => print(f, next));
  node.files.forEach(f => console.log(`${next}      ${f.path.padEnd(20)} ${f.score}`));
}

const tree = collapseSingleChildFolders(buildTree(files));
console.log('\nFolder tree (collapsed single-child chains):\n');
print(tree);
console.log(`\nroot: files=${tree.fileCount} findings=${tree.findingCount} score=${tree.score}`);
