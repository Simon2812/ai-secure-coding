import { FileReport } from "./scanner";

/**
 * A folder in the report tree. Scores roll up from every descendant file so a
 * collapsed folder still tells you how healthy its contents are.
 */
export interface FolderNode {
  name: string;
  /** Full path from the workspace root; "" for the root node. */
  path: string;
  folders: FolderNode[];
  files: FileReport[];
  /** Average score of all files beneath this folder (100 when empty). */
  score: number;
  fileCount: number;
  findingCount: number;
}

function emptyFolder(name: string, path: string): FolderNode {
  return { name, path, folders: [], files: [], score: 100, fileCount: 0, findingCount: 0 };
}

/** Depth-first roll-up of scores and counts from files into their ancestors. */
function aggregate(node: FolderNode): void {
  let scoreSum = 0;
  let fileCount = 0;
  let findingCount = 0;

  for (const file of node.files) {
    scoreSum += file.score;
    fileCount += 1;
    findingCount += file.findings.length;
  }

  for (const child of node.folders) {
    aggregate(child);
    // Weight by file count so a folder of 20 files isn't averaged against a
    // folder of 1 as if they were equal.
    scoreSum += child.score * child.fileCount;
    fileCount += child.fileCount;
    findingCount += child.findingCount;
  }

  node.fileCount = fileCount;
  node.findingCount = findingCount;
  node.score = fileCount === 0 ? 100 : Math.round(scoreSum / fileCount);

  // Worst first, folders before files at each level.
  node.folders.sort((a, b) => a.score - b.score || a.name.localeCompare(b.name));
  node.files.sort((a, b) => a.score - b.score || a.path.localeCompare(b.path));
}

/**
 * Build a folder tree from flat file reports, mirroring the workspace layout.
 */
export function buildTree(files: FileReport[]): FolderNode {
  const root = emptyFolder("", "");

  for (const file of files) {
    const segments = file.path.split("/");
    const fileName = segments.pop() ?? file.path;

    let current = root;
    let walked = "";
    for (const segment of segments) {
      walked = walked ? `${walked}/${segment}` : segment;
      let next = current.folders.find((f) => f.name === segment);
      if (!next) {
        next = emptyFolder(segment, walked);
        current.folders.push(next);
      }
      current = next;
    }
    // Keep the workspace-relative path intact — it is the key the panel uses to
    // resolve the file — and carry the basename separately for display.
    current.files.push({ ...file, displayName: fileName });
  }

  aggregate(root);
  return root;
}

/**
 * Collapse folders that contain nothing but a single subfolder, so a chain like
 * src → main → java renders as one "src/main/java" row instead of three clicks.
 */
export function collapseSingleChildFolders(node: FolderNode): FolderNode {
  const folders = node.folders.map(collapseSingleChildFolders);

  const merged = folders.map((child) => {
    let current = child;
    while (current.files.length === 0 && current.folders.length === 1) {
      const only = current.folders[0];
      current = { ...only, name: `${current.name}/${only.name}` };
    }
    return current;
  });

  return { ...node, folders: merged };
}
