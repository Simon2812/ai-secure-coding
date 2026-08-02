// Mirrors the reindent() logic in model/aiFix.ts to verify the double-indent fix.
function indentOf(line: string): string {
  return line.slice(0, line.length - line.trimStart().length);
}

function reindent(replacement: string, indent: string): string {
  const lines = replacement.split("\n");
  if (lines.length === 1) return replacement;
  const rest = lines.slice(1);
  const indented = rest.filter((l) => l.trim().length > 0);
  const common = indented.length
    ? indented.reduce((shortest, line) => {
        const current = indentOf(line);
        return current.length < shortest.length ? current : shortest;
      }, indentOf(indented[0]))
    : "";
  const normalized = rest.map((line) => {
    if (line.trim().length === 0) return "";
    const stripped = line.startsWith(common) ? line.slice(common.length) : line.trimStart();
    return indent + stripped;
  });
  return [lines[0], ...normalized].join("\n");
}

const cases: { name: string; replacement: string; indent: string }[] = [
  {
    name: "model already indented (the buffer.c bug)",
    replacement: 'printf("Data was: %s\\n", data);\n\n    free(data);',
    indent: "    ",
  },
  {
    name: "model NOT indented",
    replacement: 'uid = int(uid)\ncur.execute("SELECT ... ?", (uid,))',
    indent: "    ",
  },
  {
    name: "single line",
    replacement: 'cur.execute("SELECT ... ?", (uid,))',
    indent: "        ",
  },
  {
    name: "nested indent inside block",
    replacement: "if (x) {\n    doThing();\n}",
    indent: "  ",
  },
];

for (const c of cases) {
  console.log(`\n=== ${c.name} ===`);
  console.log("--- result (· marks a space) ---");
  console.log(
    reindent(c.replacement, c.indent)
      .split("\n")
      .map((l) => l.replace(/^ +/, (m) => "·".repeat(m.length)))
      .join("\n")
  );
}
