import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';

const BASE = `
import java.io.File;
import java.io.FileInputStream;

public class FileService {
    private static final String BASE_DIR = "/var/app/uploads/";

    private String resolveName(String requested) {
        return requested;
    }

    private String buildPath(String name) {
%%GUARD_IN_BUILDPATH%%
        return BASE_DIR + name;
    }
%%UNRELATED_METHOD%%
    public byte[] load(String requestedFile) throws Exception {
        String path = buildPath(resolveName(requestedFile));
        File target = new File(path);
        FileInputStream in = new FileInputStream(target);
        return in.readAllBytes();
    }
}
`;

const GUARD = `        if (!name.matches("[a-zA-Z0-9._-]+")) {
            throw new IllegalArgumentException("Invalid filename");
        }`;

// A guard on a variable that has nothing to do with the file path, in a method
// that is never called from load().
const UNRELATED = `
    private void auditLabel(String label) {
        if (!label.matches("[a-z]+")) {
            throw new IllegalArgumentException("bad label");
        }
    }
`;

function build(guard: string, unrelated: string): string {
  return BASE.replace("%%GUARD_IN_BUILDPATH%%", guard).replace("%%UNRELATED_METHOD%%", unrelated);
}

async function main() {
  await initAstAnalyzer();
  const run = (label: string, code: string) => {
    const found = astAnalyzeCode(code, "FileService.java")
      .filter((f) => f.cweId === "CWE-22")
      .map((f) => "L" + f.line);
    console.log(`  ${label.padEnd(52)} ${found.length ? found.join(", ") : "(suppressed)"}`);
  };

  console.log("CWE-22 findings:\n");
  run("no guard anywhere", build("", ""));
  run("real guard on `name` in buildPath()", build(GUARD, ""));
  run("guard on UNRELATED var, in an UNRELATED method", build("", UNRELATED));
}
main().catch(console.error);
