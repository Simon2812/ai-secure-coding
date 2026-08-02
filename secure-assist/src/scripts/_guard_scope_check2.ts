import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';

/**
 * Is the guard tied to the *variable* (name-based, file-global) or to the
 * actual data flow? A guard on a same-named variable in an unrelated method
 * that never touches the path would prove it is name-based.
 */
const CODE = `
import java.io.File;
import java.io.FileInputStream;

public class FileService {
    private static final String BASE_DIR = "/var/app/uploads/";

    private String buildPath(String name) {
        return BASE_DIR + name;          // NO guard here — still unsafe
    }

    /** Unrelated bookkeeping. Never called from load(). */
    private void auditLabel(String name) {
        if (!name.matches("[a-z]+")) {   // guards a DIFFERENT 'name'
            throw new IllegalArgumentException("bad label");
        }
    }

    public byte[] load(String requestedFile) throws Exception {
        String path = buildPath(requestedFile);
        File target = new File(path);
        FileInputStream in = new FileInputStream(target);
        return in.readAllBytes();
    }
}
`;

async function main() {
  await initAstAnalyzer();
  const found = astAnalyzeCode(CODE, "FileService.java")
    .filter((f) => f.cweId === "CWE-22")
    .map((f) => "L" + f.line);
  console.log("buildPath is UNGUARDED; an unrelated method guards its own 'name':");
  console.log("  CWE-22:", found.length ? found.join(", ") : "(suppressed — guard leaked by name)");
}
main().catch(console.error);
