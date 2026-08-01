import * as vscode from "vscode";
import * as http from "http";
import * as https from "https";
import { URL } from "url";

/** One exact code replacement suggested by the model. */
export interface ModelFix {
  origin: string;
  replacement: string;
}

/** One vulnerability the model reported. */
export interface ModelVulnerability {
  cwe: string;
  fixes: ModelFix[];
  start_line?: number;
  end_line?: number;
}

export interface ModelResponse {
  vulnerabilities: ModelVulnerability[];
}

/** Configured model endpoint (default local Docker server). */
export function getModelEndpoint(): string {
  return vscode.workspace
    .getConfiguration("secureAssist")
    .get<string>("modelEndpoint", "http://localhost:8000")
    .replace(/\/+$/, "");
}

/**
 * POST the code + static findings to the model's /analyze endpoint.
 * Uses Node's http(s) so it works in the extension host without a fetch polyfill.
 */
export function analyzeWithModel(
  code: string,
  staticFindings: unknown,
  endpoint: string,
  token?: vscode.CancellationToken
): Promise<ModelResponse> {
  const target = `${endpoint}/analyze`;
  const url = new URL(target);
  const body = JSON.stringify({ code, analysis: staticFindings });
  const lib = url.protocol === "https:" ? https : http;

  return new Promise<ModelResponse>((resolve, reject) => {
    const req = lib.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          const status = res.statusCode ?? 0;
          if (status >= 200 && status < 300) {
            try {
              resolve(JSON.parse(data) as ModelResponse);
            } catch {
              reject(new Error(`Model server returned invalid JSON: ${data.slice(0, 200)}`));
            }
          } else {
            reject(new Error(`Model server returned ${status}: ${data.slice(0, 200)}`));
          }
        });
      }
    );

    // Inference on a large file can take a minute; fail rather than hang forever.
    req.setTimeout(180_000, () => {
      req.destroy(new Error("The model did not respond within 180s."));
    });

    req.on("error", (err) =>
      reject(
        err.message.startsWith("The model did not respond")
          ? err
          : new Error(
              `Could not reach the model server at ${target}. ` +
                `Is the Docker container running? (${err.message})`
            )
      )
    );

    if (token) {
      token.onCancellationRequested(() => req.destroy(new Error("Cancelled")));
    }

    req.write(body);
    req.end();
  });
}
