import * as vscode from "vscode";
import * as https from "https";

/** One turn of the conversation. */
export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

/** Why the conversation was opened, which changes the question asked. */
export type Intent = "explain" | "suppress";

/** The finding the conversation is about, used to build the opening context. */
export interface FindingContext {
  cwe: string;
  title?: string;
  summary?: string;
  recommendation?: string;
  file: string;
  line?: number;
  snippet: string;
  suggestedFix?: { origin: string; replacement: string };
  intent?: Intent;
}

export type Level = "simple" | "technical";

export class MissingApiKeyError extends Error {
  constructor() {
    super(
      "No API key configured. Set secureAssist.agentApiKey in Settings to use the teacher agent."
    );
  }
}

function config<T>(key: string, fallback: T): T {
  return vscode.workspace.getConfiguration("secureAssist").get<T>(key, fallback);
}

/**
 * Instructions that shape the agent into a teacher rather than a code fixer.
 *
 * The fine-tuned model already detects and patches; this exists to explain, so
 * the prompt pushes for reasoning about the user's actual code instead of the
 * generic CWE description they could have read in the catalog.
 */
function systemPrompt(level: Level, intent: Intent = "explain"): string {
  const depth =
    level === "simple"
      ? "Explain in plain language for a developer who is not a security specialist. " +
        "Avoid jargon; when a term is unavoidable, define it in one short clause."
      : "You may assume solid security background. Be precise about the mechanism, " +
        "and mention relevant attack variants or edge cases where they matter.";

  return [
    "You are a secure-coding teacher embedded in a developer's editor.",
    "",
    "Your job is to help the developer UNDERSTAND a vulnerability in their own code.",
    "You are not a code generator: a separate model already proposes patches.",
    "",
    depth,
    "",
    "Guidelines:",
    "- Talk about the specific code you were given, quoting the relevant line, not the CWE in the abstract.",
    "- Explain how an attacker would actually exploit it, concretely, with an example input where useful.",
    "- When a fix is shown, explain WHY the approach works, not just that it does.",
    "- If the developer's assumption is wrong, correct it — kindly, but without hedging.",
    "- Keep the first answer under about 200 words. Offer to go deeper rather than front-loading everything.",
    "- Use short paragraphs. Avoid bulleted lists unless enumerating genuinely discrete items.",
    "",
    "On the suggested fix, when there is one:",
    "- It comes from a separate model, so treat it as a colleague's draft you are reviewing, not as your own work or as settled.",
    "- Start with what it gets right — usually the security approach is sound even when the code is not.",
    "- Offer concerns as your own reading: \"my concern with this as written is...\", not \"this is broken\".",
    "- Never soften a real defect into vagueness. If it would fail to compile, crash, or leave the vulnerability open, say so clearly and explain exactly why — a developer who applies a broken patch is worse off than one who was told plainly.",
    "- Where you can, suggest what would make it work rather than only naming the problem.",
    ...(intent === "suppress" ? SUPPRESS_GUIDANCE : []),
  ].join("\n");
}

/**
 * Extra instructions when the developer is deciding whether to silence a
 * finding.
 *
 * The risk here is agreement: the question arrives already framed as "I want to
 * suppress this", and a model that follows that framing will help hide a real
 * vulnerability. The verdict must therefore come from the code, and must be
 * stated even when it contradicts what the developer is about to do.
 */
const SUPPRESS_GUIDANCE = [
  "",
  "The developer is deciding whether to permanently stop reporting this finding.",
  "- Answer the question they actually have: is this a false positive, or is it real?",
  "- Open with a direct verdict — 'this looks like a false positive' or 'this is a real vulnerability' — then justify it from the code.",
  "- Do not agree simply because they intend to suppress it. If it is real, say so plainly and explain what an attacker would do.",
  "- If it genuinely is a false positive, say that too, and name the specific reason the analyzer was wrong (a guard it did not recognise, a constant it could not evaluate, a sanitiser it does not know).",
  "- If you cannot tell from the code shown, say what additional context would settle it rather than guessing.",
];

/** The opening message: the finding, its code, and any proposed fix. */
export function buildContextMessage(ctx: FindingContext): string {
  const parts: string[] = [
    `File: ${ctx.file}${ctx.line ? ` (around line ${ctx.line})` : ""}`,
    `Reported issue: ${ctx.cwe}${ctx.title ? ` — ${ctx.title}` : ""}`,
  ];
  if (ctx.summary) parts.push(`Catalog summary: ${ctx.summary}`);
  if (ctx.recommendation) parts.push(`Catalog recommendation: ${ctx.recommendation}`);

  parts.push("", "Code:", "```", ctx.snippet, "```");

  if (ctx.suggestedFix) {
    parts.push(
      "",
      "A fix has been suggested:",
      "```",
      `- ${ctx.suggestedFix.origin.split("\n").join("\n- ")}`,
      `+ ${ctx.suggestedFix.replacement.split("\n").join("\n+ ")}`,
      "```"
    );
  }

  parts.push(
    "",
    ctx.intent === "suppress"
      ? "I am about to suppress this finding, which would stop it being reported " +
          "for this code from now on. Is it a false positive, or is this a real " +
          "vulnerability I should fix instead?"
      : "Explain this issue to me."
  );
  return parts.join("\n");
}

/**
 * Stream a reply from the Anthropic Messages API.
 *
 * `onDelta` receives text as it arrives so the panel can render progressively —
 * a silent multi-second wait reads as a hang.
 */
export function streamReply(
  messages: ChatMessage[],
  level: Level,
  onDelta: (text: string) => void,
  token?: vscode.CancellationToken,
  intent: Intent = "explain"
): Promise<string> {
  const apiKey = config<string>("agentApiKey", "").trim();
  if (!apiKey) return Promise.reject(new MissingApiKeyError());

  const model = config<string>("agentModel", "claude-sonnet-5");
  const body = JSON.stringify({
    model,
    max_tokens: 1024,
    system: systemPrompt(level, intent),
    stream: true,
    messages: messages.map((m) => ({ role: m.role, content: m.content })),
  });

  return new Promise<string>((resolve, reject) => {
    const req = https.request(
      {
        hostname: "api.anthropic.com",
        path: "/v1/messages",
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
      },
      (res) => {
        const status = res.statusCode ?? 0;

        if (status < 200 || status >= 300) {
          let errorBody = "";
          res.on("data", (c) => (errorBody += c));
          res.on("end", () =>
            reject(new Error(describeHttpError(status, errorBody)))
          );
          return;
        }

        let full = "";
        let buffer = "";

        res.on("data", (chunk) => {
          buffer += chunk.toString();
          // Server-sent events are newline-delimited; keep any partial tail.
          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";

          for (const line of lines) {
            if (!line.startsWith("data:")) continue;
            const payload = line.slice(5).trim();
            if (!payload || payload === "[DONE]") continue;
            try {
              const event = JSON.parse(payload);
              if (
                event.type === "content_block_delta" &&
                event.delta?.type === "text_delta" &&
                typeof event.delta.text === "string"
              ) {
                full += event.delta.text;
                onDelta(event.delta.text);
              }
            } catch {
              // A partial or non-JSON keepalive line — skip it.
            }
          }
        });

        res.on("end", () => resolve(full));
      }
    );

    req.setTimeout(120_000, () =>
      req.destroy(new Error("The agent did not respond within 120s."))
    );
    req.on("error", (err) => reject(err));
    token?.onCancellationRequested(() => req.destroy(new Error("Cancelled")));

    req.write(body);
    req.end();
  });
}

/** Turn an API status code into something the user can act on. */
function describeHttpError(status: number, body: string): string {
  let detail = "";
  try {
    detail = JSON.parse(body)?.error?.message ?? "";
  } catch {
    detail = body.slice(0, 200);
  }

  if (status === 401) {
    return "The API key was rejected. Check secureAssist.agentApiKey in Settings.";
  }
  if (status === 400 && /credit|balance/i.test(detail)) {
    return "The API account has no credit. Add credits in the Anthropic console.";
  }
  if (status === 429) {
    return "Rate limited by the API. Wait a moment and try again.";
  }
  return `The agent request failed (HTTP ${status})${detail ? `: ${detail}` : ""}`;
}
