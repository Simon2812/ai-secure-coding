import * as vscode from "vscode";
import {
  ChatMessage,
  FindingContext,
  Level,
  Intent,
  MissingApiKeyError,
  buildContextMessage,
  streamReply,
} from "./agentClient";
import { PALETTE } from "../report/reportHtml";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Chat panel for the teacher agent.
 *
 * Separate from the fine-tuned model on purpose: that one detects and patches,
 * this one explains. It runs against a general-purpose API because teaching
 * needs conversational range that a narrow JSON-emitting fine-tune does not have.
 */
export class AgentPanel {
  private static current: AgentPanel | undefined;

  /**
   * The conversation, kept on the class rather than the instance: closing the
   * panel should not lose the thread, because the usual flow is to ask about a
   * finding, close the panel to edit the code, then come back and ask whether
   * the change was right.
   */
  private static messages: ChatMessage[] = [];
  /** What was displayed for each turn — the sent text includes file context. */
  private static transcript: { role: "user" | "assistant"; text: string }[] = [];

  private readonly panel: vscode.WebviewPanel;
  private readonly output: vscode.OutputChannel;
  private level: Level = "simple";
  /** Why the conversation was opened; shapes the system prompt. */
  private intent: Intent = "explain";
  /** File contents attached to the next question, then cleared. */
  private pendingContext: string | undefined;
  private busy = false;
  private disposables: vscode.Disposable[] = [];

  private constructor(panel: vscode.WebviewPanel, output: vscode.OutputChannel) {
    this.panel = panel;
    this.output = output;
    this.panel.webview.html = this.html();
    // The panel may have been closed and reopened mid-conversation; put the
    // transcript back so the thread is visible, not just retained internally.
    if (AgentPanel.transcript.length > 0) {
      this.post({ type: "replay", turns: AgentPanel.transcript });
    }
    this.panel.webview.onDidReceiveMessage((m) => this.onMessage(m), null, this.disposables);
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  /** Open the panel and start a conversation about a specific finding. */
  static async explain(ctx: FindingContext, output: vscode.OutputChannel): Promise<void> {
    const panel = AgentPanel.reveal(output);
    panel.intent = ctx.intent ?? "explain";
    panel.post({ type: "title", title: `${ctx.cwe}${ctx.title ? ` - ${ctx.title}` : ""}` });
    await panel.send(buildContextMessage(ctx), {
      display:
        ctx.intent === "suppress"
          ? `Is this ${ctx.cwe} finding in ${ctx.file} safe to suppress?`
          : `Explain the ${ctx.cwe} finding in ${ctx.file}.`,
    });
  }

  /**
   * Open the panel for a free-form question.
   *
   * The active file is attached but not sent yet: it is prepended to whatever
   * the developer asks first, so a question like "is this fix correct?" has the
   * code to reason about without a finding to hang the conversation on.
   */
  static open(output: vscode.OutputChannel): void {
    const panel = AgentPanel.reveal(output);
    panel.intent = "explain";

    const editor = vscode.window.activeTextEditor;
    if (editor && editor.document.uri.scheme === "file") {
      const file = vscode.workspace
        .asRelativePath(editor.document.uri, false)
        .replace(/\\/g, "/");
      const code = editor.document.getText();
      // Keep a large file from dominating the request.
      const trimmed =
        code.length > 12000 ? `${code.slice(0, 12000)}\n… (truncated)` : code;

      panel.pendingContext = [
        `For reference, here is the file I am working in (${file}):`,
        "",
        "```",
        trimmed,
        "```",
        "",
      ].join("\n");

      panel.post({ type: "title", title: `context: ${file}` });
    } else {
      panel.pendingContext = undefined;
      panel.post({ type: "title", title: "no file attached" });
    }
  }

  private static reveal(output: vscode.OutputChannel): AgentPanel {
    if (AgentPanel.current) {
      AgentPanel.current.panel.reveal(vscode.ViewColumn.Beside, true);
      return AgentPanel.current;
    }
    const panel = vscode.window.createWebviewPanel(
      "secureAssistAgent",
      "Secure Assist - Ask",
      { viewColumn: vscode.ViewColumn.Beside, preserveFocus: false },
      { enableScripts: true, retainContextWhenHidden: true }
    );
    AgentPanel.current = new AgentPanel(panel, output);
    return AgentPanel.current;
  }

  private post(message: unknown): void {
    this.panel.webview.postMessage(message);
  }

  /**
   * Send a turn and stream the reply.
   *
   * `display` lets the opening turn show a short line in the transcript while
   * the model receives the full finding context.
   */
  private async send(content: string, opts?: { display?: string }): Promise<void> {
    if (this.busy) return;
    this.busy = true;

    // A free-form conversation carries the open file into its first question.
    const withContext = this.pendingContext ? this.pendingContext + content : content;
    this.pendingContext = undefined;

    const shown = opts?.display ?? content;
    AgentPanel.messages.push({ role: "user", content: withContext });
    AgentPanel.transcript.push({ role: "user", text: shown });
    this.post({ type: "user", text: shown });
    this.post({ type: "start" });

    let reply = "";
    try {
      reply = await streamReply(
        AgentPanel.messages,
        this.level,
        (delta) => this.post({ type: "delta", text: delta }),
        undefined,
        this.intent
      );
      AgentPanel.messages.push({ role: "assistant", content: reply });
      AgentPanel.transcript.push({ role: "assistant", text: reply });
      this.post({ type: "end" });
    } catch (err: any) {
      // Drop the unanswered turn so a retry doesn't resend it twice.
      AgentPanel.messages.pop();
      AgentPanel.transcript.pop();
      const message =
        err instanceof MissingApiKeyError
          ? err.message
          : err?.message ?? String(err);
      this.post({ type: "error", text: message });
      this.output.appendLine(`[agent] ${message}`);
    } finally {
      this.busy = false;
    }
  }

  private async onMessage(msg: any): Promise<void> {
    switch (msg?.type) {
      case "ask":
        if (typeof msg.text === "string" && msg.text.trim()) {
          await this.send(msg.text.trim());
        }
        break;
      case "level":
        this.level = msg.value === "technical" ? "technical" : "simple";
        break;
      case "openSettings":
        await vscode.commands.executeCommand(
          "workbench.action.openSettings",
          "secureAssist.agentApiKey"
        );
        break;
      case "clear":
        AgentPanel.messages = [];
        AgentPanel.transcript = [];
        this.post({ type: "reset", title: "" });
        break;
    }
  }

  private html(): string {
    return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><style>${PALETTE}${STYLES}</style></head>
<body>
  <header class="bar">
    <div class="titles">
      <span class="name">Ask about this finding</span>
      <span class="subject" id="subject"></span>
    </div>
    <div class="controls">
      <button id="lvl-simple" class="seg active">Explain simply</button><button id="lvl-tech" class="seg">Technical</button>
      <button id="clear" class="ghost">Clear</button>
    </div>
  </header>

  <div id="log" class="log"></div>

  <div class="composer">
    <textarea id="q" rows="2" placeholder="Ask a follow-up…  (Enter to send, Shift+Enter for a new line)"></textarea>
    <button id="send" class="primary">Send</button>
  </div>

  <script>
    const vscode = acquireVsCodeApi();
    const log = document.getElementById('log');
    const input = document.getElementById('q');
    const send = document.getElementById('send');
    let streaming = null;

    function bubble(cls, text) {
      const el = document.createElement('div');
      el.className = 'msg ' + cls;
      el.textContent = text;
      log.appendChild(el);
      log.scrollTop = log.scrollHeight;
      return el;
    }

    function ask() {
      const text = input.value.trim();
      if (!text || send.disabled) return;
      input.value = '';
      vscode.postMessage({ type: 'ask', text });
    }

    send.addEventListener('click', ask);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ask(); }
    });

    document.getElementById('clear').addEventListener('click', () => vscode.postMessage({ type: 'clear' }));

    for (const [id, value] of [['lvl-simple', 'simple'], ['lvl-tech', 'technical']]) {
      document.getElementById(id).addEventListener('click', () => {
        vscode.postMessage({ type: 'level', value });
        document.getElementById('lvl-simple').classList.toggle('active', value === 'simple');
        document.getElementById('lvl-tech').classList.toggle('active', value === 'technical');
      });
    }

    window.addEventListener('message', (event) => {
      const msg = event.data;
      if (msg.type === 'reset') {
        log.innerHTML = '';
        document.getElementById('subject').textContent = msg.title || '';
      } else if (msg.type === 'title') {
        // Opening the panel again retitles it without discarding the thread.
        document.getElementById('subject').textContent = msg.title || '';
      } else if (msg.type === 'replay') {
        log.innerHTML = '';
        for (const turn of msg.turns || []) {
          bubble(turn.role === 'user' ? 'user' : 'bot', turn.text);
        }
      } else if (msg.type === 'user') {
        bubble('user', msg.text);
      } else if (msg.type === 'start') {
        send.disabled = true;
        streaming = bubble('bot pending', '');
      } else if (msg.type === 'delta') {
        if (streaming) {
          streaming.classList.remove('pending');
          streaming.textContent += msg.text;
          log.scrollTop = log.scrollHeight;
        }
      } else if (msg.type === 'end') {
        send.disabled = false;
        if (streaming) streaming.classList.remove('pending');
        streaming = null;
      } else if (msg.type === 'error') {
        send.disabled = false;
        if (streaming) { streaming.remove(); streaming = null; }
        const el = bubble('error', msg.text);
        if (/API key/i.test(msg.text)) {
          const btn = document.createElement('button');
          btn.className = 'ghost';
          btn.textContent = 'Open settings';
          btn.addEventListener('click', () => vscode.postMessage({ type: 'openSettings' }));
          el.appendChild(document.createElement('br'));
          el.appendChild(btn);
        }
      }
    });
  </script>
</body></html>`;
  }

  private dispose(): void {
    AgentPanel.current = undefined;
    this.panel.dispose();
    while (this.disposables.length) this.disposables.pop()?.dispose();
  }
}

const STYLES = `
* { box-sizing: border-box; }
html, body { height: 100%; }
body {
  font-family: var(--font); font-size: 13.5px; margin: 0;
  color: var(--text); background: var(--bg);
  display: flex; flex-direction: column; line-height: 1.55;
}
.bar {
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  padding: 10px 16px; border-bottom: 1px solid var(--border); background: var(--surface);
}
.titles { flex: 1; min-width: 0; }
.name { font-weight: 500; }
.subject { display: block; color: var(--text-dim); font-size: 0.78rem; }
.controls { display: flex; align-items: center; gap: 6px; }
button {
  font-family: inherit; font-size: 0.78rem; padding: 4px 11px;
  border-radius: 4px; border: 1px solid var(--border);
  background: var(--surface-2); color: var(--text); cursor: pointer;
}
button.primary { background: var(--accent); color: var(--accent-fg); border-color: transparent; }
button.ghost { background: transparent; color: var(--text-dim); }
button.seg { border-radius: 0; color: var(--text-dim); }
button.seg:first-of-type { border-radius: 4px 0 0 4px; }
button.seg:nth-of-type(2) { border-radius: 0 4px 4px 0; border-left: none; }
button.seg.active { color: var(--text); background: var(--surface); border-color: var(--border-strong); }
button:disabled { opacity: 0.5; cursor: default; }

.log { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 12px; }
.msg { max-width: 90%; padding: 10px 13px; border-radius: 10px; white-space: pre-wrap; }
.msg.user { align-self: flex-end; background: var(--accent); color: var(--accent-fg); border-bottom-right-radius: 3px; }
.msg.bot { align-self: flex-start; background: var(--surface); border: 1px solid var(--border); border-bottom-left-radius: 3px; }
.msg.error { align-self: flex-start; background: transparent; border: 1px solid var(--bad); color: var(--bad); }
/* Placeholder pulse until the first token arrives. */
.msg.pending::after { content: '…'; color: var(--text-dim); }

.composer {
  display: flex; gap: 8px; padding: 12px 16px;
  border-top: 1px solid var(--border); background: var(--surface);
}
textarea {
  flex: 1; resize: none; font-family: inherit; font-size: 13.5px; line-height: 1.5;
  padding: 8px 10px; border-radius: 6px;
  border: 1px solid var(--border); background: var(--bg); color: var(--text);
}
textarea:focus { outline: none; border-color: var(--border-strong); }
`;
