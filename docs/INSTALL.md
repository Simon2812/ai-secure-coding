# Installing Secure Assist

The extension ships as a single file, `secure-assist-0.0.1.vsix`. Everything the
analyzer needs is inside it — no dependencies to install, no network access, no
GPU.
[Download `secure-assist-0.0.1.vsix`](https://github.com/Simon2812/ai-secure-coding/releases/tag/v0.0.1)

---

## 1. Install the extension

Either method works. Both need VS Code 1.109 or newer.

**From the VS Code interface**

1. Open the **Extensions** view (`Ctrl+Shift+X`)
2. Click the **`...`** menu at the top of the panel
3. Choose **Install from VSIX...**
4. Select `secure-assist-0.0.1.vsix`

**From a terminal**

```bash
code --install-extension secure-assist-0.0.1.vsix
```

### Then reload

Installing does not activate the extension in windows that are already open.
Press `Ctrl+Shift+P`, run **Developer: Reload Window**, or just restart VS Code.

You should see these in the status bar along the bottom left:

| Icon | Shows as | What it does |
|---|---|---|
| 🛡️ | 🛡️ Scan with AI | Runs the AI analysis on the file you are editing |
| 🔍 | 🔍 Deep Scan Project | Scans every source file and opens the report |
| 💬 | 💬 Ask | Asks the security assistant about the open file |
| ⚙️ | ⚙️ | Settings (icon only, no label) |

Two more appear only when they have something to show:

| Icon | Shows as | When |
|---|---|---|
| ⚡ | ⚡ 3 AI fixes | After a scan that produced fixes for the file |
| 🚫 | 🚫 2 dismissed | When findings have been dismissed in the file |

If they are not there, the extension has not activated - reload again.

---

## 2. Use it

Open any Python, Java or C file. Findings appear as you type: a coloured
underline on the offending line, an entry in the **Problems** panel, and a
lightbulb offering an explanation.

**Deep Scan Project** scans the whole workspace and opens a report with a score
per file and folder, a CWE breakdown, and a score trend across scans.

This much needs nothing else installed. The steps below are only for the AI
features.

---

## 3. Optional — AI repairs 
**Note - model running always on cloud is future work, right now only local available**

The model runs locally in Docker and suggests fixes for the findings.

**Requirements:** Docker Desktop, an NVIDIA GPU with 8 GB VRAM (minimum, 12GB is recommended), and
about 15 GB of disk for the model weights.

```bash
docker build -f llm-module/Dockerfile_updated -t secure-coding-llm llm-module
```

Then start it, mounting the Hugging Face cache so the weights are downloaded
only once:

```powershell
secure-assist\start-model.ps1
```

The first start downloads the model and takes several minutes. Wait until this
answers before scanning:

```powershell
Invoke-RestMethod http://localhost:8000/health
```

Now **Scan with AI** in the status bar reviews the open file and proposes fixes.
Every fix is shown as a before/after diff and applied only if you accept it.
Applied fixes can be reverted, which restores the original code *and* the
finding.

If the server runs elsewhere, point the extension at it:

```
Settings → secureAssist.modelEndpoint
```

---

## 4. Optional — the AI assistant
**Note - AI agent running always on cloud is future work, right now can only be accessed with your own private API key**

The assistant explains findings in plain language: what an attacker would do
with one, why a suggested fix works, and whether dismissing it is safe.

It uses the Anthropic API and needs a key:

1. `Ctrl+,` to open Settings
2. Search for `secureAssist.agentApiKey`
3. **Select the User tab, not Workspace**, and paste the key

Putting it under Workspace writes it into `.vscode/settings.json`, which is
usually committed to version control. Under User it stays on your machine.

---

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `secureAssist.liveMode` | `true` | Analyse as you type. Turn off to analyse on save only |
| `secureAssist.modelEndpoint` | `http://localhost:8000` | Where the model server is |
| `secureAssist.enabledCwes` | all on | Which CWEs are reported and counted in the score |
| `secureAssist.agentApiKey` | — | Anthropic API key for the assistant |

---

## Troubleshooting

**No buttons in the status bar.** The extension has not activated. Reload the
window. If it still does not appear, check **Help → Toggle Developer Tools →
Console** for an activation error.

**No findings in a file that should have them.** Check the language is
supported — Python, Java and C only. Check the CWE has not been switched off in
**Settings → Suppressed findings**, and that the finding was not previously
dismissed.

**"Could not reach the model server."** The container is not running or is still
loading. `docker ps` should list it; `Invoke-RestMethod http://localhost:8000/health`
should return `status: ok`. The first start after a build takes several minutes
while the model loads.

**Scanning with AI is slow.** Expect roughly six seconds per file. Large files
take longer, because attention cost grows with the square of the file length.

**Two sets of buttons.** Both the installed extension and a development build
are running. Uninstall one:

```bash
code --uninstall-extension secure-assist.secure-assist
```

---

## Removing it

```bash
code --uninstall-extension secure-assist.secure-assist
```

Or from the Extensions view: find **Secure Assist**, click the gear, choose
**Uninstall**.

Suppressions, scan history and stored AI findings live in VS Code's workspace
storage and are removed with the extension.
