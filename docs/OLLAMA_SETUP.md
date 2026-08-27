# Running ReconTitan with Ollama + Qwen

ReconTitan finds vulnerabilities with deterministic Python. **No model decides what a
finding is.** The AI layer sits on top of that result and explains it. If the model is
unreachable, every AI surface falls back to built-in text and the scan still completes —
so a broken Ollama degrades the report, it never breaks the scanner.

---

## 1. Install and start Ollama

Download from [ollama.com](https://ollama.com). On Windows it installs to
`%LOCALAPPDATA%\Programs\Ollama` and normally starts on login.

If the API is not answering, start it manually:

```bash
ollama serve
```

Confirm it is up — this must return JSON, not a connection error:

```bash
curl http://localhost:11434/api/tags
```

---

## 2. Pull a Qwen model

```bash
ollama pull qwen2.5:1.5b-instruct
```

### Choosing the size

This matters more than it looks. The model is being asked to make security judgements,
and a small one gets them wrong in ways that read as confident.

| Model | Disk | Fits 4 GB VRAM | Quality for this job |
|---|---|---|---|
| `qwen2.5:1.5b-instruct` | ~1 GB | yes, easily | Explains a vulnerability adequately. **Triage verdicts are unreliable.** |
| `qwen2.5:3b-instruct` | ~2 GB | yes | Noticeably better reasoning. **Best balance on a 4 GB card.** |
| `qwen2.5:7b-instruct` | ~4.7 GB | no — partial CPU offload | Best quality; slower, needs ~8 GB free RAM |

**Observed with 1.5b:** asked to triage a genuinely missing `Content-Security-Policy`
header, it returned `LIKELY_FALSE_POSITIVE` while its own explanation directly below
described the vulnerability correctly. The plumbing handled that safely — the verdict was
normalised into the allowed set and marked `confidence: low` — but it shows where the
limit is. Treat 1.5b's *explanations* as useful and its *verdicts* as decorative.

To upgrade:

```bash
ollama pull qwen2.5:3b-instruct
```

Then set `OLLAMA_MODEL=qwen2.5:3b-instruct` in `.env` and restart the API.

---

## 3. Environment variables

The AI block in `.env`:

```bash
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:1.5b-instruct
OLLAMA_TIMEOUT=120
OLLAMA_NUM_CTX=4096
OLLAMA_KEEP_ALIVE=10m

AI_MAX_FINDING_EXPLANATIONS=8
AI_EXPLANATION_BUDGET_SECONDS=90
AI_EXPLANATION_CONCURRENCY=2
```

### What each one does

| Variable | Purpose |
|---|---|
| `AI_PROVIDER` | `ollama` = local only, nothing leaves the host. `auto` = Ollama, else OpenAI if keyed, else static text. `openai` = hosted only. `none` = AI off entirely. |
| `OLLAMA_BASE_URL` | Where Ollama listens. `localhost:11434` bare-metal; `http://host.docker.internal:11434` from a container reaching the host. |
| `OLLAMA_MODEL` | Pin the model. **Leave blank to auto-pick the first installed model** — convenient, but the behaviour changes the moment you pull another model, so pin it for anything you rely on. |
| `OLLAMA_TIMEOUT` | Per-request seconds. A cold model load is slow; 120 is generous on CPU. |
| `OLLAMA_NUM_CTX` | Context window. 4096 fits a scan summary comfortably. |
| `OLLAMA_KEEP_ALIVE` | How long Ollama keeps the model in memory between calls. Longer = no reload cost between findings. |

### Cost controls

Each explanation is one model round-trip, and a local CPU model takes seconds each. The
per-scan narration budget is capped three ways so a slow model can never hold a scan open:

| Variable | Default | Effect |
|---|---|---|
| `AI_MAX_FINDING_EXPLANATIONS` | `8` | How many findings get an inline explanation, highest severity first |
| `AI_EXPLANATION_BUDGET_SECONDS` | `90` | Wall-clock ceiling for the whole narration pass |
| `AI_EXPLANATION_CONCURRENCY` | `2` | Parallel requests to the model |

Findings that run out of budget keep the static explanation the report already renders.
Raise `AI_MAX_FINDING_EXPLANATIONS` for fuller reports at the cost of scan time.

---

## 4. Verify it is actually being used

```bash
curl -s http://localhost:8000/api/ai/status
```

`active_backend` tells you what is really answering:

```json
{"provider":"ollama","active_backend":"ollama","model":"qwen2.5:1.5b-instruct",
 "ollama":{"available":true,"error":""}}
```

If `active_backend` is `fallback`, the `ollama.error` field says why — connection refused
means Ollama is not running, and an empty model list means nothing has been pulled.

The report page shows the same thing as a badge beside the AI buttons: `OLLAMA ·
qwen2.5:1.5b-instruct` when live, `NO MODEL · STATIC ANSWERS` when not. **A canned
fallback answer is always visually distinguishable from a model's.**

Test a topic explanation directly:

```bash
curl -s -X POST http://localhost:8000/api/ai/explain -H "Content-Type: application/json" -d "{\"topic\":\"CORS misconfiguration\"}"
```

---

## 5. What you get in the UI

| Surface | When | What |
|---|---|---|
| Executive summary | automatic, end of scan | Risk level, posture summary, top recommendations |
| Per-finding explanation | automatic, top 8 findings | Plain English: what it is, what goes wrong, how to fix |
| **🤖 Verify with AI** | button in finding modal | Triage verdict + confidence, attacker impact, remediation, references |
| **🧠 Explain this topic** | button in finding modal | Teaches the concept behind the finding |

### What "Verify with AI" is not

It does **not** re-attack the target — pressing it sends zero packets to the scanned host.
It passes the evidence the scanner already recorded to the model and asks for a second
opinion: does this evidence support a real issue, or is it scanner noise?

Verdicts are `TRUE_POSITIVE`, `LIKELY_TRUE_POSITIVE`, `NEEDS_MANUAL_REVIEW`, or
`LIKELY_FALSE_POSITIVE`, each with a confidence level. Anything the model returns outside
that set is normalised to `NEEDS_MANUAL_REVIEW`, which is the honest reading of an unclear
answer. It is triage assistance, not proof.

---

## 6. Privacy

With `AI_PROVIDER=ollama`, **finding text never leaves your machine.** That is the main
reason to prefer a local model here: scan evidence routinely contains hostnames, paths,
and token fragments belonging to the target.

`AI_PROVIDER=openai` sends that same text to OpenAI. Only enable it for targets whose data
you are permitted to share with a third party.

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `active_backend: fallback`, error mentions `ConnectionError` | Ollama not running | `ollama serve` |
| `active_backend: fallback`, error mentions "no model is pulled" | Ollama up, no models | `ollama pull qwen2.5:1.5b-instruct` |
| Log warns `OLLAMA_MODEL=... is not installed; falling back to ...` | Pinned model not present | Pull it, or clear `OLLAMA_MODEL` to auto-pick |
| Scans feel slow after enabling AI | Narration budget too high for your hardware | Lower `AI_MAX_FINDING_EXPLANATIONS` |
| First request very slow, later ones fast | Cold model load | Raise `OLLAMA_KEEP_ALIVE` |
| Explanations good, verdicts wrong | Model too small for triage | Use `qwen2.5:3b-instruct` or larger |
