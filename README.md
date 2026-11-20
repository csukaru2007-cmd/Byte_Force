# ShipSafe (Byte_Force)

Agentic security gate for AI-generated applications: established scanners collect evidence,
a LangGraph workflow with Gemini triages it, and a deterministic policy engine decides
**CRITICAL** (block) / **MEDIUM** (review) / **GOOD** (deploy).

```
START -> intake -> [dependency_intel | code_scan | secret_scan | vuln_audit | authz_review] (parallel)
      -> normalize -> llm_triage (Gemini, advisory) -> policy (deterministic) -> report -> END
```

The graph, the FastAPI app, and the CLI are in `src/ai_agent/main.py`. The scanners are in `src/ai_agent/tools/`.

## Run locally

```bash
uv sync
uv run uvicorn ai_agent.main:app --app-dir src --reload        # web UI at http://127.0.0.1:8000
uv run python -m ai_agent.main scan path/to/repo --markdown pr.md   # CI gate (exit 0 GOOD / 2 MEDIUM / 1 CRITICAL)
```

Put `GOOGLE_API_KEY=...` in `.env` to turn on Gemini triage (optional `GEMINI_MODEL`, default `gemini-3.5-flash-lite`).

## Deploy to Vercel

1. Import this repository at https://vercel.com/new. Use the repo root as the project root and the default settings.
   `vercel.json` routes every request to `api/index.py`, which serves the FastAPI app.
2. Under Settings → Environment Variables, add `GOOGLE_API_KEY`. Optionally add `GITHUB_TOKEN`
   for higher GitHub API limits when scanning repositories.
3. Redeploy and open the URL.

On Vercel, Bandit, detect-secrets, pip-audit, PyPI intelligence and the authz checks run in the function.
Gitleaks and Semgrep are native binaries that the function does not include. They show up as
"not available in this runtime" and are not counted as failures. They do run locally and in CI when installed.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | which tools / LLM are available, the policy rules |
| GET | `/api/samples` | demo apps (clean, secrets, injection, dependencies, authz) |
| POST | `/api/scan` | `{"source":"sample","sample":"secrets"}` · `{"source":"files","files":[{"path","content"}]}` · `{"source":"github","repo":"owner/repo"}` |
| POST | `/api/scan/stream` | same body; NDJSON progress events per graph node, then the result |
| GET | `/api/graph` | Mermaid diagram of the compiled LangGraph |
