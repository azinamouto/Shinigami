# Shinigami UI — Patch 01

Frontend-only preview for Shinigami. This phase **does not run scans**, does not use mock findings, and does not expose a local HTTP API. All scan/export actions are intentionally disabled until the Go integration lands.

## Start locally

From the repository root:

```powershell
cd web
npm install
npm run dev
```

Open the localhost address printed by Vite (usually `http://127.0.0.1:5173`).

## Production build

```powershell
npm run build
```

## Next phase

Connect to a localhost-only Go API. Validate scan paths, handle cancellation and timeouts, and preserve redaction. Do not expose a general-purpose command executor.
