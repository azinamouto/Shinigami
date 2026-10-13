Shinigami UI 02 — local API integration

Terminal 1 (repository root):
  go run ./cmd/shinigami-web

Terminal 2 (repository root):
  cd web
  npm install
  npm run dev

Open http://127.0.0.1:5173

Use an absolute local directory path (example: C:\Users\admin\Downloads\shinigami-starter).
Choose native/gitleaks/osv/all and run. Reports are kept only in process memory.
Do not expose the API or Vite server publicly. The API listens only on 127.0.0.1.
The API is intended for a trusted local computer, not for multi-user deployment.
