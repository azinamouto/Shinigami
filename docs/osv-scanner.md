# OSV-Scanner v2 adapter (experimental)

Install the official OSV-Scanner v2 binary separately and add it to PATH.

```bash
go run ./cmd/shinigami scan -scanner osv .
go run ./cmd/shinigami scan -scanner all -format json .
```

`all` requires both Gitleaks and OSV-Scanner to be installed. OSV-Scanner
may contact external services to query vulnerabilities; it is **not offline**.
The adapter disables Go call analysis and never calls `fix`.
Severity is `UNKNOWN` pending validated severity mapping. The adapter has
unit tests, but real OSV v2 executable compatibility and known-vulnerable
fixtures still require validation before release.
