# shinigami

**Local-first repository security scanner — early prototype.**

Shinigami is an open-source defensive security scanner. The current prototype runs four **heuristic** configuration/code checks and outputs terminal or JSON findings. Findings are leads for human review, **not confirmed vulnerabilities**.

## Requirements

Go 1.23+

## Quick start

```bash
go run ./cmd/shinigami version
go run ./cmd/shinigami rules
go run ./cmd/shinigami scan ./path/to/repository
go run ./cmd/shinigami scan -format json ./path/to/repository
go run ./cmd/shinigami scan -fail-on-findings ./path/to/repository
```

To install locally:

```bash
go install ./cmd/shinigami
```

## Current checks

- `SHI001`: TLS certificate verification disabled
- `SHI002`: debug mode explicitly enabled
- `SHI003`: permissive CORS configuration
- `SHI004`: shell execution with `shell: true`

Scans skip common generated/vendor directories and files larger than 2 MiB. JSON findings contain no source snippets. The scanner does not execute repository code.

## Limitations

This is **not** a complete security audit. Rules are regex-based and can produce false positives and false negatives. There is no GitHub URL import, dependency audit, Gitleaks integration, Semgrep integration, SARIF, web app, or AI integration yet. Do not expose reports containing private paths without reviewing them.

## Roadmap

1. Strengthen tests, binary handling, ignore rules, and rule fixtures.
2. Integrate Gitleaks and OSV-Scanner through isolated adapters.
3. Add SARIF output and GitHub Actions examples.
4. Add secure public GitHub import; later support private repositories through a GitHub App.
5. Build a hosted dashboard only after hardening the scan execution model.

## Development

```bash
go test ./...
go vet ./...
go build ./cmd/shinigami
```

## Security

Only scan code you own or are authorized to assess. Do not treat a zero-findings result as proof of security. Please avoid posting sensitive repository contents in public issues.
