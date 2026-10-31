# Bifrost agent

The Go agent for Bifrost, Realmwatch's LLM-reviewed server management hub. The hub (a separate, private repository) proposes and reviews changes; this agent verifies each approval signature itself and runs only typed operations compiled into it. `operations/` is the source of truth for operation definitions.

## Repository rule: no real names

This repository is public. Never commit real organization, deployment, server, domain, tailnet, cloud resource or account names, addresses, credentials or production data, in code, tests, fixtures, docs, commit messages or pull requests. Use placeholders: `web-01`, `acme`, `example.com`, RFC 5737 addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Review the staged diff for identifiers before every commit.
