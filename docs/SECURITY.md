# Security baseline

- Demo authentication defaults off. Fixed fixture principals are available only when `DEMO_AUTH_MODE=true` outside production; production identity integration is not yet implemented.
- Actions are proposal-only until separately approved. The only executor is a database-only `SANDBOX_SIMULATION`; `REAL_EXTERNAL` has no registered sender and is denied by default. Requester/approver separation is enabled by default.
- The database has no host-published port. App port publications bind to localhost for local development.
- CORS accepts only the configured explicit origin allowlist.
- Database credentials in Compose and `.env.example` are disposable local-development values only.
- Do not place telemetry natural-language strings into privileged prompts or treat them as instructions. Future LLM features must isolate such strings as untrusted data, use structured evidence, and test prompt-injection cases.
- PostgreSQL RLS and server-side tenant scope are implemented for current tenant-owned tables, including proposal, approval, execution, audit-chain, checkpoint, and outbox records. See [04_SECURITY_THREAT_MODEL.md](04_SECURITY_THREAT_MODEL.md) and [09_ACTIONS_APPROVALS_EXECUTOR.md](09_ACTIONS_APPROVALS_EXECUTOR.md). Secrets management and production authentication are not implemented.
