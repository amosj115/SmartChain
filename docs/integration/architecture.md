# Integration Hub Architecture

## Current implementation

SmartChain is a Flask application using Flask-SQLAlchemy and SQLite by default. The Hub is a blueprint and service inside that application, with `IntegrationConnection` and `IntegrationTransaction` tables. Startup uses `db.create_all()`; this adds the new tables without dropping or rebuilding existing tables. There is no migration framework in the current repository.

The implemented synchronous sandbox path is:

1. An administrator submits a connector operation, a JSON object, and an idempotency key.
2. The service validates the operation contract and rejects fields outside its allowlist.
3. It canonicalizes and hashes the request, and checks the unique idempotency key.
4. A sandbox response is generated, explicitly marked non-authoritative, and stored with request/response hashes, transaction and correlation IDs, actor, and audit record.
5. Repeating the same request returns the existing transaction. Reusing its key with different content returns a conflict.

External systems are never called by this implementation. Sandbox values do not verify suppliers, publish tenders, reserve travel, or check budgets. Native SmartChain systems are listed as `INTERNAL`; listing them does not claim event-driven integration.

## Data safety

No existing tables are altered and no existing records are deleted. New tables use database uniqueness constraints and indexes for idempotency, transaction IDs, correlation IDs, target/creation time, status/creation time, and case IDs. The transaction payloads are limited to the fields explicitly allowed for each operation. Hashes provide tamper-evidence for the captured payload bytes; they are not a substitute for immutable/WORM storage or a cryptographic signature.

Credentials are not stored in the Hub. No live endpoint configuration or secrets manager integration exists yet. Production use requires a reviewed migration strategy, secure secret provider, TLS and service authentication configuration, and authorized interface specifications.

## Not implemented yet

There is no asynchronous worker or durable message queue, retry scheduler, dead-letter queue, webhook receiver/signature verification, reconciliation workflow, document exchange service, event bus, external health probe, credential manager, metrics exporter, SLA/escalation engine, or automated backup/restore flow. The current sandbox call is synchronous and should not be used as a production integration transport.

## Verification boundary

Automated tests demonstrate app startup, sandbox transaction persistence, idempotent replay, conflicting-key rejection, audit capture, and RBAC denial. They do not demonstrate browser E2E execution, external-system access, load/failure recovery, migration rollback, or production readiness.