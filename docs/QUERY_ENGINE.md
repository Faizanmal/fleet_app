# Deterministic query engine

`SnapshotQueryRepository.get_latest_snapshots` and `get_device_time_window` are PostgreSQL implementations under `fleet.db.query_repository`. The former uses a tenant-filtered CTE with `row_number() OVER (PARTITION BY tenant_id, device_id ORDER BY collected_at DESC, id DESC)`, then applies typed filters and paginates with a count query that does not join one-to-many compliance rows. All SQL values are bound parameters; the filter model forbids extra fields and operators.

Pure metric rules live in `fleet.domain.metrics`; the source-level latest selection reference lives in `fleet.domain.latest`. `QueryResult[T]` includes tenant scope, input filters, numerator/denominator/exclusion counts, requested `as_of`, scope `data_as_of`, threshold source, row provenance, and version metadata. See `docs/DATA_DICTIONARY.md` for detailed semantics and rounding.

Historical detectors are implemented in `fleet.domain.insights.detect_insights`; the authorized all-observation loader and evidence persistence path is `fleet.insights.engine.run_insights`. Unlike latest inventory, it reads the complete tenant history through the requested cutoff, bounded at 10,000 observations. Rules, risk formula, coverage behavior, examples, and limitations are in `docs/ARCHITECTURE.md`.

Run `python scripts/tasks.py eval-offline` to compare the pinned source's exact reference outputs to `evals/golden/phase04_query_oracles.json`. PostgreSQL repository parity, RLS scope, pagination, as-of, and time-window checks are in `apps/api/tests/test_query_repository_postgres.py` and require `TEST_DATABASE_URL`, `TEST_DATABASE_APP_URL`, and `TEST_DATABASE_INGEST_URL`.
