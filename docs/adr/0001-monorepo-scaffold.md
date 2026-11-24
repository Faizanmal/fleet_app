# ADR 0001: Monorepo scaffold

- Status: Accepted
- Decision: keep API, web, migrations, evaluation assets, scripts, and documentation in one repository; pin Python and JavaScript dependencies.
- Reason: one clean-clone workflow is easier to reproduce across Windows, Linux, and macOS while interfaces are still evolving.
- Consequence: Docker Compose is the supported local PostgreSQL behavior; domain schema and business decisions remain deferred.
