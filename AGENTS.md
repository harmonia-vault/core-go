# Harmonia development rules

Experimental security software: do not claim production readiness.
Use synthetic secrets/accounts only in tests. Never scan or import the host's real environment.
No CI/CD, releases, installers or live deployment are authorized for this milestone.
Before public pushes, check tracked content for secrets and personal data.
Pin installed tools in mise.toml and expose tasks through mise.
Do not overwrite existing user files. Service and environment tests use isolated test directories or VMs.
UI is authored by one scoped local Claude Opus 5.5 medium-effort invocation; no UI unit tests.
Protocol, business logic and security testing remain with Codex.
