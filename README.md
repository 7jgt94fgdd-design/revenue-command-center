# Revenue Command Center v0.7 — Backend/Auth Foundation

This version adds a real local backend foundation using Python standard-library HTTP server + SQLite:
- SQLite persistence
- organization/tenant IDs
- users and roles
- password hashing
- session tokens
- server-side tenant scoping
- audit events
- claims
- dashboard API
- login/logout
- demo seed data

Run:
python backend/server.py

Open:
http://127.0.0.1:8080

Demo accounts:
admin@demo.local / ChangeMe123!
manager@demo.local / Manager123!

IMPORTANT: This remains a development prototype. Do not enter PHI. Production healthcare use requires security engineering, risk analysis, appropriate contractual/BAA arrangements, monitoring, testing, deployment hardening, and authorized integrations.


## v1.1 Procurement Demo

See `docs/v11-pilot-demo.md` and `docs/procurement-one-pager.md` for the hospital demo script and procurement positioning. The application remains synthetic-data-only.
