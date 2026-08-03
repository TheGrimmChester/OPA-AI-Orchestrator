# Interop

ORA may call OSA for findings / `security_run_id` linkage when `PEER_OSA_URL` is set. Empty peer URLs disable those features.

Service JWTs use `OPEN_SERVICE_JWT_SECRET` with `iss`/`aud`/`scope`. Browser clients never hold the service secret.
