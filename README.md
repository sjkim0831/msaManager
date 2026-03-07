# msaManager external workspace

- This workspace is synced from `/opt/carbosys/module/EgovMsaManager`.
- Runtime root for managed projects is controlled by `CARBOSYS_ROOT` (default `/opt/carbosys`).

## Run by Maven

```bash
CARBOSYS_ROOT=/opt/carbosys ./start-mvn.sh
```

## Run by Docker

```bash
MSA_SSH_EDIT_TOKEN=change-me docker compose up -d --build
```

## Important

- For SSH edit/exec APIs, set `MSA_SSH_EDIT_TOKEN` and send `X-MSA-SSH-TOKEN` header.
- If you run a separate manager, set `DISABLE_EMBEDDED_MSA_MANAGER=true` on `carbosys-app` container.
