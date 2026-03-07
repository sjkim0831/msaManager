# msaManager external workspace

- This workspace is synced from `../projects/carbonet/EgovMsaManager`.
- Runtime root for managed projects is controlled by `CARBOSYS_ROOT` (default `../../projects/carbonet` from manager working dir).

## Run by Maven

```bash
CARBOSYS_ROOT=../../projects/carbonet ./start-mvn.sh
```

## Run by Docker

```bash
MSA_SSH_EDIT_TOKEN=change-me docker compose up -d --build
```

- Source folder is bind-mounted: `./EgovMsaManager -> /opt/util/msaManager/EgovMsaManager`
- On container start: Maven package runs automatically, then manager starts.
- Port is auto-selected in `18030-18039` (or set `MSA_MANAGER_PORT` explicitly).
- Selected port is written to `./logs/manager-port.txt`.

## Important

- For SSH edit/exec APIs, set `MSA_SSH_EDIT_TOKEN` and send `X-MSA-SSH-TOKEN` header.
- If you run a separate manager, set `DISABLE_EMBEDDED_MSA_MANAGER=true` on `carbosys-app` container.
