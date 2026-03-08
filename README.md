# msaManager external workspace

- This workspace is synced from `../projects/carbonet/EgovMsaManager`.
- Runtime root for managed projects is controlled by `CARBOSYS_ROOT` (default `../../projects/carbonet` from manager working dir).

## Run by Maven

```bash
CARBOSYS_ROOT=../../projects/carbonet ./start-mvn.sh
```

## Run by JAR

```bash
cd EgovMsaManager
java -Dcarbosys.root=/opt/projects/carbonet -jar target/EgovMsaManager.jar --server.port=18030
```

## Important

- For SSH edit/exec APIs, set `MSA_SSH_EDIT_TOKEN` and send `X-MSA-SSH-TOKEN` header.
