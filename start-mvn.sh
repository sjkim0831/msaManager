#!/usr/bin/env bash
set -euo pipefail
ROOT="${CARBOSYS_ROOT:-/opt/projects/carbosys}"
export CARBOSYS_ROOT="$ROOT"
cd "$(dirname "$0")/EgovMsaManager"
exec mvn spring-boot:run -Dspring-boot.run.jvmArguments="-Dcarbosys.root=${CARBOSYS_ROOT}"
