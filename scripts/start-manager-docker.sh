#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/util/msaManager/EgovMsaManager"
LOG_DIR="/opt/util/msaManager/logs"
PORT_FILE="${LOG_DIR}/manager-port.txt"
ROOT_DIR="${CARBOSYS_ROOT:-../../projects/carbonet}"
PORT_RANGE="${MSA_MANAGER_PORT_RANGE:-18030-18039}"
REQUESTED_PORT="${MSA_MANAGER_PORT:-}"
AUTO_BUILD_ON_START="${MSA_AUTO_BUILD_ON_START:-true}"

mkdir -p "${LOG_DIR}"

port_free() {
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${p}$"
  else
    ! netstat -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${p}$"
  fi
}

pick_port() {
  local start end p
  if [[ -n "${REQUESTED_PORT}" ]]; then
    if port_free "${REQUESTED_PORT}"; then
      echo "${REQUESTED_PORT}"
      return 0
    fi
    echo "Requested port ${REQUESTED_PORT} is busy; searching range ${PORT_RANGE}" >&2
  fi

  start="${PORT_RANGE%-*}"
  end="${PORT_RANGE#*-}"
  if [[ -z "${start}" || -z "${end}" || "${start}" == "${PORT_RANGE}" ]]; then
    start="18030"
    end="18039"
  fi

  for ((p=start; p<=end; p++)); do
    if port_free "${p}"; then
      echo "${p}"
      return 0
    fi
  done
  return 1
}

PORT="$(pick_port)" || {
  echo "No free port found in range ${PORT_RANGE}" >&2
  exit 1
}

echo "${PORT}" > "${PORT_FILE}"
echo "Using server.port=${PORT}" >&2

cd "${APP_DIR}"
if [[ "${AUTO_BUILD_ON_START,,}" == "true" ]]; then
  mvn -q -DskipTests package
else
  echo "Skip build on start (MSA_AUTO_BUILD_ON_START=${AUTO_BUILD_ON_START})" >&2
fi
exec java -Dcarbosys.root="${ROOT_DIR}" -Xms128m -Xmx256m -jar target/EgovMsaManager.jar --server.port="${PORT}"
