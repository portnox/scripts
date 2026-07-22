#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_BIN="${PORTNOX_MCP_PYTHON:-}"

if [[ -z "$PY_BIN" ]]; then
  if [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
    PY_BIN="$SCRIPT_DIR/.venv/bin/python"
  else
    PY_BIN="$(command -v python3 || true)"
  fi
fi

if [[ -z "$PY_BIN" ]]; then
  echo "Portnox MCP launcher error: python3 was not found." >&2
  exit 1
fi

# Claude Desktop launches MCP servers over stdio.
exec "$PY_BIN" "$SCRIPT_DIR/MCP Server.py" --transport stdio
