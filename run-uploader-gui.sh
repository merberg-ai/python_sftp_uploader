#!/usr/bin/env bash
# Run GUI uploader
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/sftp_uploader_gui.py" --gui "$@"
