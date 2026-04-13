#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f "venv/bin/activate" ]; then
  source venv/bin/activate
else
  echo "Virtual environment not found. Create one with install.sh first."
  exit 1
fi

python app.py
