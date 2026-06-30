#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "══════════════════════════════════════════"
echo "  ShadowCrypt++ API  v2.0.0"
echo "══════════════════════════════════════════"

if [ ! -d ".venv" ]; then
    echo "→ Creating virtual environment..."
    python -m venv .venv
fi

source .venv/bin/activate

echo "→ Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "→ Starting at http://0.0.0.0:8000"
echo "→ Swagger UI : http://localhost:8000/docs"
echo "→ ReDoc      : http://localhost:8000/redoc"
echo "══════════════════════════════════════════"

exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload \
    --log-level info
