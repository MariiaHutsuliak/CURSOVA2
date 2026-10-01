#!/usr/bin/env bash
# Повна перевірка історії Git на секрети (Gitleaks).
# Запуск з кореня проєкту:  bash scripts/secret-scan.sh
# Код завершення 0 = PASS (секретів немає), 1 = FAIL (секрет знайдено).
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "gitleaks не встановлено. Встановлення (macOS): brew install gitleaks" >&2
  exit 1
fi

gitleaks git --redact --verbose --config .gitleaks.toml .
echo "SECRET SCAN: PASS (у історії комітів секретів не знайдено)"
