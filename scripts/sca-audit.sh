#!/usr/bin/env bash
# SCA-перевірка залежностей (Software Composition Analysis) інструментом pip-audit.
# Запуск з кореня проєкту (у активованому .venv):  bash scripts/sca-audit.sh
# Код завершення 0 = нових вразливостей немає, 1 = знайдено нову вразливість.
#
# Прийняті ризики (обґрунтування та компенсувальні контролі — у SECURITY.md):
#   PYSEC-2026-2151  Flask 2.3.3        (Low)       фікс 3.1.3 несумісний з Flask-SQLAlchemy 2.5.1
#   PYSEC-2026-2270  python-dotenv 1.2.1 (Moderate)  фікс 1.2.2 потребує Python >= 3.10
#   PYSEC-2026-2132  click 8.1.8        (спірна)    фікс 8.3.3 потребує Python >= 3.10
set -euo pipefail
cd "$(dirname "$0")/.."

pip-audit -r requirements.txt \
  --ignore-vuln PYSEC-2026-2151 \
  --ignore-vuln PYSEC-2026-2270 \
  --ignore-vuln PYSEC-2026-2132
