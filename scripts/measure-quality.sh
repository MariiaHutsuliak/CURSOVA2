#!/usr/bin/env bash
# ЛР5: відтворюване вимірювання метрик якості. Працює і в Docker, і локально.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p reports

echo "== Preflight: файли з BOM (Radon на них падає) =="
SRC="app.py models.py queries.py resilience.py history_utils.py privacy"
BOM_FILES=$(grep -rl --include='*.py' -e $'\xef\xbb\xbf' $SRC 2>/dev/null || true)
if [ -n "$BOM_FILES" ]; then
  echo "ПОМИЛКА: знайдено .py-файли з BOM, метрики були б пораховані некоректно:"
  echo "$BOM_FILES"
  exit 1
fi
echo "BOM не знайдено"

echo "== Версії інструментів (фіксуються у звіті) =="
python --version
python - <<'PY'
import importlib.metadata as m
for n in ("lizard", "radon", "mutmut"):
    try:
        print(f"{n}=={m.version(n)}")
    except m.PackageNotFoundError:
        print(f"{n}: не встановлено")
PY

echo "== Lizard: складність (CCN) =="
python -m lizard app.py models.py queries.py privacy resilience.py history_utils.py \
  --xml > reports/lizard.xml
python -m lizard app.py models.py queries.py privacy resilience.py history_utils.py -C 10 -w || true

echo "== Radon: цикломатична складність та Maintainability Index =="
python -m radon cc app.py models.py queries.py privacy resilience.py -a -s -j > reports/radon-cc.json
python -m radon mi app.py models.py queries.py privacy -s -j > reports/radon-mi.json
echo "Готово: reports/lizard.xml, reports/radon-cc.json, reports/radon-mi.json"
