import json
import threading
from pathlib import Path
from datetime import datetime

HISTORY_DIR = Path("history")
HISTORY_DIR.mkdir(exist_ok=True)

# Захист від race condition: без цього блокування паралельні запити одного
# користувача (наприклад, кілька вкладок або, як у нашому випадку,
# навантажувальний тест) можуть одночасно виконати read-modify-write
# по одному й тому самому history/user_<id>.json та пошкодити файл
# (JSONDecodeError: Extra data). Виявлено під час k6-навантаження.
_history_lock = threading.Lock()

def history_file(user_id):
    return HISTORY_DIR / f"user_{user_id}.json"

def load_history(user_id):
    file = history_file(user_id)
    if not file.exists():
        return []
    with open(file, "r", encoding="utf-8") as f:
        return json.load(f)

def save_history(user_id, history_list):
    file = history_file(user_id)
    with open(file, "w", encoding="utf-8") as f:
        json.dump(history_list, f, ensure_ascii=False, indent=2)

def add_history_entry(user_id, api_name, params, result_text):
    with _history_lock:
        history = load_history(user_id)

        history.append({
            "api": api_name,
            "params": params,
            "result": result_text,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

        save_history(user_id, history)