"""Безпечне читання конфігураційного значення зі змінної середовища (Lab3, Secrets Trap, виправлення)."""
import os

from dotenv import load_dotenv

load_dotenv()  # підхоплює локальний .env (він у .gitignore і не потрапляє в git)

DEMO_API_TOKEN = os.getenv("DEMO_API_TOKEN")
