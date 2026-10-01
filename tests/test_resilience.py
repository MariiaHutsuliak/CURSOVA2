"""
Лабораторна робота №2, Завдання 3 — автоматизований тест стійкості.

Перевіряє механізм Retry + Fallback (fault_injection.py + resilience.py,
підключені у app.api_query6) автоматично, замість ручного curl:

1. test_query6_normal_mode_returns_full_response — "позитивний" тест:
   коли БД доступна (DB_FAULT_MODE не виставлений / none), fallback НЕ
   повинен спрацьовувати — ендпоінт повертає 200 з реальними даними.

2. test_query6_resilience_fallback_on_db_failure — "тест стійкості":
   під час симульованої відмови БД (DB_FAULT_MODE=error) ендпоінт має
   повернути контрольовану деградовану відповідь (503 + очікуваний JSON),
   а не 500/краш застосунку. Прогнаний у циклі 3 рази поспіль в межах
   одного тесту, щоб підтвердити детермінованість поведінки — однаковий
   результат щоразу, а не "один раз пощастило".
"""


def test_query6_normal_mode_returns_full_response(client, monkeypatch):
    monkeypatch.delenv("DB_FAULT_MODE", raising=False)

    response = client.get("/api/query6")

    assert response.status_code == 200
    data = response.get_json()
    assert "degraded" not in data
    assert "sales" in data


def test_query6_resilience_fallback_on_db_failure(client, monkeypatch):
    monkeypatch.setenv("DB_FAULT_MODE", "error")

    for attempt in range(1, 4):
        response = client.get("/api/query6")

        assert response.status_code == 503, (
            f"Прогін {attempt}/3: очікували 503 (fallback), "
            f"отримали {response.status_code}"
        )

        data = response.get_json()
        assert data["degraded"] is True
        assert data["sales"] == []
        assert "message" in data