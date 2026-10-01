import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app as flask_app


@pytest.fixture
def client():
    """
    Тестовий клієнт Flask, залогінений як operator.
    Логін відбувається через реальний маршрут /login (той самий механізм
    сесійної автентифікації, що й у бойовому застосунку), а не підміною —
    так тест перевіряє реальний шлях запиту, включно з requires_authorized_or_above.
    """
    flask_app.config["TESTING"] = True

    with flask_app.test_client() as test_client:
        login_response = test_client.post(
            "/login",
            data={"username": "operator", "password": "operator123"},
            follow_redirects=True,
        )
        assert login_response.status_code == 200, "Не вдалося залогінитись як operator у тестах"
        yield test_client