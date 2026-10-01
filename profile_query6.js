// Лабораторна робота №2 — Крок A: пробний прогін без порогів (SLO ще не встановлені)
// Мета: зібрати реальні p90/p95/p99 на /api/query6, щоб обґрунтовано підібрати thresholds.
//
// Запуск:
//   k6 run profile_query6.js

import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = 'http://127.0.0.1:5000';

export const options = {
  vus: 15,
  duration: '30s',
};

export function setup() {
  // redirects: 0 — важливо! /login при успіху повертає 302 на "/",
  // а якщо дозволити авто-редирект, res.cookies буде вже від сторінки "/",
  // а не від самої відповіді логіну, де встановлюється сесія.
  const loginRes = http.post(
    `${BASE_URL}/login`,
    { username: 'operator', password: 'operator123' },
    { redirects: 0 }
  );

  console.log(`Login response status: ${loginRes.status}`);

  const sessionCookie = loginRes.cookies['session']
    ? loginRes.cookies['session'][0].value
    : null;

  if (!sessionCookie) {
    throw new Error(
      `Логін не вдався (status=${loginRes.status}). Перевірте логін/пароль operator. Body: ${loginRes.body}`
    );
  }

  return { cookie: `session=${sessionCookie}` };
}

export default function (data) {
  const params = {
    headers: { Cookie: data.cookie },
  };

  const month = Math.floor(Math.random() * 12) + 1;
  const res = http.get(`${BASE_URL}/api/query6?month=${month}`, params);

  const ok = check(res, {
    'status is 200': (r) => r.status === 200,
  });

  // тимчасова діагностика: покажемо перші кілька неуспішних відповідей
  if (!ok && __ITER < 2 && __VU === 1) {
    console.log(`DEBUG status=${res.status} body=${res.body.substring(0, 300)}`);
  }

  sleep(1);
}