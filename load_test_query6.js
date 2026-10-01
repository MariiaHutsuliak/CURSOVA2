// Лабораторна робота №2 — Завдання 1: Performance Testing та валідація SLO
// Об'єкт тестування: GET /api/query6 (Bookstore Management System, CURSOVA2)
//
// SLO (обґрунтування у звіті, п. "Performance Testing"):
//   p95 response time <= 300 ms   (уточнено на baseline-вимірюванні без фільтрів,
//                                   найважчий випадок — повний JOIN по всій таблиці)
//   Error Rate < 1%
//
// Два режими навантаження обираються змінною середовища PROFILE:
//   k6 run -e PROFILE=normal    load_test_query6.js   -> очікується PASS
//   k6 run -e PROFILE=increased load_test_query6.js   -> очікується FAIL

import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = 'http://127.0.0.1:5000';
const PROFILE = __ENV.PROFILE || 'normal';

const LOAD_PROFILES = {
  // Нормальне навантаження: відповідає типовій ситуації, коли цей важкий
  // звіт (повний JOIN Sale -> SaleItem -> Product -> ProductCategory)
  // одночасно переглядають кілька операторів протягом робочої зміни —
  // емпірично (baseline при 1 VU: p95=141ms) і за здоровим глуздом це
  // 3-5 одночасних операторів, а не 15.
  normal: {
    stages: [
      { duration: '10s', target: 4 },   // ramp-up
      { duration: '30s', target: 4 },   // стабільне навантаження
      { duration: '5s', target: 0 },    // ramp-down
    ],
  },
  // Підвищене навантаження: імітує пікове навантаження (кінець звітного
  // періоду, коли багато операторів одночасно формують цей звіт) —
  // достатньо, щоб надійно пробити поріг p95<300ms і показати деградацію.
  increased: {
    stages: [
      { duration: '10s', target: 20 },
      { duration: '30s', target: 20 },
      { duration: '5s', target: 0 },
    ],
  },
};

export const options = {
  stages: LOAD_PROFILES[PROFILE].stages,
  thresholds: {
    http_req_duration: ['p(95)<300'],  // SLO №1: p95 response time
    http_req_failed: ['rate<0.01'],    // SLO №2: Error Rate
  },
  // явно просимо p90/p95/p99 у підсумковому звіті (за замовчуванням k6 не показує p99)
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
};

export function setup() {
  const loginRes = http.post(
    `${BASE_URL}/login`,
    { username: 'operator', password: 'operator123' },
    { redirects: 0 }
  );

  const sessionCookie = loginRes.cookies['session']
    ? loginRes.cookies['session'][0].value
    : null;

  if (!sessionCookie) {
    throw new Error(`Логін не вдався (status=${loginRes.status}).`);
  }

  console.log(`Профіль навантаження: ${PROFILE}`);
  return { cookie: `session=${sessionCookie}` };
}

export default function (data) {
  const params = { headers: { Cookie: data.cookie } };

  // Без фільтрів — гарантовано повертає весь набір продажів (JOIN Sale ->
  // SaleItem -> Product -> ProductCategory по всій таблиці), це і є
  // найважчий/типовий випадок використання цього звіту.
  const res = http.get(`${BASE_URL}/api/query6`, params);

  check(res, {
    'status is 200': (r) => r.status === 200,
  });

  sleep(1);
}