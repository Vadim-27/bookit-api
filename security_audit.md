# Аудит безпеки — Урок 9 (BookIt API)

**Обсяг:** автентифікація й авторизація: міграції `users` і `refresh_tokens`, модуль `internal/auth` (паролі, JWT, логін, refresh-токени, `Authenticate`), HTTP-шар (`internal/auth/httpapi`, `internal/platform/httpserver`, `httpjson`, `ratelimit`), команда `create-admin`.

**Метод:** AI-агент перевірив код за інструкцією із завдання 3.1 (повний текст — у [`prompts.txt`](prompts.txt), розділ «Task 3.1»): SQL-ін'єкції, mass assignment, відсутні перевірки автентифікації/RBAC, витік чутливих даних, а також довіра до заголовків проксі та rate limit. Кожну знахідку я перевірив вручну і виставив статус тріажу.

**Статуси:** *Fixed Now* — виправлено в цьому кроці; *Tracked for Later* — реальний ризик, виправлення заплановане; *False Positive* — підозра не підтвердилась або це свідоме рішення.

## Зведення

| # | Знахідка | Серйозність | Статус |
|---|---|---|---|
| F1 | Довіра до `X-Forwarded-Proto` від будь-якого клієнта | Medium | **Fixed Now** |
| F2 | За проксі всі клієнти мають один IP → спільний rate limit | High після деплою (зараз Low) | **Fixed Now** |
| F3 | Немає обмеження спроб входу на акаунт | Medium | **Fixed Now** |
| F4 | Входи й невдалі входи не фіксуються в журналі аудиту | Medium | Tracked for Later |
| F5 | Пароль `create-admin` у змінній середовища | Low | **Fixed Now** |
| F6 | CSRF на `/auth/refresh` і `/auth/logout` (cookie) | Medium | Tracked for Later |
| F7 | Прострочені refresh-токени накопичуються; немає абсолютного ліміту сесії | Low | **Fixed Now** |
| F8 | Після logout access-токен діє ще до 15 хв | Low | False Positive |
| F9 | Склейка рядків у SQL-запитах | — | False Positive |
| F10 | Mass assignment: JSON запиту → структура | — | False Positive |
| F11 | Витік хешу пароля чи токенів у відповідях і логах | — | False Positive |
| F12 | Текст клієнта в повідомленні про помилку | Low | False Positive |

Разом 12 знахідок: 5 виправлених, 2 відкладені, 5 хибних спрацювань.

## Деталі

### F1 — довіра до `X-Forwarded-Proto` · Medium · **Fixed Now**
- **Де:** [`internal/platform/httpserver/server.go`](internal/platform/httpserver/server.go) — `isHTTPS` (рядок 93) і налаштування сервера (рядок 42).
- **Ризик:** сервер вважав запит HTTPS, якщо будь-хто надіслав заголовок `X-Forwarded-Proto: https`. Зловмисник посередині (MITM) на звичайному HTTP міг додати цей заголовок і обійти відмову «потрібен HTTPS» — пароль і токени пішли б відкритим текстом. До того ж бралося **перше** значення заголовка, яке може підставити клієнт.
- **Виправлення:** використано вбудований `echo.ExtractSchemeFromHeaders()`: заголовок враховується лише від з'єднань з loopback/приватних адрес (наш TLS-проксі на тому ж хості чи в приватній мережі) і береться **останнє** значення (його ставить найближчий проксі). Від публічних адрес заголовок ігнорується.
- **Доказ:** тест `TestRequireHTTPS/a_forged_header_from_the_internet_is_ignored` у [`server_test.go`](internal/platform/httpserver/server_test.go). Перевірено, що з попередньою поведінкою цей тест падає, а з виправленням проходить.

### F2 — спільний rate limit за проксі · High після деплою · **Fixed Now**
- **Де:** [`internal/platform/httpserver/server.go`](internal/platform/httpserver/server.go) — `extractors`; конфіг `BOOKIT_TRUSTED_PROXIES` у [`config.go`](internal/platform/config/config.go).
- **Ризик:** за Cloudflare/Vercel усі запити приходять з IP проксі, тож ліміт «5 спроб входу на хвилину» став би одним на всіх: кілька запитів зловмисника заблокували б вхід усім користувачам (DoS).
- **Виправлення:** налаштовуваний список довірених проксі. Порожній (за замовчуванням, локально) — клієнт це адреса з'єднання, `X-Forwarded-For` ігнорується. Із заданими діапазонами (напр. опубліковані діапазони Cloudflare) справжній IP береться з `X-Forwarded-For`, але **лише** від довіреного проксі і як найправіше недовірене значення — ліві значення міг вигадати сам клієнт. Той самий список діє і для `X-Forwarded-Proto`.
- **Що лишилося при деплої:** вписати діапазони проксі в `BOOKIT_TRUSTED_PROXIES` (пункт у чек-листі деплою).
- **Доказ:** `TestClientIP` (заголовок без проксі ігнорується; чужий не може назвати IP; вигадане значення зліва пропускається), `TestRequireHTTPS_TrustsConfiguredProxyForTheScheme`, тести конфігу.

### F3 — немає обмеження спроб на акаунт · Medium · **Fixed Now**
- **Де:** [`internal/auth/throttle.go`](internal/auth/throttle.go), [`internal/auth/login.go`](internal/auth/login.go) (`Login`), [`internal/auth/httpapi/handler.go`](internal/auth/httpapi/handler.go).
- **Ризик:** ліміт діяв лише за IP, тож розподілений перебір паролів з багатьох адрес не зупинявся.
- **Виправлення:** невдалі входи рахуються для кожного email окремо. Перші 5 безкоштовні, далі кожна наступна спроба чекає 1 с, 2 с, 4 с… до **60 с**; спроба, що прийшла зарано, отримує `429` з `Retry-After`, і пароль навіть не перевіряється. Успіх скидає лічильник, 15 хв без невдач — теж.
- **Чому уповільнення, а не блокування:** зловмисник не може «заблокувати» чужий акаунт хибними паролями — власник у найгіршому разі чекає хвилину, а перебір сповільнюється приблизно до однієї спроби на хвилину.
- **Без витоку інформації:** невідомий і навіть некоректний email уповільнюється так само, як справжній; регістр email не дає «нових» спроб.
- **Обмеження:** лічильник у пам'яті одного екземпляра сервера (як і rate limit); для кількох екземплярів знадобиться Redis.
- **Доказ:** `TestLoginThrottle_*`, `TestLoginDelay` (затримки, вікно, скидання, прибирання пам'яті, гонки під `-race`), `TestLogin_SlowsDownAfterRepeatedFailures`, `TestLogin_SlowDownDoesNotRevealAccounts`, `TestLogin_SlowDownIsNotALockout`, `TestLogin_TooManyAttemptsAnswers429WithRetryAfter`.

### F4 — входи не фіксуються · Medium · Tracked for Later
- **Ризик:** правила проєкту вимагають журнал аудиту для входів і невдалих входів; без нього атаку на акаунти не видно.
- **План:** таблиця `audit_log` (лише додавання) разом із першими адмінськими функціями.

### F5 — пароль `create-admin` у змінній середовища · Low · **Fixed Now**
- **Де:** [`cmd/bookit/create_admin.go`](cmd/bookit/create_admin.go) — `readPassword` і `passwordFromReader`.
- **Ризик:** у терміналі без прихованого вводу (Git Bash) пароль брався зі змінної `BOOKIT_ADMIN_PASSWORD`. Якщо задати її в одному рядку з командою, пароль лишався в історії оболонки, а змінні середовища успадковують дочірні процеси.
- **Виправлення:** змінну прибрано повністю. Пароль або вводиться двічі з прихованим вводом (звичайний термінал), або передається першим рядком stdin з прапорцем `-password-stdin` (як `docker login --password-stdin`). У командному рядку й середовищі процесу пароля немає ніколи. Без терміналу й без прапорця команда відмовляє.
- **Доказ:** тест `TestPasswordFromReader` у [`create_admin_test.go`](cmd/bookit/create_admin_test.go); перевірено наживо, що стара змінна більше не приймається.

### F6 — CSRF на `/auth/refresh` і `/auth/logout` · Medium · Tracked for Later
- **Де:** [`internal/auth/httpapi/handler.go`](internal/auth/httpapi/handler.go) рядки 136 (`refresh`) і 191 (`SameSite`).
- **Ризик:** ці endpoint-и автентифікують за cookie, а такі запити браузер може надіслати з чужого сайту.
- **Чому не зараз:** cookie має `SameSite=Strict` і `Path=/api/v1/auth`, тож браузер не надсилає її з чужого сайту; фронт ходить на API через свій домен (проксі).
- **План:** якщо фронт колись буде на іншому site (`SameSite=None`), додати перевірку заголовка `Origin`.

### F7 — накопичення refresh-токенів, немає абсолютного ліміту сесії · Low · **Fixed Now**
- **Де:** [`internal/auth/login.go`](internal/auth/login.go) (`Login`, `PurgeExpiredSessions`), [`internal/auth/postgres/refresh_store.go`](internal/auth/postgres/refresh_store.go) (`Rotate`, `PurgeExpired`), міграція [`000004_add_refresh_session_expiry`](migrations/000004_add_refresh_session_expiry.up.sql), фонова задача в [`cmd/bookit/server.go`](cmd/bookit/server.go).
- **Ризик:** прострочені записи лишалися в БД назавжди; активна сесія могла продовжуватися безкінечно (кожен refresh давав ще 30 днів).
- **Виправлення:**
  - **Абсолютний ліміт сесії 90 днів.** При вході запам'ятовується кінець сесії (`session_expires_at`); кожен новий токен ланцюжка успадковує його й не може жити довше. Обмеження `expires_at <= session_expires_at` стоїть і в БД. Через 90 днів після входу пароль потрібен знову.
  - **Прибирання.** Фонова задача (при старті й далі раз на добу) видаляє токени, прострочені понад 7 днів тому, пачками по 1000. Використані, але ще не прострочені токени не чіпаються: вони потрібні для виявлення крадіжки. Задача зупиняється разом із сервером до закриття пулу БД.
- **Доказ:** тести `TestSession_EndsAfterMaxAgeHoweverActive`, `TestPurgeExpiredSessions_*`, `TestRefreshStore_RotateNeverExtendsTheSession`, `TestRefreshStore_PurgeExpired`, `periodic` (зупинка задачі). Наживо: при старті сервер видалив токен, прострочений 10 днів тому, і залишив прострочений 3 дні тому та живий. Міграцію перевірено на наявних даних і відкатом.

### F8 — access-токен після logout · Low · False Positive
- **Де:** [`login.go`](internal/auth/login.go) рядок 175 (`Logout`).
- **Чому не вразливість:** це свідоме рішення: access-токен живе лише 15 хв, а на **кожен** запит сервер перевіряє статус користувача в БД, тож призупинений користувач втрачає доступ одразу. Logout відкликає всю родину refresh-токенів.

### F9 — склейка рядків у SQL · False Positive
- **Де:** [`internal/user/postgres/repository.go`](internal/user/postgres/repository.go) рядки 60, 72; [`refresh_store.go`](internal/auth/postgres/refresh_store.go) рядок 94.
- **Чому не вразливість:** склеюються лише **константи** зі списком колонок; дані користувача завжди передаються параметрами `$1`. Тест `sql injection in email is just a value` передає `' OR '1'='1` і отримує лише «не знайдено».

### F10 — mass assignment · False Positive
- **Де:** [`internal/platform/httpjson/httpjson.go`](internal/platform/httpjson/httpjson.go) рядок 32.
- **Чому не вразливість:** запит розбирається в окремий DTO лише з дозволеними полями, а невідомі поля **відхиляються** (`DisallowUnknownFields`). Тест надсилає `"role":"super_admin"` у логіні й отримує 400, сервіс не викликається.

### F11 — витік хешу пароля чи токенів · False Positive
- **Де:** [`internal/user/user.go`](internal/user/user.go) рядок 33 (`PasswordHash` з `json:"-"`), DTO відповідей у `handler.go`.
- **Чому не вразливість:** відповіді — окремі структури без хешу; refresh-токен лише в `HttpOnly` cookie, у БД лише його SHA-256. Тести перевіряють, що паролі, хеші й токени не потрапляють ні у відповіді, ні в логи.

### F12 — текст клієнта в повідомленні про помилку · Low · False Positive
- **Де:** [`httpjson.go`](internal/platform/httpjson/httpjson.go) рядок 63 (`unknown field "role"`).
- **Чому не вразливість:** API віддає лише JSON, текст екранується; HTML не рендериться, тож XSS неможливий. Повідомлення корисне клієнтам API.

## Свідомі відмінності від завдання

| У завданні | У BookIt | Причина |
|---|---|---|
| `Register` для користувачів, тест «дублікат email → 422» | персонал не реєструється сам: перший super admin — командою `create-admin`, далі запрошення; клієнти реєструються у воркспейсі (пізніше) | бізнес-модель платформи. Дублікат email перевіряє тест репозиторію |
| `role` у JWT | у токені лише `sub`, `typ`, `ws`, `iat`, `exp`, `jti`; права читаються з БД на кожен запит | відкликання прав і призупинення діють одразу |
| Токен на 24 години | access 15 хв + одноразовий refresh-токен у `HttpOnly` cookie з виявленням крадіжки | рекомендації уроку щодо короткоживучих токенів |
| `RequireRole(...)` | `RequirePermission(perm)` | ролі — це набори прав, які owner воркспейсу налаштовує сам |
