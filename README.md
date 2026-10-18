# BookIt API

Бекенд платформи бронювання: власник (owner) створює воркспейс зі своїми ресурсами й графіком роботи — перукарня, корт, коворкінг, — а клієнти бронюють вільні слоти.

**Стек:** Go 1.27 · Echo v5 · PostgreSQL 17 (pgx v5) · golang-migrate · Docker Compose.

## Запуск локально

Потрібні Go 1.27+ і Docker.

```bash
cp .env.example .env
```

У `.env` заповніть секрети:
- `BOOKIT_DB_PASSWORD` — будь-який пароль для локальної БД; той самий пароль — у `BOOKIT_DATABASE_URL` (формат `postgres://USER:PASSWORD@127.0.0.1:5440/bookit?sslmode=disable`);
- `BOOKIT_JWT_SECRET` — щонайменше 32 байти, наприклад `openssl rand -base64 48`.

```bash
docker compose up -d --wait postgres      # PostgreSQL на 127.0.0.1:5440
docker compose run --rm migrate up        # міграції
set -a; . ./.env; set +a                  # змінні для Go (Git Bash / Linux / macOS)
```

Перший super admin створюється командою (публічної реєстрації персоналу немає). У звичайному терміналі пароль запитується двічі з прихованим вводом:

```bash
go run ./cmd/bookit create-admin -email you@example.com -name "Your Name"
```

У Git Bash (термінал не вміє приховувати ввід) пароль передається через stdin — він не потрапляє ні в історію, ні в змінні середовища:

```bash
read -rsp "Password: " P; echo
printf '%s\n' "$P" | go run ./cmd/bookit create-admin -email you@example.com -name "Your Name" -password-stdin
unset P
```

Запуск сервера:

```bash
go run ./cmd/bookit                       # http://localhost:8080
```

### Приклади запитів

```bash
API=http://localhost:8080/api/v1

# Вхід: access-токен у тілі, refresh-токен — у cookie (HttpOnly)
curl -s -c cookies.txt -X POST $API/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"your-password"}'

# Хто я (підставте access_token з відповіді вище)
curl -s $API/me -H "Authorization: Bearer <access_token>"

# Нова пара токенів за refresh-cookie; старий refresh погашається
curl -s -b cookies.txt -c cookies.txt -X POST $API/auth/refresh

# Вихід: відкликає всю сесію
curl -s -b cookies.txt -c cookies.txt -X POST $API/auth/logout
```

## Тести

```bash
go test -race ./...
```

Інтеграційні тести з реальною БД пропускаються, якщо не задано базу з застосованими міграціями:

```bash
BOOKIT_TEST_DATABASE_URL="postgres://..." go test -race ./...
```

---

## Lesson 9 Report

Завдання — у [`Homework_tasks_9.uk.md`](Homework_tasks_9.uk.md). BookIt — не LibraTrack, тому ролі й endpoint-и адаптовані; відповідність наведено нижче.

### 1.1 Дизайн безпеки

**Ролі.** Авторизація будується на правах (permission keys), а роль — це набір прав. Права читаються з БД на кожен запит, тож відкликання й призупинення діють одразу.

| Роль у завданні | Роль у BookIt | Хто це |
|---|---|---|
| `reader` | `client` | клієнт воркспейсу: бронює, бачить лише свої записи |
| `librarian` | `staff` (кастомні ролі воркспейсу) | персонал: перукар, адмін будинку |
| `admin` | `owner`, `super_admin` | власник воркспейсу; власник платформи |

Зараз реалізовано рівень платформи: `super_admin` має всі платформні права (статично), інші користувачі — жодного. Ролі воркспейсів (owner, staff з правами `own`/`all`) і клієнти з'являться разом із воркспейсами.

**Матриця доступу (реалізовано):**

| Група | Endpoint | Доступ |
|---|---|---|
| public | `POST /api/v1/auth/login` | усі (rate limit за IP + уповільнення на акаунт) |
| public | `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout` | власник refresh-cookie |
| protected | `GET /api/v1/me` | будь-який автентифікований користувач |
| platform | `/api/v1/platform/...` | автентифікований **і** з потрібним правом (`RequirePermission`) |

Повна матриця на майбутнє (гість, клієнт, персонал воркспейсу, платформа) спроєктована заздалегідь: публічні сторінки воркспейсів, бронювання клієнта, кабінет персоналу, керування воркспейсами й підписками.

**DTO (захист від mass assignment).**
- Запит розбирається в окремий DTO лише з дозволеними полями; **невідомі поля відхиляються** (`400`), розмір тіла обмежений, `Content-Type` — лише `application/json` ([`httpjson.go`](internal/platform/httpjson/httpjson.go)). Логін приймає тільки `email` і `password`; спроба передати `"role":"super_admin"` дає `400`.
- Відповіді — окремі структури, не моделі БД. `PasswordHash` має тег `json:"-"` як ще один рівень захисту ([`user.go`](internal/user/user.go)).
- Поля, які ставить лише сервер (роль, статус, воркспейс, id), користувач передати не може.

### 1.2 Ручний аудит паролів і логування

| Перевірка | Результат | Де підтверджено |
|---|---|---|
| Невідомий email і хибний пароль дають однакову відповідь `401 invalid credentials` | ✅ і **однаковий час**: для невідомого email теж виконується bcrypt із хеш-заглушкою | `TestLogin_EveryFailureLooksTheSame`, `TestLogin_UnknownAndMalformedEmailsStillRunBcrypt` |
| Пароль не потрапляє в логи запитів | ✅ тіла запитів не логуються взагалі; тести перевіряють, що пароль, хеш і токени відсутні в логах | `TestLogin_Success`, `TestLogin_ServiceFailureIsAGenericServerError` (пакет `httpapi`) |
| Помилка автентифікації/авторизації зупиняє ланцюжок | ✅ в Echo middleware просто не викликає `next` (аналог `AbortWithStatusJSON`); тести перевіряють, що сервіс не викликається | `TestEndpointsAreRateLimited`, `TestRequirePermission_WithoutRequireAuthFailsClosed` |

### 2.1 Автентифікація (bcrypt + JWT)

- Міграції: [`000002_create_users`](migrations/000002_create_users.up.sql), [`000003_create_refresh_tokens`](migrations/000003_create_refresh_tokens.up.sql), [`000004_add_refresh_session_expiry`](migrations/000004_add_refresh_session_expiry.up.sql).
- Паролі — bcrypt (`DefaultCost`), 10–72 байти ([`password.go`](internal/auth/password.go)).
- JWT — HS256, лише цей алгоритм приймається (`alg: none` відхиляється), обов'язковий `exp`, секрет лише з `BOOKIT_JWT_SECRET` з підтримкою ротації ([`token.go`](internal/auth/token.go)).
- Access-токен живе 15 хв; довгі сесії — одноразовий refresh-токен у `HttpOnly` cookie з виявленням крадіжки й абсолютним лімітом сесії 90 днів ([`login.go`](internal/auth/login.go)).

### 2.2 Middleware

- `RequireAuth` (аналог `AuthMiddleware`) і `RequirePermission` (аналог `RequireRole`) — [`middleware.go`](internal/auth/httpapi/middleware.go).
- Токен береться лише з `Authorization: Bearer`; без токена — `401` з `WWW-Authenticate`, без права — `403`. Автентифікація завжди виконується перед авторизацією.

Промпти до завдань 2.1 і 2.2 — у [`prompts.txt`](prompts.txt).

### 3.1 AI-аудит безпеки

Звіт — [`security_audit.md`](security_audit.md): 12 знахідок, 5 виправлено (*Fixed Now*), 2 відкладено (*Tracked for Later*), 5 хибних спрацювань (*False Positive*). Там же — розділ про свідомі відмінності від завдання.

### 3.2 Тести безпеки

Тести лежать поруч із кодом (а не в `auth_test.go` / `rbac_test.go` у корені). Відповідність кейсам завдання:

| Кейс завдання | Тест |
|---|---|
| Дублікат email | `TestRepository_Create_DuplicateEmail` (рівень БД; публічного `Register` для персоналу немає — див. відмінності в `security_audit.md`) |
| Вхід з правильними даними → 200 і JWT | `TestLogin_Success` (пакети `auth` і `httpapi`) |
| Хибний пароль → 401 із загальною помилкою | `TestLogin_WrongCredentialsAreAnsweredGenerically`, `TestLogin_EveryFailureLooksTheSame` |
| Захищений маршрут без токена / з простроченим → 401 | `TestAccessMatrix`, `TestAuthenticate_Rejects/expired_token` |
| `reader` на захищений маршрут персоналу → 403 | `TestAccessMatrix/platform_as_an_ordinary_user` |
| `admin` → успіх | `TestAccessMatrix/platform_as_the_super_admin` |

Усі тести: `go test -race ./...`.
