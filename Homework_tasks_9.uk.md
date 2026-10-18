## Наскрізний проєкт: LibraTrack (система керування бібліотекою)

**Ліміт часу:** до 2 годин.
**Мета:** захистити REST API **LibraTrack** за стандартами безпеки production-рівня. Реалізувати повну автентифікацію з хешуванням паролів (`bcrypt`) і видачею токенів (`JWT`), розробити рольову авторизацію через middleware (`RBAC Middleware`) та провести структурований AI-асистований аудит безпеки коду, щоб знайти й усунути вразливості.

---

### ЧАСТИНА 1: Ручні завдання (архітектура безпеки, моделювання та рев'ю) [~35 хв]
*Цей розділ охоплює завдання, що потребують критичних рішень людини, аналізу ризиків і контролю якості коду.*

* **Завдання 1.1: Ролі, матриця доступу та дизайн DTO (дизайн безпеки та контракту):**
  1. Створіть файл `security_design.txt` (або додайте розділ у `README.md`).
  2. Визначте системні ролі: щонайменше 2 ролі (`reader` і `admin`), як вимагає завдання (або 3 ролі: `reader`, `librarian`, `admin` для повної моделі).
  3. Опишіть матрицю контролю доступу для endpoint-ів LibraTrack:
     * **Публічні (без автентифікації):** `POST /api/v1/auth/register`, `POST /api/v1/auth/login`, `GET /api/v1/books`.
     * **Захищені (будь-який автентифікований користувач):** `GET /api/v1/me/loans`.
     * **Персонал (`librarian` / `admin`):** `POST /api/v1/books`, `PUT /api/v1/books/:id`, `POST /api/v1/loans`, `POST /api/v1/loans/:id/return`.
     * **Адмін (`admin`):** `GET /api/v1/users`, `PUT /api/v1/users/:id/role`.
  4. Спроєктуйте DTO запитів так, щоб запобігти вразливостям Mass Assignment: переконайтеся, що `RegisterRequest` і `UpdateProfileRequest` містять лише поля, які користувач може редагувати, а до `PasswordHash` додайте struct-тег `json:"-"`, щоб хеші не потрапляли у JSON-відповіді.

* **Завдання 1.2: Ручний аудит безпеки роботи з паролями та логування:**
  1. Перевірте handler `/auth/login`: переконайтеся, що помилки автентифікації (і невідомий email, і невірний пароль) повертають однакове повідомлення HTTP 401 (`"invalid credentials"`), щоб запобігти атакам User Enumeration.
  2. Перегляньте `LoggingMiddleware` з Уроку 7: переконайтеся, що middleware логування запитів приховує або пропускає поле `password` у тілах запитів.
  3. Перевірте поведінку переривання в middleware: переконайтеся, що помилки автентифікації/авторизації явно викликають `c.AbortWithStatusJSON()`, щоб зупинити ланцюжок виконання handler-ів Gin.

---

### ЧАСТИНА 2: Промпт-інжиніринг (автентифікація, JWT та RBAC middleware) [~40 хв]
*Цей розділ присвячений написанню точних, детально специфікованих промптів для вашого AI-асистента, щоб згенерувати код автентифікації та авторизації.*

* **Завдання 2.1: Промпт для модуля автентифікації (bcrypt + видача JWT):**
  * Складіть і виконайте промпт для генерації файлів міграцій БД (`000003_add_auth_fields.up.sql` / `.down.sql`, що додають `password_hash` і `role` до `users`) та оновіть Go-модель `User`.
  * *Вимоги до промпту для handler-ів `Register` і `Login`:*
    1. Реєстрація має хешувати паролі через `bcrypt.GenerateFromPassword` із `bcrypt.DefaultCost` (10) і за замовчуванням ставити роль `reader`.
    2. Логін має перевіряти паролі через `bcrypt.CompareHashAndPassword` і видавати підписаний JWT з `jwt.SigningMethodHS256`.
    3. Payload JWT має містити claims: `user_id`, `role` і час закінчення `exp` (24 години). Секрет підпису має завантажуватися виключно зі змінної середовища `os.Getenv("JWT_SECRET")`.
  * *Результат:* збережіть текст промпту в `prompts.txt` та інтегруйте згенеровані файли в `internal/auth/` і `internal/handler/`.

* **Завдання 2.2: Промпт для ланцюжка middleware (`AuthMiddleware` і `RequireRole`):**
  * Напишіть промпт для генерації `AuthMiddleware` (`internal/middleware/auth.go`) і `RequireRole` (`internal/middleware/rbac.go`).
  * *Вимоги до промпту:*
    1. `AuthMiddleware` має діставати токен із заголовка `Authorization: Bearer <token>`, перевіряти підпис і claim `exp`, та зберігати claims у контексті Gin через `c.Set("user_id", ...)` і `c.Set("role", ...)`.
    2. `RequireRole` має бути variadic (`allowed ...string`), перевіряти `c.Get("role")` і повертати HTTP 401 Unauthenticated (якщо користувач не автентифікований) або HTTP 403 Forbidden (якщо роль не має доступу).
    3. Промпт має показувати реєстрацію маршрутів у `main.go` через вкладені групи маршрутів Gin (`public`, `protected`, `staff`, `admin`) з правильним порядком виконання middleware (спершу Auth, потім RBAC).
  * *Результат:* збережіть промпт у `prompts.txt`.

---

### ЧАСТИНА 3: Агентне використання AI (автоматизований AI-аудит безпеки та тестування) [~45 хв]
*Використайте AI-асистента як автономного партнера для проведення аудиту безпеки та генерації повних тестів.*

* **Завдання 3.1: AI-асистоване рев'ю безпеки коду:**
  * Передайте вашому AI-агенту код створених модулів (`auth`, `middleware`, `book_handler`, `loan_handler`).
  * *Інструкція для агента (промпт):*
    > "Review this Go/Gin API code for security vulnerabilities. Check specifically for: 1) SQL injection (raw queries, string concatenation); 2) Mass assignment (binding request JSON directly to DB models); 3) Missing authentication or RBAC checks; 4) Sensitive data exposure (leaking password hashes in JSON responses). Output a structured list with line numbers, severity (Low/Medium/High), and proposed fixes. Do not rewrite files completely."
  * *Тріаж і звіт:* критично оцініть вивід AI. Складіть звіт у `security_audit.md`, що документує **щонайменше 5 знахідок** зі статусами тріажу: *Fixed Now* (виправлено зараз), *Tracked for Later* (відкладено) або *False Positive* (хибне спрацювання).

* **Завдання 3.2: AI-генеровані table-driven тести безпеки:**
  * Доручіть AI-агенту написати table-driven інтеграційні тести в `auth_test.go` і `rbac_test.go`.
  * *Інструкція для агента:*
    > "Write table-driven integration tests for auth and RBAC using httptest. Cover test cases: 1) Registering duplicate email (HTTP 422); 2) Valid login returning JWT (HTTP 200); 3) Login with wrong password (HTTP 401 generic error); 4) Calling protected route with missing/expired token (HTTP 401); 5) Reader calling POST /api/v1/books (HTTP 403 Forbidden); 6) Admin/Librarian calling POST /api/v1/books (HTTP 201 Created)."
  * *Виконання:* запустіть тести локально командою `go test -v ./...` і переконайтеся, що всі тест-кейси проходять.

---

### Критерії оцінювання та результати (самоперевірка)

Надішліть посилання на репозиторій, який містить:
1. **Міграції БД:** `000003_add_auth_fields.up.sql` і `.down.sql`.
2. **Безпечна робота з паролями:** паролі хешуються `bcrypt` при реєстрації, а `PasswordHash` має тег `json:"-"`.
3. **Дисципліна помилок і токенів:** user enumeration на `/login` унеможливлено, JWT містить `exp` і підписується з `os.Getenv("JWT_SECRET")`.
4. **Порядок middleware:** `main.go` чітко розділяє групи маршрутів (`public`, `protected`, `staff`, `admin`), а `RequireRole` виконується після `AuthMiddleware`.
5. **Журнал промптів `prompts.txt`:** містить визначення промптів для завдань 2.1 і 2.2.
6. **Аудит безпеки `security_audit.md`:** документує щонайменше 5 виявлених вразливостей з рівнями серйозності та рішеннями тріажу.
7. **Покриття тестами:** інтеграційні тести перевіряють поведінку `401 Unauthenticated` і `403 Forbidden` для ролей `reader`, `librarian` і `admin`.

---
