# TODO — Cookie-канал аутентификации (HttpOnly) для goauth

Цель: `POST /auth/token` (и связанные эндпоинты) ставит `Set-Cookie`
(HttpOnly, Secure, SameSite=Strict) **в дополнение** к JSON-ответу.
JSON остаётся всегда — для non-browser клиентов (CLI, server-to-server, mobile).
Канал opt-in через env, по умолчанию выключен.

Радиус: **containment ущерба от XSS** в браузерном SPA — refresh-токен
перестаёт быть читаемым из JS. Это НЕ защита от самого XSS (CSP и
санитайзинг — забота фронтенда), и это надо честно написать в доках.

Upstream: правим сразу в main (репо и есть upstream), fork-цены нет.

## Статус: реализовано ✅

`make test` зелёный (с `-race`), `go build`/`go vet` чистые.

## 0. Решения (зафиксированы)

- [x] Имена кук: `goauth_access`, `goauth_refresh` — фиксированные константы,
      без `__Host-` префикса (он требует незапрещаемого Secure, а
      `AUTH_COOKIE_SECURE` выключаем для dev-сетапов).
- [x] SameSite: `strict` по умолчанию, `AUTH_COOKIE_SAMESITE=lax` как opt-out.
- [x] Secure: `AUTH_COOKIE_SECURE` default `true`.
- [x] Domain: не ставится (host-only), env нет.
- [x] Access-кука ставится вместе с refresh.
- [x] Refresh grant по куке при пустом `refresh_token` в body.

## 1. Конфигурация

- [x] `pkg/authcookie/config.go`: envconfig, `AUTH_COOKIE_ENABLED/_SECURE/_SAMESITE`,
      samesite валидируется на старте
- [x] `.env.example` — с комментариями

## 2. Пакет `pkg/authcookie`

- [x] `New(cfg)`, `Set(w, access, refresh, accessTTL, refreshTTL)`, `Clear(w)`,
      `AccessFromRequest(r)`, `RefreshFromRequest(r)`, `Enabled()`
      — сигнатуры через `net/http`, gin не нужен
- [x] `wire.go`: `var Set = wire.NewSet(LoadConfig, New)`
- [x] Unit-тесты: атрибуты, lax, disabled-режим, Clear, roundtrip, пустое значение

## 3. Выдача: `auth_token`

- [x] `http_v1.go`: `Set` после успешного grant (оба гранта), refresh из куки
      при пустом body, JSON не изменился
- [x] `Pair.RefreshExpiresAt` (`internal/service/tokens/issuer.go`) →
      `Output.RefreshExpiresAt json:"-"` для Max-Age refresh-куки
- [ ] Хендлер-тест именно `auth_token` (usecase concrete — нужен свой фейк;
      путь кук покрыт тестами middleware + authcookie)

## 4. Middleware

- [x] `credential()`: header > кука, `Auth()`/`AuthSilent()`
- [x] `AdminToken()` не тронут — header-only
- [x] `*authcookie.Cookies` в конструктор через wire
- [x] Тесты: кука на обеих поверхностях, приоритет header, disabled → игнор,
      expired-кука → 401 на обеих поверхностях одинаково, мусор/пустая кука

## 5. Смежные эндпоинты

- [x] `auth_password_change` — перевыпуск кук новой парой (`RefreshExpiresAt` тоже)
- [x] `auth_revoke` / `auth_logout_all` — `Clear`
- [ ] Отдельные хендлер-тесты (правка — по одному вызову, покрыто тестами пакета)

## 6. CORS

- [x] `Config.AllowCredentials` (не env) + `NewWithCookies` в wire — флаг
      склеивается из `authcookie.Enabled()`, разъехаться не может
- [x] `Access-Control-Allow-Credentials: true` на простые ответы и preflight
- [x] Fail-fast: `*` + credentials → ошибка на старте
- [x] Тесты: заголовок по/вне allowlist, отсутствие по умолчанию, wildcard-отказ

## 7. Wire / codegen

- [x] `authcookie.Set` в `cmd/wire.go`, `wire ./cmd/` прогнан, маркеры на месте

## 8. Документация

- [x] `README.md`: раздел «Cookie channel», строка у эндпоинтов, 3 строки
      в таблице конфигурации
- [x] `plugin/skills/goauth/SKILL.md` — абзац про канал
- [x] `plugin/commands/goauth-verify.md` — сценарий с cookie-jar

## 9. Приёмка

- [x] `make test` зелёный
- [ ] Ручной сценарий на живом сервисе: login → jar → `/auth/me` без заголовка →
      refresh с пустым body → `/auth/logout-all` → куки удалены → 401
      (шаги воспроизведены в `goauth-verify.md`)
- [x] Выключен — поведение как раньше (тесты middleware/cors/authcookie
      фиксируют disabled-режим)
