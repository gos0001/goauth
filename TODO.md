# TODO — Строковые durations в config.json (v2.0.2)

Баг: `config.example.json` пишет длительности строками (`"access_ttl": "15m"`),
а поля конфигов — голый `time.Duration`. Для `encoding/json` это просто int64:
`TextUnmarshaler` у `time.Duration` в stdlib НЕТ (проверено по
`$(go env GOROOT)/src/time/time.go` — методы только у `Time`). Копируешь пример
как есть → при старте:

```
init app: config section "token": json: cannot unmarshal string into Go
struct field Config.access_ttl of type time.Duration
```

Контейнер циклично падает. Затронуты ВСЕ Duration-поля: `token.access_ttl` /
`token.refresh_ttl`, `admin.reauth_window`, `webhook.timeout` / `.backoff_*`,
`ratelimit.backoff_*` / `.failure_window`, `cors.max_age`, `audit.retention` /
`.cleanup_interval`, `outbox.*`, `sessions.cleanup_interval`,
`redis.default_ttl`, `webhook.interval`.

Почему проскочило: смоук-тесты этапа 0 гоняли кастомный `Rule` ("5/1m") и
дефолты при ОТСУТСТВИИ ключей; ни e2e, ни смоук не парсили строковое duration.
Обход пользователей: опускать duration-поля — срабатывают предзаполненные
дефолты.

Радиус: boot-fail на дефолтном примере конфига. Класс: пример-документация
несовместим с кодом.

## План фикса (вариант A — нормализация в appconfig.Section)

- [x] `pkg/appconfig`: перед `json.Unmarshal` — `normalizeDurations(dst, raw)`:
      reflect-обход `dst`, поля типа `time.Duration` (и указатели на него);
      если raw-значение ключа — JSON-строка → `time.ParseDuration` → подмена
      значения на число (наносекунды). Числа/null проходят как есть.
      Ошибка вида `config section "token": access_ttl: time: invalid duration "15x"`
      — с именем секции и ключа.
      Ноль изменений в 19 config-структурах, поля остаются `time.Duration`.
      Реализовано сверх плана: вложенные структуры (dotted-пути), embedded —
      тоже. Точный текст stdlib-ошибки на текущем Go:
      `time: unknown unit "x" in duration "15x"`.
- [x] Отклонено: кастомный тип `appconfig.Duration` (тип-валидно, но диф во все
      конфиги + конверсии на границах — больше шансов новых багов).
- [x] Отклонено: числа (наносекунды) в примере — UX-ужас.

## Тесты (то, чего не хватало)

- [x] `pkg/appconfig/config_test.go`: строка `"15m"`, число, невалидная строка,
      null → дефолт сохраняется.
- [x] `cmd/config_example_test.go` — регрессия: читать реальный
      `config.example.json` (private_key → dummy), прогнать через
      `appconfig.Load` + все `LoadConfig`, ассерты:
      `token.AccessTTL == 15m`, `admin.ReauthWindow == 15m`, `cors.MaxAge == 12h`,
      `audit.Retention == 720h`, `ratelimit.BackoffBase == 1s`,
      `redis.DefaultTTL == 1h`, `webhook.Timeout == 10s` и т.д.
      Пример и код больше не смогут разъехаться.
- [ ] Следующий e2e-смоук — минимум одно строковое duration в конфиге
      (именно так баг и проскочил). В репо e2e-харнесса нет — пункт для
      внешнего смоук-цикла; внутри репо регрессию держит тест выше.

## Релиз

- [x] Коммит `fix: parse string durations in config sections`
- [ ] Тег `v2.0.2` → CI двигает `:latest` / `:2.0.2` / `:2.0` / `:2`
- [ ] Примечание пользователям: после v2.0.1 replace-пин не нужен
      (module path `/v2`), после v2.0.2 duration-поля можно не опускать.

## Статус: код готов

`make test` зелёный (`-race`), `go vet` / `golangci-lint` чистые.
Смоук: `config.example.json` с dummy-ключом через `go run ./cmd` — все
секции парсятся, boot доходит до redis-dial (сервисы не подняты), а не до
unmarshal-ошибки. Осталось: тег + примечание.
