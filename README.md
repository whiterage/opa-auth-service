# HTTP-сервис с авторизацией через OPA

Небольшой Go-сервис с защищённым эндпоинтом `GET /resource`. Bearer JWT имеет
структуру claims Keycloak, а решение о доступе принимает встроенная библиотека
OPA по Rego-политике.

## Как проходит запрос

1. Клиент отправляет `Authorization: Bearer <JWT>`.
2. `MockJWTParser` извлекает роли из `realm_access.roles`.
3. Middleware формирует OPA input:

   ```json
   {
     "method": "GET",
     "path": "/resource",
     "roles": ["reader"]
   }
   ```

4. Подготовленный OPA-запрос вычисляет `data.authz.allow`.
5. При `allow = true` запрос передаётся обработчику, иначе возвращается `403`.

`PrepareForEval` вызывается при старте программы, а затем только при изменении
файла политики. Между изменениями один `PreparedEvalQuery` переиспользуется
всеми HTTP-запросами; внутри HTTP middleware политика не компилируется.

## Политика доступа

- `admin` может выполнять любой HTTP-метод;
- `reader` может выполнять только `GET`;
- остальные запросы запрещены благодаря `default allow := false`.

Рабочая политика загружается из `policy/authz.rego`. Сервис следит за файлом и
применяет изменения без перезапуска. Если изменённая политика не компилируется,
ошибка записывается в лог, а последняя корректная версия продолжает работать.

## Запуск

Требуется Go 1.25 или новее.

```bash
go mod download
go run ./cmd/server
```

Сервис запустится на `http://localhost:8080`.

По умолчанию используется `policy/authz.rego`. Другой путь можно передать через
переменную окружения:

```bash
POLICY_PATH=/absolute/path/to/authz.rego go run ./cmd/server
```

Разрешённый запрос с ролью `reader`:

```bash
TOKEN='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsicmVhZGVyIl19fQ.mock-signature'

curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/resource
```

Ожидаемый статус: `200 OK`.

Запрещённый запрос с ролью `guest`:

```bash
TOKEN='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZ3Vlc3QiXX19.mock-signature'

curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/resource
```

Ожидаемый статус: `403 Forbidden` с понятным JSON-телом:

```json
{
  "error": "forbidden",
  "message": "access denied by authorization policy"
}
```

Без Bearer-токена сервис вернёт `401 Unauthorized`.

## Hot-reload политики

После запуска измените и сохраните `policy/authz.rego`. Наблюдатель подготовит
новый OPA-запрос и атомарно заменит текущий. Новые запросы сразу начнут
проверяться по обновлённой политике, перезапуск сервиса не требуется.

`PrepareForEval` при hot-reload неизбежно вызывается повторно, но только в ответ
на изменение политики, а не на каждый HTTP-запрос.

## Тесты

Go-тест middleware:

```bash
go test ./...
```

Тесты Rego-политики требуют OPA CLI. На macOS его можно установить командой
`brew install opa`, после чего выполнить:

```bash
opa test ./policy -v
```

## Ограничение mock JWT

`MockJWTParser` декодирует payload JWT, но не проверяет подпись, issuer,
audience и срок действия. Это сделано только потому, что задание разрешает
замокать claims. В production JWT необходимо проверять по публичным ключам
Keycloak (JWKS) до передачи ролей в OPA.
