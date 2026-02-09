# temporal-secure-payload

Выборочное шифрование payload для Temporal SDK (Go).

## Возможности

* Шифрует только payload, помеченные metadata-ключом `temporal-sensitive=1`.
* Оставляет остальные payload без изменений.
* Работает как Temporal `DataConverter`, который можно передать в `client.Dial(...)` и worker.
* Публичные контракты представлены через интерфейсы (`PayloadCodec`).

## Как работает выборочное шифрование

Вам не нужно вручную задавать metadata.

Когда вы оборачиваете значение через `securepayload.Sensitive(...)`, пакет
внутри помечает payload ключом `temporal-sensitive=1`. Кодек проверяет этот
маркер и шифрует только помеченные payload.

## Установка

```bash
go get github.com/efeligne/temporal-secure-payload
```

## Быстрый старт

Используйте одинаковый `DataConverter` на обеих сторонах:

* клиент/стартер workflow
* worker, который выполняет и декодирует payload

```go
import (
    "os"

    securepayload "github.com/efeligne/temporal-secure-payload"
    "go.temporal.io/sdk/client"
)

dc, err := securepayload.NewDataConverter(os.Getenv("TEMPORAL_ENCRYPTION_KEY"))
if err != nil {
    return err
}

c, err := client.Dial(client.Options{
    HostPort:      hostPort,
    Namespace:     namespace,
    DataConverter: dc,
})
```

Помечайте чувствительные значения через `securepayload.Sensitive(...)`:

```go
memo := map[string]interface{}{
    "requestId": "abc-123",
    "auth":      securepayload.Sensitive(map[string]string{"jwt": "..."}),
}
```

## Сквозной пример: клиент -> воркер (JWT)

1. Сторона клиента: настраивает converter и запускает workflow с чувствительным JWT в `Memo["auth"]`.
2. Сторона воркера: настраивает тот же converter и декодирует `Memo["auth"]` в JWT.

```go
// сторона клиента
dc, err := securepayload.NewDataConverter(os.Getenv("TEMPORAL_ENCRYPTION_KEY"))
if err != nil {
    return err
}

c, err := client.Dial(client.Options{
    HostPort:      hostPort,
    Namespace:     namespace,
    DataConverter: dc,
})
if err != nil {
    return err
}

_, err = c.ExecuteWorkflow(
    context.Background(),
    client.StartWorkflowOptions{
        ID:        "wf-jwt-example",
        TaskQueue: "default",
        Memo: map[string]interface{}{
            "auth": securepayload.Sensitive(map[string]string{
                "jwt": "...",
            }),
        },
    },
    "MyWorkflow",
)
if err != nil {
    return err
}
```

```go
// сторона воркера
dc, err := securepayload.NewDataConverter(os.Getenv("TEMPORAL_ENCRYPTION_KEY"))
if err != nil {
    return err
}

c, err := client.Dial(client.Options{
    HostPort:      hostPort,
    Namespace:     namespace,
    DataConverter: dc,
})
if err != nil {
    return err
}

w := worker.New(c, "default", worker.Options{})
w.RegisterWorkflow(func(ctx workflow.Context) error {
    memoPayload := workflow.GetInfo(ctx).Memo.Fields["auth"]
    var auth map[string]string
    if err := dc.FromPayload(memoPayload, &auth); err != nil {
        return err
    }

    jwt := auth["jwt"] // уже расшифрован converter-ом
    _ = jwt
    return nil
})
```

## Публичный API

* `type PayloadCodec interface`
* `func NewCodec(key string) (PayloadCodec, error)`
* `func NewDataConverter(key string) (converter.DataConverter, error)`
* `func NewDataConverterWithCodec(payloadCodec PayloadCodec) converter.DataConverter`
* `func Sensitive(v any) any`
* `func ParseKey(key string) ([]byte, error)`

Пример dependency injection:

```go
payloadCodec, err := securepayload.NewCodec(key)
if err != nil {
    return err
}

dataConverter := securepayload.NewDataConverterWithCodec(payloadCodec)
```

## Публичные методы: назначение и примеры

### ParseKey

Назначение: валидировать и нормализовать ключ шифрования в 32 raw-байта.

```go
keyBytes, err := securepayload.ParseKey(os.Getenv("TEMPORAL_ENCRYPTION_KEY"))
if err != nil {
    return err
}
_ = keyBytes
```

### NewCodec

Назначение: создать выборочный payload-кодек, который шифрует только
помеченные payload.

```go
payloadCodec, err := securepayload.NewCodec(os.Getenv("TEMPORAL_ENCRYPTION_KEY"))
if err != nil {
    return err
}
_ = payloadCodec
```

### NewDataConverter

Назначение: создать готовый Temporal DataConverter из ключа.

```go
dc, err := securepayload.NewDataConverter(os.Getenv("TEMPORAL_ENCRYPTION_KEY"))
if err != nil {
    return err
}

client, err := client.Dial(client.Options{
    HostPort:      hostPort,
    Namespace:     namespace,
    DataConverter: dc,
})
```

### NewDataConverterWithCodec

Назначение: собрать DataConverter с внедрённым кодеком (под DI).

```go
payloadCodec, err := securepayload.NewCodec(key)
if err != nil {
    return err
}

dc := securepayload.NewDataConverterWithCodec(payloadCodec)
```

### Sensitive

Назначение: пометить значение как чувствительное, чтобы пакет шифровал
только это значение.

```go
memo := map[string]interface{}{
    "requestId": "abc-123",
    "auth":      securepayload.Sensitive(map[string]string{"jwt": "..."}),
}
```

## Форматы ключа

`NewDataConverter` / `NewCodec` принимают:

* raw-строку длиной 32 байта
* base64-строку с 32-байтовым ключом
* hex-строку с 32-байтовым ключом

## Важные ограничения

* Не помещайте секреты в `WorkflowID`, логи и Search Attributes.
* Если значение не обернуто в `securepayload.Sensitive(...)`, пакет не будет его шифровать.
* Если Temporal UI настроен на codec endpoint, который умеет расшифровывать payload, пользователи с доступом к этому endpoint смогут читать расшифрованные значения.
