# temporal-secure-payload

Selective payload encryption for Temporal SDK (Go).

## Features

* Encrypts only payloads marked with metadata key `temporal-sensitive=1`.
* Leaves other payloads unchanged.
* Works as a Temporal `DataConverter` you can pass to `client.Dial(...)` and workers.
* Exposes interface-based public contracts (`PayloadCodec`).

## How Selective Encryption Works

You do not need to set metadata manually.

When you wrap a value with `securepayload.Sensitive(...)`, the package marks the
payload internally with `temporal-sensitive=1`. The codec checks this marker and
encrypts only marked payloads.

## Installation

```bash
go get github.com/efeligne/temporal-secure-payload
```

## Quick Start

Use the same `DataConverter` on both sides:

* workflow starter/client
* worker that executes/decode payloads

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

Mark sensitive values using `securepayload.Sensitive(...)`:

```go
memo := map[string]interface{}{
    "requestId": "abc-123",
    "auth":      securepayload.Sensitive(map[string]string{"jwt": "..."}),
}
```

## End-to-End Example: Client -> Worker (JWT)

1. Client side: configure converter and start workflow with sensitive JWT in `Memo["auth"]`.
2. Worker side: configure the same converter and decode `Memo["auth"]` into JWT.

```go
// client side
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
// worker side
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

    jwt := auth["jwt"] // already decrypted by converter
    _ = jwt
    return nil
})
```

## Public API

* `type PayloadCodec interface`
* `func NewCodec(key string) (PayloadCodec, error)`
* `func NewDataConverter(key string) (converter.DataConverter, error)`
* `func NewDataConverterWithCodec(payloadCodec PayloadCodec) converter.DataConverter`
* `func Sensitive(v any) any`
* `func ParseKey(key string) ([]byte, error)`

Dependency-injection example:

```go
payloadCodec, err := securepayload.NewCodec(key)
if err != nil {
    return err
}

dataConverter := securepayload.NewDataConverterWithCodec(payloadCodec)
```

## Public Methods: Purpose and Examples

### ParseKey

Purpose: validate and normalize encryption key into 32 raw bytes.

```go
keyBytes, err := securepayload.ParseKey(os.Getenv("TEMPORAL_ENCRYPTION_KEY"))
if err != nil {
    return err
}
_ = keyBytes
```

### NewCodec

Purpose: create selective payload codec that encrypts only marked payloads.

```go
payloadCodec, err := securepayload.NewCodec(os.Getenv("TEMPORAL_ENCRYPTION_KEY"))
if err != nil {
    return err
}
_ = payloadCodec
```

### NewDataConverter

Purpose: create ready-to-use Temporal DataConverter from key.

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

Purpose: build DataConverter with injected codec (DI-friendly).

```go
payloadCodec, err := securepayload.NewCodec(key)
if err != nil {
    return err
}

dc := securepayload.NewDataConverterWithCodec(payloadCodec)
```

### Sensitive

Purpose: mark a value as sensitive so package encrypts only this value.

```go
memo := map[string]interface{}{
    "requestId": "abc-123",
    "auth":      securepayload.Sensitive(map[string]string{"jwt": "..."}),
}
```

## Key Formats

`NewDataConverter` / `NewCodec` accept:

* 32-byte raw string
* base64-encoded 32-byte key
* hex-encoded 32-byte key

## Important Notes

* Do not put secrets in `WorkflowID`, logs, or Search Attributes.
* If a value is not wrapped with `securepayload.Sensitive(...)`, it is not encrypted by this package.
* If Temporal UI is configured with a codec endpoint that can decrypt payloads, users with access to that endpoint can read decrypted values.
