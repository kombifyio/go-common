# Observability helpers

`observability` provides optional Sentry request and panic instrumentation for
Go services. Empty configuration is a no-op, which keeps self-hosted
installations independent of a hosted telemetry service.

```go
shutdown := observability.MustInit(observability.Config{Service: "example"})
defer shutdown()
```

The package scrubs request data before forwarding any event and owns no
deployment or credential policy.
