# Service-call helpers

`servicecall` provides optional authenticated HTTP calls between operator-owned
services. Authentication is disabled by default so local/self-hosted callers
can use the same client without a hosted secret source.

```go
client := servicecall.NewClient(servicecall.Config{Enabled: false})
```

The package carries no provider, deployment, or network-topology authority.
Use the public module path when importing it:

```go
import "github.com/kombifyio/go-common/servicecall"
```
