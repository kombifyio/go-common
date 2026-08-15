# toolauth Security Notes

## Token Storage

| Platform | Store | Key Material |
|----------|-------|-------------|
| Windows | Credential Manager | OS-managed encryption |
| macOS | AES-256-GCM file | IOPlatformUUID (hardware-bound) |
| Linux | AES-256-GCM file | /etc/machine-id |

The file-based store provides machine-binding: tokens encrypted on one machine cannot be decrypted on another. This is NOT a security boundary against local attackers with user-level file access on the same machine.

For higher security requirements, provide a custom `TokenStore` implementation using OS keychain APIs (macOS Keychain, Linux libsecret/kwallet).

## Key Derivation

Encryption key = SHA-256("kombify-toolauth:" + machineID). This is a single-pass hash, not a KDF. Acceptable because the threat model is cross-machine portability prevention, not brute-force resistance.

## Thread Safety

All Client methods are safe for concurrent use. Token and entitlement caches use sync.RWMutex. Usage buffer uses sync.Mutex.
