//go:build !windows

package toolauth

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// machineID returns a stable machine identifier for the current platform.
// On Linux it reads /etc/machine-id. On macOS it uses the IOPlatformUUID
// from IOKit (falling back to hostname only as a last resort).
// On other platforms it uses hostname.
func machineID() (string, error) {
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile("/etc/machine-id")
		if err != nil {
			return "", fmt.Errorf("toolauth: read /etc/machine-id: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	case "darwin":
		data, err := os.ReadFile("/etc/machine-id")
		if err == nil {
			return strings.TrimSpace(string(data)), nil
		}
		// On macOS, /etc/machine-id does not exist. Use the hardware UUID from IOKit.
		cmd := exec.CommandContext(context.Background(), "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
		out, err := cmd.Output()
		if err == nil {
			// Parse IOPlatformUUID from output
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "IOPlatformUUID") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						uuid := strings.Trim(strings.TrimSpace(parts[1]), "\"")
						if uuid != "" {
							return uuid, nil
						}
					}
				}
			}
		}
		// Final fallback: hostname (least stable, but better than failing)
		host, err := os.Hostname()
		if err != nil {
			return "", fmt.Errorf("toolauth: no machine ID available: %w", err)
		}
		return host, nil
	default:
		name, err := os.Hostname()
		if err != nil {
			return "", fmt.Errorf("toolauth: hostname: %w", err)
		}
		return name, nil
	}
}
