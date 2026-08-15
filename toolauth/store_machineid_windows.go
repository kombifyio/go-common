//go:build windows

package toolauth

import (
	"fmt"
	"os/exec"
	"strings"
)

// machineID returns the Windows MachineGuid from the registry.
func machineID() (string, error) {
	out, err := exec.Command(
		"reg", "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`,
		"/v", "MachineGuid",
	).Output()
	if err != nil {
		return "", fmt.Errorf("toolauth: read MachineGuid from registry: %w", err)
	}
	// Output format: "    MachineGuid    REG_SZ    <guid>"
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "MachineGuid") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return parts[len(parts)-1], nil
			}
		}
	}
	return "", fmt.Errorf("toolauth: MachineGuid not found in registry output")
}
