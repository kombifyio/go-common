package referenceid

import (
	"strings"
	"testing"
)

func TestValidExecutionChannelClosesLocalAndExternalIdentityGrammar(t *testing.T) {
	valid := []string{
		"channel-home-main",
		"channel.home:main_1",
		"execution-channel://sha256/" + strings.Repeat("a", 64),
	}
	for _, value := range valid {
		if !ValidExecutionChannel(value) {
			t.Errorf("valid channel %q rejected", value)
		}
	}
	invalid := []string{
		"",
		"https://node.example.test/action",
		"ssh://root@node",
		"secret://material",
		"execution-channel://node-a",
		"execution-channel://sha256/" + strings.Repeat("A", 64),
		"execution-channel://sha256/" + strings.Repeat("a", 63),
		"channel\nother",
		strings.Repeat("a", 129),
	}
	for _, value := range invalid {
		if ValidExecutionChannel(value) {
			t.Errorf("invalid channel %q accepted", value)
		}
	}
}
