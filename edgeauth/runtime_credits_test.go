package edgeauth

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestParseCloudRuntimeCredits(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		want  ManagedServerCredit
		valid bool
	}{
		{name: "limited", raw: `{"managed_servers":{"mode":"limited","limit":3}}`, want: ManagedServerCredit{Mode: ManagedServerCreditModeLimited, Limit: 3}, valid: true},
		{name: "unlimited", raw: `{"managed_servers":{"mode":"unlimited"}}`, want: ManagedServerCredit{Mode: ManagedServerCreditModeUnlimited}, valid: true},
		{name: "missing managed servers", raw: `{}`},
		{name: "null managed servers", raw: `{"managed_servers":null}`},
		{name: "unknown outer field", raw: `{"managed_servers":{"mode":"limited","limit":3},"override":true}`},
		{name: "unknown managed field", raw: `{"managed_servers":{"mode":"limited","limit":3,"caller":true}}`},
		{name: "unknown mode", raw: `{"managed_servers":{"mode":"elastic"}}`},
		{name: "noncanonical uppercase mode", raw: `{"managed_servers":{"mode":"LIMITED","limit":3}}`},
		{name: "noncanonical padded mode", raw: `{"managed_servers":{"mode":" limited ","limit":3}}`},
		{name: "limited missing limit", raw: `{"managed_servers":{"mode":"limited"}}`},
		{name: "limited zero", raw: `{"managed_servers":{"mode":"limited","limit":0}}`},
		{name: "limited fractional", raw: `{"managed_servers":{"mode":"limited","limit":3.5}}`},
		{name: "limited string", raw: `{"managed_servers":{"mode":"limited","limit":"3"}}`},
		{name: "unlimited with limit", raw: `{"managed_servers":{"mode":"unlimited","limit":3}}`},
		{name: "multiple values", raw: `{"managed_servers":{"mode":"unlimited"}} {}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCloudRuntimeCredits(json.RawMessage(tt.raw))
			if !tt.valid {
				if !errors.Is(err, ErrCloudRuntimeCreditsInvalid) {
					t.Fatalf("error = %v, want ErrCloudRuntimeCreditsInvalid", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCloudRuntimeCredits() error = %v", err)
			}
			if got.ManagedServers != tt.want {
				t.Fatalf("managed_servers = %#v, want %#v", got.ManagedServers, tt.want)
			}
		})
	}
}

func TestVerifiedCloudRuntimeCreditsRequiresBindingAndClosedSchema(t *testing.T) {
	unverified := FlagSet{Budgets: map[string]json.RawMessage{
		CloudRuntimeCreditsBudgetName: json.RawMessage(`{"managed_servers":{"mode":"unlimited"}}`),
	}}
	if _, _, err := unverified.VerifiedCloudRuntimeCredits(); !errors.Is(err, ErrVerifiedDecisionAuthorityAbsent) {
		t.Fatalf("error = %v, want ErrVerifiedDecisionAuthorityAbsent", err)
	}
}
