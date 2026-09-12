package denial

import (
	"encoding/json"
	"os"
	"testing"
)

func TestParseValidEntitlementDenial(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid-entitlement-denial.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	envelope, err := Parse(raw)
	if err != nil {
		t.Fatalf("valid workspace fixture must parse: %v", err)
	}
	if envelope.ErrorCode == "" || envelope.ReasonCode == "" {
		t.Fatalf("required codes missing: %#v", envelope)
	}
	if envelope.Retryable {
		t.Fatal("entitlement denial must not be retryable")
	}
	if envelope.UserGuidance.Title == "" || envelope.UserGuidance.Body == "" || len(envelope.UserGuidance.NextSteps) == 0 {
		t.Fatalf("user_guidance object incomplete: %#v", envelope.UserGuidance)
	}

	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var round map[string]any
	if err := json.Unmarshal(encoded, &round); err != nil {
		t.Fatal(err)
	}
	guidance, ok := round["user_guidance"].(map[string]any)
	if !ok {
		t.Fatalf("encoded user_guidance is not an object: %T", round["user_guidance"])
	}
	if _, ok := guidance["next_steps"].([]any); !ok {
		t.Fatalf("encoded next_steps missing: %#v", guidance)
	}
}

func TestParseRejectsStringUserGuidance(t *testing.T) {
	raw, err := os.ReadFile("testdata/invalid-string-guidance.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if _, err := Parse(raw); err == nil {
		t.Fatal("string user_guidance must fail closed")
	}
}
