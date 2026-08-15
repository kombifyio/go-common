package edgeauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func newDecisionRequest(t *testing.T, secret, keyID string, now time.Time) *http.Request {
	t.Helper()
	const signedPath = "/api/v1/stacks/stack-1/managed-runtimes?provider=ionos"
	r, err := http.NewRequest(http.MethodPost, "https://techstack.internal"+signedPath, nil)
	if err != nil {
		t.Fatalf("new decision request: %v", err)
	}
	timestamp := now.Unix()
	r.Header.Set(HeaderEdgeAuth, EdgeAuthValueJWT)
	r.Header.Set(HeaderEdgeService, "techstack")
	r.Header.Set(HeaderPublicPrefix, "/v1/techstack")
	r.Header.Set(HeaderUserID, "auth0|owner-1")
	r.Header.Set(HeaderOrgID, "tenant-1")
	r.Header.Set(HeaderRequestID, "request-1")
	r.Header.Set(HeaderEdgeKeyID, "edge-primary")
	r.Header.Set(HeaderEdgeTimestamp, fmt.Sprintf("%d", timestamp))
	r.Header.Set(HeaderEdgeNonce, "nonce-1")
	r.Header.Set(HeaderEdgeSignedPath, signedPath)
	edgePayload := buildSignaturePayload(
		edgeSignatureVersionV2,
		r.Method,
		signedPath,
		"edge-primary",
		r,
		fmt.Sprintf("%d", timestamp),
		"nonce-1",
	)
	edgeSignature := edgeSignatureVersionV2 + "=" + signPayload("edge-secret", edgePayload)
	r.Header.Set(HeaderEdgeSignature, edgeSignature)

	decision, err := SignDecisionHeaders(DecisionSignInput{
		Secret: secret, KeyID: keyID,
		Method: r.Method, SignedPath: signedPath,
		Audience: "techstack", PublicPrefix: "/v1/techstack",
		SubjectID: "auth0|owner-1", TenantID: "tenant-1", RequestID: "request-1",
		EdgeKeyID: "edge-primary", EdgeTimestamp: fmt.Sprintf("%d", timestamp),
		EdgeNonce: "nonce-1", EdgeSignature: edgeSignature,
		Flags: map[string]bool{"techstack.managed.runtime": true},
		Budgets: map[string]any{
			CloudRuntimeCreditsBudgetName: map[string]any{
				"managed_servers": map[string]any{"mode": "limited", "limit": 3},
			},
		},
	})
	if err != nil {
		t.Fatalf("sign decision: %v", err)
	}
	for header, values := range decision {
		for _, value := range values {
			r.Header.Add(header, value)
		}
	}
	return r
}

func cloneDecisionRequest(t *testing.T, source *http.Request) *http.Request {
	t.Helper()
	clone := source.Clone(source.Context())
	clone.Header = source.Header.Clone()
	return clone
}

func decisionVerifyConfig(now time.Time) DecisionVerifyConfig {
	return DecisionVerifyConfig{
		PrimarySecret: "flags-secret", PrimaryKeyID: "flags-primary",
		ExpectedAudience: "techstack", ExpectedPublicPrefix: "/v1/techstack",
		SignatureWindow: 5 * time.Minute, Now: func() time.Time { return now },
		IdentityConfig: Config{
			EdgeAuthSecret: "edge-secret", EdgeAuthKeyID: "edge-primary",
			SignatureWindow: 5 * time.Minute,
		},
	}
}

func newFlagRequest(t *testing.T, h http.Header) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "https://api.kombify.io/v1/ai/chat", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, vs := range h {
		for _, v := range vs {
			r.Header.Set(k, v)
		}
	}
	return r
}

func TestSignAndVerifyFlagHeaders(t *testing.T) {
	const secret = "test-edge-secret"
	cfg := Config{EdgeAuthSecret: secret, SignatureWindow: 5 * time.Minute}

	h, err := SignFlagHeaders(secret, "primary",
		map[string]bool{"ai.tier.standard": true, "ai.voice": false},
		map[string]any{"ai.tokens": map[string]any{"monthly": 1000000, "rpm": 60}},
		time.Now())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	fs, err := VerifyFlagHeaders(newFlagRequest(t, h), cfg)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !fs.Bool("ai.tier.standard", false) {
		t.Fatal("expected ai.tier.standard true")
	}
	if fs.Bool("ai.voice", true) {
		t.Fatal("expected ai.voice false")
	}
	if fs.Bool("ai.tier.ultra", false) {
		t.Fatal("absent flag must return fail-closed default")
	}
	if _, ok := fs.Budgets["ai.tokens"]; !ok {
		t.Fatal("expected ai.tokens budget present")
	}
}

func TestVerifyFlagHeadersTamperRejected(t *testing.T) {
	const secret = "test-edge-secret"
	cfg := Config{EdgeAuthSecret: secret, SignatureWindow: 5 * time.Minute}

	h, err := SignFlagHeaders(secret, "primary", map[string]bool{"ai.tier.standard": false}, nil, time.Now())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Tamper: flip the flag payload without re-signing.
	h.Set(HeaderFlags, `{"ai.tier.standard":true}`)

	if _, err := VerifyFlagHeaders(newFlagRequest(t, h), cfg); err == nil {
		t.Fatal("expected tampered flag payload to be rejected")
	}
}

func TestVerifyFlagHeadersMissingSecret(t *testing.T) {
	h, _ := SignFlagHeaders("s", "primary", map[string]bool{"ai.tier.standard": true}, nil, time.Now())
	// No secret configured and none in env => fail-closed.
	t.Setenv("EDGE_AUTH_SECRET", "")
	t.Setenv("EDGE_AUTH_SECRET_NEXT", "")
	if _, err := VerifyFlagHeaders(newFlagRequest(t, h), Config{}); err == nil {
		t.Fatal("expected error when no edge secret is configured")
	}
}

func TestBuildDecisionSignaturePayloadGolden(t *testing.T) {
	got := BuildDecisionSignaturePayload(
		"flags-primary",
		"post",
		"/api/v1/stacks/stack-1/managed-runtimes?provider=ionos",
		"techstack",
		"/v1/techstack",
		"auth0|owner-1",
		"tenant-1",
		"request-1",
		"edge-primary",
		"1784730000",
		"nonce-1",
		"v2=edge-signature",
		`{"techstack.managed.runtime":true}`,
		`{"cloud.runtime.credits":{"managed_servers":{"limit":3,"mode":"limited"}}}`,
	)
	want := "v2\nflags-primary\nPOST\n/api/v1/stacks/stack-1/managed-runtimes?provider=ionos\n" +
		"techstack\n/v1/techstack\nauth0|owner-1\ntenant-1\nrequest-1\nedge-primary\n" +
		"1784730000\nnonce-1\nv2=edge-signature\n" +
		`{"techstack.managed.runtime":true}` + "\n" +
		`{"cloud.runtime.credits":{"managed_servers":{"limit":3,"mode":"limited"}}}`
	if got != want {
		t.Fatalf("payload mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestSignAndVerifyDecisionHeaders(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	r := newDecisionRequest(t, "flags-secret", "flags-primary", now)
	got, err := VerifyDecisionHeaders(r, decisionVerifyConfig(now))
	if err != nil {
		t.Fatalf("VerifyDecisionHeaders() error = %v", err)
	}
	binding, ok := got.VerifiedDecisionBinding()
	if !ok {
		t.Fatal("expected verified decision binding")
	}
	if binding.SubjectID != "auth0|owner-1" || binding.TenantID != "tenant-1" ||
		binding.Audience != "techstack" || binding.Method != http.MethodPost ||
		binding.RequestID != "request-1" || binding.Nonce != "nonce-1" ||
		!binding.IssuedAt.Equal(now) {
		t.Fatalf("binding = %#v", binding)
	}
	credits, creditsBinding, err := got.VerifiedCloudRuntimeCredits()
	if err != nil {
		t.Fatalf("VerifiedCloudRuntimeCredits() error = %v", err)
	}
	if creditsBinding != binding {
		t.Fatalf("credits binding = %#v, want %#v", creditsBinding, binding)
	}
	if credits.ManagedServers.Mode != ManagedServerCreditModeLimited || credits.ManagedServers.Limit != 3 {
		t.Fatalf("credits = %#v", credits)
	}
}

func TestVerifyDecisionHeadersRejectsTransplants(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	base := newDecisionRequest(t, "flags-secret", "flags-primary", now)
	config := decisionVerifyConfig(now)
	tests := []struct {
		name   string
		mutate func(*http.Request, *DecisionVerifyConfig)
	}{
		{name: "subject", mutate: func(r *http.Request, _ *DecisionVerifyConfig) { r.Header.Set(HeaderUserID, "auth0|other") }},
		{name: "tenant", mutate: func(r *http.Request, _ *DecisionVerifyConfig) { r.Header.Set(HeaderOrgID, "tenant-2") }},
		{name: "audience", mutate: func(r *http.Request, _ *DecisionVerifyConfig) { r.Header.Set(HeaderEdgeService, "simulate") }},
		{name: "configured audience", mutate: func(_ *http.Request, cfg *DecisionVerifyConfig) { cfg.ExpectedAudience = "simulate" }},
		{name: "public prefix", mutate: func(r *http.Request, _ *DecisionVerifyConfig) { r.Header.Set(HeaderPublicPrefix, "/v1/simulate") }},
		{name: "method", mutate: func(r *http.Request, _ *DecisionVerifyConfig) { r.Method = http.MethodDelete }},
		{name: "path", mutate: func(r *http.Request, _ *DecisionVerifyConfig) { r.URL.Path = "/api/v1/stacks/stack-2/managed-runtimes" }},
		{name: "request id", mutate: func(r *http.Request, _ *DecisionVerifyConfig) { r.Header.Set(HeaderRequestID, "request-2") }},
		{name: "nonce", mutate: func(r *http.Request, _ *DecisionVerifyConfig) { r.Header.Set(HeaderEdgeNonce, "nonce-2") }},
		{name: "edge identity signature", mutate: func(r *http.Request, _ *DecisionVerifyConfig) {
			r.Header.Set(HeaderEdgeSignature, "v2=other-edge-signature")
		}},
		{name: "decision budget", mutate: func(r *http.Request, _ *DecisionVerifyConfig) {
			r.Header.Set(HeaderBudgets, `{"cloud.runtime.credits":{"managed_servers":{"mode":"unlimited"}}}`)
		}},
		{name: "unknown decision key", mutate: func(r *http.Request, _ *DecisionVerifyConfig) { r.Header.Set(HeaderFlagsKeyID, "unknown") }},
		{name: "stale", mutate: func(_ *http.Request, cfg *DecisionVerifyConfig) {
			cfg.Now = func() time.Time { return now.Add(6 * time.Minute) }
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := cloneDecisionRequest(t, base)
			cfg := config
			tt.mutate(r, &cfg)
			if _, err := VerifyDecisionHeaders(r, cfg); err == nil {
				t.Fatal("expected transplanted decision to be rejected")
			}
		})
	}
}

func TestVerifyDecisionHeadersAcceptsNextRotationKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	r := newDecisionRequest(t, "next-secret", "flags-next", now)
	config := decisionVerifyConfig(now)
	config.PrimarySecret = "old-secret"
	config.NextSecret = "next-secret"
	config.NextKeyID = "flags-next"
	if _, err := VerifyDecisionHeaders(r, config); err != nil {
		t.Fatalf("next rotation key rejected: %v", err)
	}
}

func TestVerifyDecisionHeadersRejectsAmbiguousRotationKeyIDs(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	r := newDecisionRequest(t, "flags-secret", "flags-primary", now)
	config := decisionVerifyConfig(now)
	config.NextSecret = "next-secret"
	config.NextKeyID = config.PrimaryKeyID
	if _, err := VerifyDecisionHeaders(r, config); err == nil {
		t.Fatal("expected duplicate rotation key ids to be rejected")
	}
}

func TestVerifyDecisionHeadersRejectsFlagsSignerWithoutValidIdentityEnvelope(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	r := newDecisionRequest(t, "flags-secret", "flags-primary", now)
	r.Header.Set(HeaderEdgeSignature, "v2=forged-by-flags-key-holder")
	decision, err := SignDecisionHeaders(DecisionSignInput{
		Secret: "flags-secret", KeyID: "flags-primary",
		Method: r.Method, SignedPath: r.Header.Get(HeaderEdgeSignedPath),
		Audience: "techstack", PublicPrefix: "/v1/techstack",
		SubjectID: r.Header.Get(HeaderUserID), TenantID: r.Header.Get(HeaderOrgID),
		RequestID: r.Header.Get(HeaderRequestID), EdgeKeyID: r.Header.Get(HeaderEdgeKeyID),
		EdgeTimestamp: r.Header.Get(HeaderEdgeTimestamp), EdgeNonce: r.Header.Get(HeaderEdgeNonce),
		EdgeSignature: r.Header.Get(HeaderEdgeSignature),
		Budgets: map[string]any{CloudRuntimeCreditsBudgetName: map[string]any{
			"managed_servers": map[string]any{"mode": "unlimited"},
		}},
	})
	if err != nil {
		t.Fatalf("sign attacker-held flags key: %v", err)
	}
	for header, values := range decision {
		r.Header.Del(header)
		for _, value := range values {
			r.Header.Add(header, value)
		}
	}
	if _, err := VerifyDecisionHeaders(r, decisionVerifyConfig(now)); err == nil {
		t.Fatal("expected valid decision signature with forged identity envelope to be rejected")
	}
}

func TestVerifyDecisionHeadersRejectsDetachedV1Budget(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	r := newDecisionRequest(t, "flags-secret", "flags-primary", now)
	v1, err := SignFlagHeaders(
		"flags-secret",
		"flags-primary",
		map[string]bool{"techstack.managed.runtime": true},
		map[string]any{CloudRuntimeCreditsBudgetName: map[string]any{"managed_servers": map[string]any{"mode": "unlimited"}}},
		now,
	)
	if err != nil {
		t.Fatalf("sign v1: %v", err)
	}
	for header, values := range v1 {
		r.Header.Del(header)
		for _, value := range values {
			r.Header.Add(header, value)
		}
	}
	if _, err := VerifyDecisionHeaders(r, decisionVerifyConfig(now)); err == nil {
		t.Fatal("expected detached v1 budget to be rejected")
	}
}

func TestApplicationConstructedFlagSetHasNoVerifiedDecisionBinding(t *testing.T) {
	set := FlagSet{Budgets: map[string]json.RawMessage{
		CloudRuntimeCreditsBudgetName: json.RawMessage(`{"managed_servers":{"mode":"unlimited"}}`),
	}}
	if _, ok := set.VerifiedDecisionBinding(); ok {
		t.Fatal("application-constructed FlagSet must not carry verified decision provenance")
	}
}

func TestVerifiedDecisionProvenanceRejectsPostVerifyMutation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	set, err := VerifyDecisionHeaders(newDecisionRequest(t, "flags-secret", "flags-primary", now), decisionVerifyConfig(now))
	if err != nil {
		t.Fatalf("verify decision: %v", err)
	}
	set.Budgets[CloudRuntimeCreditsBudgetName] = json.RawMessage(`{"managed_servers":{"mode":"unlimited"}}`)
	if _, ok := set.VerifiedDecisionBinding(); ok {
		t.Fatal("mutated decision must lose verified provenance")
	}
	if _, _, ok := set.VerifiedBudget(CloudRuntimeCreditsBudgetName); ok {
		t.Fatal("mutated budget must not be returned as verified")
	}
}

func TestFlagsContextDetachesVerifiedDecisionMaps(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	set, err := VerifyDecisionHeaders(newDecisionRequest(t, "flags-secret", "flags-primary", now), decisionVerifyConfig(now))
	if err != nil {
		t.Fatalf("verify decision: %v", err)
	}
	ctx := FlagsToContext(t.Context(), set)
	set.Budgets[CloudRuntimeCreditsBudgetName] = json.RawMessage(`{"managed_servers":{"mode":"unlimited"}}`)

	fromContext, ok := FlagsFromContext(ctx)
	if !ok {
		t.Fatal("missing context decision")
	}
	raw, _, ok := fromContext.VerifiedBudget(CloudRuntimeCreditsBudgetName)
	if !ok {
		t.Fatal("context decision lost verified provenance")
	}
	credits, err := ParseCloudRuntimeCredits(raw)
	if err != nil {
		t.Fatalf("parse context credits: %v", err)
	}
	if credits.ManagedServers.Mode != ManagedServerCreditModeLimited {
		t.Fatalf("context decision was mutated: %#v", credits)
	}

	fromContext.Budgets[CloudRuntimeCreditsBudgetName] = json.RawMessage(`{"managed_servers":{"mode":"unlimited"}}`)
	again, _ := FlagsFromContext(ctx)
	credits, err = ParseCloudRuntimeCredits(again.Budgets[CloudRuntimeCreditsBudgetName])
	if err != nil || credits.ManagedServers.Mode != ManagedServerCreditModeLimited {
		t.Fatalf("context value leaked mutable map: credits=%#v err=%v", credits, err)
	}
}
