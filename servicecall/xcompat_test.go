package servicecall

import (
	"testing"
	"time"
)

// Cross-language interop: a JWT issued by the TypeScript port of this package
// (kombify-Cloud/src/lib/server/servicecall.ts) must verify here.
//
// Pinned token regenerated with /tmp/gen_token.mjs (iat=2024-01-01,
// exp=2040-01-01 so the vector does not age out). Regenerate if either
// implementation changes its canonical JWT header, claim ordering, or
// base64url scheme — a failure here means the two sides drifted.
func TestTSGeneratedToken_VerifyInGo(t *testing.T) {
	const secret = "shared-secret-for-xcompat"
	const tsToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJpc3MiOiJrb21iaWZ5LWNsb3VkIiwiYXVkIjoia29tYmlmeS1haSIsImlhdCI6MTcwNDA2NzIwMCwiZXhwIjoyMjA4OTg4ODAwLCJzdmMiOiJjbG91ZCIsInJlcV9pZCI6Inhjb21wYXQtMSIsIm9uX2JlaGFsZl9vZiI6eyJzdWIiOiJhdXRoMHx0ZXN0dXNlciIsIm9yZ19pZCI6Im9yZ19hIiwiZW1haWwiOiJ1QHgiLCJyb2xlcyI6WyJwcm8iXX19." +
		"JxIxIC0wo6ZH7ku74wouak6JNQIm5tK4F2eYSWxetKY"

	claims, err := VerifyToken(tsToken, secret, "")
	if err != nil {
		t.Fatalf("Go could not verify TS-signed token: %v", err)
	}
	if claims.Iss != "kombify-cloud" || claims.Aud != "kombify-ai" || claims.Svc != "cloud" {
		t.Errorf("iss/aud/svc mismatch: %+v", claims)
	}
	if claims.RequestID != "xcompat-1" {
		t.Errorf("req_id=%q want xcompat-1", claims.RequestID)
	}
	if claims.OnBehalfOf == nil || claims.OnBehalfOf.Sub != "auth0|testuser" {
		t.Fatalf("OnBehalfOf lost: %+v", claims.OnBehalfOf)
	}
	if claims.OnBehalfOf.OrgID != "org_a" || claims.OnBehalfOf.Email != "u@x" {
		t.Errorf("OnBehalfOf fields: %+v", claims.OnBehalfOf)
	}
	if len(claims.OnBehalfOf.Roles) != 1 || claims.OnBehalfOf.Roles[0] != "pro" {
		t.Errorf("roles: %+v", claims.OnBehalfOf.Roles)
	}
}

func TestGoGeneratedToken_Roundtrip(t *testing.T) {
	const secret = "shared-secret-for-xcompat"
	tok, err := IssueToken(Config{ServiceName: "cloud", Secret: secret, TokenTTL: time.Minute}, "ai", &OnBehalfOf{
		Sub: "auth0|testuser", OrgID: "org_a", Email: "u@x", Roles: []string{"pro"},
	}, "xcompat-2")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	c, err := VerifyToken(tok, secret, "")
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if c.OnBehalfOf == nil || c.OnBehalfOf.Sub != "auth0|testuser" {
		t.Errorf("Sub: %+v", c.OnBehalfOf)
	}
}
