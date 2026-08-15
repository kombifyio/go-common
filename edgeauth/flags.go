package edgeauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Signed feature-flag / token-budget delivery headers.
//
// ENTITLEMENTS-ARCHITECTURE §8.1 removes the feature_flags claim array from the
// session JWT. Instead the Cloudflare Edge Router evaluates Flagship per request
// (sub-ms) and forwards the result to the origin as signed per-request headers.
// This file is the origin-side reference verifier and the test/edge-side signer.
//
// The flag headers carry their OWN signature (HeaderFlagsSignature), separate
// from the identity-header signature in edgeauth.go, so the two evolve and
// verify independently. Both reuse EDGE_AUTH_SECRET[_NEXT] and the same HMAC.
const (
	// HeaderFlags is a JSON object {"<dotted.key>": bool, ...}.
	HeaderFlags = "X-Kombify-Flags"
	// HeaderBudgets is a JSON object {"<dotted.key>": {<budget object>}, ...}.
	HeaderBudgets = "X-Kombify-Budgets"
	// HeaderFlagsSignature is "v1=<base64url-hmac>" over the flags payload.
	HeaderFlagsSignature = "X-Kombify-Flags-Signature"
	// HeaderFlagsTimestamp is the unix-seconds timestamp bound into the signature.
	HeaderFlagsTimestamp = "X-Kombify-Flags-Timestamp"
	// HeaderFlagsKeyID identifies which EDGE_AUTH secret signed the payload.
	HeaderFlagsKeyID = "X-Kombify-Flags-Key-ID"

	decisionSignatureVersionV2 = "v2"
)

// FlagSet is the verified set of per-request flags and budgets from the edge.
type FlagSet struct {
	Flags   map[string]bool
	Budgets map[string]json.RawMessage

	// decisionBinding is deliberately unexported. Callers may still construct a
	// FlagSet for non-authoritative release flags, but only this package can mark
	// a commercial decision as verified against the request-bound v2 envelope.
	decisionBinding *DecisionBinding
	decisionDigest  [sha256.Size]byte
}

// DecisionBinding is the immutable provenance of a request-bound v2 flag and
// budget decision. Origins must compare SubjectID and TenantID with their
// authenticated resource operation before treating a budget as authority.
type DecisionBinding struct {
	Version      string
	KeyID        string
	SubjectID    string
	TenantID     string
	Audience     string
	PublicPrefix string
	Method       string
	SignedPath   string
	RequestID    string
	EdgeKeyID    string
	Nonce        string
	IssuedAt     time.Time
}

// VerifiedDecisionBinding returns request-bound commercial-decision
// provenance only when FlagSet came from VerifyDecisionHeaders. A FlagSet
// assembled by application code or restored from a job payload has no such
// provenance and must fail closed for cost-bearing authorization.
func (f FlagSet) VerifiedDecisionBinding() (DecisionBinding, bool) {
	if f.decisionBinding == nil || f.decisionDigest == ([sha256.Size]byte{}) || f.decisionDigest != flagSetDigest(f) {
		return DecisionBinding{}, false
	}
	return *f.decisionBinding, true
}

// VerifiedBudget returns a detached copy of one budget together with its
// request binding. It fails closed if application code changed any flag or
// budget after verification.
func (f FlagSet) VerifiedBudget(key string) (json.RawMessage, DecisionBinding, bool) {
	binding, ok := f.VerifiedDecisionBinding()
	if !ok {
		return nil, DecisionBinding{}, false
	}
	raw, ok := f.Budgets[key]
	if !ok {
		return nil, DecisionBinding{}, false
	}
	return append(json.RawMessage(nil), raw...), binding, true
}

// Bool returns the flag value, or def if absent (fail-closed: callers pass false
// for entitlement flags).
func (f FlagSet) Bool(key string, def bool) bool {
	if f.Flags == nil {
		return def
	}
	if v, ok := f.Flags[key]; ok {
		return v
	}
	return def
}

type flagsCtxKey struct{}

// FlagsToContext stores a verified FlagSet for downstream handlers.
func FlagsToContext(ctx context.Context, fs FlagSet) context.Context {
	return context.WithValue(ctx, flagsCtxKey{}, cloneFlagSet(fs))
}

// FlagsFromContext retrieves a FlagSet previously stored by FlagsToContext.
func FlagsFromContext(ctx context.Context) (FlagSet, bool) {
	fs, ok := ctx.Value(flagsCtxKey{}).(FlagSet)
	return cloneFlagSet(fs), ok
}

func cloneFlagSet(in FlagSet) FlagSet {
	out := FlagSet{
		Flags:          make(map[string]bool, len(in.Flags)),
		Budgets:        make(map[string]json.RawMessage, len(in.Budgets)),
		decisionDigest: in.decisionDigest,
	}
	for key, value := range in.Flags {
		out.Flags[key] = value
	}
	for key, value := range in.Budgets {
		out.Budgets[key] = append(json.RawMessage(nil), value...)
	}
	if in.decisionBinding != nil {
		binding := *in.decisionBinding
		out.decisionBinding = &binding
	}
	return out
}

func flagSetDigest(set FlagSet) [sha256.Size]byte {
	flagsJSON, flagsErr := json.Marshal(set.Flags)
	budgetsJSON, budgetsErr := json.Marshal(set.Budgets)
	if flagsErr != nil || budgetsErr != nil {
		return [sha256.Size]byte{}
	}
	return sha256.Sum256(append(append(flagsJSON, '\n'), budgetsJSON...))
}

func flagsPayload(keyID, timestamp, flagsJSON, budgetsJSON string) string {
	return strings.Join([]string{edgeSignatureVersion, keyID, timestamp, flagsJSON, budgetsJSON}, "\n")
}

// DecisionSignInput binds one flags/budgets decision to the already minted
// Edge identity envelope and exact origin request. EdgeTimestamp, EdgeNonce,
// EdgeKeyID, and EdgeSignature must be copied from that same identity envelope.
type DecisionSignInput struct {
	Secret        string
	KeyID         string
	Method        string
	SignedPath    string
	Audience      string
	PublicPrefix  string
	SubjectID     string
	TenantID      string
	RequestID     string
	EdgeKeyID     string
	EdgeTimestamp string
	EdgeNonce     string
	EdgeSignature string
	Flags         map[string]bool
	Budgets       map[string]any
}

// DecisionVerifyConfig fixes the trusted signing keys and intended origin
// audience. ExpectedAudience is mandatory; ExpectedPublicPrefix is optional
// and should be set when one origin serves multiple public route prefixes.
type DecisionVerifyConfig struct {
	PrimarySecret        string
	NextSecret           string
	PrimaryKeyID         string
	NextKeyID            string
	ExpectedAudience     string
	ExpectedPublicPrefix string
	SignatureWindow      time.Duration
	Now                  func() time.Time
	// IdentityConfig verifies the exact Edge identity envelope whose
	// signature/timestamp/nonce are bound into the decision signature. It must
	// use the Edge identity keys, which may differ from the decision keys.
	IdentityConfig Config
}

// BuildDecisionSignaturePayload is the canonical v2 flags/budgets payload.
// Its field order is a cross-language wire contract shared with kombify-Gateway.
func BuildDecisionSignaturePayload(
	keyID, method, signedPath, audience, publicPrefix, subjectID, tenantID,
	requestID, edgeKeyID, timestamp, nonce, edgeSignature, flagsJSON, budgetsJSON string,
) string {
	return strings.Join([]string{
		decisionSignatureVersionV2,
		keyID,
		strings.ToUpper(method),
		signedPath,
		audience,
		publicPrefix,
		subjectID,
		tenantID,
		requestID,
		edgeKeyID,
		timestamp,
		nonce,
		edgeSignature,
		flagsJSON,
		budgetsJSON,
	}, "\n")
}

// SignDecisionHeaders signs a request-bound v2 decision. It does not mint the
// Edge identity envelope; callers must pass fields from the exact envelope
// already created for the same upstream request.
func SignDecisionHeaders(input DecisionSignInput) (http.Header, error) {
	secret := strings.TrimSpace(input.Secret)
	if secret == "" {
		return nil, fmt.Errorf("edge_decision_secret_missing")
	}
	keyID := strings.TrimSpace(input.KeyID)
	if keyID == "" {
		keyID = defaultEdgeKeyID
	}
	for name, value := range map[string]string{
		"method":         input.Method,
		"signed_path":    input.SignedPath,
		"audience":       input.Audience,
		"subject":        input.SubjectID,
		"tenant":         input.TenantID,
		"request_id":     input.RequestID,
		"edge_key_id":    input.EdgeKeyID,
		"edge_timestamp": input.EdgeTimestamp,
		"edge_nonce":     input.EdgeNonce,
		"edge_signature": input.EdgeSignature,
	} {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("edge_decision_binding_missing: %s", name)
		}
	}
	if !supportsEntitlementIdentitySignature(input.EdgeSignature) {
		return nil, fmt.Errorf("edge_decision_identity_version_invalid")
	}
	if err := validateTimestampAt(input.EdgeTimestamp, defaultSignatureWindow, time.Now()); err != nil {
		return nil, err
	}

	flags := input.Flags
	if flags == nil {
		flags = map[string]bool{}
	}
	budgets := input.Budgets
	if budgets == nil {
		budgets = map[string]any{}
	}
	flagsJSON, err := json.Marshal(flags)
	if err != nil {
		return nil, err
	}
	budgetsJSON, err := json.Marshal(budgets)
	if err != nil {
		return nil, err
	}
	payload := BuildDecisionSignaturePayload(
		keyID,
		input.Method,
		input.SignedPath,
		strings.TrimSpace(input.Audience),
		strings.TrimSpace(input.PublicPrefix),
		strings.TrimSpace(input.SubjectID),
		strings.TrimSpace(input.TenantID),
		strings.TrimSpace(input.RequestID),
		strings.TrimSpace(input.EdgeKeyID),
		strings.TrimSpace(input.EdgeTimestamp),
		strings.TrimSpace(input.EdgeNonce),
		strings.TrimSpace(input.EdgeSignature),
		string(flagsJSON),
		string(budgetsJSON),
	)

	h := http.Header{}
	h.Set(HeaderFlags, string(flagsJSON))
	h.Set(HeaderBudgets, string(budgetsJSON))
	h.Set(HeaderFlagsTimestamp, strings.TrimSpace(input.EdgeTimestamp))
	h.Set(HeaderFlagsKeyID, keyID)
	h.Set(HeaderFlagsSignature, decisionSignatureVersionV2+"="+signPayload(secret, payload))
	return h, nil
}

// VerifyDecisionHeaders verifies a request-bound v2 flags/budgets decision.
// It rejects detached v1 headers and binds the decision to subject, tenant,
// intended audience, method/path, request id, and the exact Edge identity
// timestamp/nonce/signature. Exact HTTP retries remain the origin's durable
// idempotency responsibility; changing any bound field invalidates the HMAC.
func VerifyDecisionHeaders(r *http.Request, cfg DecisionVerifyConfig) (FlagSet, error) {
	if r == nil {
		return FlagSet{}, fmt.Errorf("edge_decision_request_missing")
	}
	if strings.TrimSpace(cfg.ExpectedAudience) == "" {
		return FlagSet{}, fmt.Errorf("edge_decision_audience_missing")
	}
	keys, err := resolveDecisionVerificationKeys(cfg)
	if err != nil {
		return FlagSet{}, err
	}
	envelope, err := readDecisionEnvelope(r, cfg)
	if err != nil {
		return FlagSet{}, err
	}
	if !verifyDecisionEnvelopeSignature(r.Method, envelope, keys) {
		return FlagSet{}, fmt.Errorf("edge_decision_signature_invalid")
	}
	return decodeVerifiedDecision(r.Method, envelope)
}

type decisionVerificationKeys struct {
	primarySecret string
	nextSecret    string
	primaryKeyID  string
	nextKeyID     string
}

func resolveDecisionVerificationKeys(cfg DecisionVerifyConfig) (decisionVerificationKeys, error) {
	keys := decisionVerificationKeys{
		primarySecret: strings.TrimSpace(firstNonEmpty(cfg.PrimarySecret, os.Getenv("EDGE_FLAGS_SECRET"), os.Getenv("EDGE_AUTH_SECRET"))),
		nextSecret:    strings.TrimSpace(firstNonEmpty(cfg.NextSecret, os.Getenv("EDGE_FLAGS_SECRET_NEXT"), os.Getenv("EDGE_AUTH_SECRET_NEXT"))),
		primaryKeyID:  strings.TrimSpace(firstNonEmpty(cfg.PrimaryKeyID, os.Getenv("EDGE_FLAGS_KEY_ID"), defaultEdgeKeyID)),
		nextKeyID:     strings.TrimSpace(firstNonEmpty(cfg.NextKeyID, os.Getenv("EDGE_FLAGS_KEY_ID_NEXT"), defaultEdgeNextKeyID)),
	}
	if keys.primarySecret == "" && keys.nextSecret == "" {
		return decisionVerificationKeys{}, fmt.Errorf("edge_decision_secret_missing")
	}
	if keys.primarySecret != "" && keys.nextSecret != "" && keys.primaryKeyID == keys.nextKeyID {
		return decisionVerificationKeys{}, fmt.Errorf("edge_decision_rotation_key_id_conflict")
	}
	return keys, nil
}

type decisionEnvelope struct {
	flagsJSON     string
	budgetsJSON   string
	timestamp     string
	keyID         string
	signature     string
	audience      string
	publicPrefix  string
	subjectID     string
	tenantID      string
	requestID     string
	edgeKeyID     string
	nonce         string
	edgeSignature string
	signedPath    string
}

func readDecisionEnvelope(r *http.Request, cfg DecisionVerifyConfig) (decisionEnvelope, error) {
	envelope := decisionEnvelope{
		flagsJSON: r.Header.Get(HeaderFlags), budgetsJSON: r.Header.Get(HeaderBudgets),
		timestamp:    strings.TrimSpace(r.Header.Get(HeaderFlagsTimestamp)),
		keyID:        strings.TrimSpace(r.Header.Get(HeaderFlagsKeyID)),
		signature:    strings.TrimSpace(r.Header.Get(HeaderFlagsSignature)),
		audience:     strings.TrimSpace(r.Header.Get(HeaderEdgeService)),
		publicPrefix: strings.TrimSpace(r.Header.Get(HeaderPublicPrefix)),
		subjectID:    strings.TrimSpace(r.Header.Get(HeaderUserID)), tenantID: strings.TrimSpace(r.Header.Get(HeaderOrgID)),
		requestID: strings.TrimSpace(r.Header.Get(HeaderRequestID)), edgeKeyID: strings.TrimSpace(r.Header.Get(HeaderEdgeKeyID)),
		nonce: strings.TrimSpace(r.Header.Get(HeaderEdgeNonce)), edgeSignature: strings.TrimSpace(r.Header.Get(HeaderEdgeSignature)),
		signedPath: strings.TrimSpace(r.Header.Get(HeaderEdgeSignedPath)),
	}
	if decisionEnvelopeMissing(envelope) {
		return decisionEnvelope{}, fmt.Errorf("edge_decision_binding_missing")
	}
	if !strings.HasPrefix(envelope.signature, decisionSignatureVersionV2+"=") {
		return decisionEnvelope{}, fmt.Errorf("edge_decision_signature_version_invalid")
	}
	if envelope.audience != strings.TrimSpace(cfg.ExpectedAudience) {
		return decisionEnvelope{}, fmt.Errorf("edge_decision_audience_mismatch")
	}
	if expectedPrefix := strings.TrimSpace(cfg.ExpectedPublicPrefix); expectedPrefix != "" && envelope.publicPrefix != expectedPrefix {
		return decisionEnvelope{}, fmt.Errorf("edge_decision_public_prefix_mismatch")
	}
	if envelope.signedPath != requestSignedPath(r) {
		return decisionEnvelope{}, fmt.Errorf("edge_decision_path_mismatch")
	}
	if envelope.timestamp != strings.TrimSpace(r.Header.Get(HeaderEdgeTimestamp)) {
		return decisionEnvelope{}, fmt.Errorf("edge_decision_timestamp_mismatch")
	}
	if !supportsEntitlementIdentitySignature(envelope.edgeSignature) {
		return decisionEnvelope{}, fmt.Errorf("edge_decision_identity_version_invalid")
	}
	identityConfig := cfg.IdentityConfig
	if identityConfig.SignatureWindow <= 0 {
		identityConfig.SignatureWindow = cfg.SignatureWindow
	}
	if err := verifyEdgeSignature(r, identityConfig); err != nil {
		return decisionEnvelope{}, fmt.Errorf("edge_decision_identity_invalid: %w", err)
	}
	now := time.Now()
	if cfg.Now != nil {
		now = cfg.Now()
	}
	if err := validateTimestampAt(envelope.timestamp, cfg.SignatureWindow, now); err != nil {
		return decisionEnvelope{}, err
	}
	return envelope, nil
}

func decisionEnvelopeMissing(envelope decisionEnvelope) bool {
	for _, value := range []string{
		envelope.flagsJSON, envelope.budgetsJSON, envelope.timestamp, envelope.keyID,
		envelope.signature, envelope.audience, envelope.subjectID, envelope.tenantID,
		envelope.requestID, envelope.edgeKeyID, envelope.nonce, envelope.edgeSignature,
		envelope.signedPath,
	} {
		if value == "" {
			return true
		}
	}
	return false
}

func verifyDecisionEnvelopeSignature(method string, envelope decisionEnvelope, keys decisionVerificationKeys) bool {
	payload := BuildDecisionSignaturePayload(
		envelope.keyID, method, envelope.signedPath, envelope.audience, envelope.publicPrefix,
		envelope.subjectID, envelope.tenantID, envelope.requestID, envelope.edgeKeyID,
		envelope.timestamp, envelope.nonce, envelope.edgeSignature, envelope.flagsJSON, envelope.budgetsJSON,
	)
	presented := strings.TrimPrefix(envelope.signature, decisionSignatureVersionV2+"=")
	for _, candidate := range []struct{ keyID, secret string }{
		{keys.primaryKeyID, keys.primarySecret},
		{keys.nextKeyID, keys.nextSecret},
	} {
		if candidate.secret != "" && envelope.keyID == candidate.keyID &&
			hmac.Equal([]byte(presented), []byte(signPayload(candidate.secret, payload))) {
			return true
		}
	}
	return false
}

func decodeVerifiedDecision(method string, envelope decisionEnvelope) (FlagSet, error) {
	fs := FlagSet{Flags: map[string]bool{}, Budgets: map[string]json.RawMessage{}}
	if err := json.Unmarshal([]byte(envelope.flagsJSON), &fs.Flags); err != nil {
		return FlagSet{}, fmt.Errorf("edge_flags_payload_invalid")
	}
	if err := json.Unmarshal([]byte(envelope.budgetsJSON), &fs.Budgets); err != nil {
		return FlagSet{}, fmt.Errorf("edge_budgets_payload_invalid")
	}
	issuedSeconds, _ := strconv.ParseInt(envelope.timestamp, 10, 64)
	fs.decisionBinding = &DecisionBinding{
		Version: decisionSignatureVersionV2, KeyID: envelope.keyID,
		SubjectID: envelope.subjectID, TenantID: envelope.tenantID, Audience: envelope.audience,
		PublicPrefix: envelope.publicPrefix, Method: strings.ToUpper(method), SignedPath: envelope.signedPath,
		RequestID: envelope.requestID, EdgeKeyID: envelope.edgeKeyID, Nonce: envelope.nonce,
		IssuedAt: time.Unix(issuedSeconds, 0).UTC(),
	}
	fs.decisionDigest = flagSetDigest(fs)
	return fs, nil
}

func supportsEntitlementIdentitySignature(signature string) bool {
	return strings.HasPrefix(strings.TrimSpace(signature), edgeSignatureVersionV2+"=")
}

// SignFlagHeaders produces the signed flag-delivery headers. Edge/runtime and
// tests use this; secret is an EDGE_AUTH secret, keyID its identifier. Map keys
// are marshalled in sorted order by encoding/json, so signing is deterministic.
func SignFlagHeaders(secret, keyID string, flags map[string]bool, budgets map[string]any, ts time.Time) (http.Header, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("edge_flags_secret_missing")
	}
	if keyID == "" {
		keyID = defaultEdgeKeyID
	}
	if flags == nil {
		flags = map[string]bool{}
	}
	if budgets == nil {
		budgets = map[string]any{}
	}
	flagsJSON, err := json.Marshal(flags)
	if err != nil {
		return nil, err
	}
	budgetsJSON, err := json.Marshal(budgets)
	if err != nil {
		return nil, err
	}
	timestamp := fmt.Sprintf("%d", ts.Unix())
	sig := signPayload(secret, flagsPayload(keyID, timestamp, string(flagsJSON), string(budgetsJSON)))

	h := http.Header{}
	h.Set(HeaderFlags, string(flagsJSON))
	h.Set(HeaderBudgets, string(budgetsJSON))
	h.Set(HeaderFlagsTimestamp, timestamp)
	h.Set(HeaderFlagsKeyID, keyID)
	h.Set(HeaderFlagsSignature, edgeSignatureVersion+"="+sig)
	return h, nil
}

// VerifyFlagHeaders verifies and parses the signed flag headers on r. It is
// fail-closed: any missing header, bad signature, or stale timestamp yields an
// error and an empty FlagSet. Reuses the EDGE_AUTH secrets/window from Config.
func VerifyFlagHeaders(r *http.Request, cfg Config) (FlagSet, error) {
	primary := strings.TrimSpace(firstNonEmpty(cfg.EdgeAuthSecret, os.Getenv("EDGE_AUTH_SECRET")))
	next := strings.TrimSpace(firstNonEmpty(cfg.EdgeAuthNextSecret, os.Getenv("EDGE_AUTH_SECRET_NEXT")))
	primaryKeyID := strings.TrimSpace(firstNonEmpty(cfg.EdgeAuthKeyID, os.Getenv("EDGE_AUTH_KEY_ID"), defaultEdgeKeyID))
	nextKeyID := strings.TrimSpace(firstNonEmpty(cfg.EdgeAuthNextKeyID, os.Getenv("EDGE_AUTH_KEY_ID_NEXT"), defaultEdgeNextKeyID))
	if primary == "" && next == "" {
		return FlagSet{}, fmt.Errorf("edge_flags_secret_missing")
	}

	flagsJSON := r.Header.Get(HeaderFlags)
	budgetsJSON := r.Header.Get(HeaderBudgets)
	timestamp := strings.TrimSpace(r.Header.Get(HeaderFlagsTimestamp))
	keyID := strings.TrimSpace(r.Header.Get(HeaderFlagsKeyID))
	signature := strings.TrimSpace(r.Header.Get(HeaderFlagsSignature))
	if flagsJSON == "" || timestamp == "" || keyID == "" || signature == "" {
		return FlagSet{}, fmt.Errorf("edge_flags_missing")
	}
	if budgetsJSON == "" {
		budgetsJSON = "{}"
	}
	if !strings.HasPrefix(signature, edgeSignatureVersion+"=") {
		return FlagSet{}, fmt.Errorf("edge_flags_signature_version_invalid")
	}
	if err := validateTimestamp(timestamp, cfg.SignatureWindow); err != nil {
		return FlagSet{}, err
	}

	presented := strings.TrimPrefix(signature, edgeSignatureVersion+"=")
	payload := flagsPayload(keyID, timestamp, flagsJSON, budgetsJSON)
	verified := false
	for _, candidate := range []struct{ keyID, secret string }{
		{primaryKeyID, primary},
		{nextKeyID, next},
	} {
		if candidate.secret == "" || keyID != candidate.keyID {
			continue
		}
		if hmac.Equal([]byte(presented), []byte(signPayload(candidate.secret, payload))) {
			verified = true
			break
		}
	}
	if !verified {
		return FlagSet{}, fmt.Errorf("edge_flags_signature_invalid")
	}

	fs := FlagSet{Flags: map[string]bool{}, Budgets: map[string]json.RawMessage{}}
	if err := json.Unmarshal([]byte(flagsJSON), &fs.Flags); err != nil {
		return FlagSet{}, fmt.Errorf("edge_flags_payload_invalid")
	}
	if err := json.Unmarshal([]byte(budgetsJSON), &fs.Budgets); err != nil {
		return FlagSet{}, fmt.Errorf("edge_budgets_payload_invalid")
	}
	return fs, nil
}
