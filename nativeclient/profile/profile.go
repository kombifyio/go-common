// Package profile implements the client side of the Kombify
// ClientConnectionProfile v1 contract: strict fail-closed parsing, validation,
// and discovery fetching of `GET /.well-known/kombify-client`.
//
// The wire contract is owned by
// kombify-Core/standards/client-connection-profile.v1.schema.json and
// CLIENT-CONNECTION-PROFILE-STANDARD.md; behavior rules come from
// NATIVE-CLIENT-PLATFORM-STANDARD.md section 3. This package carries no
// product-specific branches: every Kombify native client consumes it
// unchanged.
//
// Registry membership of capability identifiers is a server/workspace-side
// gate (client-capability-registry.v1.json); clients validate capability
// syntax only and never infer availability from unregistered names.
package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// WellKnownPath is the discovery route every Kombify server publishes.
const WellKnownPath = "/.well-known/kombify-client"

// Deployment modes of ClientConnectionProfile v1.
const (
	ModeCloud      = "cloud"
	ModeSelfHosted = "self_hosted"
	ModeLocal      = "local"
)

// Native auth flows advertised by ClientConnectionProfile v1.
const (
	FlowAuthorizationCodePKCE = "authorization_code_pkce"
	FlowDeviceAuthorization   = "device_authorization"
	FlowLocalBootstrap        = "local_bootstrap"
)

// Offline write policies of the sync block.
const (
	OfflineWriteDisabled = "disabled"
	OfflineWriteOutbox   = "outbox"
)

// Errors returned by this package.
var (
	// ErrInvalidProfile wraps every validation failure. The error text lists
	// each violated rule with its JSON location.
	ErrInvalidProfile = errors.New("profile: invalid client connection profile")
	// ErrFetchFailed wraps discovery transport failures.
	ErrFetchFailed = errors.New("profile: discovery fetch failed")
)

// Profile is the parsed ClientConnectionProfile v1 document.
type Profile struct {
	Version        string            `json:"version"`
	DeploymentMode string            `json:"deployment_mode"`
	BaseURL        string            `json:"base_url"`
	InstanceID     string            `json:"instance_id"`
	WorkspaceID    string            `json:"workspace_id,omitempty"`
	OIDC           OIDC              `json:"oidc"`
	Capabilities   []string          `json:"capabilities"`
	APIVersions    map[string]string `json:"api_versions"`
	Sync           Sync              `json:"sync"`
}

// OIDC is the public identity metadata block. It never carries secrets;
// client_id is public metadata by contract.
type OIDC struct {
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Audience string   `json:"audience,omitempty"`
	Scopes   []string `json:"scopes"`
	Flow     string   `json:"flow"`
}

// Sync is the offline/sync policy block.
type Sync struct {
	OfflineRead  bool   `json:"offline_read"`
	OfflineWrite string `json:"offline_write"`
	ETag         bool   `json:"etag"`
	Tombstones   bool   `json:"tombstones"`
}

// HasCapability reports whether the profile advertises the capability id.
// Capabilities describe availability, not authorization: protected actions
// still handle a fail-closed entitlement denial.
func (p *Profile) HasCapability(id string) bool {
	for _, c := range p.Capabilities {
		if c == id {
			return true
		}
	}
	return false
}

var (
	forbiddenKey        = regexp.MustCompile(`(?i)(?:secret|token|password|credential|private[-_]?key|api[-_]?key)`)
	identifierPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,127}$`)
	workspacePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	scopePattern        = regexp.MustCompile(`^[A-Za-z0-9:._/-]+$`)
	capabilityPattern   = regexp.MustCompile(`^[a-z][a-z0-9.-]*$`)
	versionValuePattern = regexp.MustCompile(`^v?[0-9]+(?:\.[0-9]+){0,2}(?:[-+][0-9A-Za-z.-]+)?$`)
)

var (
	allowedTopLevel = map[string]bool{
		"version": true, "deployment_mode": true, "base_url": true,
		"instance_id": true, "workspace_id": true, "oidc": true,
		"capabilities": true, "api_versions": true, "sync": true,
	}
	requiredTopLevel = []string{
		"version", "deployment_mode", "base_url", "instance_id",
		"oidc", "capabilities", "api_versions", "sync",
	}
	allowedOIDC = map[string]bool{
		"issuer": true, "client_id": true, "audience": true,
		"scopes": true, "flow": true,
	}
	syncRequiredKeys = []string{"offline_read", "offline_write", "etag", "tombstones"}
	// All sync keys except offline_write are booleans.
	syncBoolKeys = []string{syncRequiredKeys[0], syncRequiredKeys[2], syncRequiredKeys[3]}
	allowedSync  = keySet(syncRequiredKeys)
	validModes   = map[string]bool{ModeCloud: true, ModeSelfHosted: true, ModeLocal: true}
	validFlows   = map[string]bool{
		FlowAuthorizationCodePKCE: true,
		FlowDeviceAuthorization:   true,
		FlowLocalBootstrap:        true,
	}
)

func keySet(keys []string) map[string]bool {
	set := make(map[string]bool, len(keys))
	for _, key := range keys {
		set[key] = true
	}
	return set
}

// Parse validates raw against the full v1 contract and returns the typed
// profile. Validation is fail-closed: unknown fields anywhere, secret-bearing
// key names anywhere, insecure remote URLs, and mode/flow mismatches all
// reject the document.
func Parse(raw []byte) (*Profile, error) {
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("%w: not valid JSON: %v", ErrInvalidProfile, err)
	}
	root, ok := document.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: profile must be a JSON object", ErrInvalidProfile)
	}

	var violations []string
	rejectSecretKeys(document, "profile", &violations)
	rejectUnknownKeys(root, allowedTopLevel, "profile", &violations)
	for _, key := range requiredTopLevel {
		if _, present := root[key]; !present {
			violations = append(violations, "profile."+key+": required")
		}
	}

	mode, _ := root["deployment_mode"].(string)
	if version, _ := root["version"].(string); version != "1" {
		violations = append(violations, `profile.version: must equal "1"`)
	}
	if !validModes[mode] {
		violations = append(violations, "profile.deployment_mode: unsupported mode")
	}
	validateEndpoint(root["base_url"], "profile.base_url", mode, &violations)
	if id, _ := root["instance_id"].(string); !identifierPattern.MatchString(id) {
		violations = append(violations, "profile.instance_id: invalid stable identifier")
	}
	if workspace, present := root["workspace_id"]; present {
		if s, ok := workspace.(string); !ok || !workspacePattern.MatchString(s) {
			violations = append(violations, "profile.workspace_id: invalid identifier")
		}
	}
	validateOIDC(root["oidc"], mode, &violations)
	validateCapabilities(root["capabilities"], &violations)
	validateAPIVersions(root["api_versions"], &violations)
	validateSync(root["sync"], &violations)

	if len(violations) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalidProfile, strings.Join(violations, "; "))
	}

	parsed := &Profile{}
	if err := json.Unmarshal(raw, parsed); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProfile, err)
	}
	return parsed, nil
}

func validateOIDC(value any, mode string, violations *[]string) {
	oidc, ok := value.(map[string]any)
	if !ok {
		*violations = append(*violations, "profile.oidc: must be an object")
		return
	}
	rejectUnknownKeys(oidc, allowedOIDC, "profile.oidc", violations)
	for _, key := range []string{"issuer", "client_id", "scopes", "flow"} {
		if _, present := oidc[key]; !present {
			*violations = append(*violations, "profile.oidc."+key+": required")
		}
	}
	validateEndpoint(oidc["issuer"], "profile.oidc.issuer", mode, violations)
	if clientID, _ := oidc["client_id"].(string); clientID == "" || len(clientID) > 256 {
		*violations = append(*violations, "profile.oidc.client_id: required public client identifier")
	}
	if audience, present := oidc["audience"]; present {
		if s, ok := audience.(string); !ok || s == "" || len(s) > 512 {
			*violations = append(*violations, "profile.oidc.audience: invalid public audience")
		}
	}
	validateScopes(oidc["scopes"], violations)
	validateFlow(oidc["flow"], mode, violations)
}

// validateFlow enforces the mode/flow matrix of section 3/4.
func validateFlow(value any, mode string, violations *[]string) {
	flow, _ := value.(string)
	if !validFlows[flow] {
		*violations = append(*violations, "profile.oidc.flow: unsupported flow")
	}
	if mode == ModeCloud && flow != FlowAuthorizationCodePKCE {
		*violations = append(*violations, "profile.oidc.flow: cloud requires authorization_code_pkce")
	}
	if mode == ModeSelfHosted && flow != FlowAuthorizationCodePKCE && flow != FlowDeviceAuthorization {
		*violations = append(*violations, "profile.oidc.flow: self_hosted requires PKCE or device authorization")
	}
}

func validateScopes(value any, violations *[]string) {
	scopes, ok := value.([]any)
	if !ok || len(scopes) == 0 {
		*violations = append(*violations, "profile.oidc.scopes: at least one scope is required")
		return
	}
	seen := map[string]bool{}
	for _, entry := range scopes {
		scope, ok := entry.(string)
		if !ok || !scopePattern.MatchString(scope) {
			*violations = append(*violations, "profile.oidc.scopes: invalid scope value")
			return
		}
		if seen[scope] {
			*violations = append(*violations, "profile.oidc.scopes: duplicate scope")
			return
		}
		seen[scope] = true
	}
}

func validateCapabilities(value any, violations *[]string) {
	capabilities, ok := value.([]any)
	if !ok {
		*violations = append(*violations, "profile.capabilities: must be an array")
		return
	}
	seen := map[string]bool{}
	for index, entry := range capabilities {
		capability, ok := entry.(string)
		if !ok || !capabilityPattern.MatchString(capability) {
			*violations = append(*violations, fmt.Sprintf("profile.capabilities[%d]: invalid capability identifier", index))
			continue
		}
		if seen[capability] {
			*violations = append(*violations, "profile.capabilities: duplicates are forbidden")
			return
		}
		seen[capability] = true
	}
}

func validateAPIVersions(value any, violations *[]string) {
	versions, ok := value.(map[string]any)
	if !ok || len(versions) == 0 {
		*violations = append(*violations, "profile.api_versions: at least one API version is required")
		return
	}
	for name, version := range versions {
		if !capabilityPattern.MatchString(name) {
			*violations = append(*violations, "profile.api_versions."+name+": invalid API identifier")
		}
		if s, ok := version.(string); !ok || !versionValuePattern.MatchString(s) {
			*violations = append(*violations, "profile.api_versions."+name+": invalid version")
		}
	}
}

func validateSync(value any, violations *[]string) {
	sync, ok := value.(map[string]any)
	if !ok {
		*violations = append(*violations, "profile.sync: must be an object")
		return
	}
	rejectUnknownKeys(sync, allowedSync, "profile.sync", violations)
	for _, key := range syncRequiredKeys {
		if _, present := sync[key]; !present {
			*violations = append(*violations, "profile.sync."+key+": required")
		}
	}
	for _, key := range syncBoolKeys {
		if value, present := sync[key]; present {
			if _, ok := value.(bool); !ok {
				*violations = append(*violations, "profile.sync."+key+": must be boolean")
			}
		}
	}
	if write, _ := sync["offline_write"].(string); write != OfflineWriteDisabled && write != OfflineWriteOutbox {
		*violations = append(*violations, "profile.sync.offline_write: must be disabled or outbox")
	}
}

var loopbackHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "[::1]": true, "::1": true}

func validateEndpoint(value any, location, mode string, violations *[]string) {
	raw, ok := value.(string)
	if !ok || raw == "" {
		*violations = append(*violations, location+": must be a non-empty URL")
		return
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		*violations = append(*violations, location+": invalid URL")
		return
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		*violations = append(*violations, location+": user-info, query, and fragment are forbidden")
	}
	secure := parsed.Scheme == "https"
	localLoopback := mode == ModeLocal && parsed.Scheme == "http" && loopbackHosts[parsed.Hostname()]
	if !secure && !localLoopback {
		*violations = append(*violations, location+": HTTPS is required except for local loopback HTTP")
	}
}

func rejectUnknownKeys(object map[string]any, allowed map[string]bool, location string, violations *[]string) {
	for key := range object {
		if !allowed[key] {
			*violations = append(*violations, location+"."+key+": unknown field")
		}
	}
}

func rejectSecretKeys(value any, location string, violations *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if forbiddenKey.MatchString(key) {
				*violations = append(*violations, location+"."+key+": secret-bearing field is forbidden")
			}
			rejectSecretKeys(nested, location+"."+key, violations)
		}
	case []any:
		for index, nested := range typed {
			rejectSecretKeys(nested, fmt.Sprintf("%s[%d]", location, index), violations)
		}
	}
}

// Fetch retrieves and validates the connection profile from
// `<baseURL>/.well-known/kombify-client`. A nil client defaults to a 10 s
// timeout. The response is limited to 1 MiB.
func Fetch(ctx context.Context, baseURL string, client *http.Client) (*Profile, error) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("%w: base URL is required", ErrFetchFailed)
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+WellKnownPath, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status %d", ErrFetchFailed, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}
	return Parse(body)
}
