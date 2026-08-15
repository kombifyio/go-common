// Package fga provides a fail-closed fine-grained authorization client for the
// kombify platform (ADR 0030). It is the Go twin of @kombify/fga (TypeScript)
// in kombify-Gateway/packages/fga — same API surface, same env-var contract.
//
// Backend: managed Auth0 FGA (prod) or self-hosted OpenFGA (CI/shadow).
// Legacy checks resolve errors to DENY. CheckStrict preserves dependency errors
// for HTTP boundaries that must distinguish a definitive deny from an outage,
// while DeleteTuplesIdempotent provides a write-authoritative revocation path.
//
// Self-hosted builds that have no FGA backend should use the build tag
// approach: in edition=selfhost the authorization decision falls back to
// Postgres RLS owner-checks, so the FGA wrapper is not called. Callers must
// guard with the appropriate edition flag before calling this package.
//
// Usage:
//
//	fgaClient, err := fga.FromEnv()
//	if err != nil {
//	    // FGA not configured — deny or fall back per edition rules.
//	}
//	allowed, err := fgaClient.CheckStrict(ctx, fga.UserPrincipal(sub), fga.CanRead, fga.DocumentObject(docID))
package fga

import (
	"context"
	"fmt"
	"os"

	openfga "github.com/openfga/go-sdk"
	"github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
)

// ensure openfga is referenced directly to avoid unused import after BatchCheck simplification
var _ = openfga.TupleKey{}

// --- Model vocabulary (mirrors kombify-Gateway/packages/fga/src/lib/index.ts) --

// Type constants match the FGA model types in kombify-Gateway/packages/fga/model.fga.
const (
	TypeUser        = "user"
	TypeAgentClass  = "agent_class"
	TypeOrg         = "org"
	TypeTeam        = "team"
	TypeTenant      = "tenant"
	TypeDocument    = "document"
	TypeChunk       = "chunk"
	TypeSurface     = "surface"
	TypeServer      = "server"
	TypeTool        = "tool"
	TypeEntitlement = "entitlement"
)

// Relation constants match the FGA model relations.
const (
	CanRead       = "can_read"
	CanCall       = "can_call"
	Viewer        = "viewer"
	Caller        = "caller"
	Member        = "member"
	ExcludedClass = "excluded_class"
	Accessor      = "accessor"
	Grantee       = "grantee"
	Has           = "has"
)

// Principal/object builders produce the type:id strings FGA expects.

func UserPrincipal(sub string) string           { return TypeUser + ":" + sub }
func AgentClassPrincipal(class string) string   { return TypeAgentClass + ":" + class }
func DocumentObject(id string) string           { return TypeDocument + ":" + id }
func ChunkObject(id string) string              { return TypeChunk + ":" + id }
func ToolObject(id string) string               { return TypeTool + ":" + id }
func EntitlementObject(lookupKey string) string { return TypeEntitlement + ":" + lookupKey }

// --- Config ----------------------------------------------------------------

// Config holds the FGA backend connection parameters.
type Config struct {
	APIURL               string
	StoreID              string
	AuthorizationModelID string
	// When set, the client uses Auth0 FGA client-credentials (managed prod).
	// When nil, it connects to a local/self-hosted OpenFGA instance without auth.
	Credentials *ClientCredentials
}

// ClientCredentials holds OAuth2 client-credentials for managed Auth0 FGA.
type ClientCredentials struct {
	ClientID       string
	ClientSecret   string
	APITokenIssuer string
	APIAudience    string
}

// ErrNotConfigured is returned by FromEnv when required env vars are absent.
var ErrNotConfigured = fmt.Errorf("fga: not configured (AUTH0_FGA_STORE_ID / FGA_STORE_ID missing)")

// FromEnv builds a KombifyFga client from environment variables.
// Supports both the the configured secret source ADR names (AUTH0_FGA_*) and the OpenFGA standard
// names (FGA_*) — mirrors fgaConfigFromEnv in @kombify/fga.
// Returns ErrNotConfigured when the mandatory fields are absent; callers must
// treat this as a DENY.
func FromEnv() (*KombifyFga, error) {
	cfg := configFromEnv()
	if cfg == nil {
		return nil, ErrNotConfigured
	}
	return FromConfig(cfg)
}

// FromConfig builds a KombifyFga client from an explicit Config.
func FromConfig(cfg *Config) (*KombifyFga, error) {
	fc := client.ClientConfiguration{
		ApiUrl:               cfg.APIURL,
		StoreId:              cfg.StoreID,
		AuthorizationModelId: cfg.AuthorizationModelID,
	}
	if cfg.Credentials != nil {
		fc.Credentials = &credentials.Credentials{
			Method: credentials.CredentialsMethodClientCredentials,
			Config: &credentials.Config{
				ClientCredentialsClientId:       cfg.Credentials.ClientID,
				ClientCredentialsClientSecret:   cfg.Credentials.ClientSecret,
				ClientCredentialsApiTokenIssuer: cfg.Credentials.APITokenIssuer,
				ClientCredentialsApiAudience:    cfg.Credentials.APIAudience,
			},
		}
	}
	c, err := client.NewSdkClient(&fc)
	if err != nil {
		return nil, fmt.Errorf("fga: create sdk client: %w", err)
	}
	return &KombifyFga{backend: c}, nil
}

func configFromEnv() *Config {
	apiURL := firstNonEmpty(os.Getenv("AUTH0_FGA_API_HOST"), os.Getenv("FGA_API_URL"))
	storeID := firstNonEmpty(os.Getenv("AUTH0_FGA_STORE_ID"), os.Getenv("FGA_STORE_ID"))
	if apiURL == "" || storeID == "" {
		return nil
	}
	cfg := &Config{
		APIURL:               apiURL,
		StoreID:              storeID,
		AuthorizationModelID: firstNonEmpty(os.Getenv("AUTH0_FGA_MODEL_ID"), os.Getenv("FGA_MODEL_ID")),
	}
	clientID := firstNonEmpty(os.Getenv("AUTH0_FGA_CLIENT_ID"), os.Getenv("FGA_CLIENT_ID"))
	secret := firstNonEmpty(os.Getenv("AUTH0_FGA_CLIENT_SECRET"), os.Getenv("FGA_CLIENT_SECRET"))
	if clientID != "" && secret != "" {
		cfg.Credentials = &ClientCredentials{
			ClientID:       clientID,
			ClientSecret:   secret,
			APITokenIssuer: firstNonEmpty(os.Getenv("AUTH0_FGA_API_TOKEN_ISSUER"), os.Getenv("FGA_API_TOKEN_ISSUER"), "auth.fga.dev"),
			APIAudience:    firstNonEmpty(os.Getenv("AUTH0_FGA_API_AUDIENCE"), os.Getenv("FGA_API_AUDIENCE")),
		}
	}
	return cfg
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// --- Client ----------------------------------------------------------------

// KombifyFga is the FGA client. Legacy Check methods collapse dependency errors
// to a false decision; strict methods preserve errors for application policy.
type KombifyFga struct {
	backend *client.OpenFgaClient
}

// CheckStrict performs one higher-consistency relationship check and preserves
// backend/transport failures. Higher consistency is intentional at an
// authorization boundary: a recently revoked tuple must not be served from the
// latency-optimized cache and mistaken for current authority.
func (f *KombifyFga) CheckStrict(ctx context.Context, user, relation, object string) (bool, error) {
	if f == nil || f.backend == nil {
		return false, fmt.Errorf("fga: relationship checker unavailable")
	}
	res, err := f.backend.Check(ctx).Options(client.ClientCheckOptions{
		Consistency: openfga.CONSISTENCYPREFERENCE_HIGHER_CONSISTENCY.Ptr(),
	}).Body(client.ClientCheckRequest{
		User:     user,
		Relation: relation,
		Object:   object,
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("fga: relationship check: %w", err)
	}
	if res == nil {
		return false, fmt.Errorf("fga: relationship check returned no decision")
	}
	return res.GetAllowed(), nil
}

// Check performs a single relationship check. It retains the original
// fail-closed compatibility contract: any strict-check error becomes a false
// decision with no error. New application boundaries should call CheckStrict.
func (f *KombifyFga) Check(ctx context.Context, user, relation, object string) (bool, error) {
	allowed, err := f.CheckStrict(ctx, user, relation, object)
	if err != nil {
		return false, nil //nolint:nilerr // compatibility fail-closed behavior
	}
	return allowed, nil
}

// BatchCheck checks one principal against many objects. Returns a map keyed by
// object → allowed. Uses individual Check calls since ClientBatchCheck is
// primarily correlation-id based. FAIL-CLOSED: any error → false for that object.
func (f *KombifyFga) BatchCheck(ctx context.Context, user, relation string, objects []string) (map[string]bool, error) {
	result := make(map[string]bool, len(objects))
	for _, o := range objects {
		allowed, _ := f.Check(ctx, user, relation, o)
		result[o] = allowed
	}
	return result, nil
}

// CheckObo performs an agent-on-behalf-of check: the agent is authorized only
// when BOTH the user principal AND the agent-class principal have the relation
// (intersection, not union). FAIL-CLOSED on any error.
func (f *KombifyFga) CheckObo(ctx context.Context, userSub, agentClass, relation, object string) (bool, error) {
	userOK, _ := f.Check(ctx, UserPrincipal(userSub), relation, object)
	if !userOK {
		return false, nil
	}
	agentOK, _ := f.Check(ctx, AgentClassPrincipal(agentClass), relation, object)
	return agentOK, nil
}

// BatchCheckObo performs OBO batch check. An object is allowed only if BOTH
// principals are allowed (intersection). FAIL-CLOSED on any error.
func (f *KombifyFga) BatchCheckObo(ctx context.Context, userSub, agentClass, relation string, objects []string) (map[string]bool, error) {
	userMap, _ := f.BatchCheck(ctx, UserPrincipal(userSub), relation, objects)
	agentMap, _ := f.BatchCheck(ctx, AgentClassPrincipal(agentClass), relation, objects)
	result := make(map[string]bool, len(objects))
	for _, o := range objects {
		result[o] = userMap[o] && agentMap[o]
	}
	return result, nil
}

// WriteTuples writes FGA relationship tuples (for use by the entitlement broker).
func (f *KombifyFga) WriteTuples(ctx context.Context, tuples []openfga.TupleKey) error {
	keys := make([]client.ClientTupleKey, len(tuples))
	for i, t := range tuples {
		keys[i] = client.ClientTupleKey{
			User:     t.GetUser(),
			Relation: t.GetRelation(),
			Object:   t.GetObject(),
		}
	}
	_, err := f.backend.WriteTuples(ctx).Body(keys).Execute()
	return err
}

// DeleteTuples removes FGA relationship tuples.
func (f *KombifyFga) DeleteTuples(ctx context.Context, tuples []openfga.TupleKeyWithoutCondition) error {
	return f.deleteTuples(ctx, tuples, client.CLIENT_WRITE_REQUEST_ON_MISSING_DELETES_ERROR)
}

// DeleteTuplesIdempotent removes relationship tuples with provider-native
// OnMissingDeletes=IGNORE semantics. Success is therefore an authoritative
// write result even when the tuple was already absent; consumers must not use a
// potentially stale read as an absence receipt.
func (f *KombifyFga) DeleteTuplesIdempotent(ctx context.Context, tuples []openfga.TupleKeyWithoutCondition) error {
	return f.deleteTuples(ctx, tuples, client.CLIENT_WRITE_REQUEST_ON_MISSING_DELETES_IGNORE)
}

func (f *KombifyFga) deleteTuples(ctx context.Context, tuples []openfga.TupleKeyWithoutCondition, onMissing client.ClientWriteRequestOnMissingDeletes) error {
	if f == nil || f.backend == nil {
		return fmt.Errorf("fga: relationship writer unavailable")
	}
	keys := make([]client.ClientTupleKeyWithoutCondition, len(tuples))
	for i, t := range tuples {
		keys[i] = client.ClientTupleKeyWithoutCondition{
			User:     t.GetUser(),
			Relation: t.GetRelation(),
			Object:   t.GetObject(),
		}
	}
	_, err := f.backend.DeleteTuples(ctx).Options(client.ClientWriteOptions{
		Conflict: client.ClientWriteConflictOptions{OnMissingDeletes: onMissing},
	}).Body(keys).Execute()
	return err
}
