package edgeauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// CloudRuntimeCreditsBudgetName is the Cloud-owned commercial capacity
	// decision delivered in the request-bound Edge decision envelope.
	CloudRuntimeCreditsBudgetName = "cloud.runtime.credits" // #nosec G101 -- public product budget name, not credential material.

	// ManagedServerCreditModeLimited carries a positive hard-accounting limit.
	ManagedServerCreditModeLimited ManagedServerCreditMode = "limited"
	// ManagedServerCreditModeUnlimited explicitly removes the managed-server
	// ceiling. Absence or zero never implies unlimited.
	ManagedServerCreditModeUnlimited ManagedServerCreditMode = "unlimited"

	maxManagedServerCreditLimit = 2147483647
)

var (
	ErrCloudRuntimeCreditsInvalid      = errors.New("edgeauth: cloud runtime credits invalid")
	ErrVerifiedDecisionAuthorityAbsent = errors.New("edgeauth: verified decision authority absent")
)

// ManagedServerCreditMode is the closed managed-server capacity mode.
type ManagedServerCreditMode string

// ManagedServerCredit is the validated managed-server portion of
// cloud.runtime.credits. Limit is zero only for explicit unlimited mode.
type ManagedServerCredit struct {
	Mode  ManagedServerCreditMode
	Limit int
}

// CloudRuntimeCredits is the closed Cloud-owned runtime budget projection.
type CloudRuntimeCredits struct {
	ManagedServers ManagedServerCredit
}

// VerifiedCloudRuntimeCredits atomically requires intact request-bound
// provenance, the canonical budget key, and the closed runtime-credit schema.
// Cost-bearing origins should use this accessor instead of reading Budgets
// directly.
func (f FlagSet) VerifiedCloudRuntimeCredits() (CloudRuntimeCredits, DecisionBinding, error) {
	raw, binding, ok := f.VerifiedBudget(CloudRuntimeCreditsBudgetName)
	if !ok {
		return CloudRuntimeCredits{}, DecisionBinding{}, ErrVerifiedDecisionAuthorityAbsent
	}
	credits, err := ParseCloudRuntimeCredits(raw)
	if err != nil {
		return CloudRuntimeCredits{}, DecisionBinding{}, err
	}
	return credits, binding, nil
}

type cloudRuntimeCreditsWire struct {
	ManagedServers json.RawMessage `json:"managed_servers"`
}

type managedServerCreditWire struct {
	Mode  string          `json:"mode"`
	Limit json.RawMessage `json:"limit,omitempty"`
}

// ParseCloudRuntimeCredits parses the only supported budget variants:
// {"managed_servers":{"mode":"limited","limit":N}} or
// {"managed_servers":{"mode":"unlimited"}}. Unknown fields, nulls,
// fractional/zero limits, and a limit on unlimited mode fail closed.
func ParseCloudRuntimeCredits(raw json.RawMessage) (CloudRuntimeCredits, error) {
	var outer cloudRuntimeCreditsWire
	if err := decodeClosedJSON(raw, &outer); err != nil {
		return CloudRuntimeCredits{}, fmt.Errorf("%w: %v", ErrCloudRuntimeCreditsInvalid, err)
	}
	managedRaw := bytes.TrimSpace(outer.ManagedServers)
	if len(managedRaw) == 0 || bytes.Equal(managedRaw, []byte("null")) {
		return CloudRuntimeCredits{}, fmt.Errorf("%w: managed_servers is required", ErrCloudRuntimeCreditsInvalid)
	}

	var managed managedServerCreditWire
	if err := decodeClosedJSON(managedRaw, &managed); err != nil {
		return CloudRuntimeCredits{}, fmt.Errorf("%w: managed_servers: %v", ErrCloudRuntimeCreditsInvalid, err)
	}
	mode := ManagedServerCreditMode(managed.Mode)
	switch mode {
	case ManagedServerCreditModeUnlimited:
		if len(bytes.TrimSpace(managed.Limit)) != 0 {
			return CloudRuntimeCredits{}, fmt.Errorf("%w: unlimited managed_servers cannot carry limit", ErrCloudRuntimeCreditsInvalid)
		}
		return CloudRuntimeCredits{ManagedServers: ManagedServerCredit{Mode: mode}}, nil
	case ManagedServerCreditModeLimited:
		limitRaw := bytes.TrimSpace(managed.Limit)
		if len(limitRaw) == 0 || bytes.Equal(limitRaw, []byte("null")) {
			return CloudRuntimeCredits{}, fmt.Errorf("%w: limited managed_servers requires limit", ErrCloudRuntimeCreditsInvalid)
		}
		var limit int
		if err := decodeClosedJSON(limitRaw, &limit); err != nil || limit <= 0 || limit > maxManagedServerCreditLimit {
			return CloudRuntimeCredits{}, fmt.Errorf("%w: limited managed_servers requires a supported positive integer", ErrCloudRuntimeCreditsInvalid)
		}
		return CloudRuntimeCredits{ManagedServers: ManagedServerCredit{Mode: mode, Limit: limit}}, nil
	default:
		return CloudRuntimeCredits{}, fmt.Errorf("%w: managed_servers mode is unsupported", ErrCloudRuntimeCreditsInvalid)
	}
}

func decodeClosedJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}
