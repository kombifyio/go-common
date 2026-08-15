package runtimeexecutor

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBackupTargetBindingIsCanonicalTargetScopedAndDigestBound(t *testing.T) {
	input := validRequest()
	input.BackupTargetBindings = []BackupTargetBinding{validBackupTargetBinding()}
	input.AuthorizationTime = "2026-07-21T11:00:00Z"
	input.RuntimeTargets[0].BackupTargetBindingRefs = []string{input.BackupTargetBindings[0].ID}
	input.RuntimeTargets[0].BackupTargetCapabilities = []AccessCapability{{
		Ref: "offsite-object-backup", ContractHash: input.BackupTargetBindings[0].CapabilityContractHash,
	}}

	sealed, err := SealRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := sealed.Validate(); err != nil {
		t.Fatal(err)
	}
	clone := CloneExecutionRequest(sealed)
	clone.BackupTargetBindings[0].TargetNodeRefs[0] = "changed"
	clone.RuntimeTargets[0].BackupTargetBindingRefs[0] = "changed"
	clone.RuntimeTargets[0].BackupTargetCapabilities[0].Ref = "changed"
	if sealed.BackupTargetBindings[0].TargetNodeRefs[0] == "changed" ||
		sealed.RuntimeTargets[0].BackupTargetBindingRefs[0] == "changed" ||
		sealed.RuntimeTargets[0].BackupTargetCapabilities[0].Ref == "changed" {
		t.Fatal("backup-target authority clone shares mutable storage")
	}

	tampered := CloneExecutionRequest(sealed)
	tampered.BackupTargetBindings[0].CustodyAttestationRef = "backup-custody-attestation://sha256/" + strings.Repeat("d", 64)
	if err := tampered.Validate(); err == nil {
		t.Fatal("request accepted a projection that no longer matches its canonical hash")
	}

	for name, mutate := range map[string]func(*ExecutionRequest){
		"unknown capability": func(request *ExecutionRequest) {
			request.BackupTargetBindings[0].CapabilityRef = "general-storage"
		},
		"cross Site": func(request *ExecutionRequest) {
			request.BackupTargetBindings[0].SiteRef = "site-other"
		},
		"cross node": func(request *ExecutionRequest) {
			request.BackupTargetBindings[0].TargetNodeRefs = []string{"node-other"}
		},
		"binding endpoint": func(request *ExecutionRequest) {
			request.BackupTargetBindings[0].BindingRef = "https://storage.example/binding"
		},
		"target endpoint": func(request *ExecutionRequest) {
			request.BackupTargetBindings[0].BackupTargetRef = "https://storage.example/bucket"
		},
		"credential custody": func(request *ExecutionRequest) {
			request.BackupTargetBindings[0].CustodyAttestationRef = "secret://backup/token"
		},
		"contract owner substitution": func(request *ExecutionRequest) {
			request.BackupTargetBindings[0].ContractOwnerRef = "provider-other"
		},
		"capability contract substitution": func(request *ExecutionRequest) {
			request.BackupTargetBindings[0].CapabilityContractHash = digest("other-capability")
		},
		"orphan binding": func(request *ExecutionRequest) {
			request.RuntimeTargets[0].BackupTargetBindingRefs = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := CloneExecutionRequest(sealed)
			mutate(&candidate)
			if _, err := SealRequest(candidate); err == nil {
				t.Fatal("invalid backup-target authority sealed")
			}
		})
	}
}

func TestInvokeAtRejectsExpiredBackupTargetBindingBeforeAdapter(t *testing.T) {
	input := validRequest()
	input.BackupTargetBindings = []BackupTargetBinding{validBackupTargetBinding()}
	input.AuthorizationTime = "2026-07-21T11:00:00Z"
	input.RuntimeTargets[0].BackupTargetBindingRefs = []string{input.BackupTargetBindings[0].ID}
	input.RuntimeTargets[0].BackupTargetCapabilities = []AccessCapability{{
		Ref: "offsite-object-backup", ContractHash: input.BackupTargetBindings[0].CapabilityContractHash,
	}}
	sealed, err := SealRequest(input)
	if err != nil {
		t.Fatal(err)
	}

	validExecutor := &mockExecutor{identity: sealed.Executor, outcome: exactOutcome(sealed)}
	if _, err := InvokeAt(t.Context(), validExecutor, sealed, mustAccessTime(t, "2026-07-21T11:00:00Z")); err != nil {
		t.Fatalf("fresh backup-target binding rejected: %v", err)
	}
	expired := CloneExecutionRequest(sealed)
	expired.AuthorizationTime = expired.BackupTargetBindings[0].ValidUntil
	expired, err = SealRequest(expired)
	if err != nil {
		t.Fatal(err)
	}
	executor := &mockExecutor{identity: expired.Executor, outcome: exactOutcome(expired)}
	if _, err := InvokeAt(t.Context(), executor, expired, mustAccessTime(t, expired.BackupTargetBindings[0].ValidUntil)); err == nil {
		t.Fatal("expired backup-target binding reached Invoke")
	}
	if executor.calls != 0 {
		t.Fatal("expired backup-target binding reached the adapter")
	}
}

func TestEmptyBackupTargetBindingProjectionPreservesWireShape(t *testing.T) {
	nilInput := validRequest()
	emptyInput := validRequest()
	emptyInput.BackupTargetBindings = []BackupTargetBinding{}
	emptyInput.RuntimeTargets[0].BackupTargetBindingRefs = []string{}
	emptyInput.RuntimeTargets[0].BackupTargetCapabilities = []AccessCapability{}
	nilSealed, err := SealRequest(nilInput)
	if err != nil {
		t.Fatal(err)
	}
	emptySealed, err := SealRequest(emptyInput)
	if err != nil {
		t.Fatal(err)
	}
	if nilSealed.RequestDigest != emptySealed.RequestDigest {
		t.Fatalf("nil and empty optional backup-target authority changed the request digest: %s != %s", nilSealed.RequestDigest, emptySealed.RequestDigest)
	}
	data, err := json.Marshal(emptySealed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "backup_target_bindings") || strings.Contains(string(data), "backup_target_binding_refs") {
		t.Fatalf("empty optional backup-target authority changed the v1beta1 wire shape: %s", data)
	}
}

func validBackupTargetBinding() BackupTargetBinding {
	return BackupTargetBinding{
		ID: "backup-target/site-a/offsite-object-backup", Kind: "backup-target",
		RuntimeRequirementID: "module-a/unit-a/instance-a", StackID: "stack-a", SiteRef: "site-a",
		CapabilityRef: "offsite-object-backup", ContractOwnerRef: "provider-a",
		CapabilityContractHash: digest("backup-target-contract"), TargetNodeRefs: []string{"node-a"},
		RequirementsHash:      digest("backup-target-requirement"),
		BindingRef:            "backup-target-binding://sha256/" + strings.Repeat("a", 64),
		BindingHash:           digest("backup-target-binding"),
		BackupTargetRef:       "backup-target://sha256/" + strings.Repeat("b", 64),
		CustodyAttestationRef: "backup-custody-attestation://sha256/" + strings.Repeat("c", 64),
		StackKitsVersion:      "v0.7.0-beta.1", CandidateDigest: digest("candidate"), SpecHash: digest("spec"),
		IssuedAt: "2026-07-21T10:00:00Z", ValidUntil: "2026-07-21T12:00:00Z",
	}
}
