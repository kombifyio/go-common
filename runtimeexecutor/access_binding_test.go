package runtimeexecutor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAccessBindingIsCanonicalTargetScopedAndDigestBound(t *testing.T) {
	input := validRequest()
	input.AccessBindings = []AccessBinding{validHomeAccessBinding()}
	input.AuthorizationTime = "2026-07-21T11:00:00Z"
	input.RuntimeTargets[0].AccessBindingRefs = []string{"home-access/site-a/private-remote-access"}
	input.RuntimeTargets[0].AccessCapabilities = []AccessCapability{{Ref: "private-remote-access", ContractHash: digest("home-access-contract")}}

	sealed, err := SealRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := sealed.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(sealed.AccessBindings) != 1 || sealed.AccessBindings[0].ID != sealed.RuntimeTargets[0].AccessBindingRefs[0] {
		t.Fatalf("access authority was not retained exactly: %#v", sealed)
	}
	clone := CloneExecutionRequest(sealed)
	clone.AccessBindings[0].TargetNodeRefs[0] = "changed"
	clone.RuntimeTargets[0].AccessBindingRefs[0] = "changed"
	clone.RuntimeTargets[0].AccessCapabilities[0].Ref = "changed"
	if sealed.AccessBindings[0].TargetNodeRefs[0] == "changed" || sealed.RuntimeTargets[0].AccessBindingRefs[0] == "changed" || sealed.RuntimeTargets[0].AccessCapabilities[0].Ref == "changed" {
		t.Fatal("access authority clone shares mutable storage")
	}

	changed := CloneExecutionRequest(sealed)
	changed.AccessBindings[0].RequirementsHash = digest("other-requirement")
	resealed, err := SealRequest(changed)
	if err != nil {
		t.Fatal(err)
	}
	if resealed.RequestDigest == sealed.RequestDigest {
		t.Fatal("access binding substitution did not change the sealed request digest")
	}
	tamperedProjection := CloneExecutionRequest(sealed)
	tamperedProjection.AccessBindings[0].BindingHash = digest("tampered-upstream-binding")
	if err := tamperedProjection.Validate(); err == nil {
		t.Fatal("request accepted fields that no longer match the canonical projection hash")
	}

	for name, mutate := range map[string]func(*ExecutionRequest){
		"unknown capability": func(request *ExecutionRequest) {
			request.AccessBindings[0].CapabilityRef = "general-lan"
		},
		"cross Site": func(request *ExecutionRequest) {
			request.AccessBindings[0].SiteRef = "site-other"
		},
		"cross node": func(request *ExecutionRequest) {
			request.AccessBindings[0].TargetNodeRefs = []string{"node-other"}
		},
		"binding endpoint": func(request *ExecutionRequest) {
			request.AccessBindings[0].BindingRef = "https://home.example/access"
		},
		"fabric endpoint": func(request *ExecutionRequest) {
			request.AccessBindings[0].AccessFabricRef = "https://home.example/fabric"
		},
		"secret owner": func(request *ExecutionRequest) {
			request.AccessBindings[0].ContractOwnerRef = "secret://access/token"
		},
		"contract owner substitution": func(request *ExecutionRequest) {
			request.AccessBindings[0].ContractOwnerRef = "provider-other"
		},
		"capability contract substitution": func(request *ExecutionRequest) {
			request.AccessBindings[0].CapabilityContractHash = digest("other-capability")
		},
		"invalid version": func(request *ExecutionRequest) {
			request.AccessBindings[0].StackKitsVersion = "latest"
		},
		"reversed validity": func(request *ExecutionRequest) {
			request.AccessBindings[0].ValidUntil = request.AccessBindings[0].IssuedAt
		},
		"excess validity": func(request *ExecutionRequest) {
			request.AccessBindings[0].ValidUntil = "2026-07-23T10:00:00Z"
		},
		"noncanonical timestamp": func(request *ExecutionRequest) {
			request.AccessBindings[0].IssuedAt = "2026-07-21T10:00:00+00:00"
		},
		"orphan binding": func(request *ExecutionRequest) {
			request.RuntimeTargets[0].AccessBindingRefs = nil
		},
		"unknown binding ref": func(request *ExecutionRequest) {
			request.RuntimeTargets[0].AccessBindingRefs[0] = "home-access/site-a/absent"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := CloneExecutionRequest(sealed)
			mutate(&candidate)
			if _, err := SealRequest(candidate); err == nil {
				t.Fatal("invalid access authority sealed")
			}
		})
	}

	duplicate := CloneExecutionRequest(sealed)
	duplicate.AccessBindings = append(duplicate.AccessBindings, duplicate.AccessBindings[0])
	if _, err := SealRequest(duplicate); err == nil {
		t.Fatal("duplicate access authority sealed")
	}
	multiplyReferenced := CloneExecutionRequest(sealed)
	multiplyReferenced.RuntimeTargets[1].AccessBindingRefs = []string{multiplyReferenced.AccessBindings[0].ID}
	if _, err := SealRequest(multiplyReferenced); err == nil {
		t.Fatal("access authority referenced by multiple runtime targets")
	}

	multiSite := CloneExecutionRequest(sealed)
	multiSite.RuntimeTargets[0].SiteRefs = []string{"site-a", "site-b"}
	multiSite.RuntimeTargets[0].NodeRefs = []string{"node-a", "node-b"}
	second := multiSite.AccessBindings[0]
	second.ID = "home-access/site-b/private-remote-access"
	second.SiteRef = "site-b"
	second.TargetNodeRefs = []string{"node-b"}
	second.BindingRef = "home-access-binding://sha256/" + strings.Repeat("c", 64)
	second.BindingHash = digest("home-access-binding-site-b")
	second.AccessFabricRef = "home-access-fabric://sha256/" + strings.Repeat("d", 64)
	second.ProjectionHash = ""
	multiSite.AccessBindings = append(multiSite.AccessBindings, second)
	multiSite.RuntimeTargets[0].AccessBindingRefs = append(multiSite.RuntimeTargets[0].AccessBindingRefs, second.ID)
	if _, err := SealRequest(multiSite); err == nil {
		t.Fatal("multi-Site access target sealed without explicit node-to-Site authority")
	}
}

func TestInvokeAtRejectsExpiredAccessBindingImmediatelyBeforeAdapter(t *testing.T) {
	input := validRequest()
	input.AccessBindings = []AccessBinding{validHomeAccessBinding()}
	input.AuthorizationTime = "2026-07-21T11:00:00Z"
	input.RuntimeTargets[0].AccessBindingRefs = []string{input.AccessBindings[0].ID}
	input.RuntimeTargets[0].AccessCapabilities = []AccessCapability{{Ref: "private-remote-access", ContractHash: input.AccessBindings[0].CapabilityContractHash}}
	sealed, err := SealRequest(input)
	if err != nil {
		t.Fatal(err)
	}

	validExecutor := &mockExecutor{identity: sealed.Executor, outcome: exactOutcome(sealed)}
	if _, err := InvokeAt(t.Context(), validExecutor, sealed, mustAccessTime(t, "2026-07-21T11:00:00Z")); err != nil {
		t.Fatalf("fresh access binding rejected: %v", err)
	}
	expiredRequest := CloneExecutionRequest(sealed)
	expiredRequest.AuthorizationTime = expiredRequest.AccessBindings[0].ValidUntil
	expiredRequest, err = SealRequest(expiredRequest)
	if err != nil {
		t.Fatal(err)
	}
	expiredExecutor := &mockExecutor{identity: expiredRequest.Executor, outcome: exactOutcome(expiredRequest)}
	if _, err := InvokeAt(t.Context(), expiredExecutor, expiredRequest, mustAccessTime(t, expiredRequest.AccessBindings[0].ValidUntil)); err == nil {
		t.Fatal("expired access binding reached Invoke")
	}
	if expiredExecutor.calls != 0 {
		t.Fatal("expired access binding reached the adapter")
	}
}

func TestEmptyAccessBindingProjectionPreservesWireShape(t *testing.T) {
	nilInput := validRequest()
	emptyInput := validRequest()
	emptyInput.AccessBindings = []AccessBinding{}
	emptyInput.RuntimeTargets[0].AccessBindingRefs = []string{}
	emptyInput.RuntimeTargets[0].AccessCapabilities = []AccessCapability{}
	nilSealed, err := SealRequest(nilInput)
	if err != nil {
		t.Fatal(err)
	}
	emptySealed, err := SealRequest(emptyInput)
	if err != nil {
		t.Fatal(err)
	}
	if nilSealed.RequestDigest != emptySealed.RequestDigest {
		t.Fatalf("nil and empty optional access authority changed the canonical request digest: %s != %s", nilSealed.RequestDigest, emptySealed.RequestDigest)
	}
	data, err := json.Marshal(emptySealed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "access_bindings") || strings.Contains(string(data), "access_binding_refs") {
		t.Fatalf("empty optional access authority changed the v1beta1 wire shape: %s", data)
	}
}

func validHomeAccessBinding() AccessBinding {
	return AccessBinding{
		ID: "home-access/site-a/private-remote-access", Kind: "home-access",
		RuntimeRequirementID: "module-a/unit-a/instance-a", StackID: "stack-a", SiteRef: "site-a",
		CapabilityRef: "private-remote-access", ContractOwnerRef: "provider-a",
		CapabilityContractHash: digest("home-access-contract"), TargetNodeRefs: []string{"node-a"},
		RequirementsHash: digest("home-access-requirement"),
		BindingRef:       "home-access-binding://sha256/" + strings.Repeat("a", 64),
		BindingHash:      digest("home-access-binding"),
		AccessFabricRef:  "home-access-fabric://sha256/" + strings.Repeat("b", 64),
		StackKitsVersion: "v0.7.0-beta.1", CandidateDigest: digest("candidate"), SpecHash: digest("spec"),
		IssuedAt: "2026-07-21T10:00:00Z", ValidUntil: "2026-07-21T12:00:00Z",
	}
}

func mustAccessTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
