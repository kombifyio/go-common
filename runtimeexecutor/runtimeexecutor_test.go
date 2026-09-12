package runtimeexecutor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestSealValidateCloneAndHash(t *testing.T) {
	input := validRequest()
	input.RuntimeTargets[0].SiteRefs = []string{"site-b", "site-a"}
	input.RuntimeTargets[0].NodeRefs = []string{"node-b", "node-a"}
	input.RuntimeTargets[0].ArtifactRefs = []string{"env", "compose"}
	input.HealthTargets[0].NodeRefs = []string{"node-b", "node-a"}
	for index := 0; index < 2; index++ {
		input.Artifacts[index].SiteRefs = []string{"site-b", "site-a"}
		input.Artifacts[index].NodeRefs = []string{"node-b", "node-a"}
	}
	sealed, err := SealRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := sealed.Validate(); err != nil {
		t.Fatal(err)
	}
	if sealed.APIVersion != APIVersion || sealed.RequestDigest == "" || sealed.ArtifactSetHash == "" {
		t.Fatalf("incomplete sealed request: %#v", sealed)
	}
	if sealed.RuntimeTargets[0].SiteRefs[0] != "site-a" || sealed.RuntimeTargets[0].NodeRefs[0] != "node-a" ||
		sealed.RuntimeTargets[0].ArtifactRefs[0] != "compose" || sealed.Artifacts[0].NodeRefs[0] != "node-a" ||
		input.RuntimeTargets[0].NodeRefs[0] != "node-b" {
		t.Fatal("SealRequest did not canonicalize defensively")
	}

	reversed := cloneArtifacts(sealed.Artifacts)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	hash, err := ComputeArtifactSetHash(reversed)
	if err != nil || hash != sealed.ArtifactSetHash {
		t.Fatalf("canonical artifact hash = %q, %v", hash, err)
	}

	clone := CloneExecutionRequest(sealed)
	clone.RuntimeTargets[0].SiteRefs[0] = "changed"
	clone.RuntimeTargets[0].NodeRefs[0] = "changed"
	clone.RuntimeTargets[0].DaemonBindings[0].Engine = "changed"
	clone.RuntimeTargets[0].ArtifactRefs[0] = "changed"
	clone.RuntimeTargets[0].AccessBindingRefs = []string{"changed"}
	clone.HealthTargets[0].SiteRefs[0] = "changed"
	clone.Artifacts[0].NodeRefs[0] = "changed"
	clone.Artifacts[0].Content[0] ^= 0xff
	if sealed.RuntimeTargets[0].SiteRefs[0] == "changed" || sealed.RuntimeTargets[0].NodeRefs[0] == "changed" ||
		sealed.RuntimeTargets[0].DaemonBindings[0].Engine == "changed" || sealed.RuntimeTargets[0].ArtifactRefs[0] == "changed" ||
		sealed.HealthTargets[0].SiteRefs[0] == "changed" || sealed.Artifacts[0].NodeRefs[0] == "changed" ||
		bytes.Equal(clone.Artifacts[0].Content, sealed.Artifacts[0].Content) {
		t.Fatal("CloneExecutionRequest shares mutable storage")
	}

	for name, mutate := range map[string]func(*ExecutionRequest){
		"plan substitution":     func(request *ExecutionRequest) { request.PlanHash = digest("other-plan") },
		"artifact substitution": func(request *ExecutionRequest) { request.Artifacts[0].Content[0] ^= 0xff },
		"target substitution":   func(request *ExecutionRequest) { request.RuntimeTargets[0].OwnerContractHash = digest("other-owner") },
		"execution channel substitution": func(request *ExecutionRequest) {
			request.RuntimeTargets[0].ExecutionChannelRef = "channel-other"
		},
		"module owner version": func(request *ExecutionRequest) {
			request.RuntimeTargets[0].OwnerVersion = "forbidden-version"
		},
		"provider owner version missing": func(request *ExecutionRequest) {
			request.RuntimeTargets[1].OwnerVersion = ""
		},
		"site substitution":     func(request *ExecutionRequest) { request.RuntimeTargets[0].SiteRefs[0] = "other-site" },
		"workload substitution": func(request *ExecutionRequest) { request.RuntimeTargets[0].WorkloadRef = "other-workload" },
		"image substitution": func(request *ExecutionRequest) {
			request.RuntimeTargets[0].ImageRef = "registry.example/other@sha256:" + strings.Repeat("a", 64)
		},
		"image digest substitution": func(request *ExecutionRequest) {
			request.RuntimeTargets[0].ImageDigest = digest("other-image")
		},
		"daemon substitution": func(request *ExecutionRequest) {
			request.RuntimeTargets[0].DaemonBindings[0].SocketPath = "/run/other.sock"
		},
		"artifact ref substitution":  func(request *ExecutionRequest) { request.RuntimeTargets[0].ArtifactRefs[0] = "other-artifact" },
		"health route substitution":  func(request *ExecutionRequest) { request.HealthTargets[0].RouteRef = "other-route" },
		"health source substitution": func(request *ExecutionRequest) { request.HealthTargets[0].SourceRef = "other-health" },
		"artifact owner substitution": func(request *ExecutionRequest) {
			request.Artifacts[0].OwnerContractHash = digest("other-artifact-owner")
		},
		"noncanonical digest": func(request *ExecutionRequest) {
			request.ManifestHash = "sha256:" + "A" + request.ManifestHash[len("sha256:A"):]
		},
		"secret-like ref": func(request *ExecutionRequest) { request.RuntimeTargets[0].ProviderRef = "secret://provider/token" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := CloneExecutionRequest(sealed)
			mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("substituted request validated")
			}
		})
	}

	badArtifacts := cloneArtifacts(sealed.Artifacts)
	badArtifacts = append(badArtifacts, badArtifacts[0])
	if _, err := ComputeArtifactSetHash(badArtifacts); err == nil {
		t.Fatal("duplicate artifacts hashed")
	}
	remappedArtifacts := cloneArtifacts(sealed.Artifacts)
	remappedArtifacts[0].OwnerContractHash = digest("remapped-owner")
	remappedHash, err := ComputeArtifactSetHash(remappedArtifacts)
	if err != nil || remappedHash == sealed.ArtifactSetHash {
		t.Fatalf("artifact owner mapping was not hash-bound: %q, %v", remappedHash, err)
	}
	badHierarchy := CloneExecutionRequest(sealed)
	badHierarchy.Artifacts[0].ModuleRef, badHierarchy.Artifacts[0].ModuleContractHash = "", ""
	if _, err := SealRequest(badHierarchy); err == nil {
		t.Fatal("artifact instance without module/unit authority sealed")
	}
	badSocket := CloneExecutionRequest(sealed)
	badSocket.RuntimeTargets[0].DaemonBindings[0].SocketPath = "/run/../credential.sock"
	if _, err := SealRequest(badSocket); err == nil {
		t.Fatal("noncanonical daemon socket sealed")
	}
	unknownArtifact := CloneExecutionRequest(sealed)
	unknownArtifact.RuntimeTargets[0].ArtifactRefs[0] = "absent-artifact"
	if _, err := SealRequest(unknownArtifact); err == nil {
		t.Fatal("unknown runtime artifact ref sealed")
	}
	duplicateDaemon := CloneExecutionRequest(sealed)
	duplicateDaemon.RuntimeTargets[0].DaemonBindings = append(duplicateDaemon.RuntimeTargets[0].DaemonBindings, duplicateDaemon.RuntimeTargets[0].DaemonBindings[0])
	if _, err := SealRequest(duplicateDaemon); err == nil {
		t.Fatal("duplicate daemon binding sealed")
	}
	wrongDaemonEngine := CloneExecutionRequest(sealed)
	wrongDaemonEngine.RuntimeTargets[0].DaemonBindings[0].Engine = "containerd"
	if _, err := SealRequest(wrongDaemonEngine); err == nil {
		t.Fatal("daemon engine substitution sealed")
	}
	orphanArtifact := CloneExecutionRequest(sealed)
	orphanArtifact.RuntimeTargets[0].ArtifactRefs = []string{"compose"}
	if _, err := SealRequest(orphanArtifact); err == nil {
		t.Fatal("orphan render-instance artifact sealed")
	}
	duplicateReference := CloneExecutionRequest(sealed)
	duplicateTarget := duplicateReference.RuntimeTargets[0]
	duplicateTarget.RequirementID = "module-a/unit-a/instance-a-duplicate"
	duplicateTarget.ArtifactRefs = []string{"compose"}
	duplicateReference.RuntimeTargets = append(duplicateReference.RuntimeTargets, duplicateTarget)
	if _, err := SealRequest(duplicateReference); err == nil {
		t.Fatal("multiply referenced render-instance artifact sealed")
	}
	ownerSubstitution := CloneExecutionRequest(sealed)
	ownerSubstitution.Artifacts[0].SiteRefs = []string{"other-site"}
	if _, err := SealRequest(ownerSubstitution); err == nil {
		t.Fatal("artifact placement substitution sealed")
	}
	planArtifactReference := CloneExecutionRequest(sealed)
	planArtifactReference.RuntimeTargets[0].ArtifactRefs = append(planArtifactReference.RuntimeTargets[0].ArtifactRefs, "plan-metadata")
	if _, err := SealRequest(planArtifactReference); err == nil {
		t.Fatal("plan-owned artifact runtime reference sealed")
	}
	wrongRenderOwner := CloneExecutionRequest(sealed)
	wrongRenderOwner.Artifacts[0].OwnerRef = wrongRenderOwner.RuntimeTargets[0].OwnerRef
	if _, err := SealRequest(wrongRenderOwner); err == nil {
		t.Fatal("module owner substituted for render-instance owner")
	}
	planRuntimeAuthority := CloneExecutionRequest(sealed)
	planRuntimeAuthority.Artifacts[2].OutputRef = "forbidden-runtime-output"
	if _, err := SealRequest(planRuntimeAuthority); err == nil {
		t.Fatal("plan-owned artifact with runtime output authority sealed")
	}
	planOwnerSubstitution := CloneExecutionRequest(sealed)
	planOwnerSubstitution.Artifacts[2].OwnerRef = digest("other-plan")
	if _, err := SealRequest(planOwnerSubstitution); err == nil {
		t.Fatal("plan-owned artifact with substituted owner digest sealed")
	}
	foundProviderOwnerWithoutArtifacts := false
	for _, target := range sealed.RuntimeTargets {
		if target.OwnerKind == "provider-owner" && len(target.ArtifactRefs) == 0 {
			foundProviderOwnerWithoutArtifacts = true
		}
	}
	if !foundProviderOwnerWithoutArtifacts {
		t.Fatal("non-rendering provider-owner without artifacts was not retained")
	}
}

func TestInvokeExactOutcomeCancellationPanicAndCopies(t *testing.T) {
	request, err := SealRequest(validRequest())
	if err != nil {
		t.Fatal(err)
	}
	executor := &mockExecutor{identity: request.Executor, mutateRequest: true, outcome: exactOutcome(request)}
	result, err := Invoke(context.Background(), executor, request)
	if err != nil {
		t.Fatal(err)
	}
	if executor.calls != 1 || result.ResultDigest == "" || result.RequestDigest != request.RequestDigest {
		t.Fatalf("calls/result = %d / %#v", executor.calls, result)
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	if request.Artifacts[0].Content[0] == executor.request.Artifacts[0].Content[0] {
		t.Fatal("test executor did not mutate its private request copy")
	}
	resultClone := CloneExecutionResult(result)
	resultClone.Runtime[0].InstanceRef = "changed"
	if result.Runtime[0].InstanceRef == "changed" {
		t.Fatal("CloneExecutionResult shares mutable storage")
	}
	outcomeClone := CloneExecutionOutcome(executor.outcome)
	outcomeClone.Runtime[0].InstanceRef = "changed"
	if executor.outcome.Runtime[0].InstanceRef == "changed" {
		t.Fatal("CloneExecutionOutcome shares mutable storage")
	}

	for name, outcome := range map[string]ExecutionOutcome{
		"missing": {Health: exactOutcome(request).Health},
		"extra": func() ExecutionOutcome {
			value := exactOutcome(request)
			value.Runtime = append(value.Runtime, value.Runtime[0])
			return value
		}(),
		"duplicate": func() ExecutionOutcome {
			value := exactOutcome(request)
			value.Runtime = append(value.Runtime, value.Runtime[0])
			return value
		}(),
		"substitution": func() ExecutionOutcome {
			value := exactOutcome(request)
			value.Runtime[0].InstanceRef = "other-instance"
			return value
		}(),
		"secret observation": func() ExecutionOutcome {
			value := exactOutcome(request)
			value.Runtime[0].ObservationRef = "secret://executor/token"
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			adapter := &mockExecutor{identity: request.Executor, outcome: outcome}
			_, err := Invoke(context.Background(), adapter, request)
			if err == nil {
				t.Fatal("invalid outcome accepted")
			}
		})
	}

	wrongIdentity := &mockExecutor{identity: ExecutorIdentity{ID: "other", Version: "v1", Digest: digest("other")}, outcome: exactOutcome(request)}
	if _, err := Invoke(context.Background(), wrongIdentity, request); codeOf(err) != ErrorIdentityMismatch {
		t.Fatalf("identity mismatch error = %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	preCancelled := &mockExecutor{identity: request.Executor, outcome: exactOutcome(request)}
	if _, err := Invoke(canceled, preCancelled, request); codeOf(err) != ErrorCancelled || !errors.Is(err, context.Canceled) || preCancelled.calls != 0 {
		t.Fatalf("pre-cancel = %v, calls=%d", err, preCancelled.calls)
	}

	during, cancelDuring := context.WithCancel(context.Background())
	duringExecutor := &mockExecutor{identity: request.Executor, outcome: exactOutcome(request), onExecute: cancelDuring}
	if _, err := Invoke(during, duringExecutor, request); codeOf(err) != ErrorCancelled || duringExecutor.calls != 1 {
		t.Fatalf("during-cancel = %v, calls=%d", err, duringExecutor.calls)
	}

	panicExecutor := &mockExecutor{identity: request.Executor, panicExecute: true}
	if _, err := Invoke(context.Background(), panicExecutor, request); codeOf(err) != ErrorExecutorPanic || strings.Contains(err.Error(), "credential") {
		t.Fatalf("execute panic error = %v", err)
	}
	panicIdentity := &mockExecutor{panicIdentity: true}
	if _, err := Invoke(context.Background(), panicIdentity, request); codeOf(err) != ErrorExecutorPanic {
		t.Fatalf("identity panic error = %v", err)
	}
}

func TestResultDigestRejectsMutation(t *testing.T) {
	request, err := SealRequest(validRequest())
	if err != nil {
		t.Fatal(err)
	}
	result, err := Invoke(context.Background(), &mockExecutor{identity: request.Executor, outcome: exactOutcome(request)}, request)
	if err != nil {
		t.Fatal(err)
	}
	result.Runtime[0].ObservationDigest = digest("substituted")
	if err := result.Validate(); err == nil {
		t.Fatal("mutated result retained canonical digest")
	}
	result, err = Invoke(context.Background(), &mockExecutor{identity: request.Executor, outcome: exactOutcome(request)}, request)
	if err != nil {
		t.Fatal(err)
	}
	result.RequestDigest = digest("substituted-request")
	if err := result.Validate(); err == nil {
		t.Fatal("result accepted substituted request digest")
	}
}

type mockExecutor struct {
	identity      ExecutorIdentity
	outcome       ExecutionOutcome
	request       ExecutionRequest
	calls         int
	mutateRequest bool
	panicIdentity bool
	panicExecute  bool
	onExecute     func()
}

func (e *mockExecutor) Identity() ExecutorIdentity {
	if e.panicIdentity {
		panic("credential-that-must-not-escape")
	}
	return e.identity
}

func (e *mockExecutor) Execute(_ context.Context, request ExecutionRequest) (ExecutionOutcome, error) {
	e.calls++
	e.request = request
	if e.panicExecute {
		panic("credential-that-must-not-escape")
	}
	if e.onExecute != nil {
		e.onExecute()
	}
	if e.mutateRequest {
		e.request.Artifacts[0].Content[0] ^= 0xff
	}
	return e.outcome, nil
}

func validRequest() ExecutionRequest {
	return ExecutionRequest{
		Executor: ExecutorIdentity{ID: "native-runtime", Version: "0.7.0-beta.1", Digest: digest("executor")},
		PlanHash: digest("plan"), ManifestHash: digest("manifest"), GenerationReceiptHash: digest("generation-receipt"),
		RequirementsHash: digest("requirements"), EvidenceBundleHash: digest("evidence"),
		RuntimeTargets: []RuntimeTarget{{
			RequirementID: "module-a/unit-a/instance-a", OwnerKind: "module", OwnerRef: "module-a", OwnerContractHash: digest("owner"),
			ProviderRef: "provider-a", ProviderContractHash: digest("provider"), ModuleRef: "module-a", ModuleContractHash: digest("module"),
			UnitRef: "unit-a", UnitContractHash: digest("unit"), RuntimeKind: "container", RuntimeDelivery: "compose",
			RuntimeEngine: "docker", InstanceRef: "instance-a", SiteRefs: []string{"site-a"}, NodeRefs: []string{"node-a"},
			ExecutionChannelRef: "channel-node-a",
			WorkloadRef:         "workload-a", ImageRef: "registry.example/app:1.0.0", ImageDigest: digest("image-a"),
			DaemonBindings: []DaemonTarget{{Ref: "docker", InstanceRef: "daemon-a", Engine: "docker", SocketPath: "/var/run/docker.sock"}},
			ArtifactRefs:   []string{"compose", "env"},
		}, {
			RequirementID: "provider-owner/provider-a/owner-a", OwnerKind: "provider-owner", OwnerRef: "owner-a", OwnerVersion: "1.0.0", OwnerContractHash: digest("provider-owner"),
			ProviderRef: "provider-a", ProviderContractHash: digest("provider"), RuntimeKind: "native", RuntimeDelivery: "owner-api",
			InstanceRef: "provider-owner-a", SiteRefs: []string{"site-a"}, NodeRefs: []string{"node-a"}, ArtifactRefs: []string{},
		}},
		HealthTargets: []HealthTarget{{RequirementID: "health-a", SourceRef: "health-contract-a", ContractHash: digest("health"), Phase: "post-apply", Kind: "http", TargetKind: "module", TargetRef: "module-a", RouteRef: "route-a", BackendPoolRef: "backend-a", SiteRefs: []string{"site-a"}, NodeRefs: []string{"node-a"}}},
		Artifacts: []Artifact{
			{ID: "compose", Kind: "runtime", Format: "yaml", Mode: "apply", OwnerKind: "render-instance", OwnerRef: "instance-a", OwnerContractHash: digest("unit"), ProviderRef: "provider-a", ProviderContractHash: digest("provider"), ModuleRef: "module-a", ModuleContractHash: digest("module"), UnitRef: "unit-a", UnitContractHash: digest("unit"), InstanceRef: "instance-a", OutputRef: "runtime-output", SiteRefs: []string{"site-a"}, NodeRefs: []string{"node-a"}, Content: []byte("services: {}\n"), Digest: digestBytes([]byte("services: {}\n"))},
			{ID: "env", Kind: "runtime", Format: "dotenv", Mode: "apply", OwnerKind: "render-instance", OwnerRef: "instance-a", OwnerContractHash: digest("unit"), ProviderRef: "provider-a", ProviderContractHash: digest("provider"), ModuleRef: "module-a", ModuleContractHash: digest("module"), UnitRef: "unit-a", UnitContractHash: digest("unit"), InstanceRef: "instance-a", OutputRef: "runtime-output", SiteRefs: []string{"site-a"}, NodeRefs: []string{"node-a"}, Content: []byte("MODE=test\n"), Digest: digestBytes([]byte("MODE=test\n"))},
			{ID: "plan-metadata", Kind: "metadata", Format: "json", Mode: "apply", OwnerKind: "plan", OwnerRef: digest("plan"), OwnerContractHash: digest("plan"), SiteRefs: []string{}, NodeRefs: []string{}, Content: []byte("{}\n"), Digest: digestBytes([]byte("{}\n"))},
		},
	}
}

func exactOutcome(request ExecutionRequest) ExecutionOutcome {
	result := ExecutionOutcome{}
	for _, target := range request.RuntimeTargets {
		result.Runtime = append(result.Runtime, RuntimeOutcome{RequirementID: target.RequirementID, InstanceRef: target.InstanceRef, Status: RuntimeStatusApplied, ObservationRef: "runtime-observation://native/runtime-a", ObservationDigest: digest("runtime-observation")})
	}
	for _, target := range request.HealthTargets {
		result.Health = append(result.Health, HealthOutcome{RequirementID: target.RequirementID, TargetRef: target.TargetRef, Status: HealthStatusHealthy, ObservationRef: "health-observation://native/health-a", ObservationDigest: digest("health-observation")})
	}
	return result
}

func codeOf(err error) ErrorCode {
	var contractErr *Error
	if errors.As(err, &contractErr) {
		return contractErr.Code
	}
	return ""
}

func digest(value string) string { return digestBytes([]byte(value)) }
func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
