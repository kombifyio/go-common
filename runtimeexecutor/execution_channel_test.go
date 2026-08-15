package runtimeexecutor

import (
	"context"
	"strings"
	"testing"
)

func TestExecutionChannelRequestValidatesExactScopeAndClones(t *testing.T) {
	request := validExecutionChannelRequest()
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	clone := CloneExecutionChannelRequest(request)
	clone.RuntimeTargets[0].SiteRefs[0] = "caller-mutated"
	clone.RuntimeTargets[0].ArtifactRefs[0] = "caller-mutated"
	clone.HealthTargets[0].NodeRefs[0] = "caller-mutated"
	if request.RuntimeTargets[0].SiteRefs[0] != "site-a" || request.RuntimeTargets[0].ArtifactRefs[0] != "compose" || request.HealthTargets[0].NodeRefs[0] != "node-a" {
		t.Fatalf("channel clone mutation escaped: %#v", request)
	}

	var _ ExecutionChannelFactory = executionChannelFactoryFunc(nil)
	var _ ExecutionChannelAdmission = executionChannelAdmissionFunc(nil)
	var _ Executor = executionChannelExecutorStub{}
}

func TestExecutionChannelRequestRejectsEscapedOrAmbiguousScope(t *testing.T) {
	tests := map[string]func(*ExecutionChannelRequest){
		"empty channel":          func(value *ExecutionChannelRequest) { value.ChannelRef = "" },
		"foreign target channel": func(value *ExecutionChannelRequest) { value.RuntimeTargets[0].ExecutionChannelRef = "channel-other" },
		"foreign target site":    func(value *ExecutionChannelRequest) { value.RuntimeTargets[0].SiteRefs = []string{"site-b"} },
		"foreign target node":    func(value *ExecutionChannelRequest) { value.RuntimeTargets[0].NodeRefs = []string{"node-b"} },
		"foreign health site":    func(value *ExecutionChannelRequest) { value.HealthTargets[0].SiteRefs = []string{"site-b"} },
		"foreign health node":    func(value *ExecutionChannelRequest) { value.HealthTargets[0].NodeRefs = []string{"node-b"} },
		"unowned health":         func(value *ExecutionChannelRequest) { value.HealthTargets[0].TargetRef = "module-other" },
		"missing runtime":        func(value *ExecutionChannelRequest) { value.RuntimeTargets = nil },
		"missing health":         func(value *ExecutionChannelRequest) { value.HealthTargets = nil },
		"invalid target":         func(value *ExecutionChannelRequest) { value.RuntimeTargets[0].OwnerRef = "" },
		"duplicate requirement": func(value *ExecutionChannelRequest) {
			other := CloneExecutionChannelRequest(*value).RuntimeTargets[0]
			other.InstanceRef = "instance-b"
			value.RuntimeTargets = append(value.RuntimeTargets, other)
		},
		"ambiguous health": func(value *ExecutionChannelRequest) {
			other := CloneExecutionChannelRequest(*value).RuntimeTargets[0]
			other.RequirementID = "module-a/unit-a/instance-b"
			other.InstanceRef = "instance-b"
			value.RuntimeTargets = append(value.RuntimeTargets, other)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := validExecutionChannelRequest()
			mutate(&request)
			if err := request.Validate(); err == nil {
				t.Fatalf("accepted invalid channel request: %#v", request)
			}
		})
	}
}

func TestExecutionChannelRequestAcceptsOnlyCanonicalChannelIdentity(t *testing.T) {
	request := validExecutionChannelRequest()
	externalRef := "execution-channel://sha256/" + strings.Repeat("a", 64)
	request.ChannelRef = externalRef
	request.RuntimeTargets[0].ExecutionChannelRef = externalRef
	if err := request.Validate(); err != nil {
		t.Fatalf("canonical external channel rejected: %v", err)
	}

	for name, value := range map[string]string{
		"endpoint":       "https://node.example.test/action",
		"ssh":            "ssh://root@node",
		"unbound scheme": "execution-channel://node-a",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validExecutionChannelRequest()
			candidate.ChannelRef = value
			candidate.RuntimeTargets[0].ExecutionChannelRef = value
			if err := candidate.Validate(); err == nil {
				t.Fatal("non-canonical channel accepted")
			}
		})
	}
}

func validExecutionChannelRequest() ExecutionChannelRequest {
	request := validRequest()
	return ExecutionChannelRequest{
		ChannelRef: "channel-node-a", SiteRef: "site-a", NodeRef: "node-a",
		RuntimeTargets: []RuntimeTarget{request.RuntimeTargets[0]},
		HealthTargets:  []HealthTarget{request.HealthTargets[0]},
	}
}

type executionChannelFactoryFunc func(ExecutionChannelRequest) (ExecutionChannelAdmission, error)

func (f executionChannelFactoryFunc) AdmitExecutionChannel(request ExecutionChannelRequest) (ExecutionChannelAdmission, error) {
	return f(request)
}

type executionChannelAdmissionFunc func(ExecutionChannelLocalExecutor) (Executor, error)

func (f executionChannelAdmissionFunc) PrepareExecutionChannel(local ExecutionChannelLocalExecutor) (Executor, error) {
	return f(local)
}

type executionChannelExecutorStub struct{}

func (executionChannelExecutorStub) Identity() ExecutorIdentity { return validRequest().Executor }
func (executionChannelExecutorStub) Execute(context.Context, ExecutionRequest) (ExecutionOutcome, error) {
	return ExecutionOutcome{}, nil
}
