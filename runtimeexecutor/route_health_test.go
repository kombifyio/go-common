package runtimeexecutor

import "testing"

func TestRouteHealthTargetBindsExactRuntimeAndClosedProbe(t *testing.T) {
	request := validRequest()
	request.HealthTargets = append(request.HealthTargets, validRouteHealthTarget(request.RuntimeTargets[0]))
	sealed, err := SealRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	var route HealthTarget
	for _, candidate := range sealed.HealthTargets {
		if candidate.TargetKind == "route" {
			route = candidate
		}
	}
	if route.RuntimeRequirementID != request.RuntimeTargets[0].RequirementID || route.Probe == nil || len(route.Probe.ExpectedStatuses) != 2 || route.Probe.ExpectedStatuses[0] != 200 {
		t.Fatalf("sealed route health target = %#v", route)
	}
	clone := CloneExecutionRequest(sealed)
	clone.HealthTargets[1].Probe.ExpectedStatuses[0] = 500
	if route.Probe.ExpectedStatuses[0] != 200 {
		t.Fatal("route probe status slice aliases a caller-owned request")
	}
}

func TestRouteHealthTargetRejectsAuthorityAndProbeSubstitution(t *testing.T) {
	tests := map[string]func(*HealthTarget){
		"missing runtime owner": func(target *HealthTarget) { target.RuntimeRequirementID = "" },
		"unknown runtime owner": func(target *HealthTarget) { target.RuntimeRequirementID = "module-b/unit-b/instance-b" },
		"foreign node":          func(target *HealthTarget) { target.NodeRefs = []string{"node-b"} },
		"route mismatch":        func(target *HealthTarget) { target.RouteRef = "route-b" },
		"missing pool":          func(target *HealthTarget) { target.BackendPoolRef = "" },
		"address-bearing HTTPS": func(target *HealthTarget) { target.Probe.Protocol = "https" },
		"redirects":             func(target *HealthTarget) { target.Probe.FollowRedirects = true },
		"relative path":         func(target *HealthTarget) { target.Probe.Path = "healthz" },
		"invalid status":        func(target *HealthTarget) { target.Probe.ExpectedStatuses = []int{99} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := validRequest()
			route := validRouteHealthTarget(request.RuntimeTargets[0])
			mutate(&route)
			request.HealthTargets = append(request.HealthTargets, route)
			if _, err := SealRequest(request); err == nil {
				t.Fatal("unsafe route health target was sealed")
			}
		})
	}
}

func TestExecutionChannelAcceptsRouteHealthOnlyForItsExactRuntime(t *testing.T) {
	request := validRequest()
	runtime := request.RuntimeTargets[0]
	route := validRouteHealthTarget(runtime)
	channel := ExecutionChannelRequest{
		ChannelRef: runtime.ExecutionChannelRef, SiteRef: runtime.SiteRefs[0], NodeRef: runtime.NodeRefs[0],
		RuntimeTargets: []RuntimeTarget{runtime}, HealthTargets: []HealthTarget{request.HealthTargets[0], route},
	}
	if err := channel.Validate(); err != nil {
		t.Fatal(err)
	}
	channel.HealthTargets[1].RuntimeRequirementID = "provider-owner/provider-a/owner-a"
	if err := channel.Validate(); err == nil {
		t.Fatal("execution channel accepted a route probe owned by another runtime")
	}
}

func validRouteHealthTarget(target RuntimeTarget) HealthTarget {
	return HealthTarget{
		RequirementID: "route-health-a/runtime/instance-a", RuntimeRequirementID: target.RequirementID,
		SourceRef: "module-a-health-a", ContractHash: digest("route-health"), Phase: "post-apply", Kind: "http",
		TargetKind: "route", TargetRef: "route-a", RouteRef: "route-a", BackendPoolRef: "route-a-pool-aaaaaaaaaaaa",
		Probe:    &HealthProbe{Protocol: "http", Port: 8080, TimeoutSeconds: 10, Method: "GET", Path: "/healthz", ExpectedStatuses: []int{204, 200}},
		SiteRefs: append([]string(nil), target.SiteRefs...), NodeRefs: append([]string(nil), target.NodeRefs...),
	}
}
