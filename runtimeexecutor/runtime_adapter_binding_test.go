package runtimeexecutor

import "testing"

func TestRuntimeAdapterBindingSealsExactCoreAgentAndHandoffAuthority(t *testing.T) {
	input := validRuntimeAdapterRequest()
	sealed, err := SealRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := sealed.Validate(); err != nil {
		t.Fatal(err)
	}
	adapter := sealed.RuntimeTargets[0].RuntimeAdapter
	if adapter == nil || adapter.ID != "komodo" || len(adapter.Agents) != 1 || adapter.Agents[0].ID != "komodo-periphery" {
		t.Fatalf("sealed adapter binding = %#v", adapter)
	}
	if sealed.Artifacts[0].ExecutionClass == "" {
		t.Fatal("SealRequest did not materialize artifact execution classes")
	}

	clone := CloneExecutionRequest(sealed)
	clone.RuntimeTargets[0].RuntimeAdapter.ArtifactRefs[0] = "changed"
	clone.RuntimeTargets[0].RuntimeAdapter.Agents[0].ArtifactRefs[0] = "changed"
	if sealed.RuntimeTargets[0].RuntimeAdapter.ArtifactRefs[0] == "changed" || sealed.RuntimeTargets[0].RuntimeAdapter.Agents[0].ArtifactRefs[0] == "changed" {
		t.Fatal("CloneExecutionRequest shares runtime-adapter storage")
	}

	for name, mutate := range map[string]func(*ExecutionRequest){
		"adapter substitution": func(request *ExecutionRequest) {
			request.RuntimeTargets[0].RuntimeAdapter.ID = "coolify"
		},
		"provider hash substitution": func(request *ExecutionRequest) {
			request.RuntimeTargets[0].RuntimeAdapter.ProviderContractHash = digest("other-provider")
		},
		"core module substitution": func(request *ExecutionRequest) {
			request.RuntimeTargets[0].RuntimeAdapter.ModuleRef = "other-core"
		},
		"agent module substitution": func(request *ExecutionRequest) {
			request.RuntimeTargets[0].RuntimeAdapter.Agents[0].ModuleRef = "other-agent"
		},
		"handoff execution widening": func(request *ExecutionRequest) {
			artifactByID(request.Artifacts, "komodo-core-handoff").ExecutionClass = ArtifactExecutionClassExecutable
		},
		"handoff owner substitution": func(request *ExecutionRequest) {
			artifactByID(request.Artifacts, "komodo-periphery-handoff").ModuleContractHash = digest("other-agent")
		},
		"credential ref": func(request *ExecutionRequest) {
			request.RuntimeTargets[0].RuntimeAdapter.ProviderRef = "credential://komodo/token"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := CloneExecutionRequest(sealed)
			mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("substituted runtime-adapter request validated")
			}
		})
	}
}

func TestSelectedPaaSRequiresRuntimeAdapterBinding(t *testing.T) {
	input := validRequest()
	input.RuntimeTargets[0].RuntimeDelivery = "selected-paas"
	if _, err := SealRequest(input); err == nil {
		t.Fatal("selected-paas target without exact runtime-adapter authority sealed")
	}
}

func validRuntimeAdapterRequest() ExecutionRequest {
	request := validRequest()
	target := &request.RuntimeTargets[0]
	target.RuntimeDelivery = "selected-paas"
	target.RuntimeAdapter = &RuntimeAdapterBinding{
		ID: "komodo", ProviderRef: "stackkits-komodo", ProviderVersion: "1.0.0", ProviderContractHash: digest("komodo-provider"),
		ModuleRef: "stackkits-komodo-core-runtime", ModuleVersion: "1.0.0", ModuleContractHash: digest("komodo-core"),
		ArtifactRefs: []string{"komodo-core-handoff"},
		Agents: []RuntimeAdapterAgentBinding{{
			ID: "komodo-periphery", ModuleRef: "stackkits-komodo-periphery-runtime", ModuleVersion: "1.0.0", ModuleContractHash: digest("komodo-periphery"),
			ArtifactRefs: []string{"komodo-periphery-handoff"},
		}},
	}
	request.Artifacts = append(request.Artifacts,
		adapterTestArtifact("komodo-core-handoff", "stackkits-komodo-core-runtime", digest("komodo-core"), "komodo-core-instance", "platform/komodo/core-runtime-adapter.json"),
		adapterTestArtifact("komodo-periphery-handoff", "stackkits-komodo-periphery-runtime", digest("komodo-periphery"), "komodo-periphery-instance", "platform/komodo/periphery-agent.json"),
	)
	return request
}

func adapterTestArtifact(id, moduleRef, moduleHash, instanceRef, outputRef string) Artifact {
	content := []byte("{}\n")
	return Artifact{
		ID: id, Kind: "native-config", Format: "json", Mode: "apply", ExecutionClass: ArtifactExecutionClassContractHandoff,
		OwnerKind: "render-instance", OwnerRef: instanceRef, OwnerContractHash: digest(moduleRef + "-unit"),
		ProviderRef: "stackkits-komodo", ProviderContractHash: digest("komodo-provider"), ModuleRef: moduleRef, ModuleContractHash: moduleHash,
		UnitRef: moduleRef + "-unit", UnitContractHash: digest(moduleRef + "-unit"), InstanceRef: instanceRef, OutputRef: outputRef,
		SiteRefs: []string{"site-a"}, NodeRefs: []string{"node-a"}, Digest: digestBytes(content), Content: content,
	}
}

func artifactByID(artifacts []Artifact, id string) *Artifact {
	for index := range artifacts {
		if artifacts[index].ID == id {
			return &artifacts[index]
		}
	}
	return nil
}
