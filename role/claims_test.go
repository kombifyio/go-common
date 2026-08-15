package role

import (
	"reflect"
	"testing"
)

func TestExtractRoleFromClaims_NamespacedArray(t *testing.T) {
	claims := map[string]any{
		DefaultRoleClaimNamespace: []any{"global_admin"},
	}
	if got := ExtractRoleFromClaims(claims, ""); got != GlobalAdmin {
		t.Fatalf("want global_admin, got %q", got)
	}
}

func TestExtractRoleFromClaims_HighestWins(t *testing.T) {
	claims := map[string]any{
		DefaultRoleClaimNamespace: []any{"user", "manager", "developer"},
	}
	if got := ExtractRoleFromClaims(claims, ""); got != Developer {
		t.Fatalf("want developer (highest), got %q", got)
	}
}

func TestExtractRoleFromClaims_FlatRolesArray(t *testing.T) {
	claims := map[string]any{
		"roles": []string{"manager"},
	}
	if got := ExtractRoleFromClaims(claims, ""); got != Manager {
		t.Fatalf("want manager, got %q", got)
	}
}

func TestExtractRoleFromClaims_FlatRoleString(t *testing.T) {
	claims := map[string]any{
		"role": "user",
	}
	if got := ExtractRoleFromClaims(claims, ""); got != User {
		t.Fatalf("want user, got %q", got)
	}
}

func TestExtractRoleFromClaims_NamespaceBeatsFlat(t *testing.T) {
	// Namespaced claim should be considered together with flat; highest wins.
	claims := map[string]any{
		DefaultRoleClaimNamespace: []any{"developer"},
		"roles":                   []any{"user"},
	}
	if got := ExtractRoleFromClaims(claims, ""); got != Developer {
		t.Fatalf("want developer, got %q", got)
	}
}

func TestExtractRoleFromClaims_UnknownRolesIgnored(t *testing.T) {
	claims := map[string]any{
		DefaultRoleClaimNamespace: []any{"not_a_role", "also_bogus"},
	}
	if got := ExtractRoleFromClaims(claims, ""); got != User {
		t.Fatalf("want default user, got %q", got)
	}
}

func TestExtractRoleFromClaims_EmptyClaims(t *testing.T) {
	if got := ExtractRoleFromClaims(nil, ""); got != User {
		t.Fatalf("want default user on nil, got %q", got)
	}
	if got := ExtractRoleFromClaims(map[string]any{}, ""); got != User {
		t.Fatalf("want default user on empty, got %q", got)
	}
}

func TestExtractRoleFromClaims_CustomNamespace(t *testing.T) {
	claims := map[string]any{
		"https://example.com/roles": []any{"manager"},
	}
	if got := ExtractRoleFromClaims(claims, "https://example.com/roles"); got != Manager {
		t.Fatalf("want manager, got %q", got)
	}
}

func TestExtractAllRolesFromClaims_SortedAndDeduped(t *testing.T) {
	claims := map[string]any{
		DefaultRoleClaimNamespace: []any{"user", "developer"},
		"roles":                   []any{"manager", "developer"}, // developer dup
		"role":                    "user",                        // user dup
	}
	got := ExtractAllRolesFromClaims(claims, "")
	want := []Role{Developer, Manager, User}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestExtractAllRolesFromClaims_DefaultsToUser(t *testing.T) {
	got := ExtractAllRolesFromClaims(nil, "")
	if !reflect.DeepEqual(got, []Role{User}) {
		t.Fatalf("want [user] default, got %v", got)
	}
}
