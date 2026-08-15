package fga

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	openfga "github.com/openfga/go-sdk"
)

func TestCheckStrictUsesHigherConsistencyAndPreservesErrors(t *testing.T) {
	var requestBody string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		requestBody = string(body)
		if strings.Contains(request.URL.Path, "/check") {
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"allowed":true}`))
			return
		}
		response.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := newTestFGAClient(t, server.URL)
	allowed, err := client.CheckStrict(context.Background(), "user:owner", "accessor", "surface:tenant/inventory/servers")
	if err != nil || !allowed {
		t.Fatalf("CheckStrict = %v, %v", allowed, err)
	}
	if !strings.Contains(requestBody, `"consistency":"HIGHER_CONSISTENCY"`) {
		t.Fatalf("strict request did not require higher consistency: %s", requestBody)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusServiceUnavailable)
		_, _ = response.Write([]byte(`{"code":"unavailable"}`))
	}))
	defer failing.Close()
	failingClient := newTestFGAClient(t, failing.URL)
	if _, strictErr := failingClient.CheckStrict(context.Background(), "user:owner", "accessor", "surface:tenant/inventory/servers"); strictErr == nil {
		t.Fatal("CheckStrict swallowed the backend failure")
	}
	allowed, err = failingClient.Check(context.Background(), "user:owner", "accessor", "surface:tenant/inventory/servers")
	if err != nil || allowed {
		t.Fatalf("legacy fail-closed Check = %v, %v", allowed, err)
	}
}

func TestDeleteTuplesIdempotentUsesProviderNativeMissingIgnore(t *testing.T) {
	var requestBody string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		requestBody = string(body)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := newTestFGAClient(t, server.URL)
	err := client.DeleteTuplesIdempotent(context.Background(), []openfga.TupleKeyWithoutCondition{{
		User: "user:owner", Relation: "accessor", Object: "surface:tenant/inventory/servers",
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`"on_missing":"ignore"`,
		`"user":"user:owner"`,
		`"relation":"accessor"`,
		`"object":"surface:tenant/inventory/servers"`,
	} {
		if !strings.Contains(requestBody, required) {
			t.Fatalf("idempotent delete body missing %s: %s", required, requestBody)
		}
	}
}

func TestStrictMethodsRejectNilClient(t *testing.T) {
	var client *KombifyFga
	if _, err := client.CheckStrict(context.Background(), "user:owner", "accessor", "surface:tenant/inventory/servers"); err == nil {
		t.Fatal("nil CheckStrict succeeded")
	}
	if err := client.DeleteTuplesIdempotent(context.Background(), nil); err == nil {
		t.Fatal("nil DeleteTuplesIdempotent succeeded")
	}
}

func newTestFGAClient(t *testing.T, apiURL string) *KombifyFga {
	t.Helper()
	client, err := FromConfig(&Config{
		APIURL: apiURL, StoreID: "01H00000000000000000000000", AuthorizationModelID: "01H00000000000000000000001",
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
