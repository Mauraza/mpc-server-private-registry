package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadOnlyRegistryTools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "test-user" || password != "test-password" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "expected GET", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2.0/health":
			fmt.Fprint(w, `{"status":"healthy","components":[{"name":"core","status":"healthy"}]}`)
		case "/api/v2.0/search":
			if got := r.URL.Query().Get("q"); got != "payments" {
				t.Errorf("search query = %q, want payments", got)
			}
			fmt.Fprint(w, `{"project":[{"project_id":7,"name":"payments","public":false}],"repository":[{"project_name":"payments","repository_name":"payments/api","tag_count":3,"star_count":2,"pull_count":9}]}`)
		case "/api/v2.0/quotas":
			if r.URL.Query().Get("reference") != "project" || r.URL.Query().Get("reference_id") != "7" ||
				r.URL.Query().Get("page") != "1" || r.URL.Query().Get("page_size") != "100" {
				t.Errorf("unexpected quota query: %v", r.URL.Query())
			}
			fmt.Fprint(w, `[{"id":1,"ref":{"id":7,"name":"payments","type":"project"},"hard":{"storage":1000,"count":20},"used":{"storage":400,"count":3}}]`)
		case "/api/v2.0/projects":
			if r.URL.Query().Get("name") != "payments" {
				t.Errorf("project query = %q, want payments", r.URL.Query().Get("name"))
			}
			fmt.Fprint(w, `[{"project_id":7,"name":"payments","repo_count":2,"creation_time":"2026-01-01T00:00:00Z"}]`)
		case "/api/v2.0/projects/payments/repositories":
			if r.URL.Query().Get("page") != "1" || r.URL.Query().Get("page_size") != "100" {
				t.Errorf("unexpected repository pagination: %v", r.URL.Query())
			}
			fmt.Fprint(w, `[{"name":"payments/api","artifact_count":4},{"name":"payments/web","artifact_count":6}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldURL, oldUsername, oldPassword := *privateRegistryURL, *privateRegistryUsername, *privateRegistryPassword
	*privateRegistryURL, *privateRegistryUsername, *privateRegistryPassword = server.URL, "test-user", "test-password"
	defer func() {
		*privateRegistryURL, *privateRegistryUsername, *privateRegistryPassword = oldURL, oldUsername, oldPassword
	}()

	ctx := context.Background()
	t.Run("health", func(t *testing.T) {
		_, result, err := GetHealth(ctx, nil, GetHealthParams{})
		if err != nil {
			t.Fatal(err)
		}
		if result.Status != "healthy" || len(result.Components) != 1 || result.Components[0].Name != "core" {
			t.Fatalf("unexpected health result: %+v", result)
		}
	})
	t.Run("search", func(t *testing.T) {
		_, result, err := Search(ctx, nil, SearchParams{Query: " payments "})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Projects) != 1 || result.Projects[0].Name != "payments" ||
			len(result.Repositories) != 1 || result.Repositories[0].Name != "payments/api" {
			t.Fatalf("unexpected search result: %+v", result)
		}
	})
	t.Run("quotas", func(t *testing.T) {
		_, result, err := ListQuotas(ctx, nil, ListQuotasParams{Project: "payments"})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Quotas) != 1 || result.Quotas[0].Reference.Name != "payments" ||
			result.Quotas[0].Used["storage"] != 400 {
			t.Fatalf("unexpected quota result: %+v", result)
		}
	})
	t.Run("project summary", func(t *testing.T) {
		_, result, err := GetProjectSummary(ctx, nil, ProjectSummaryParams{Project: "payments"})
		if err != nil {
			t.Fatal(err)
		}
		if !result.Found || result.RepositoryCount != 2 || result.ArtifactCount != 10 ||
			result.Project.Name != "payments" {
			t.Fatalf("unexpected project summary: %+v", result)
		}
	})

}

func TestCreateProject(t *testing.T) {
	var expectedName string
	var expectedPublic bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "test-user" || password != "test-password" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2.0/projects" {
			http.Error(w, "unexpected request", http.StatusMethodNotAllowed)
			return
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}

		var payload struct {
			ProjectName string `json:"project_name"`
			Public      bool   `json:"public"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode project request: %v", err)
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if payload.ProjectName != expectedName || payload.Public != expectedPublic {
			t.Errorf("project payload = %+v, want name %q public %t", payload, expectedName, expectedPublic)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	oldURL, oldUsername, oldPassword := *privateRegistryURL, *privateRegistryUsername, *privateRegistryPassword
	*privateRegistryURL, *privateRegistryUsername, *privateRegistryPassword = server.URL, "test-user", "test-password"
	defer func() {
		*privateRegistryURL, *privateRegistryUsername, *privateRegistryPassword = oldURL, oldUsername, oldPassword
	}()

	for _, test := range []struct {
		name   string
		args   CreateProjectParams
		public bool
	}{
		{name: "defaults to private", args: CreateProjectParams{Project: " demo "}, public: false},
		{name: "creates public project", args: CreateProjectParams{Project: "public-demo", Public: true}, public: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			expectedName = strings.TrimSpace(test.args.Project)
			expectedPublic = test.public
			_, result, err := CreateProject(context.Background(), nil, test.args)
			if err != nil {
				t.Fatal(err)
			}
			if result.Project != expectedName || result.Public != expectedPublic {
				t.Fatalf("unexpected create result: %+v", result)
			}
		})
	}

	t.Run("requires project name", func(t *testing.T) {
		_, _, err := CreateProject(context.Background(), nil, CreateProjectParams{Project: " \t "})
		if err == nil || !strings.Contains(err.Error(), "project is a required parameter") {
			t.Fatalf("CreateProject error = %v, want required-parameter error", err)
		}
	})
}

func TestPrivateRegistryHTTPClientTLSVerification(t *testing.T) {
	original := *insecureSkipTLSVerify
	defer func() {
		*insecureSkipTLSVerify = original
	}()

	for _, skipVerification := range []bool{false, true} {
		*insecureSkipTLSVerify = skipVerification
		client := newPrivateRegistryHTTPClient()
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("client transport has type %T, want *http.Transport", client.Transport)
		}

		if got := transport.TLSClientConfig.InsecureSkipVerify; got != skipVerification {
			t.Errorf("InsecureSkipVerify = %t, want %t", got, skipVerification)
		}
	}
}

func TestScanImageRequiresNonWhitespaceParameters(t *testing.T) {
	originalPassword := *privateRegistryPassword
	*privateRegistryPassword = "test-password"
	defer func() {
		*privateRegistryPassword = originalPassword
	}()

	tests := []struct {
		name string
		args ScanImageParams
	}{
		{name: "missing parameters"},
		{name: "whitespace parameters", args: ScanImageParams{Project: " ", Repository: "\t", Tag: "\n"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := ScanImage(context.Background(), nil, test.args)
			if err == nil || !strings.Contains(err.Error(), "project, repository, and tag are required parameters") {
				t.Fatalf("ScanImage error = %v, want required-parameters error", err)
			}
		})
	}
}

func TestPrivateRegistryHTTPClientTLSVerificationWithSelfSignedCert(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	original := *insecureSkipTLSVerify
	defer func() {
		*insecureSkipTLSVerify = original
	}()

	*insecureSkipTLSVerify = false
	response, err := newPrivateRegistryHTTPClient().Get(server.URL)
	if err == nil {
		response.Body.Close()
		t.Fatal("expected default TLS verification to reject the self-signed certificate")
	}

	*insecureSkipTLSVerify = true
	response, err = newPrivateRegistryHTTPClient().Get(server.URL)
	if err != nil {
		t.Fatalf("explicit insecure TLS opt-in failed: %v", err)
	}
	response.Body.Close()
}

func TestValidateMCPAuth(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		token   string
		wantErr bool
	}{
		{name: "localhost without token", host: "localhost"},
		{name: "IPv4 loopback without token", host: "127.0.0.1"},
		{name: "IPv6 loopback without token", host: "::1"},
		{name: "wildcard without token", host: "0.0.0.0", wantErr: true},
		{name: "remote host without token", host: "registry-host", wantErr: true},
		{name: "remote host with token", host: "0.0.0.0", token: "secret"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateMCPAuth(test.host, test.token)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateMCPAuth(%q, %q) error = %v, wantErr %t", test.host, test.token, err, test.wantErr)
			}
		})
	}
}

func TestRequireBearerToken(t *testing.T) {
	nextCalled := false
	handler := requireBearerToken("secret", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{name: "missing token", wantStatus: http.StatusUnauthorized},
		{name: "wrong scheme", authHeader: "Basic secret", wantStatus: http.StatusUnauthorized},
		{name: "wrong token", authHeader: "Bearer wrong", wantStatus: http.StatusUnauthorized},
		{name: "valid token", authHeader: "Bearer secret", wantStatus: http.StatusNoContent},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nextCalled = false
			req := httptest.NewRequest(http.MethodPost, "/mpc-spr", nil)
			req.Header.Set("Authorization", test.authHeader)
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, req)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
			if nextCalled != (test.wantStatus == http.StatusNoContent) {
				t.Fatalf("next called = %t, want %t", nextCalled, test.wantStatus == http.StatusNoContent)
			}
		})
	}
}
