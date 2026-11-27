package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestEnvironmentDefaultsAndFlagPrecedence(t *testing.T) {
	t.Setenv("PRIVATE_REGISTRY_URL", "https://registry.example")
	t.Setenv("PRIVATE_REGISTRY_USERNAME", "robot")
	t.Setenv("PRIVATE_REGISTRY_PASSWORD", "env-password")
	t.Setenv("MCP_AUTH_TOKEN", "env-token")

	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	registryURL := flags.String("private-registry-url", "default-url", "")
	username := flags.String("private-registry-username", "admin", "")
	password := flags.String("private-registry-password", "", "")
	token := flags.String("mcp-auth-token", "", "")
	if err := applyEnvironmentDefaults(flags); err != nil {
		t.Fatal(err)
	}
	if err := flags.Parse([]string{"--private-registry-password=flag-password", "--mcp-auth-token="}); err != nil {
		t.Fatal(err)
	}
	if *registryURL != "https://registry.example" || *username != "robot" ||
		*password != "flag-password" || *token != "" {
		t.Fatalf("unexpected configuration: URL=%q username=%q password=%q token=%q",
			*registryURL, *username, *password, *token)
	}
}

func TestMissingEnvironmentPreservesFlagDefaults(t *testing.T) {
	for _, name := range []string{"PRIVATE_REGISTRY_URL", "PRIVATE_REGISTRY_USERNAME", "PRIVATE_REGISTRY_PASSWORD", "MCP_AUTH_TOKEN"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	registryURL := flags.String("private-registry-url", "default-url", "")
	username := flags.String("private-registry-username", "admin", "")
	password := flags.String("private-registry-password", "", "")
	token := flags.String("mcp-auth-token", "", "")
	if err := applyEnvironmentDefaults(flags); err != nil {
		t.Fatal(err)
	}
	if *registryURL != "default-url" || *username != "admin" || *password != "" || *token != "" {
		t.Fatal("missing environment variables changed flag defaults")
	}
}

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

func resetReadinessCache() {
	readinessCache.mu.Lock()
	readinessCache.expires = time.Time{}
	readinessCache.healthy = false
	readinessCache.mu.Unlock()
}

func TestHealthzHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recorder := httptest.NewRecorder()

	healthzHandler(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
}

func TestReadyzHandler(t *testing.T) {
	tests := []struct {
		name          string
		noCredentials bool
		backendStatus int
		backendBody   string
		wantStatus    int
	}{
		{name: "healthy", backendStatus: http.StatusOK, backendBody: `{"status":"healthy"}`, wantStatus: http.StatusOK},
		{name: "unhealthy status", backendStatus: http.StatusOK, backendBody: `{"status":"unhealthy"}`, wantStatus: http.StatusServiceUnavailable},
		{name: "backend error", backendStatus: http.StatusInternalServerError, wantStatus: http.StatusServiceUnavailable},
		{name: "missing credentials", noCredentials: true, wantStatus: http.StatusServiceUnavailable},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.backendStatus)
				fmt.Fprint(w, test.backendBody)
			}))
			defer server.Close()

			oldURL, oldPassword := *privateRegistryURL, *privateRegistryPassword
			*privateRegistryURL = server.URL
			*privateRegistryPassword = "test-password"
			if test.noCredentials {
				*privateRegistryPassword = ""
			}
			defer func() {
				*privateRegistryURL, *privateRegistryPassword = oldURL, oldPassword
			}()
			resetReadinessCache()

			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			recorder := httptest.NewRecorder()

			readyzHandler(recorder, req)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
		})
	}
}

func TestNewHTTPHandlerProbesBypassAuth(t *testing.T) {
	resetReadinessCache()
	oldPassword := *privateRegistryPassword
	*privateRegistryPassword = ""
	defer func() { *privateRegistryPassword = oldPassword }()

	server := mcp.NewServer(&mcp.Implementation{Name: "test"}, nil)
	handler := newHTTPHandler(server, "secret")

	for _, path := range []string{"/healthz", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, req)

			if recorder.Code == http.StatusUnauthorized {
				t.Fatalf("%s should not require bearer auth, got 401", path)
			}
		})
	}

	t.Run("/mpc-spr requires auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mpc-spr", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
		}
	})
}
