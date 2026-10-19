// Copyright 2025 The Go MCP SDK Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	host                    = flag.String("host", "localhost", "host to listen on")
	port                    = flag.String("port", "8080", "port to listen on")
	stdio                   = flag.Bool("stdio", false, "use stdio transport instead of Streamable HTTP")
	privateRegistryURL      = flag.String("private-registry-url", "http://localhost:8080", "Private Registry instance URL")
	privateRegistryUsername = flag.String("private-registry-username", "admin", "Private Registry username for API access")
	privateRegistryPassword = flag.String("private-registry-password", "", "Private Registry password for API access")
	insecureSkipTLSVerify   = flag.Bool("insecure-skip-tls-verify", false, "skip TLS certificate verification for the Private Registry")
	mcpAuthToken            = flag.String("mcp-auth-token", "", "bearer token required when listening on a non-loopback host")
	// Timeout for long-running scans (independent of the client's context)
	scanTimeout      = flag.Duration("scan-timeout", 30*time.Minute, "maximum time to wait for a project scan")
	progressInterval = flag.Duration("progress-interval", 30*time.Second, "interval between progress notifications while scanning")
)

// newPrivateRegistryHTTPClient builds an HTTP client configured to talk to the
// Private Registry instance. TLS certificate verification is enabled by default.
func newPrivateRegistryHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: *insecureSkipTLSVerify, //nolint:gosec // Explicitly controlled by the insecure-skip-tls-verify flag.
			},
		},
	}
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateMCPAuth(host, token string) error {
	if !isLoopbackHost(host) && strings.TrimSpace(token) == "" {
		return fmt.Errorf("mcp-auth-token is required when host %q is not loopback", host)
	}
	return nil
}

func requireBearerToken(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, suppliedToken, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") ||
			subtle.ConstantTimeCompare([]byte(suppliedToken), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func privateRegistryAPIGet(ctx context.Context, path string, query url.Values, result any) error {
	endpoint := fmt.Sprintf("%s/api/v2.0/%s", strings.TrimRight(*privateRegistryURL, "/"), strings.TrimLeft(path, "/"))
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create Harbor API request: %w", err)
	}
	httpReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
	httpReq.Header.Set("Accept", "application/json")

	resp, err := newPrivateRegistryHTTPClient().Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to call Harbor API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return fmt.Errorf("Harbor API returned status %d and its error body could not be read: %w", resp.StatusCode, readErr)
		}
		return fmt.Errorf("Harbor API returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if result == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("failed to decode Harbor API response: %w", err)
	}
	return nil
}

// ScanImageParams defines the input for the privateRegistry image scanning tool.
type ScanImageParams struct {
	Project    string `json:"project" jsonschema:"The privateRegistry project name"`
	Repository string `json:"repository" jsonschema:"The repository name within the project"`
	Tag        string `json:"tag" jsonschema:"The image tag to scan"`
}

// Vulnerability represents a single vulnerability found in an image.
type Vulnerability struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	FixVersion  string `json:"fix_version,omitempty"`
}

// ScanResult is the output of the image scanning tool.
type ScanResult struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// ScanProjectParams defines the input for scanning all images in a project.
type ScanProjectParams struct {
	Project string `json:"project" jsonschema:"The privateRegistry project name to scan"`
}

// ImageVulnerabilitySummary provides a summary of vulnerabilities for a single image.
type ImageVulnerabilitySummary struct {
	ImageName     string `json:"image_name"`
	CriticalCount int    `json:"critical_count"`
	HighCount     int    `json:"high_count"`
	MediumCount   int    `json:"medium_count"`
	LowCount      int    `json:"low_count"`
	UnknownCount  int    `json:"unknown_count"`
	TotalCount    int    `json:"total_count"`
}

// ScanProjectResult is the output of the project scanning tool.
type ScanProjectResult struct {
	Images []ImageVulnerabilitySummary `json:"images"`
}

// privateRegistryVulnerabilityReport represents the structure of the vulnerability report
// object returned by privateRegistry, which contains the list of vulnerabilities.
type privateRegistryVulnerabilityReport struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// FindPatchedImageParams defines the input for the tool that finds a patched image.
type FindPatchedImageParams struct {
	Project    string `json:"project" jsonschema:"The Private Registry project name of the image"`
	Repository string `json:"repository" jsonschema:"The repository name of the image"`
	Tag        string `json:"tag" jsonschema:"The current tag of the image to find a patch for"`
	CVEID      string `json:"cve_id" jsonschema:"The CVE ID to check for absence in newer versions"`
}

// FindPatchedImageResult is the output of the find_patched_image tool.
type FindPatchedImageResult struct {
	Found         bool   `json:"found"`
	Image         string `json:"image,omitempty"`
	Location      string `json:"location,omitempty"`
	CriticalCount int    `json:"critical_count,omitempty"`
	HighCount     int    `json:"high_count,omitempty"`
}

// GetVulnerabilitiesParams defines the input for the tool that retrieves all vulnerabilities for a given image.
type GetVulnerabilitiesParams struct {
	Project    string `json:"project" jsonschema:"The Private Registry project name"`
	Repository string `json:"repository" jsonschema:"The repository name within the project"`
	Tag        string `json:"tag" jsonschema:"The image tag to get vulnerabilities for"`
}

// GetVulnerabilitiesResult is the output of the get_vulnerabilities tool.
type GetVulnerabilitiesResult struct {
	ImageName       string          `json:"image_name"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	TotalCount      int             `json:"total_count"`
}

// GetSBOMParams defines the input for the tool that retrieves the SBOM for a given image.
type GetSBOMParams struct {
	Project    string `json:"project" jsonschema:"The Private Registry project name"`
	Repository string `json:"repository" jsonschema:"The repository name within the project"`
	Tag        string `json:"tag" jsonschema:"The image tag to get the SBOM for"`
}

// GetSBOMResult is the output of the get_sbom tool.
type GetSBOMResult struct {
	ImageName string                 `json:"image_name"`
	SBOM      map[string]interface{} `json:"sbom,omitempty"`
	// SBOMURL is the direct download link for the Software Bill of Materials.
	SBOMURL string `json:"sbom_url,omitempty"`
}

// GetProjectSBOMParams defines the input for the tool that retrieves SBOMs for all images in a project.
type GetProjectSBOMParams struct {
	Project string `json:"project" jsonschema:"The Private Registry project name"`
}

// SBOMInfo holds the SBOM for a single image.
type SBOMInfo struct {
	ImageName  string `json:"image_name"`
	ScanStatus string `json:"scan_status"`
	SBOMURL    string `json:"sbom_url,omitempty"`
}

// GetProjectSBOMResult is the output of the get_project_sbom tool.
type GetProjectSBOMResult struct {
}

// ListProjectsParams defines the input for the tool that lists registry projects. It takes no parameters.
type ListProjectsParams struct {
}

// ProjectInfo describes a single Private Registry project.
type ProjectInfo struct {
	Name         string `json:"name"`
	RepoCount    int    `json:"repo_count,omitempty"`
	CreationTime string `json:"creation_time,omitempty"`
}

// ListProjectsResult is the output of the list_projects tool.
type ListProjectsResult struct {
	Projects []ProjectInfo `json:"projects"`
}

// CreateProjectParams defines the input for creating a Harbor project.
type CreateProjectParams struct {
	Project string `json:"project" jsonschema:"Name of the project to create"`
	Public  bool   `json:"public,omitempty" jsonschema:"Whether the project is publicly accessible (default false)"`
}

// CreateProjectResult describes the newly created Harbor project.
type CreateProjectResult struct {
	Project string `json:"project"`
	Public  bool   `json:"public"`
}

// GetHealthResult describes the overall registry health and its components.
type GetHealthResult struct {
	Status     string                 `json:"status,omitempty"`
	Components []RegistryHealthStatus `json:"components"`
}

// GetHealthParams defines the input for checking Harbor health. It takes no parameters.
type GetHealthParams struct{}

// RegistryHealthStatus describes the status of one Harbor component.
type RegistryHealthStatus struct {
	Name   string `json:"name,omitempty"`
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

// SearchParams defines the input for searching registry projects and repositories.
type SearchParams struct {
	Query string `json:"query" jsonschema:"Text to search for in project and repository names"`
}

// SearchProject describes a project returned by Harbor's search endpoint.
type SearchProject struct {
	ID     int64  `json:"project_id"`
	Name   string `json:"name"`
	Public bool   `json:"public"`
}

// SearchRepository describes a repository returned by Harbor's search endpoint.
type SearchRepository struct {
	Name        string `json:"repository_name"`
	ProjectName string `json:"project_name,omitempty"`
	TagCount    int    `json:"tag_count,omitempty"`
	StarCount   int    `json:"star_count,omitempty"`
	PullCount   int    `json:"pull_count,omitempty"`
}

// SearchResult contains matching projects and repositories.
type SearchResult struct {
	Projects     []SearchProject    `json:"projects"`
	Repositories []SearchRepository `json:"repositories"`
}

// ListQuotasParams defines filters and pagination for listing registry quotas.
type ListQuotasParams struct {
	Project  string `json:"project,omitempty" jsonschema:"Optional project name to filter quota results"`
	Page     int    `json:"page,omitempty" jsonschema:"Page number (default 1)"`
	PageSize int    `json:"page_size,omitempty" jsonschema:"Results per page, from 1 to 100 (default 100)"`
}

// RegistryQuota describes a Harbor quota and its current usage.
type RegistryQuota struct {
	ID         int64            `json:"id"`
	Reference  QuotaReference   `json:"ref"`
	Hard       map[string]int64 `json:"hard,omitempty"`
	Used       map[string]int64 `json:"used,omitempty"`
	UpdateTime string           `json:"update_time,omitempty"`
}

// QuotaReference identifies the resource governed by a quota.
type QuotaReference struct {
	ID   int64  `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

// ListQuotasResult contains the requested page of quotas.
type ListQuotasResult struct {
	Quotas   []RegistryQuota `json:"quotas"`
	Page     int             `json:"page"`
	PageSize int             `json:"page_size"`
}

// ProjectSummaryParams defines the input for the read-only project overview tool.
type ProjectSummaryParams struct {
	Project string `json:"project" jsonschema:"The Harbor project name"`
}

// ProjectSummaryResult summarizes project metadata and repository artifact counts.
type ProjectSummaryResult struct {
	Found           bool        `json:"found"`
	Project         ProjectInfo `json:"project"`
	RepositoryCount int         `json:"repository_count"`
	ArtifactCount   int         `json:"artifact_count"`
}

// GetProjectParams defines the input for the tool that fetches a single project's details.
type GetProjectParams struct {
	Project string `json:"project" jsonschema:"The Private Registry project name"`
}

// GetProjectResult is the output of the get_project tool.
type GetProjectResult struct {
	Found   bool        `json:"found"`
	Project ProjectInfo `json:"project"`
}

// ListRepositoriesParams defines the input for the tool that lists repositories in a project.
type ListRepositoriesParams struct {
	Project string `json:"project" jsonschema:"The Private Registry project name"`
}

// RepositoryInfo describes a single repository within a project.
type RepositoryInfo struct {
	Name          string `json:"name"`
	ArtifactCount int    `json:"artifact_count,omitempty"`
}

// ListRepositoriesResult is the output of the list_repositories tool.
type ListRepositoriesResult struct {
	Repositories []RepositoryInfo `json:"repositories"`
}

// ListTagsParams defines the input for the tool that lists tags in a repository.
type ListTagsParams struct {
	Project    string `json:"project" jsonschema:"The Private Registry project name"`
	Repository string `json:"repository" jsonschema:"The repository name within the project"`
}

// TagInfo describes a single tag of an artifact within a repository.
type TagInfo struct {
	Name         string `json:"name"`
	ArtifactType string `json:"artifact_type,omitempty"`
}

// ListTagsResult is the output of the list_tags tool.
type ListTagsResult struct {
	Tags []TagInfo `json:"tags"`
}

// ListChartsParams defines the input for the tool that lists Helm charts in a project.
type ListChartsParams struct {
	Project string `json:"project" jsonschema:"The Private Registry project name"`
}

// ChartInfo describes a single Helm chart.
type ChartInfo struct {
	Name          string `json:"name"`
	LatestVersion string `json:"latest_version,omitempty"`
}

// ListChartsResult is the output of the list_charts tool.
type ListChartsResult struct {
	Charts []ChartInfo `json:"charts"`
}

// ListChartVersionsParams defines the input for the tool that lists versions of a Helm chart.
type ListChartVersionsParams struct {
	Project string `json:"project" jsonschema:"The Private Registry project name"`
	Chart   string `json:"chart" jsonschema:"The Helm chart name"`
}

// ChartVersionInfo describes a single version of a Helm chart.
type ChartVersionInfo struct {
	Version    string `json:"version"`
	AppVersion string `json:"app_version,omitempty"`
}

// ListChartVersionsResult is the output of the list_chart_versions tool.
type ListChartVersionsResult struct {
	Versions []ChartVersionInfo `json:"versions"`
}

// ScanImage is a tool handler that triggers a vulnerability scan in Private Registry for a given
// container image and returns the results.
func ScanImage(ctx context.Context, req *mcp.CallToolRequest, args ScanImageParams) (*mcp.CallToolResult, ScanResult, error) {
	if *privateRegistryPassword == "" {
		return nil, ScanResult{}, fmt.Errorf("private-registry-password flag is not set")
	}

	// Sanitize string inputs to prevent issues with leading/trailing whitespace.
	args.Project = strings.TrimSpace(args.Project)
	args.Repository = strings.TrimSpace(args.Repository)
	args.Tag = strings.TrimSpace(args.Tag)
	if args.Project == "" || args.Repository == "" || args.Tag == "" {
		return nil, ScanResult{}, fmt.Errorf("project, repository, and tag are required parameters")
	}

	// The repository name in the Private Registry API needs to be URL-encoded,
	// especially if it contains slashes.
	repo := strings.ReplaceAll(args.Repository, "/", "%2F")

	// 1. Trigger the scan
	scanURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/scan",
		*privateRegistryURL, args.Project, repo, args.Tag)

	httpClient := newPrivateRegistryHTTPClient()
	httpClient.Timeout = 3 * time.Minute

	// Include "vulnerability" in the scan request.
	scanPayload := strings.NewReader(`{"scan_type": "vulnerability"}`)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", scanURL, scanPayload)
	if err != nil {
		return nil, ScanResult{}, fmt.Errorf("failed to create scan request: %w", err)
	}
	httpReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
	httpReq.Header.Set("Content-Type", "application/json")

	scanResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, ScanResult{}, fmt.Errorf("failed to trigger scan: %w", err)
	}
	defer scanResp.Body.Close()

	fmt.Printf("resp %s", scanResp.Body)

	// A 202 Accepted status means the scan was successfully triggered.
	// Other statuses might indicate an ongoing scan or an error.
	if scanResp.StatusCode != http.StatusAccepted && scanResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(scanResp.Body)
		return nil, ScanResult{}, fmt.Errorf("failed to trigger scan, status %d: %s", scanResp.StatusCode, string(body))
	}

	// 2. Poll for scan completion.
	// In a production system, you might want a more robust polling strategy with timeouts.
	// For this example, we'll poll for a short period.
	reportURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities",
		*privateRegistryURL, args.Project, repo, args.Tag)

	var reportData map[string]privateRegistryVulnerabilityReport
	for i := 0; i < 60; i++ { // Poll up to 60 times
		time.Sleep(5 * time.Second) // Wait before checking

		reportReq, err := http.NewRequestWithContext(ctx, "GET", reportURL, nil)
		if err != nil {
			return nil, ScanResult{}, fmt.Errorf("failed to create report request: %w", err)
		}
		reportReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
		reportReq.Header.Set("Accept", "application/json")

		reportResp, err := httpClient.Do(reportReq)
		if err != nil {
			return nil, ScanResult{}, fmt.Errorf("failed to get scan report: %w", err)
		}

		if reportResp.StatusCode == http.StatusOK {
			// Private Registry returns a map where the key is the mime-type of the report.
			if err := json.NewDecoder(reportResp.Body).Decode(&reportData); err != nil {
				reportResp.Body.Close()
				return nil, ScanResult{}, fmt.Errorf("failed to decode report: %w", err)
			}
			reportResp.Body.Close()
			// We found the report, break the loop.
			goto found
		}
		reportResp.Body.Close()
	}

	return nil, ScanResult{}, fmt.Errorf("timed out waiting for scan report")

found:
	vulnerabilities := []Vulnerability{}
	// The report is a map, e.g., {"application/vnd.security.vulnerability.report; version=1.1": [...]}.
	// We just need the values from the first entry.
	for _, report := range reportData {
		// The actual list of vulnerabilities is inside the report object.
		if report.Vulnerabilities != nil {
			vulnerabilities = report.Vulnerabilities
		}
		break
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: fmt.Sprintf("Found %d vulnerabilities.", len(vulnerabilities))},
		},
	}, ScanResult{Vulnerabilities: vulnerabilities}, nil
}

// GetVulnerabilities retrieves the vulnerability report for a specific container image from privateRegistry.
func GetVulnerabilities(ctx context.Context, req *mcp.CallToolRequest, args GetVulnerabilitiesParams) (*mcp.CallToolResult, GetVulnerabilitiesResult, error) {
	if *privateRegistryPassword == "" {
		return nil, GetVulnerabilitiesResult{}, fmt.Errorf("private-registry-password flag is not set")
	}

	// Sanitize string inputs.
	args.Project = strings.TrimSpace(args.Project)
	args.Repository = strings.TrimSpace(args.Repository)
	args.Tag = strings.TrimSpace(args.Tag)
	if args.Project == "" || args.Repository == "" || args.Tag == "" {
		return nil, GetVulnerabilitiesResult{}, fmt.Errorf("project, repository, and tag are required parameters")
	}

	httpClient := newPrivateRegistryHTTPClient()

	repo := strings.ReplaceAll(args.Repository, "/", "%2F")
	reportURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities",
		*privateRegistryURL, args.Project, repo, args.Tag)

	log.Printf("Fetching vulnerabilities for %s/%s:%s", args.Project, args.Repository, args.Tag)

	reportReq, err := http.NewRequestWithContext(ctx, "GET", reportURL, nil)
	if err != nil {
		return nil, GetVulnerabilitiesResult{}, fmt.Errorf("failed to create report request: %w", err)
	}
	reportReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
	reportReq.Header.Set("Accept", "application/json")

	reportResp, err := httpClient.Do(reportReq)
	if err != nil {
		return nil, GetVulnerabilitiesResult{}, fmt.Errorf("failed to get scan report: %w", err)
	}
	defer reportResp.Body.Close()

	if reportResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(reportResp.Body)
		return nil, GetVulnerabilitiesResult{}, fmt.Errorf("failed to get vulnerability report, status %d: %s", reportResp.StatusCode, string(body))
	}

	var reportData map[string]privateRegistryVulnerabilityReport
	if err := json.NewDecoder(reportResp.Body).Decode(&reportData); err != nil {
		return nil, GetVulnerabilitiesResult{}, fmt.Errorf("failed to decode report: %w", err)
	}

	var vulnerabilities []Vulnerability
	for _, report := range reportData {
		if report.Vulnerabilities != nil {
			vulnerabilities = report.Vulnerabilities
		}
		break
	}

	result := GetVulnerabilitiesResult{
		ImageName:       fmt.Sprintf("%s/%s:%s", args.Project, args.Repository, args.Tag),
		Vulnerabilities: vulnerabilities,
		TotalCount:      len(vulnerabilities),
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: fmt.Sprintf("Found %d vulnerabilities for image %s.", len(vulnerabilities), result.ImageName)},
		},
	}, result, nil
}

// GetSBOM retrieves the Software Bill of Materials (SBOM) for a specific container image from privateRegistry.
func GetSBOM(ctx context.Context, req *mcp.CallToolRequest, args GetSBOMParams) (*mcp.CallToolResult, GetSBOMResult, error) {
	if *privateRegistryPassword == "" {
		return nil, GetSBOMResult{}, fmt.Errorf("private-registry-password flag is not set")
	}

	// Sanitize string inputs.
	args.Project = strings.TrimSpace(args.Project)
	args.Repository = strings.TrimSpace(args.Repository)
	args.Tag = strings.TrimSpace(args.Tag)
	if args.Project == "" || args.Repository == "" || args.Tag == "" {
		return nil, GetSBOMResult{}, fmt.Errorf("project, repository, and tag are required parameters")
	}

	httpClient := newPrivateRegistryHTTPClient()

	repo := strings.ReplaceAll(args.Repository, "/", "%2F")

	// 1. Get artifact details to find the digest.
	artifactURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s",
		*privateRegistryURL, args.Project, repo, args.Tag)
	log.Printf("Getting artifact details from: %s", artifactURL)
	artifactReq, err := http.NewRequestWithContext(ctx, "GET", artifactURL, nil)
	if err != nil {
		return nil, GetSBOMResult{}, fmt.Errorf("failed to create artifact details request: %w", err)
	}
	artifactReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
	artifactResp, err := httpClient.Do(artifactReq)
	if err != nil {
		return nil, GetSBOMResult{}, fmt.Errorf("failed to get artifact details: %w", err)
	}
	defer artifactResp.Body.Close()

	if artifactResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(artifactResp.Body)
		return nil, GetSBOMResult{}, fmt.Errorf("failed to get artifact details, status %d: %s", artifactResp.StatusCode, string(body))
	}

	var artifact struct {
		Digest string `json:"digest"`
	}
	if err := json.NewDecoder(artifactResp.Body).Decode(&artifact); err != nil {
		return nil, GetSBOMResult{}, fmt.Errorf("failed to decode artifact details: %w", err)
	}

	if artifact.Digest == "" {
		return nil, GetSBOMResult{}, fmt.Errorf("could not find digest for artifact %s/%s:%s", args.Project, args.Repository, args.Tag)
	}
	log.Printf("Found digest '%s' for artifact %s/%s:%s", artifact.Digest, args.Project, args.Repository, args.Tag)

	// 2. Download the SBOM using the digest.
	sbomURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/sbom",
		*privateRegistryURL, args.Project, repo, artifact.Digest)
	log.Printf("Downloading SBOM from: %s", sbomURL)

	sbomReq, err := http.NewRequestWithContext(ctx, "GET", sbomURL, nil)
	if err != nil {
		return nil, GetSBOMResult{}, fmt.Errorf("failed to create SBOM download request: %w", err)
	}
	sbomReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
	// The API returns a JSON response that contains the SBOM as a raw JSON object.
	sbomReq.Header.Set("Accept", "application/json")

	var sbomResp *http.Response
	sbomResp, err = httpClient.Do(sbomReq)
	if err != nil {
		return nil, GetSBOMResult{}, fmt.Errorf("failed to download SBOM: %w", err)
	}

	if sbomResp.StatusCode == http.StatusOK {
		goto found
	} else if sbomResp.StatusCode == http.StatusNotFound {
		// SBOM does not exist, we need to trigger a scan.
		log.Printf("SBOM not found for %s. Triggering a scan.", artifact.Digest)
		scanURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/scan",
			*privateRegistryURL, args.Project, repo, args.Tag)
		scanPayload := strings.NewReader(`{"scan_type": "sbom"}`)
		scanReq, err := http.NewRequestWithContext(ctx, "POST", scanURL, scanPayload)
		if err != nil {
			return nil, GetSBOMResult{}, fmt.Errorf("failed to create scan request: %w", err)
		}
		scanReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
		scanReq.Header.Set("Content-Type", "application/json")
		scanReq.Header.Set("X-Accept-Vulnerabilities", "application/vnd.security.vulnerability.report; version=1.1, application/vnd.cyclonedx+json; version=1.4")

		scanResp, err := httpClient.Do(scanReq)
		if err != nil {
			return nil, GetSBOMResult{}, fmt.Errorf("failed to trigger scan: %w", err)
		}
		defer scanResp.Body.Close()

		if scanResp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(scanResp.Body)
			return nil, GetSBOMResult{}, fmt.Errorf("failed to trigger scan, status %d: %s", scanResp.StatusCode, string(body))
		}

		// Poll for the SBOM to become available.
		for i := 0; i < 60; i++ { // Poll for up to 5 minutes
			time.Sleep(5 * time.Second)
			pollResp, err := httpClient.Do(sbomReq) // Reuse the sbomReq
			if err != nil {
				continue
			}
			if pollResp.StatusCode == http.StatusOK {
				sbomResp = pollResp
				goto found
			}
			pollResp.Body.Close()
		}
		return nil, GetSBOMResult{}, fmt.Errorf("timed out waiting for SBOM after scan")
	} else {
		body, _ := io.ReadAll(sbomResp.Body)
		sbomResp.Body.Close()
		// Check for a specific Private Registry limitation with Docker v2 manifests.
		if strings.Contains(string(body), "SBOM isn't supported for IMAGE") {
			// Construct the UI link for the SBOM
			uiLink := fmt.Sprintf("%s/mcp-spr/projects/1/repositories/%s/artifacts-tab/artifacts/%s?tab=sbom", strings.TrimSuffix(*privateRegistryURL, "/api/v2.0"), args.Repository, artifact.Digest)
			imageName := fmt.Sprintf("%s/%s:%s", args.Project, args.Repository, args.Tag)
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("SUSE Private Registry does not support SBOM generation for image %s because it uses an older manifest format (Docker v2). However, the SBOM may be available in the privateRegistry UI at: %s", imageName, uiLink)},
				},
			}, GetSBOMResult{ImageName: imageName, SBOMURL: uiLink}, nil
		}
		return nil, GetSBOMResult{}, fmt.Errorf("failed to download SBOM, status %d: %s", sbomResp.StatusCode, string(body))
	}

found:
	var sbom map[string]interface{}
	if err := json.NewDecoder(sbomResp.Body).Decode(&sbom); err != nil {
		sbomResp.Body.Close()
		return nil, GetSBOMResult{}, fmt.Errorf("failed to decode SBOM: %w", err)
	}
	sbomResp.Body.Close()

	result := GetSBOMResult{
		ImageName: fmt.Sprintf("%s/%s:%s", args.Project, args.Repository, args.Tag),
		SBOM:      sbom,
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Successfully retrieved SBOM for image %s.", result.ImageName)}},
	}, result, nil
}

// GetProjectSBOM retrieves the Software Bill of Materials (SBOM) for all images in a specific privateRegistry project.
func GetProjectSBOM(ctx context.Context, req *mcp.CallToolRequest, args GetProjectSBOMParams) (*mcp.CallToolResult, GetProjectSBOMResult, error) {
	if *privateRegistryPassword == "" {
		return nil, GetProjectSBOMResult{}, fmt.Errorf("private-registry-password flag is not set")
	}
	if args.Project == "" {
		return nil, GetProjectSBOMResult{}, fmt.Errorf("project is a required parameter")
	}

	// Sanitize string inputs.
	args.Project = strings.TrimSpace(args.Project)

	httpClient := newPrivateRegistryHTTPClient()

	// 1. List repositories in the project
	log.Printf("Starting SBOM retrieval for project: %s", args.Project)
	reposURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories", *privateRegistryURL, args.Project)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", reposURL, nil)
	if err != nil {
		return nil, GetProjectSBOMResult{}, fmt.Errorf("failed to create list repositories request: %w", err)
	}
	httpReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)

	repoResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, GetProjectSBOMResult{}, fmt.Errorf("failed to list repositories: %w", err)
	}
	defer repoResp.Body.Close()

	if repoResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(repoResp.Body)
		return nil, GetProjectSBOMResult{}, fmt.Errorf("failed to list repositories, status %d: %s", repoResp.StatusCode, string(body))
	}

	type Repository struct {
		Name string `json:"name"`
	}
	var repositories []Repository
	if err := json.NewDecoder(repoResp.Body).Decode(&repositories); err != nil {
		return nil, GetProjectSBOMResult{}, fmt.Errorf("failed to decode repositories list: %w", err)
	}
	log.Printf("Found %d repositories in project %s.", len(repositories), args.Project)

	var imagesScanned int

	// 2. For each repository, list artifacts and get their SBOM.
	for _, repo := range repositories {
		log.Printf("Processing repository for SBOMs: %s", repo.Name)
		repoNameOnly := strings.TrimPrefix(repo.Name, args.Project+"/")
		repoNameEncoded := strings.ReplaceAll(repoNameOnly, "/", "%2F")

		artifactsURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts", *privateRegistryURL, args.Project, repoNameEncoded)
		artifactsReq, err := http.NewRequestWithContext(ctx, "GET", artifactsURL, nil)
		if err != nil {
			log.Printf("Error creating artifacts request for %s: %v", repo.Name, err)
			continue
		}
		artifactsReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)

		artifactsResp, err := httpClient.Do(artifactsReq)
		if err != nil {
			log.Printf("Error listing artifacts for %s: %v", repo.Name, err)
			continue
		}

		type Artifact struct {
			Type   string `json:"type"`
			Digest string `json:"digest"`
			Tags   []struct {
				// We only need the name for now.
				Name string `json:"name"`
			} `json:"tags"`
		}
		var artifacts []Artifact
		if err := json.NewDecoder(artifactsResp.Body).Decode(&artifacts); err != nil {
			log.Printf("Error decoding artifacts for %s: %v", repo.Name, err)
			artifactsResp.Body.Close()
			continue
		}
		artifactsResp.Body.Close()

		// 3. For each image artifact, get its SBOM.
		for _, artifact := range artifacts {
			if artifact.Type != "IMAGE" || len(artifact.Tags) == 0 {
				continue
			}
			tag := artifact.Tags[0].Name // Use the first tag.

			// Trigger an SBOM scan for the image artifact.
			log.Printf("Triggering SBOM scan for image: %s:%s", repo.Name, tag)
			scanURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/scan",
				*privateRegistryURL, args.Project, repoNameEncoded, tag)

			scanPayload := strings.NewReader(`{"scan_type": "sbom"}`)
			scanReq, err := http.NewRequestWithContext(ctx, "POST", scanURL, scanPayload)
			if err != nil {
				log.Printf("Error creating SBOM scan request for %s:%s: %v", repo.Name, tag, err)
				continue
			}
			scanReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
			scanReq.Header.Set("Content-Type", "application/json")
			scanReq.Header.Set("X-Accept-Vulnerabilities", "application/vnd.cyclonedx+json; version=1.4")

			scanResp, err := httpClient.Do(scanReq)
			if err != nil {
				log.Printf("Error triggering SBOM scan for %s:%s: %v", repo.Name, tag, err)
				continue
			}
			scanResp.Body.Close()

			if scanResp.StatusCode == http.StatusAccepted {
				imagesScanned++
			} else {
				log.Printf("Failed to trigger SBOM scan for %s:%s, status: %d", repo.Name, tag, scanResp.StatusCode)
			}
		}
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Successfully triggered SBOM generation for %d images in project %s. The SBOMs will be available shortly.", imagesScanned, args.Project)}},
	}, GetProjectSBOMResult{}, nil
}

// ListProjects lists all projects visible in the Private Registry.
func ListProjects(ctx context.Context, req *mcp.CallToolRequest, args ListProjectsParams) (*mcp.CallToolResult, ListProjectsResult, error) {
	if *privateRegistryPassword == "" {
		return nil, ListProjectsResult{}, fmt.Errorf("private-registry-password flag is not set")
	}

	httpClient := newPrivateRegistryHTTPClient()

	projectsURL := fmt.Sprintf("%s/api/v2.0/projects", *privateRegistryURL)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", projectsURL, nil)
	if err != nil {
		return nil, ListProjectsResult{}, fmt.Errorf("failed to create list projects request: %w", err)
	}
	httpReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, ListProjectsResult{}, fmt.Errorf("failed to list projects: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, ListProjectsResult{}, fmt.Errorf("failed to list projects, status %d: %s", resp.StatusCode, string(body))
	}

	type harborProject struct {
		Name         string `json:"name"`
		RepoCount    int    `json:"repo_count"`
		CreationTime string `json:"creation_time"`
	}
	var projects []harborProject
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return nil, ListProjectsResult{}, fmt.Errorf("failed to decode projects list: %w", err)
	}

	result := ListProjectsResult{Projects: make([]ProjectInfo, 0, len(projects))}
	for _, p := range projects {
		result.Projects = append(result.Projects, ProjectInfo{Name: p.Name, RepoCount: p.RepoCount, CreationTime: p.CreationTime})
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found %d projects.", len(result.Projects))}},
	}, result, nil
}

// CreateProject creates a Harbor project. Projects are private unless public is true.
func CreateProject(ctx context.Context, req *mcp.CallToolRequest, args CreateProjectParams) (*mcp.CallToolResult, CreateProjectResult, error) {
	if *privateRegistryPassword == "" {
		return nil, CreateProjectResult{}, fmt.Errorf("private-registry-password flag is not set")
	}
	args.Project = strings.TrimSpace(args.Project)
	if args.Project == "" {
		return nil, CreateProjectResult{}, fmt.Errorf("project is a required parameter")
	}

	payload, err := json.Marshal(struct {
		ProjectName string `json:"project_name"`
		Public      bool   `json:"public"`
	}{
		ProjectName: args.Project,
		Public:      args.Public,
	})
	if err != nil {
		return nil, CreateProjectResult{}, fmt.Errorf("failed to encode project creation request: %w", err)
	}

	endpoint := strings.TrimRight(*privateRegistryURL, "/") + "/api/v2.0/projects"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return nil, CreateProjectResult{}, fmt.Errorf("failed to create Harbor project request: %w", err)
	}
	httpReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := newPrivateRegistryHTTPClient().Do(httpReq)
	if err != nil {
		return nil, CreateProjectResult{}, fmt.Errorf("failed to create Harbor project %q: %w", args.Project, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return nil, CreateProjectResult{}, fmt.Errorf("Harbor returned status %d creating project %q and its error body could not be read: %w", resp.StatusCode, args.Project, readErr)
		}
		return nil, CreateProjectResult{}, fmt.Errorf("Harbor returned status %d creating project %q: %s", resp.StatusCode, args.Project, strings.TrimSpace(string(body)))
	}

	result := CreateProjectResult{Project: args.Project, Public: args.Public}
	visibility := "private"
	if result.Public {
		visibility = "public"
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Created %s project %q.", visibility, result.Project)}},
	}, result, nil
}

// GetHealth retrieves the current health status of Harbor and its components.
func GetHealth(ctx context.Context, req *mcp.CallToolRequest, args GetHealthParams) (*mcp.CallToolResult, GetHealthResult, error) {
	if *privateRegistryPassword == "" {
		return nil, GetHealthResult{}, fmt.Errorf("private-registry-password flag is not set")
	}

	var health GetHealthResult
	if err := privateRegistryAPIGet(ctx, "health", nil, &health); err != nil {
		return nil, GetHealthResult{}, fmt.Errorf("failed to get Harbor health: %w", err)
	}
	if health.Components == nil {
		health.Components = []RegistryHealthStatus{}
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Harbor health: %s (%d components).", health.Status, len(health.Components))}},
	}, health, nil
}

// Search searches Harbor projects and repositories by name.
func Search(ctx context.Context, req *mcp.CallToolRequest, args SearchParams) (*mcp.CallToolResult, SearchResult, error) {
	if *privateRegistryPassword == "" {
		return nil, SearchResult{}, fmt.Errorf("private-registry-password flag is not set")
	}
	args.Query = strings.TrimSpace(args.Query)
	if args.Query == "" {
		return nil, SearchResult{}, fmt.Errorf("query is a required parameter")
	}

	var harborResults struct {
		Projects     []SearchProject    `json:"project"`
		Repositories []SearchRepository `json:"repository"`
	}
	query := url.Values{"q": []string{args.Query}}
	if err := privateRegistryAPIGet(ctx, "search", query, &harborResults); err != nil {
		return nil, SearchResult{}, fmt.Errorf("failed to search Harbor: %w", err)
	}
	if harborResults.Projects == nil {
		harborResults.Projects = []SearchProject{}
	}
	if harborResults.Repositories == nil {
		harborResults.Repositories = []SearchRepository{}
	}
	result := SearchResult{Projects: harborResults.Projects, Repositories: harborResults.Repositories}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found %d projects and %d repositories matching %q.", len(result.Projects), len(result.Repositories), args.Query)}},
	}, result, nil
}

// ListQuotas retrieves a page of project quotas, optionally filtered by project name.
func ListQuotas(ctx context.Context, req *mcp.CallToolRequest, args ListQuotasParams) (*mcp.CallToolResult, ListQuotasResult, error) {
	if *privateRegistryPassword == "" {
		return nil, ListQuotasResult{}, fmt.Errorf("private-registry-password flag is not set")
	}
	if args.Page == 0 {
		args.Page = 1
	}
	if args.Page < 1 {
		return nil, ListQuotasResult{}, fmt.Errorf("page must be greater than zero")
	}
	if args.PageSize == 0 {
		args.PageSize = 100
	}
	if args.PageSize < 1 || args.PageSize > 100 {
		return nil, ListQuotasResult{}, fmt.Errorf("page_size must be between 1 and 100")
	}
	args.Project = strings.TrimSpace(args.Project)

	query := url.Values{
		"page":      []string{fmt.Sprint(args.Page)},
		"page_size": []string{fmt.Sprint(args.PageSize)},
	}
	if args.Project != "" {
		var projects []struct {
			ID   int64  `json:"project_id"`
			Name string `json:"name"`
		}
		projectQuery := url.Values{"name": []string{args.Project}}
		if err := privateRegistryAPIGet(ctx, "projects", projectQuery, &projects); err != nil {
			return nil, ListQuotasResult{}, fmt.Errorf("failed to find project %s: %w", args.Project, err)
		}
		var projectID int64
		for _, project := range projects {
			if project.Name == args.Project {
				projectID = project.ID
				break
			}
		}
		if projectID == 0 {
			return nil, ListQuotasResult{}, fmt.Errorf("project %q not found", args.Project)
		}
		query.Set("reference", "project")
		query.Set("reference_id", fmt.Sprint(projectID))
	}
	var quotas []RegistryQuota
	if err := privateRegistryAPIGet(ctx, "quotas", query, &quotas); err != nil {
		return nil, ListQuotasResult{}, fmt.Errorf("failed to list Harbor quotas: %w", err)
	}
	if quotas == nil {
		quotas = []RegistryQuota{}
	}
	result := ListQuotasResult{Quotas: quotas, Page: args.Page, PageSize: args.PageSize}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found %d quotas on page %d (page size %d).", len(result.Quotas), result.Page, result.PageSize)}},
	}, result, nil
}

// GetProjectSummary returns project metadata and aggregated repository/artifact counts without starting scans.
func GetProjectSummary(ctx context.Context, req *mcp.CallToolRequest, args ProjectSummaryParams) (*mcp.CallToolResult, ProjectSummaryResult, error) {
	if *privateRegistryPassword == "" {
		return nil, ProjectSummaryResult{}, fmt.Errorf("private-registry-password flag is not set")
	}
	args.Project = strings.TrimSpace(args.Project)
	if args.Project == "" {
		return nil, ProjectSummaryResult{}, fmt.Errorf("project is a required parameter")
	}

	projectQuery := url.Values{"name": []string{args.Project}}
	var projects []ProjectInfo
	if err := privateRegistryAPIGet(ctx, "projects", projectQuery, &projects); err != nil {
		return nil, ProjectSummaryResult{}, fmt.Errorf("failed to get project details: %w", err)
	}

	var project *ProjectInfo
	for i := range projects {
		if projects[i].Name == args.Project {
			project = &projects[i]
			break
		}
	}
	if project == nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Project %s not found.", args.Project)}},
		}, ProjectSummaryResult{Found: false}, nil
	}

	const pageSize = 100
	const maxPages = 1000
	var repositories []RepositoryInfo
	for page := 1; page <= maxPages; page++ {
		query := url.Values{
			"page":      []string{fmt.Sprint(page)},
			"page_size": []string{fmt.Sprint(pageSize)},
		}
		path := "projects/" + url.PathEscape(args.Project) + "/repositories"
		var pageRepositories []RepositoryInfo
		if err := privateRegistryAPIGet(ctx, path, query, &pageRepositories); err != nil {
			return nil, ProjectSummaryResult{}, fmt.Errorf("failed to list repositories for project %s: %w", args.Project, err)
		}
		repositories = append(repositories, pageRepositories...)
		if len(pageRepositories) < pageSize {
			break
		}
		if page == maxPages {
			return nil, ProjectSummaryResult{}, fmt.Errorf("project %s has more repositories than the supported pagination limit", args.Project)
		}
	}

	artifactCount := 0
	for _, repository := range repositories {
		artifactCount += repository.ArtifactCount
	}
	result := ProjectSummaryResult{
		Found:           true,
		Project:         *project,
		RepositoryCount: len(repositories),
		ArtifactCount:   artifactCount,
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Project %s has %d repositories and %d artifacts.", result.Project.Name, result.RepositoryCount, result.ArtifactCount)}},
	}, result, nil
}

// GetProject fetches details for a single Private Registry project by name.
func GetProject(ctx context.Context, req *mcp.CallToolRequest, args GetProjectParams) (*mcp.CallToolResult, GetProjectResult, error) {
	if *privateRegistryPassword == "" {
		return nil, GetProjectResult{}, fmt.Errorf("private-registry-password flag is not set")
	}
	if args.Project == "" {
		return nil, GetProjectResult{}, fmt.Errorf("project is a required parameter")
	}
	args.Project = strings.TrimSpace(args.Project)

	httpClient := newPrivateRegistryHTTPClient()

	// Search by name rather than fetching by ID to avoid Harbor's ID-vs-name
	// resolution header (X-Is-Resource-Name).
	projectsURL := fmt.Sprintf("%s/api/v2.0/projects?name=%s", *privateRegistryURL, url.QueryEscape(args.Project))
	httpReq, err := http.NewRequestWithContext(ctx, "GET", projectsURL, nil)
	if err != nil {
		return nil, GetProjectResult{}, fmt.Errorf("failed to create get project request: %w", err)
	}
	httpReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, GetProjectResult{}, fmt.Errorf("failed to get project: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, GetProjectResult{}, fmt.Errorf("failed to get project, status %d: %s", resp.StatusCode, string(body))
	}

	type harborProject struct {
		Name         string `json:"name"`
		RepoCount    int    `json:"repo_count"`
		CreationTime string `json:"creation_time"`
	}
	var projects []harborProject
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return nil, GetProjectResult{}, fmt.Errorf("failed to decode project: %w", err)
	}

	for _, p := range projects {
		if p.Name == args.Project {
			result := GetProjectResult{Found: true, Project: ProjectInfo{Name: p.Name, RepoCount: p.RepoCount, CreationTime: p.CreationTime}}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found project %s.", p.Name)}},
			}, result, nil
		}
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Project %s not found.", args.Project)}},
	}, GetProjectResult{Found: false}, nil
}

// ListRepositories lists all repositories within a Private Registry project.
func ListRepositories(ctx context.Context, req *mcp.CallToolRequest, args ListRepositoriesParams) (*mcp.CallToolResult, ListRepositoriesResult, error) {
	if *privateRegistryPassword == "" {
		return nil, ListRepositoriesResult{}, fmt.Errorf("private-registry-password flag is not set")
	}
	if args.Project == "" {
		return nil, ListRepositoriesResult{}, fmt.Errorf("project is a required parameter")
	}
	args.Project = strings.TrimSpace(args.Project)

	httpClient := newPrivateRegistryHTTPClient()

	reposURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories", *privateRegistryURL, args.Project)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", reposURL, nil)
	if err != nil {
		return nil, ListRepositoriesResult{}, fmt.Errorf("failed to create list repositories request: %w", err)
	}
	httpReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, ListRepositoriesResult{}, fmt.Errorf("failed to list repositories: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, ListRepositoriesResult{}, fmt.Errorf("failed to list repositories, status %d: %s", resp.StatusCode, string(body))
	}

	type harborRepository struct {
		Name          string `json:"name"`
		ArtifactCount int    `json:"artifact_count"`
	}
	var repositories []harborRepository
	if err := json.NewDecoder(resp.Body).Decode(&repositories); err != nil {
		return nil, ListRepositoriesResult{}, fmt.Errorf("failed to decode repositories list: %w", err)
	}

	result := ListRepositoriesResult{Repositories: make([]RepositoryInfo, 0, len(repositories))}
	for _, r := range repositories {
		result.Repositories = append(result.Repositories, RepositoryInfo{Name: r.Name, ArtifactCount: r.ArtifactCount})
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found %d repositories in project %s.", len(result.Repositories), args.Project)}},
	}, result, nil
}

// ListTags lists all tags of artifacts within a repository.
func ListTags(ctx context.Context, req *mcp.CallToolRequest, args ListTagsParams) (*mcp.CallToolResult, ListTagsResult, error) {
	if *privateRegistryPassword == "" {
		return nil, ListTagsResult{}, fmt.Errorf("private-registry-password flag is not set")
	}
	if args.Project == "" || args.Repository == "" {
		return nil, ListTagsResult{}, fmt.Errorf("project and repository are required parameters")
	}
	args.Project = strings.TrimSpace(args.Project)
	args.Repository = strings.TrimSpace(args.Repository)

	httpClient := newPrivateRegistryHTTPClient()

	repoEncoded := strings.ReplaceAll(args.Repository, "/", "%2F")
	artifactsURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts?with_tag=true", *privateRegistryURL, args.Project, repoEncoded)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", artifactsURL, nil)
	if err != nil {
		return nil, ListTagsResult{}, fmt.Errorf("failed to create list tags request: %w", err)
	}
	httpReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, ListTagsResult{}, fmt.Errorf("failed to list tags: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, ListTagsResult{}, fmt.Errorf("failed to list tags, status %d: %s", resp.StatusCode, string(body))
	}

	type harborArtifact struct {
		Type string `json:"type"`
		Tags []struct {
			Name string `json:"name"`
		} `json:"tags"`
	}
	var artifacts []harborArtifact
	if err := json.NewDecoder(resp.Body).Decode(&artifacts); err != nil {
		return nil, ListTagsResult{}, fmt.Errorf("failed to decode artifacts list: %w", err)
	}

	var tags []TagInfo
	for _, a := range artifacts {
		for _, t := range a.Tags {
			tags = append(tags, TagInfo{Name: t.Name, ArtifactType: a.Type})
		}
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found %d tags in %s/%s.", len(tags), args.Project, args.Repository)}},
	}, ListTagsResult{Tags: tags}, nil
}

// ListCharts lists Helm charts in a project. This relies on Harbor's legacy chart
// repository (ChartMuseum-backed) API, which is disabled by default on Harbor 2.11+.
func ListCharts(ctx context.Context, req *mcp.CallToolRequest, args ListChartsParams) (*mcp.CallToolResult, ListChartsResult, error) {
	if *privateRegistryPassword == "" {
		return nil, ListChartsResult{}, fmt.Errorf("private-registry-password flag is not set")
	}
	if args.Project == "" {
		return nil, ListChartsResult{}, fmt.Errorf("project is a required parameter")
	}
	args.Project = strings.TrimSpace(args.Project)

	httpClient := newPrivateRegistryHTTPClient()

	chartsURL := fmt.Sprintf("%s/api/chartrepo/%s/charts", *privateRegistryURL, args.Project)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", chartsURL, nil)
	if err != nil {
		return nil, ListChartsResult{}, fmt.Errorf("failed to create list charts request: %w", err)
	}
	httpReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, ListChartsResult{}, fmt.Errorf("failed to list charts: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ListChartsResult{}, fmt.Errorf("chart repository API not found (status 404) for project %s; this Harbor instance may not have Helm chart support enabled", args.Project)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, ListChartsResult{}, fmt.Errorf("failed to list charts, status %d: %s", resp.StatusCode, string(body))
	}

	type harborChart struct {
		Name   string `json:"name"`
		Latest struct {
			Version string `json:"version"`
		} `json:"latest_version"`
	}
	var charts []harborChart
	if err := json.NewDecoder(resp.Body).Decode(&charts); err != nil {
		return nil, ListChartsResult{}, fmt.Errorf("failed to decode charts list: %w", err)
	}

	result := ListChartsResult{Charts: make([]ChartInfo, 0, len(charts))}
	for _, c := range charts {
		result.Charts = append(result.Charts, ChartInfo{Name: c.Name, LatestVersion: c.Latest.Version})
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found %d Helm charts in project %s.", len(result.Charts), args.Project)}},
	}, result, nil
}

// ListChartVersions lists versions of a single Helm chart. Like ListCharts, this relies
// on Harbor's legacy chart repository API, which is disabled by default on Harbor 2.11+.
func ListChartVersions(ctx context.Context, req *mcp.CallToolRequest, args ListChartVersionsParams) (*mcp.CallToolResult, ListChartVersionsResult, error) {
	if *privateRegistryPassword == "" {
		return nil, ListChartVersionsResult{}, fmt.Errorf("private-registry-password flag is not set")
	}
	if args.Project == "" || args.Chart == "" {
		return nil, ListChartVersionsResult{}, fmt.Errorf("project and chart are required parameters")
	}
	args.Project = strings.TrimSpace(args.Project)
	args.Chart = strings.TrimSpace(args.Chart)

	httpClient := newPrivateRegistryHTTPClient()

	versionsURL := fmt.Sprintf("%s/api/chartrepo/%s/charts/%s", *privateRegistryURL, args.Project, args.Chart)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", versionsURL, nil)
	if err != nil {
		return nil, ListChartVersionsResult{}, fmt.Errorf("failed to create list chart versions request: %w", err)
	}
	httpReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, ListChartVersionsResult{}, fmt.Errorf("failed to list chart versions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ListChartVersionsResult{}, fmt.Errorf("chart %s not found (status 404) in project %s; this Harbor instance may not have Helm chart support enabled", args.Chart, args.Project)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, ListChartVersionsResult{}, fmt.Errorf("failed to list chart versions, status %d: %s", resp.StatusCode, string(body))
	}

	type harborChartVersion struct {
		Version    string `json:"version"`
		AppVersion string `json:"appVersion"`
	}
	var versions []harborChartVersion
	if err := json.NewDecoder(resp.Body).Decode(&versions); err != nil {
		return nil, ListChartVersionsResult{}, fmt.Errorf("failed to decode chart versions: %w", err)
	}

	result := ListChartVersionsResult{Versions: make([]ChartVersionInfo, 0, len(versions))}
	for _, v := range versions {
		result.Versions = append(result.Versions, ChartVersionInfo{Version: v.Version, AppVersion: v.AppVersion})
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found %d versions of chart %s in project %s.", len(result.Versions), args.Chart, args.Project)}},
	}, result, nil
}

// ScanProject scans all images in a given Private Registry project and returns a summary of vulnerabilities.
func ScanProject(ctx context.Context, req *mcp.CallToolRequest, args ScanProjectParams) (*mcp.CallToolResult, ScanProjectResult, error) {
	if *privateRegistryPassword == "" {
		// It's good practice to log when returning an error.
		log.Println("Error: private-registry-password flag is not set.")
		return nil, ScanProjectResult{}, fmt.Errorf("private-registry-password flag is not set")
	}
	if args.Project == "" {
		return nil, ScanProjectResult{}, fmt.Errorf("private-registry-password flag is not set")
	}

	// Sanitize string inputs.
	args.Project = strings.TrimSpace(args.Project)

	httpClient := newPrivateRegistryHTTPClient()

	// Use an independent operation context so scans continue even if the client
	// disconnects. Also provide a periodic progress notification to the client.
	opCtx, cancel := context.WithTimeout(context.Background(), *scanTimeout)
	defer cancel()

	var totalRepos int
	var processedRepos int64

	var progressToken interface{}
	if req != nil {
		if p, ok := req.GetParams().(mcp.RequestParams); ok {
			progressToken = p.GetProgressToken()
		}
	}

	// Start progress notifier if we have a session to notify.
	if req != nil && req.GetSession() != nil {
		go func() {
			ticker := time.NewTicker(*progressInterval)
			defer ticker.Stop()
			for {
				select {
				case <-opCtx.Done():
					return
				case <-ticker.C:
					prog := float64(atomic.LoadInt64(&processedRepos))
					tot := float64(totalRepos)
					msg := fmt.Sprintf("Processed %d of %d repositories", atomic.LoadInt64(&processedRepos), totalRepos)
					if ss, ok := req.GetSession().(*mcp.ServerSession); ok {
						_ = ss.NotifyProgress(context.Background(), &mcp.ProgressNotificationParams{
							ProgressToken: progressToken,
							Message:       msg,
							Progress:      prog,
							Total:         tot,
						})
					}
				}
			}
		}()
	}

	// 1. List repositories in the project
	log.Printf("Starting scan for project: %s", args.Project)
	reposURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories", *privateRegistryURL, args.Project)
	httpReq, err := http.NewRequestWithContext(opCtx, "GET", reposURL, nil)
	if err != nil {
		return nil, ScanProjectResult{}, fmt.Errorf("failed to create list repositories request: %w", err)
	}
	httpReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)

	repoResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, ScanProjectResult{}, fmt.Errorf("failed to list repositories: %w", err)
	}
	defer repoResp.Body.Close()

	if repoResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(repoResp.Body)
		return nil, ScanProjectResult{}, fmt.Errorf("failed to list repositories, status %d: %s", repoResp.StatusCode, string(body))
	}

	type Repository struct {
		Name string `json:"name"`
	}
	var repositories []Repository
	if err := json.NewDecoder(repoResp.Body).Decode(&repositories); err != nil {
		return nil, ScanProjectResult{}, fmt.Errorf("failed to decode repositories list: %w", err)
	}
	log.Printf("Found %d repositories in project %s.", len(repositories), args.Project)
	totalRepos = len(repositories)

	var allSummaries []ImageVulnerabilitySummary

	// 2. For each repository, list artifacts and get vulnerability summaries
	for _, repo := range repositories {
		atomic.AddInt64(&processedRepos, 1)
		// Private Registry repo names include the project, e.g., "my-project/my-repo". We need the part after the slash.
		log.Printf("Processing repository: %s", repo.Name)
		repoNameOnly := strings.TrimPrefix(repo.Name, args.Project+"/")
		repoNameEncoded := strings.ReplaceAll(repoNameOnly, "/", "%2F")

		artifactsURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts", *privateRegistryURL, args.Project, repoNameEncoded)
		artifactsReq, err := http.NewRequestWithContext(opCtx, "GET", artifactsURL, nil)
		if err != nil {
			log.Printf("Error creating artifacts request for %s: %v", repo.Name, err)
			continue
		}
		artifactsReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)

		artifactsResp, err := httpClient.Do(artifactsReq)
		if err != nil {
			log.Printf("Error listing artifacts for %s: %v", repo.Name, err)
			continue
		}

		type Artifact struct {
			Type string `json:"type"`
			Tags []struct {
				Name string `json:"name"`
			} `json:"tags"`
		}
		var artifacts []Artifact
		if err := json.NewDecoder(artifactsResp.Body).Decode(&artifacts); err != nil {
			log.Printf("Error decoding artifacts for %s: %v", repo.Name, err)
			artifactsResp.Body.Close()
			continue
		}
		artifactsResp.Body.Close()
		log.Printf("Found %d artifacts in repository %s.", len(artifacts), repo.Name)

		// 3. For each artifact, get its summary
		for _, artifact := range artifacts {
			// Skip artifacts that are not container images (like Helm charts)
			if artifact.Type != "IMAGE" {
				log.Printf("Skipping scan for non-image artifact of type %s in repo %s", artifact.Type, repo.Name)
				continue
			}

			if len(artifact.Tags) == 0 {
				continue // Skip artifacts with no tags
			}
			tag := artifact.Tags[0].Name // Use the first tag to identify the image

			// 4. Trigger a scan for the image artifact.
			log.Printf("Triggering scan for image: %s:%s", repo.Name, tag)
			scanURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/scan",
				*privateRegistryURL, args.Project, repoNameEncoded, tag)

			// Include "vulnerability" in the scan request.
			scanPayload := strings.NewReader(`{"scan_type": "vulnerability"}`)
			scanReq, err := http.NewRequestWithContext(opCtx, "POST", scanURL, scanPayload)
			if err != nil {
				log.Printf("Error creating scan request for %s:%s: %v", repo.Name, tag, err)
				continue
			}
			scanReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
			scanReq.Header.Set("Content-Type", "application/json")

			scanResp, err := httpClient.Do(scanReq)
			if err != nil {
				log.Printf("Error triggering scan for %s:%s: %v", repo.Name, tag, err)
				continue
			}
			// A 202 Accepted status means the scan was successfully triggered.
			// Other statuses might indicate an ongoing scan or an error, which we can ignore for now.
			log.Printf("Scan trigger for %s:%s returned status: %d", repo.Name, tag, scanResp.StatusCode)
			scanResp.Body.Close()

			// 5. Poll for the scan report.
			log.Printf("Polling for scan report for %s:%s...", repo.Name, tag)
			reportURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities",
				*privateRegistryURL, args.Project, repoNameEncoded, tag)

			var reportData map[string]privateRegistryVulnerabilityReport
			var reportFound bool
			for i := 0; i < 60; i++ { // Poll up to 60 times
				timer := time.NewTimer(3 * time.Second)
				select {
				case <-opCtx.Done():
					timer.Stop()
					log.Printf("Operation context done while polling for %s:%s: %v", repo.Name, tag, opCtx.Err())
					return nil, ScanProjectResult{}, fmt.Errorf("project scan timed out while polling for %s:%s: %w", repo.Name, tag, opCtx.Err())
				case <-timer.C:
				}

				reportReq, err := http.NewRequestWithContext(opCtx, "GET", reportURL, nil)
				if err != nil {
					log.Printf("Error creating report request for %s:%s: %v", repo.Name, tag, err)
					break // Stop polling for this image on error
				}
				reportReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
				reportReq.Header.Set("Accept", "application/json")

				reportResp, err := httpClient.Do(reportReq)
				if err != nil {
					if opCtx.Err() != nil {
						return nil, ScanProjectResult{}, fmt.Errorf("project scan timed out while fetching report for %s:%s: %w", repo.Name, tag, opCtx.Err())
					}
					log.Printf("Error getting report for %s:%s: %v", repo.Name, tag, err)
					break // Stop polling for this image on error
				}

				if reportResp.StatusCode == http.StatusOK {
					if err := json.NewDecoder(reportResp.Body).Decode(&reportData); err != nil {
						log.Printf("Error decoding report for %s:%s: %v", repo.Name, tag, err)
						reportResp.Body.Close()
						break // Stop polling
					}
					reportResp.Body.Close()
					reportFound = true
					log.Printf("Successfully fetched scan report for %s:%s", repo.Name, tag)
					break // Report found, exit poll loop
				}
				reportResp.Body.Close()
			}

			summary := ImageVulnerabilitySummary{ImageName: fmt.Sprintf("%s:%s", repo.Name, tag)}
			if reportFound {
				for _, report := range reportData {
					if report.Vulnerabilities != nil {
						summary.TotalCount = len(report.Vulnerabilities)
						for _, vuln := range report.Vulnerabilities {
							switch vuln.Severity {
							case "Critical":
								summary.CriticalCount++
							case "High":
								summary.HighCount++
							case "Medium":
								summary.MediumCount++
							case "Low":
								summary.LowCount++
							default:
								summary.UnknownCount++
							}
						}
					}
					break // Only process the first report type
				}
			} else {
				log.Printf("Timed out or failed to get scan report for %s:%s", repo.Name, tag)
			}
			allSummaries = append(allSummaries, summary)
		}
	}

	// Send final progress state if possible
	if req != nil && req.GetSession() != nil {
		if ss, ok := req.GetSession().(*mcp.ServerSession); ok {
			_ = ss.NotifyProgress(context.Background(), &mcp.ProgressNotificationParams{
				ProgressToken: progressToken,
				Message:       fmt.Sprintf("Completed scan for project %s", args.Project),
				Progress:      float64(atomic.LoadInt64(&processedRepos)),
				Total:         float64(totalRepos),
			})
		}
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: fmt.Sprintf("Completed scan for project %s", args.Project)},
		},
	}, ScanProjectResult{Images: allSummaries}, nil
}

// FindPatchedImage finds a newer version of an image without a specific CVE.
func FindPatchedImage(ctx context.Context, req *mcp.CallToolRequest, args FindPatchedImageParams) (*mcp.CallToolResult, FindPatchedImageResult, error) {
	if *privateRegistryPassword == "" {
		return nil, FindPatchedImageResult{}, fmt.Errorf("private-registry-password flag is not set")
	}

	args.Project = strings.TrimSpace(args.Project)
	args.Repository = strings.TrimSpace(args.Repository)
	args.Tag = strings.TrimSpace(args.Tag)
	args.CVEID = strings.TrimSpace(args.CVEID)

	httpClient := newPrivateRegistryHTTPClient()

	// 1. Search in the local Private Registry instance.
	log.Printf("[%s] START: Searching for patched image for %s/%s:%s (CVE: %s)", time.Now().Format(time.RFC3339), args.Project, args.Repository, args.Tag, args.CVEID)
	repoNameEncoded := strings.ReplaceAll(args.Repository, "/", "%2F")
	artifactsURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts?with_tag=true", *privateRegistryURL, args.Project, repoNameEncoded)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", artifactsURL, nil)
	if err != nil {
		return nil, FindPatchedImageResult{}, fmt.Errorf("failed to create list artifacts request: %w", err)
	}
	httpReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
	log.Printf("[%s] Step 1/3: Searching local Private Registry artifacts at %s", time.Now().Format(time.RFC3339), artifactsURL)

	artifactsResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, FindPatchedImageResult{}, fmt.Errorf("failed to list artifacts: %w", err)
	}
	defer artifactsResp.Body.Close()

	if artifactsResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(artifactsResp.Body)
		return nil, FindPatchedImageResult{}, fmt.Errorf("failed to list artifacts, status %d: %s", artifactsResp.StatusCode, string(body))
	}
	log.Printf("[%s] Private Registry artifact search returned status %d", time.Now().Format(time.RFC3339), artifactsResp.StatusCode)

	type Artifact struct {
		Type     string    `json:"type"`
		PushTime time.Time `json:"push_time"`
		Digest   string    `json:"digest"`
		Tags     []struct {
			Name string `json:"name"`
		} `json:"tags"`
	}
	var artifacts []Artifact
	if err := json.NewDecoder(artifactsResp.Body).Decode(&artifacts); err != nil {
		return nil, FindPatchedImageResult{}, fmt.Errorf("failed to decode artifacts list: %w", err)
	}
	log.Printf("[%s] Found %d total artifacts in local Private Registry to evaluate.", time.Now().Format(time.RFC3339), len(artifacts))

	var originalArtifact Artifact
	for _, artifact := range artifacts {
		for _, tag := range artifact.Tags {
			if tag.Name == args.Tag {
				originalArtifact = artifact
				break
			}
		}
		if originalArtifact.Digest != "" {
			break
		}
	}

	if originalArtifact.PushTime.IsZero() {
		log.Printf("Could not find original image %s:%s in project %s", args.Repository, args.Tag, args.Project)
		// We can still proceed, but we can't guarantee we are only checking newer images.
	}

	// Get the vulnerability summary for the original image to compare against.
	var originalVulnCount struct{ Critical, High int }
	if originalArtifact.Digest != "" {
		log.Printf("Getting vulnerability summary for original image %s:%s", args.Repository, args.Tag)
		reportURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", *privateRegistryURL, args.Project, repoNameEncoded, originalArtifact.Tags[0].Name)
		reportReq, _ := http.NewRequestWithContext(ctx, "GET", reportURL, nil)
		reportReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
		reportReq.Header.Set("Accept", "application/json")

		reportResp, err := httpClient.Do(reportReq)
		if err == nil && reportResp.StatusCode == http.StatusOK {
			var reportData map[string]privateRegistryVulnerabilityReport
			if err := json.NewDecoder(reportResp.Body).Decode(&reportData); err == nil {
				for _, report := range reportData {
					for _, vuln := range report.Vulnerabilities {
						if vuln.Severity == "Critical" {
							originalVulnCount.Critical++
						} else if vuln.Severity == "High" {
							originalVulnCount.High++
						}
					}
					break
				}
			}
			reportResp.Body.Close()
		} else if reportResp != nil {
			reportResp.Body.Close()
		}
		log.Printf("Original image vulnerability counts: Critical=%d, High=%d", originalVulnCount.Critical, originalVulnCount.High)
	}

	// Get all tags from the local repository to find newer ones.
	var localTags []string
	for _, a := range artifacts {
		if a.Type == "IMAGE" && len(a.Tags) > 0 {
			localTags = append(localTags, a.Tags[0].Name)
		}
	}

	newerTags := findNewerTags(localTags, args.Tag)
	log.Printf("Found %d newer tags in local Private Registry to check: %v", len(newerTags), newerTags)

	for _, tag := range newerTags {
		// Find the artifact corresponding to the newer tag.
		var artifact Artifact
		for _, a := range artifacts {
			if len(a.Tags) > 0 && a.Tags[0].Name == tag {
				artifact = a
				break
			}
		}
		if artifact.Digest == "" {
			continue
		}

		log.Printf("Checking local image %s:%s", args.Repository, tag)
		reportURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", *privateRegistryURL, args.Project, repoNameEncoded, tag)
		reportReq, _ := http.NewRequestWithContext(ctx, "GET", reportURL, nil)
		reportReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
		reportReq.Header.Set("Accept", "application/json")

		reportResp, err := httpClient.Do(reportReq)
		if err != nil || reportResp.StatusCode != http.StatusOK {
			if err != nil {
				log.Printf("Failed to get report for %s:%s: %v", args.Repository, tag, err)
			} else {
				log.Printf("Failed to get report for %s:%s, status: %d", args.Repository, tag, reportResp.StatusCode)
				reportResp.Body.Close()
			}
			continue
		}

		var reportData map[string]privateRegistryVulnerabilityReport
		if err := json.NewDecoder(reportResp.Body).Decode(&reportData); err != nil {
			reportResp.Body.Close()
			continue
		}
		reportResp.Body.Close()

		cveFound := false
		var candidateVulnCount struct{ Critical, High int }
		for _, report := range reportData {
			for _, vuln := range report.Vulnerabilities {
				if vuln.ID == args.CVEID {
					cveFound = true
				}
				switch vuln.Severity {
				case "Critical":
					candidateVulnCount.Critical++
				case "High":
					candidateVulnCount.High++
				}
			}
			// We only need to process the first report in the map.
			break
		}

		if cveFound {
			log.Printf("Image %s:%s contains target CVE %s. Skipping.", args.Repository, tag, args.CVEID)
			continue
		}

		// If we have info on the original image, ensure the new one is not worse.
		if originalArtifact.Digest != "" {
			if candidateVulnCount.Critical > originalVulnCount.Critical || candidateVulnCount.High > originalVulnCount.High {
				log.Printf("Image %s:%s is a candidate, but has more Critical/High vulnerabilities (%d/%d) than original (%d/%d). Skipping.",
					args.Repository, tag, candidateVulnCount.Critical, candidateVulnCount.High, originalVulnCount.Critical, originalVulnCount.High)
				continue
			}
		}

		if !cveFound {
			imageName := fmt.Sprintf("%s/%s/%s:%s", *privateRegistryURL, args.Project, args.Repository, tag)
			result := FindPatchedImageResult{
				Found:         true,
				Image:         imageName,
				Location:      "local-private-registry",
				CriticalCount: candidateVulnCount.Critical,
				HighCount:     candidateVulnCount.High,
			}
			summaryText := fmt.Sprintf("Found patched image in local Private Registry: %s. It has %d Critical and %d High vulnerabilities.", imageName, result.CriticalCount, result.HighCount)
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: summaryText}},
			}, result, nil
		}
	}

	// Create a new HTTP client with a timeout for external API calls to prevent hangs.
	externalAPIClient := &http.Client{
		Timeout: 30 * time.Second, // 30-second timeout for external registry API calls.
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}

	// Extract the base repository name for searching external registries.
	// e.g., "library/postgres" -> "postgres"
	baseRepoName := args.Repository
	if lastSlash := strings.LastIndex(baseRepoName, "/"); lastSlash != -1 {
		baseRepoName = baseRepoName[lastSlash+1:]
	}
	// 2. Search registry.suse.com by using Private Registry as a proxy cache.
	log.Printf("[%s] Step 2/3: Patched image not found in local Private Registry. Searching registry.suse.com for '%s'", time.Now().Format(time.RFC3339), baseRepoName)

	suseSearchPerformed := false
	// --- New Direct Lookup Logic ---
	// First, try to list tags directly assuming args.Repository is a valid repo name.
	suseRepoToSearch := "suse/" + args.Repository
	log.Printf("Attempting direct tag listing for SUSE repository: %s", suseRepoToSearch)
	suseRepoFullName := "registry.suse.com/" + suseRepoToSearch
	proxyProjectName := "proxy-suse"
	if err := ensureProxyProject(ctx, proxyProjectName, "https://registry.suse.com", httpClient); err != nil {
		log.Printf("Failed to ensure SUSE proxy project exists, SUSE search may fail: %v", err)
	}
	tags, err := listTagsWithCrane(ctx, suseRepoFullName)
	if err == nil {
		suseSearchPerformed = true                 // Mark that we've successfully interacted with this repo.
		newerTags := findNewerTags(tags, args.Tag) // Assuming crane returns tags sorted by version
		log.Printf("Found %d newer tags for SUSE repo %s using crane: %v", len(newerTags), suseRepoToSearch, newerTags)
		for _, tag := range newerTags {
			imageToScan := fmt.Sprintf("%s:%s", suseRepoFullName, tag)
			log.Printf("Found patched image in registry.suse.com: %s", imageToScan)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found patched image in registry.suse.com: %s", imageToScan)}}}, FindPatchedImageResult{Found: true, Image: imageToScan, Location: "registry.suse.com"}, nil
		}
	} else {
		if err != exec.ErrNotFound {
			log.Printf("crane command failed for %s (%v), falling back to HTTP API.", suseRepoFullName, err)
		} else {
			log.Printf("'crane' command not found, falling back to HTTP API for SUSE search.")
		}
		// Fallback to HTTP API
		suseDirectTagsURL := fmt.Sprintf("https://registry.suse.com/v2/%s/tags/list", suseRepoToSearch)
		tagsReq, httpErr := http.NewRequestWithContext(ctx, "GET", suseDirectTagsURL, nil)
		if httpErr != nil {
			log.Printf("Failed to create direct tag list request for %s: %v", args.Repository, httpErr)
			// Don't return, fall back to search.
		} else {
			tagsReq.Header.Set("Accept", "application/json")
			tagsResp, httpErr := externalAPIClient.Do(tagsReq)
			if httpErr == nil && tagsResp.StatusCode == http.StatusOK {
				suseSearchPerformed = true // Mark that we've successfully interacted with this repo.
				log.Printf("Direct tag listing successful for %s", suseRepoToSearch)
				var tagsResult struct {
					Tags []string `json:"tags"`
				}
				if err := json.NewDecoder(tagsResp.Body).Decode(&tagsResult); err != nil {
					log.Printf("Failed to decode tags from direct lookup for %s: %v", suseRepoToSearch, err)
					tagsResp.Body.Close()
				} else {
					newerTags := findNewerTags(tagsResult.Tags, args.Tag)
					log.Printf("Found %d newer tags for SUSE repo %s: %v", len(newerTags), suseRepoToSearch, newerTags)
					tagsResp.Body.Close()
					for _, tag := range newerTags {
						cveFound, err := scanprivateRegistryArtifact(ctx, proxyProjectName, suseRepoToSearch, tag, args.CVEID, httpClient)
						if err == nil && !cveFound {
							imageToScan := fmt.Sprintf("registry.suse.com/%s:%s", suseRepoToSearch, tag)
							return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found patched image in registry.suse.com: %s", imageToScan)}}}, FindPatchedImageResult{Found: true, Image: imageToScan, Location: "registry.suse.com"}, nil
						}
					}
				}
			} else {
				if tagsResp != nil {
					tagsResp.Body.Close()
				}
				log.Printf("Direct tag listing for %s failed, falling back to search.", args.Repository)
			}
		}

	}
	// --- End of New Logic ---

	// Fallback to searching SUSE registry if direct lookup failed.
	if !suseSearchPerformed {
		log.Printf("Falling back to crane catalog search for '%s' on registry.suse.com", baseRepoName)
		matchingRepos, err := searchReposWithCrane(ctx, "registry.suse.com", baseRepoName)
		if err != nil {
			log.Printf("crane catalog search failed: %v", err)
		}

		log.Printf("crane catalog found %d potential repositories for '%s'", len(matchingRepos), baseRepoName)
		for _, repoName := range matchingRepos {
			// After finding a repository, we need to list its tags.
			tagsURL := fmt.Sprintf("https://registry.suse.com/v2/%s/tags/list", repoName) // Using HTTP fallback here for speed.
			tagsReq, err := http.NewRequestWithContext(ctx, "GET", tagsURL, nil)
			if err != nil {
				log.Printf("Failed to create request for SUSE tags for %s: %v", repoName, err)
				continue
			}
			tagsReq.Header.Set("Accept", "application/json")

			tagsResp, err := externalAPIClient.Do(tagsReq)
			if err != nil || tagsResp.StatusCode != http.StatusOK {
				log.Printf("Failed to get tags from SUSE registry for %s", repoName)
				if tagsResp != nil {
					tagsResp.Body.Close()
				}
				continue
			}

			var tagsResult struct {
				Tags []string `json:"tags"`
			}
			if err := json.NewDecoder(tagsResp.Body).Decode(&tagsResult); err != nil {
				log.Printf("Failed to decode tags from SUSE registry for %s: %v", repoName, err)
				tagsResp.Body.Close()
				continue
			}
			tagsResp.Body.Close()

			newerTags := findNewerTags(tagsResult.Tags, args.Tag)
			log.Printf("Found %d newer tags for SUSE repo %s to check: %v", len(newerTags), repoName, newerTags)
			// Now we can scan the image:tag
			for _, tag := range newerTags {
				cveFound, err := scanprivateRegistryArtifact(ctx, proxyProjectName, repoName, tag, args.CVEID, httpClient)
				if err == nil && !cveFound {
					imageToScan := fmt.Sprintf("registry.suse.com/%s:%s", repoName, tag)
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found patched image in registry.suse.com: %s", imageToScan)}}}, FindPatchedImageResult{Found: true, Image: imageToScan, Location: "registry.suse.com"}, nil
				}
			}
		}
	}

	// 3. If not found, search in Docker Hub.
	log.Printf("[%s] Step 3/3: Patched image not found in registry.suse.com. Searching Docker Hub for '%s'", time.Now().Format(time.RFC3339), baseRepoName)

	dockerSearchURL := fmt.Sprintf("https://hub.docker.com/v2/search/repositories/?query=%s", url.QueryEscape(baseRepoName))
	dockerSearchReq, err := http.NewRequestWithContext(ctx, "GET", dockerSearchURL, nil)
	if err != nil {
		log.Printf("Failed to create search request for Docker Hub for %s: %v", args.Repository, err)
		return notFoundResult(args), FindPatchedImageResult{}, nil
	}

	dockerSearchResp, err := externalAPIClient.Do(dockerSearchReq)
	if err != nil || dockerSearchResp.StatusCode != http.StatusOK {
		if err != nil {
			log.Printf("Failed to search Docker Hub for %s: %v", args.Repository, err)
		} else {
			log.Printf("Failed to search Docker Hub for %s, status: %d", args.Repository, dockerSearchResp.StatusCode)
			dockerSearchResp.Body.Close()
		}
		return notFoundResult(args), FindPatchedImageResult{}, nil
	}

	var dockerSearchResults struct {
		Results []struct {
			RepoName string `json:"repo_name"`
		} `json:"results"`
	}
	if err := json.NewDecoder(dockerSearchResp.Body).Decode(&dockerSearchResults); err != nil {
		log.Printf("Failed to decode search results from Docker Hub for %s: %v", args.Repository, err)
		dockerSearchResp.Body.Close()
		return notFoundResult(args), FindPatchedImageResult{}, nil
	}
	dockerSearchResp.Body.Close()

	for _, repo := range dockerSearchResults.Results {
		// Check if the found repo name is the one we are looking for.
		// It could be "postgres" or "library/postgres".
		if repo.RepoName != baseRepoName && repo.RepoName != "library/"+baseRepoName {
			continue
		}

		// Fetch all tags for the repository from Docker Hub.
		log.Printf("Fetching tags for Docker Hub repository: %s", repo.RepoName)
		dockerTagsURL := fmt.Sprintf("https://hub.docker.com/v2/repositories/%s/tags/?page_size=100", repo.RepoName)
		tagsReq, err := http.NewRequestWithContext(ctx, "GET", dockerTagsURL, nil)
		if err != nil {
			log.Printf("Failed to create tag list request for Docker Hub repo %s: %v", repo.RepoName, err)
			continue
		}

		tagsResp, err := externalAPIClient.Do(tagsReq)
		if err != nil || tagsResp.StatusCode != http.StatusOK {
			log.Printf("Failed to get tags for Docker Hub repo %s: %v", repo.RepoName, err)
			if tagsResp != nil {
				tagsResp.Body.Close()
			}
			continue
		}

		var tagsResult struct {
			Results []struct {
				Name string `json:"name"`
			} `json:"results"`
		}
		if err := json.NewDecoder(tagsResp.Body).Decode(&tagsResult); err != nil {
			log.Printf("Failed to decode tags for Docker Hub repo %s: %v", repo.RepoName, err)
			tagsResp.Body.Close()
			continue
		}
		tagsResp.Body.Close()

		log.Printf("Found %d tags for %s. Scanning for patched version...", len(tagsResult.Results), repo.RepoName)
		var dockerTags []string
		for _, t := range tagsResult.Results {
			dockerTags = append(dockerTags, t.Name)
		}
		newerTags := findNewerTags(dockerTags, args.Tag)
		log.Printf("Found %d newer tags for Docker Hub repo %s to check: %v", len(newerTags), repo.RepoName, newerTags)
		for _, tag := range newerTags {
			imageToScan := fmt.Sprintf("%s:%s", repo.RepoName, tag)
			proxyProjectName := "proxy-dockerhub"
			if err := ensureProxyProject(ctx, proxyProjectName, "https://hub.docker.com", httpClient); err != nil {
				log.Printf("Failed to ensure Docker Hub proxy project exists: %v", err)
				break
			}

			cveFound, err := scanprivateRegistryArtifact(ctx, proxyProjectName, repo.RepoName, tag, args.CVEID, httpClient)
			if err == nil && !cveFound {
				log.Printf("Found patched image in Docker Hub: %s", imageToScan)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found patched image in Docker Hub: %s", imageToScan)}}}, FindPatchedImageResult{Found: true, Image: imageToScan, Location: "docker-hub"}, nil
			}
		}
	}

	log.Printf("[%s] END: Patched image not found in any registry for %s/%s:%s without CVE %s", time.Now().Format(time.RFC3339), args.Project, args.Repository, args.Tag, args.CVEID)
	return notFoundResult(args), FindPatchedImageResult{}, nil
}

// ensureProxyProject checks if a proxy cache project exists in Private Registry and creates it if not.
func ensureProxyProject(ctx context.Context, projectName, upstreamURL string, client *http.Client) error {
	// Check if project exists
	projectURL := fmt.Sprintf("%s/api/v2.0/projects/%s", *privateRegistryURL, projectName)
	req, err := http.NewRequestWithContext(ctx, "GET", projectURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create check project request: %w", err)
	}
	req.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to check for project %s: %w", projectName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Printf("Proxy project '%s' already exists.", projectName)
		return nil // Project exists
	}

	if resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("unexpected status when checking for project %s: %d", projectName, resp.StatusCode)
	}

	// Project does not exist, so create it.
	log.Printf("Proxy project '%s' not found. Creating it now for upstream %s.", projectName, upstreamURL)
	createURL := fmt.Sprintf("%s/api/v2.0/projects", *privateRegistryURL)
	createBody := fmt.Sprintf(`{
        "project_name": "%s",
        "public": false,
        "registry_id": 0, // This needs to be the ID of a pre-configured proxy cache endpoint.
                           // Assuming a default or pre-existing one. For a real system, this needs to be robust.
        "storage_limit": -1
    }`, projectName) // Simplified for example. A real implementation would need to find the correct registry_id.

	// This is a placeholder. A robust implementation needs to find the ID of the proxy registry endpoint.
	// For now, we assume the user has set one up and we are just creating the project.
	// The real power comes from Private Registry automatically pulling from the associated endpoint.
	// Let's just create a normal project and let Private Registry's proxy rules handle it.
	createBody = fmt.Sprintf(`{"project_name": "%s", "public": false}`, projectName)

	createReq, err := http.NewRequestWithContext(ctx, "POST", createURL, strings.NewReader(createBody))
	if err != nil {
		return fmt.Errorf("failed to create project creation request: %w", err)
	}
	createReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
	createReq.Header.Set("Content-Type", "application/json")

	createResp, err := client.Do(createReq)
	if err != nil {
		return fmt.Errorf("failed to create project %s: %w", projectName, err)
	}
	defer createResp.Body.Close()

	if createResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(createResp.Body)
		return fmt.Errorf("failed to create project %s, status %d: %s", projectName, createResp.StatusCode, string(body))
	}

	log.Printf("Successfully created project '%s'.", projectName)
	return nil
}

// scanprivateRegistryArtifact triggers a scan for an artifact within Private Registry and checks for a CVE.
func scanprivateRegistryArtifact(ctx context.Context, project, repo, tag, cveID string, client *http.Client) (bool, error) {
	repoNameEncoded := strings.ReplaceAll(repo, "/", "%2F")

	// Trigger scan
	scanURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/scan", *privateRegistryURL, project, repoNameEncoded, tag)
	scanReq, _ := http.NewRequestWithContext(ctx, "POST", scanURL, nil)
	scanReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
	scanResp, err := client.Do(scanReq)
	if err != nil {
		return false, fmt.Errorf("failed to trigger scan on %s/%s:%s: %w", project, repo, tag, err)
	}
	scanResp.Body.Close()

	// Poll for results
	reportURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", *privateRegistryURL, project, repoNameEncoded, tag)
	for i := 0; i < 60; i++ {
		time.Sleep(5 * time.Second)
		reportReq, _ := http.NewRequestWithContext(ctx, "GET", reportURL, nil)
		reportReq.SetBasicAuth(*privateRegistryUsername, *privateRegistryPassword)
		reportReq.Header.Set("Accept", "application/json")
		reportResp, err := client.Do(reportReq)
		if err != nil {
			continue
		}

		if reportResp.StatusCode == http.StatusOK {
			var reportData map[string]privateRegistryVulnerabilityReport
			if err := json.NewDecoder(reportResp.Body).Decode(&reportData); err != nil {
				reportResp.Body.Close()
				continue
			}
			reportResp.Body.Close()

			for _, report := range reportData {
				for _, vuln := range report.Vulnerabilities {
					if vuln.ID == cveID {
						return true, nil // CVE found
					}
				}
			}
			return false, nil // Scan complete, CVE not found
		}
		reportResp.Body.Close()
	}
	return false, fmt.Errorf("timed out waiting for scan report for %s/%s:%s", project, repo, tag)
}

// notFoundResult returns a standard 'not found' result for FindPatchedImage.
func notFoundResult(args FindPatchedImageParams) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: fmt.Sprintf("Could not find a patched version for %s/%s:%s without CVE %s in local Private Registry, registry.suse.com, or Docker Hub.",
					args.Project, args.Repository, args.Tag, args.CVEID),
			},
		},
	}
}

// listTagsWithCrane uses the 'crane' command-line tool to list tags for a repository.
func listTagsWithCrane(ctx context.Context, repoName string) ([]string, error) {
	log.Printf("Listing tags for %s using crane.", repoName)
	cmd := exec.CommandContext(ctx, "crane", "ls", repoName)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("crane command failed with exit code %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		if err == exec.ErrNotFound {
			return nil, fmt.Errorf("'crane' command not found in PATH")
		}
		return nil, fmt.Errorf("failed to execute crane command: %w", err)
	}

	return strings.Split(strings.TrimSpace(string(output)), "\n"), nil
}

// searchReposWithCrane uses 'crane catalog' to find repositories matching a search term.
func searchReposWithCrane(ctx context.Context, registry, searchTerm string) ([]string, error) {
	log.Printf("Searching for repositories matching '%s' in catalog of %s using crane.", searchTerm, registry)
	cmd := exec.CommandContext(ctx, "crane", "catalog", registry)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("crane catalog failed with exit code %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		if err == exec.ErrNotFound {
			return nil, fmt.Errorf("'crane' command not found in PATH")
		}
		return nil, fmt.Errorf("failed to execute crane catalog: %w", err)
	}

	var matchingRepos []string
	allRepos := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, repo := range allRepos {
		if strings.Contains(repo, searchTerm) {
			matchingRepos = append(matchingRepos, repo)
		}
	}
	return matchingRepos, nil
}

// findNewerTags sorts a list of tags using version semantics and returns a slice
// containing only the tags that are newer than the specified currentTag.
func findNewerTags(tags []string, currentTag string) []string {
	versions := make([]*version.Version, 0, len(tags))
	for _, t := range tags {
		v, err := version.NewVersion(t)
		if err == nil {
			versions = append(versions, v)
		}
	}

	// Sort the versions in ascending order.
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].LessThan(versions[j])
	})

	// Find the index of the current tag.
	currentIndex := -1
	for i, v := range versions {
		if v.Original() == currentTag {
			currentIndex = i
			break
		}
	}

	var newerTags []string
	if currentIndex != -1 {
		for i := currentIndex + 1; i < len(versions); i++ {
			newerTags = append(newerTags, versions[i].Original())
		}
	}
	// Return in descending order (newest first)
	for i, j := 0, len(newerTags)-1; i < j; i, j = i+1, j-1 {
		newerTags[i], newerTags[j] = newerTags[j], newerTags[i]
	}
	return newerTags
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "This program runs an MCP server over Streamable HTTP or stdio.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEndpoints:\n")
		fmt.Fprintf(os.Stderr, "  /mpc-spr   - Private Registry scanning service\n")
		os.Exit(1)
	}
	flag.Parse()

	var authToken string
	if !*stdio {
		authToken = strings.TrimSpace(*mcpAuthToken)
		if err := validateMCPAuth(*host, authToken); err != nil {
			log.Fatal(err)
		}
	}
	addr := fmt.Sprintf("%s:%s", *host, *port)

	privateRegistryServer := mcp.NewServer(&mcp.Implementation{Name: "private-registry-scanner"}, nil)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "scan_image",
		Description: "Scans a container image in Private Registry for vulnerabilities using Trivy.",
	}, ScanImage)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "scan_project",
		Description: "Scans all images in a Private Registry project and provides a vulnerability summary.",
	}, ScanProject)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "find_patched_image",
		Description: "Finds a newer version of an image without a specific CVE.",
	}, FindPatchedImage)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "get_vulnerabilities",
		Description: "Retrieves all vulnerabilities for a specific container image from Private Registry.",
	}, GetVulnerabilities)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "get_sbom",
		Description: "Retrieves the Software Bill of Materials (SBOM) for a specific container image from privateRegistry.",
	}, GetSBOM)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "get_project_sbom",
		Description: "Retrieves the Software Bill of Materials (SBOM) for all images in a privateRegistry project.",
	}, GetProjectSBOM)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "list_projects",
		Description: "Lists all projects available in the Private Registry.",
	}, ListProjects)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "create_project",
		Description: "Creates a Harbor project. Projects are private by default; set public to true to make one publicly accessible.",
	}, CreateProject)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "get_project",
		Description: "Retrieves details for a single Private Registry project by name.",
	}, GetProject)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "get_health",
		Description: "Checks Harbor's overall health and reports component statuses.",
	}, GetHealth)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "search",
		Description: "Searches Harbor projects and repositories by name.",
	}, Search)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "list_quotas",
		Description: "Lists project storage and artifact-count quotas, optionally filtered by project name.",
	}, ListQuotas)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "get_project_summary",
		Description: "Summarizes project details and repository/artifact counts without starting scans.",
	}, GetProjectSummary)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "list_repositories",
		Description: "Lists all repositories within a Private Registry project.",
	}, ListRepositories)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "list_tags",
		Description: "Lists all tags of artifacts within a repository.",
	}, ListTags)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "list_charts",
		Description: "Lists Helm charts in a project. Requires the Harbor instance to have chart repository support enabled (removed by default in Harbor 2.11+).",
	}, ListCharts)
	mcp.AddTool(privateRegistryServer, &mcp.Tool{
		Name:        "list_chart_versions",
		Description: "Lists versions of a single Helm chart. Requires the Harbor instance to have chart repository support enabled (removed by default in Harbor 2.11+).",
	}, ListChartVersions)

	if *stdio {
		if err := privateRegistryServer.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			log.Fatal(err)
		}
		return
	}

	log.Printf("MCP servers serving at %s", addr)
	var handler http.Handler = mcp.NewStreamableHTTPHandler(
		func(request *http.Request) *mcp.Server {
			url := request.URL.Path
			log.Printf("Handling request for URL %s\n", url)
			if url == "/mpc-spr" {
				return privateRegistryServer
			}
			return nil
		},
		nil,
	)
	if authToken != "" {
		handler = requireBearerToken(authToken, handler)
	}
	log.Fatal(http.ListenAndServe(addr, handler))
}
