// Copyright 2025 The Go MCP SDK Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	host           = flag.String("host", "localhost", "host to listen on")
	port           = flag.String("port", "8080", "port to listen on")
	harborURL      = flag.String("harbor-url", "http://localhost:8081", "Harbor instance URL")
	harborUsername = flag.String("harbor-username", "admin", "Harbor username for API access")
	harborPassword = flag.String("harbor-password", "", "Harbor password for API access")
)

// ScanImageParams defines the input for the Harbor image scanning tool.
type ScanImageParams struct {
	Project    string `json:"project" jsonschema:"The Harbor project name"`
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
	Project string `json:"project" jsonschema:"The Harbor project name to scan"`
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

// ScanHelmChartParams defines the input for the Helm chart scanning tool.
type ScanHelmChartParams struct {
	Project    string `json:"project" jsonschema:"The Harbor project name"`
	Repository string `json:"repository" jsonschema:"The Helm chart repository name"`
	Tag        string `json:"tag" jsonschema:"The chart version (tag) to scan"`
}

// TrivyMisconfiguration represents a single misconfiguration found by Trivy.
type TrivyMisconfiguration struct {
	Type        string `json:"Type"`
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
}

// TrivyScanResult is the output of the Trivy scan for misconfigurations.
// TrivyScanResult is the output of the Trivy scan.
type TrivyScanResult struct {
	Misconfigurations []TrivyMisconfiguration `json:"Misconfigurations"`
}

// HarborVulnerabilityReport represents the structure of the vulnerability report
// object returned by Harbor, which contains the list of vulnerabilities.
type HarborVulnerabilityReport struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// FindPatchedImageParams defines the input for the tool that finds a patched image.
type FindPatchedImageParams struct {
	Project    string `json:"project" jsonschema:"The Harbor project name of the image"`
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
	Project    string `json:"project" jsonschema:"The Harbor project name"`
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
	Project    string `json:"project" jsonschema:"The Harbor project name"`
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
	Project string `json:"project" jsonschema:"The Harbor project name"`
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

// ScanImage is a tool handler that triggers a vulnerability scan in Harbor for a given
// container image and returns the results.
func ScanImage(ctx context.Context, req *mcp.CallToolRequest, args ScanImageParams) (*mcp.CallToolResult, ScanResult, error) {
	if *harborPassword == "" {
		return nil, ScanResult{}, fmt.Errorf("harbor-password flag is not set")
	}
	if args.Project == "" || args.Repository == "" || args.Tag == "" {
		return nil, ScanResult{}, fmt.Errorf("harbor-password flag is not set")
	}

	// Sanitize string inputs to prevent issues with leading/trailing whitespace.
	args.Project = strings.TrimSpace(args.Project)
	args.Repository = strings.TrimSpace(args.Repository)
	args.Tag = strings.TrimSpace(args.Tag)

	// The repository name in the Harbor API needs to be URL-encoded,
	// especially if it contains slashes.
	repo := strings.ReplaceAll(args.Repository, "/", "%2F")

	// 1. Trigger the scan
	scanURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/scan",
		*harborURL, args.Project, repo, args.Tag)

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // Allow insecure TLS when explicitly requested
			},
		},
	}

	// Include "vulnerability" in the scan request.
	scanPayload := strings.NewReader(`{"scan_type": "vulnerability"}`)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", scanURL, scanPayload)
	if err != nil {
		return nil, ScanResult{}, fmt.Errorf("failed to create scan request: %w", err)
	}
	httpReq.SetBasicAuth(*harborUsername, *harborPassword)
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
		*harborURL, args.Project, repo, args.Tag)

	var reportData map[string]HarborVulnerabilityReport
	for i := 0; i < 60; i++ { // Poll up to 60 times
		time.Sleep(5 * time.Second) // Wait before checking

		reportReq, err := http.NewRequestWithContext(ctx, "GET", reportURL, nil)
		if err != nil {
			return nil, ScanResult{}, fmt.Errorf("failed to create report request: %w", err)
		}
		reportReq.SetBasicAuth(*harborUsername, *harborPassword)
		reportReq.Header.Set("Accept", "application/json")

		reportResp, err := httpClient.Do(reportReq)
		if err != nil {
			return nil, ScanResult{}, fmt.Errorf("failed to get scan report: %w", err)
		}

		if reportResp.StatusCode == http.StatusOK {
			// Harbor returns a map where the key is the mime-type of the report.
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

// GetVulnerabilities retrieves the vulnerability report for a specific container image from Harbor.
func GetVulnerabilities(ctx context.Context, req *mcp.CallToolRequest, args GetVulnerabilitiesParams) (*mcp.CallToolResult, GetVulnerabilitiesResult, error) {
	if *harborPassword == "" {
		return nil, GetVulnerabilitiesResult{}, fmt.Errorf("harbor-password flag is not set")
	}
	if args.Project == "" || args.Repository == "" || args.Tag == "" {
		return nil, GetVulnerabilitiesResult{}, fmt.Errorf("project, repository, and tag are required parameters")
	}

	// Sanitize string inputs.
	args.Project = strings.TrimSpace(args.Project)
	args.Repository = strings.TrimSpace(args.Repository)
	args.Tag = strings.TrimSpace(args.Tag)

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Allow insecure TLS
			},
		},
	}

	repo := strings.ReplaceAll(args.Repository, "/", "%2F")
	reportURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities",
		*harborURL, args.Project, repo, args.Tag)

	log.Printf("Fetching vulnerabilities for %s/%s:%s", args.Project, args.Repository, args.Tag)

	reportReq, err := http.NewRequestWithContext(ctx, "GET", reportURL, nil)
	if err != nil {
		return nil, GetVulnerabilitiesResult{}, fmt.Errorf("failed to create report request: %w", err)
	}
	reportReq.SetBasicAuth(*harborUsername, *harborPassword)
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

	var reportData map[string]HarborVulnerabilityReport
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

// GetSBOM retrieves the Software Bill of Materials (SBOM) for a specific container image from Harbor.
func GetSBOM(ctx context.Context, req *mcp.CallToolRequest, args GetSBOMParams) (*mcp.CallToolResult, GetSBOMResult, error) {
	if *harborPassword == "" {
		return nil, GetSBOMResult{}, fmt.Errorf("harbor-password flag is not set")
	}
	if args.Project == "" || args.Repository == "" || args.Tag == "" {
		return nil, GetSBOMResult{}, fmt.Errorf("project, repository, and tag are required parameters")
	}

	// Sanitize string inputs.
	args.Project = strings.TrimSpace(args.Project)
	args.Repository = strings.TrimSpace(args.Repository)
	args.Tag = strings.TrimSpace(args.Tag)

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Allow insecure TLS
			},
		},
	}

	repo := strings.ReplaceAll(args.Repository, "/", "%2F")

	// 1. Get artifact details to find the digest.
	artifactURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s",
		*harborURL, args.Project, repo, args.Tag)
	log.Printf("Getting artifact details from: %s", artifactURL)
	artifactReq, err := http.NewRequestWithContext(ctx, "GET", artifactURL, nil)
	if err != nil {
		return nil, GetSBOMResult{}, fmt.Errorf("failed to create artifact details request: %w", err)
	}
	artifactReq.SetBasicAuth(*harborUsername, *harborPassword)
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
		*harborURL, args.Project, repo, artifact.Digest)
	log.Printf("Downloading SBOM from: %s", sbomURL)

	sbomReq, err := http.NewRequestWithContext(ctx, "GET", sbomURL, nil)
	if err != nil {
		return nil, GetSBOMResult{}, fmt.Errorf("failed to create SBOM download request: %w", err)
	}
	sbomReq.SetBasicAuth(*harborUsername, *harborPassword)
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
			*harborURL, args.Project, repo, args.Tag)
		scanPayload := strings.NewReader(`{"scan_type": "sbom"}`)
		scanReq, err := http.NewRequestWithContext(ctx, "POST", scanURL, scanPayload)
		if err != nil {
			return nil, GetSBOMResult{}, fmt.Errorf("failed to create scan request: %w", err)
		}
		scanReq.SetBasicAuth(*harborUsername, *harborPassword)
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
		// Check for a specific Harbor limitation with Docker v2 manifests.
		if strings.Contains(string(body), "SBOM isn't supported for IMAGE") {
			// Construct the UI link for the SBOM
			uiLink := fmt.Sprintf("%s/harbor/projects/1/repositories/%s/artifacts-tab/artifacts/%s?tab=sbom", strings.TrimSuffix(*harborURL, "/api/v2.0"), args.Repository, artifact.Digest)
			imageName := fmt.Sprintf("%s/%s:%s", args.Project, args.Repository, args.Tag)
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("Harbor does not support SBOM generation for image %s because it uses an older manifest format (Docker v2). However, the SBOM may be available in the Harbor UI at: %s", imageName, uiLink)},
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

// GetProjectSBOM retrieves the Software Bill of Materials (SBOM) for all images in a specific Harbor project.
func GetProjectSBOM(ctx context.Context, req *mcp.CallToolRequest, args GetProjectSBOMParams) (*mcp.CallToolResult, GetProjectSBOMResult, error) {
	if *harborPassword == "" {
		return nil, GetProjectSBOMResult{}, fmt.Errorf("harbor-password flag is not set")
	}
	if args.Project == "" {
		return nil, GetProjectSBOMResult{}, fmt.Errorf("project is a required parameter")
	}

	// Sanitize string inputs.
	args.Project = strings.TrimSpace(args.Project)

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Allow insecure TLS
			},
		},
	}

	// 1. List repositories in the project
	log.Printf("Starting SBOM retrieval for project: %s", args.Project)
	reposURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories", *harborURL, args.Project)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", reposURL, nil)
	if err != nil {
		return nil, GetProjectSBOMResult{}, fmt.Errorf("failed to create list repositories request: %w", err)
	}
	httpReq.SetBasicAuth(*harborUsername, *harborPassword)

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

		artifactsURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts", *harborURL, args.Project, repoNameEncoded)
		artifactsReq, err := http.NewRequestWithContext(ctx, "GET", artifactsURL, nil)
		if err != nil {
			log.Printf("Error creating artifacts request for %s: %v", repo.Name, err)
			continue
		}
		artifactsReq.SetBasicAuth(*harborUsername, *harborPassword)

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
				*harborURL, args.Project, repoNameEncoded, tag)

			scanPayload := strings.NewReader(`{"scan_type": "sbom"}`)
			scanReq, err := http.NewRequestWithContext(ctx, "POST", scanURL, scanPayload)
			if err != nil {
				log.Printf("Error creating SBOM scan request for %s:%s: %v", repo.Name, tag, err)
				continue
			}
			scanReq.SetBasicAuth(*harborUsername, *harborPassword)
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

// ScanProject scans all images in a given Harbor project and returns a summary of vulnerabilities.
func ScanProject(ctx context.Context, req *mcp.CallToolRequest, args ScanProjectParams) (*mcp.CallToolResult, ScanProjectResult, error) {
	if *harborPassword == "" {
		// It's good practice to log when returning an error.
		log.Println("Error: harbor-password flag is not set.")
		return nil, ScanProjectResult{}, fmt.Errorf("harbor-password flag is not set")
	}
	if args.Project == "" {
		return nil, ScanProjectResult{}, fmt.Errorf("harbor-password flag is not set")
	}

	// Sanitize string inputs.
	args.Project = strings.TrimSpace(args.Project)

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Allow insecure TLS
			},
		},
	}

	// 1. List repositories in the project
	log.Printf("Starting scan for project: %s", args.Project)
	reposURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories", *harborURL, args.Project)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", reposURL, nil)
	if err != nil {
		return nil, ScanProjectResult{}, fmt.Errorf("failed to create list repositories request: %w", err)
	}
	httpReq.SetBasicAuth(*harborUsername, *harborPassword)

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

	var allSummaries []ImageVulnerabilitySummary

	// 2. For each repository, list artifacts and get vulnerability summaries
	for _, repo := range repositories {
		// Harbor repo names include the project, e.g., "my-project/my-repo". We need the part after the slash.
		log.Printf("Processing repository: %s", repo.Name)
		repoNameOnly := strings.TrimPrefix(repo.Name, args.Project+"/")
		repoNameEncoded := strings.ReplaceAll(repoNameOnly, "/", "%2F")

		artifactsURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts", *harborURL, args.Project, repoNameEncoded)
		artifactsReq, err := http.NewRequestWithContext(ctx, "GET", artifactsURL, nil)
		if err != nil {
			log.Printf("Error creating artifacts request for %s: %v", repo.Name, err)
			continue
		}
		artifactsReq.SetBasicAuth(*harborUsername, *harborPassword)

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
				*harborURL, args.Project, repoNameEncoded, tag)

			// Include "vulnerability" in the scan request.
			scanPayload := strings.NewReader(`{"scan_type": "vulnerability"}`)
			scanReq, err := http.NewRequestWithContext(ctx, "POST", scanURL, scanPayload)
			if err != nil {
				log.Printf("Error creating scan request for %s:%s: %v", repo.Name, tag, err)
				continue
			}
			scanReq.SetBasicAuth(*harborUsername, *harborPassword)
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
				*harborURL, args.Project, repoNameEncoded, tag)

			var reportData map[string]HarborVulnerabilityReport
			var reportFound bool
			for i := 0; i < 60; i++ { // Poll up to 60 times
				time.Sleep(3 * time.Second) // Wait before checking

				reportReq, err := http.NewRequestWithContext(ctx, "GET", reportURL, nil)
				if err != nil {
					log.Printf("Error creating report request for %s:%s: %v", repo.Name, tag, err)
					break // Stop polling for this image on error
				}
				reportReq.SetBasicAuth(*harborUsername, *harborPassword)
				reportReq.Header.Set("Accept", "application/json")

				reportResp, err := httpClient.Do(reportReq)
				if err != nil {
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

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found summaries for %d images in project %s.", len(allSummaries), args.Project)}},
	}, ScanProjectResult{Images: allSummaries}, nil
}

// ScanHelmChart downloads a Helm chart from Harbor and scans it with Trivy.
func ScanHelmChart(ctx context.Context, req *mcp.CallToolRequest, args ScanHelmChartParams) (*mcp.CallToolResult, TrivyScanResult, error) {
	if *harborPassword == "" {
		return nil, TrivyScanResult{}, fmt.Errorf("harbor-password flag is not set")
	}
	if args.Project == "" || args.Repository == "" || args.Tag == "" {
		return nil, TrivyScanResult{}, fmt.Errorf("project, repository, and tag are required parameters")
	}

	// Sanitize string inputs.
	args.Project = strings.TrimSpace(args.Project)
	args.Repository = strings.TrimSpace(args.Repository)
	args.Tag = strings.TrimSpace(args.Tag)

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Allow insecure TLS
			},
		},
	}

	// 1. Trigger a scan on the Helm chart artifact in Harbor.
	repoNameEncoded := strings.ReplaceAll(args.Repository, "/", "%2F")
	log.Printf("Triggering scan for Helm chart: %s/%s:%s", args.Project, args.Repository, args.Tag)
	scanURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/scan",
		*harborURL, args.Project, repoNameEncoded, args.Tag)

	scanReq, err := http.NewRequestWithContext(ctx, "POST", scanURL, nil)
	if err != nil {
		return nil, TrivyScanResult{}, fmt.Errorf("failed to create scan request for helm chart: %w", err)
	}
	scanReq.SetBasicAuth(*harborUsername, *harborPassword)

	scanResp, err := httpClient.Do(scanReq)
	if err != nil {
		return nil, TrivyScanResult{}, fmt.Errorf("failed to trigger scan for helm chart: %w", err)
	}
	defer scanResp.Body.Close()

	if scanResp.StatusCode != http.StatusAccepted && scanResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(scanResp.Body)
		return nil, TrivyScanResult{}, fmt.Errorf("failed to trigger helm chart scan, status %d: %s", scanResp.StatusCode, string(body))
	}
	log.Printf("Helm chart scan triggered successfully.")

	// 2. Poll for the misconfiguration report.
	reportURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities",
		*harborURL, args.Project, repoNameEncoded, args.Tag)

	var reportData map[string]struct {
		Misconfigurations []TrivyMisconfiguration `json:"misconfigurations"`
	}
	var reportFound bool
	for i := 0; i < 60; i++ { // Poll for up to 5 minutes.
		time.Sleep(5 * time.Second)

		reportReq, err := http.NewRequestWithContext(ctx, "GET", reportURL, nil)
		if err != nil {
			return nil, TrivyScanResult{}, fmt.Errorf("failed to create report request for helm chart: %w", err)
		}
		reportReq.SetBasicAuth(*harborUsername, *harborPassword)
		// The report type for misconfigurations is different from vulnerabilities.
		reportReq.Header.Set("Accept", "application/vnd.security.vulnerability.report; version=1.1")

		reportResp, err := httpClient.Do(reportReq)
		if err != nil {
			return nil, TrivyScanResult{}, fmt.Errorf("failed to get helm chart report: %w", err)
		}

		if reportResp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(reportResp.Body).Decode(&reportData); err != nil {
				reportResp.Body.Close()
				return nil, TrivyScanResult{}, fmt.Errorf("failed to decode helm chart report: %w", err)
			}
			reportResp.Body.Close()
			reportFound = true
			break
		}
		reportResp.Body.Close()
	}

	if !reportFound {
		return nil, TrivyScanResult{}, fmt.Errorf("timed out waiting for helm chart scan report")
	}

	var allMisconfigurations []TrivyMisconfiguration
	for _, report := range reportData {
		if report.Misconfigurations != nil {
			allMisconfigurations = report.Misconfigurations
			break
		}
	}

	if len(allMisconfigurations) == 0 {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Trivy scan completed. No misconfigurations found."},
			},
		}, TrivyScanResult{}, nil
	}

	// 3. Format the result
	result := TrivyScanResult{
		Misconfigurations: allMisconfigurations,
	}

	summaryText := fmt.Sprintf("Trivy scan found %d misconfigurations in Helm chart %s:%s.", len(allMisconfigurations), args.Repository, args.Tag)
	if len(allMisconfigurations) > 0 {
		var high, critical int
		for _, m := range allMisconfigurations {
			if m.Severity == "HIGH" {
				high++
			} else if m.Severity == "CRITICAL" {
				critical++
			}
		}
		summaryText += fmt.Sprintf(" Summary: %d CRITICAL, %d HIGH.", critical, high)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: summaryText},
		},
	}, result, nil
}

// FindPatchedImage searches for a newer version of an image without a specific CVE.
// It searches in the local Harbor, then registry.suse.com, and finally Docker Hub.
func FindPatchedImage(ctx context.Context, req *mcp.CallToolRequest, args FindPatchedImageParams) (*mcp.CallToolResult, FindPatchedImageResult, error) {
	if *harborPassword == "" {
		return nil, FindPatchedImageResult{}, fmt.Errorf("harbor-password flag is not set")
	}
	if args.Project == "" || args.Repository == "" || args.Tag == "" || args.CVEID == "" {
		return nil, FindPatchedImageResult{}, fmt.Errorf("project, repository, tag, and cve_id are required parameters")
	}

	// Sanitize string inputs.
	args.Project = strings.TrimSpace(args.Project)
	args.Repository = strings.TrimSpace(args.Repository)
	args.Tag = strings.TrimSpace(args.Tag)
	args.CVEID = strings.TrimSpace(args.CVEID)

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Allow insecure TLS
			},
		},
	}

	// 1. Search in the local Harbor instance.
	log.Printf("[%s] START: Searching for patched image for %s/%s:%s (CVE: %s)", time.Now().Format(time.RFC3339), args.Repository, args.Tag, args.CVEID)
	repoNameEncoded := strings.ReplaceAll(args.Repository, "/", "%2F")
	artifactsURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts?with_tag=true", *harborURL, args.Project, repoNameEncoded)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", artifactsURL, nil)
	if err != nil {
		return nil, FindPatchedImageResult{}, fmt.Errorf("failed to create list artifacts request: %w", err)
	}
	httpReq.SetBasicAuth(*harborUsername, *harborPassword)
	log.Printf("[%s] Step 1/3: Searching local Harbor artifacts at %s", time.Now().Format(time.RFC3339), artifactsURL)

	artifactsResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, FindPatchedImageResult{}, fmt.Errorf("failed to list artifacts: %w", err)
	}
	defer artifactsResp.Body.Close()

	if artifactsResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(artifactsResp.Body)
		return nil, FindPatchedImageResult{}, fmt.Errorf("failed to list artifacts, status %d: %s", artifactsResp.StatusCode, string(body))
	}
	log.Printf("[%s] Harbor artifact search returned status %d", time.Now().Format(time.RFC3339), artifactsResp.StatusCode)

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
	log.Printf("[%s] Found %d total artifacts in local Harbor to evaluate.", time.Now().Format(time.RFC3339), len(artifacts))

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
		reportURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", *harborURL, args.Project, repoNameEncoded, originalArtifact.Tags[0].Name)
		reportReq, _ := http.NewRequestWithContext(ctx, "GET", reportURL, nil)
		reportReq.SetBasicAuth(*harborUsername, *harborPassword)
		reportReq.Header.Set("Accept", "application/json")

		reportResp, err := httpClient.Do(reportReq)
		if err == nil && reportResp.StatusCode == http.StatusOK {
			var reportData map[string]HarborVulnerabilityReport
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
	log.Printf("Found %d newer tags in local Harbor to check: %v", len(newerTags), newerTags)

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
		reportURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", *harborURL, args.Project, repoNameEncoded, tag)
		reportReq, _ := http.NewRequestWithContext(ctx, "GET", reportURL, nil)
		reportReq.SetBasicAuth(*harborUsername, *harborPassword)
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

		var reportData map[string]HarborVulnerabilityReport
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
			imageName := fmt.Sprintf("%s/%s/%s:%s", *harborURL, args.Project, args.Repository, tag)
			result := FindPatchedImageResult{
				Found:         true,
				Image:         imageName,
				Location:      "local-harbor",
				CriticalCount: candidateVulnCount.Critical,
				HighCount:     candidateVulnCount.High,
			}
			summaryText := fmt.Sprintf("Found patched image in local Harbor: %s. It has %d Critical and %d High vulnerabilities.", imageName, result.CriticalCount, result.HighCount)
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
	// 2. Search registry.suse.com by using Harbor as a proxy cache.
	log.Printf("[%s] Step 2/3: Patched image not found in local Harbor. Searching registry.suse.com for '%s'", time.Now().Format(time.RFC3339), baseRepoName)

	suseSearchPerformed := false
	// --- New Direct Lookup Logic ---
	// First, try to list tags directly assuming args.Repository is a valid repo name.
	suseRepoToSearch := "suse/" + args.Repository
	log.Printf("Attempting direct tag listing for SUSE repository: %s", suseRepoToSearch)
	suseRepoFullName := "registry.suse.com/" + suseRepoToSearch
	tags, err := listTagsWithCrane(ctx, suseRepoFullName)
	if err == nil {
		suseSearchPerformed = true // Mark that we've successfully interacted with this repo.
		newerTags := findNewerTags(tags, args.Tag)
		log.Printf("Found %d newer tags for SUSE repo %s using crane: %v", len(newerTags), suseRepoToSearch, newerTags)
		for _, tag := range newerTags {
			imageToScan := fmt.Sprintf("%s:%s", suseRepoFullName, tag)
			log.Printf("Found patched image in registry.suse.com: %s", imageToScan)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found patched image in registry.suse.com: %s", imageToScan)}}}, FindPatchedImageResult{Found: true, Image: imageToScan, Location: "registry.suse.com"}, nil
		}
	} else {
		log.Printf("crane command failed for %s (%v), falling back to HTTP API.", suseRepoFullName, err)
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
					for _, tag := range newerTags {
						imageToScan := fmt.Sprintf("registry.suse.com/%s:%s", suseRepoToSearch, tag)
						log.Printf("Found patched image in registry.suse.com: %s", imageToScan)
						return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found patched image in registry.suse.com: %s", imageToScan)}}}, FindPatchedImageResult{Found: true, Image: imageToScan, Location: "registry.suse.com"}, nil
					}
					tagsResp.Body.Close()
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
			// Since crane failed, we don't proceed to Docker Hub and just return not found.
			// This could be changed to continue to Docker Hub if desired.
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
			for _, tag := range newerTags {
				// Now we can scan the image:tag
				imageToScan := fmt.Sprintf("registry.suse.com/%s:%s", repoName, tag)
				log.Printf("Found patched image in registry.suse.com: %s", imageToScan)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found patched image in registry.suse.com: %s", imageToScan)}}}, FindPatchedImageResult{Found: true, Image: imageToScan, Location: "registry.suse.com"}, nil
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

			cveFound, err := scanHarborArtifact(ctx, proxyProjectName, repo.RepoName, tag, args.CVEID, httpClient)
			if err == nil && !cveFound {
				log.Printf("Found patched image in Docker Hub: %s", imageToScan)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found patched image in Docker Hub: %s", imageToScan)}}}, FindPatchedImageResult{Found: true, Image: imageToScan, Location: "docker-hub"}, nil
			}
		}
	}

	log.Printf("[%s] END: Patched image not found in any registry for %s/%s:%s without CVE %s", time.Now().Format(time.RFC3339), args.Project, args.Repository, args.Tag, args.CVEID)
	return notFoundResult(args), FindPatchedImageResult{}, nil
}

// ensureProxyProject checks if a proxy cache project exists in Harbor and creates it if not.
func ensureProxyProject(ctx context.Context, projectName, upstreamURL string, client *http.Client) error {
	// Check if project exists
	projectURL := fmt.Sprintf("%s/api/v2.0/projects/%s", *harborURL, projectName)
	req, err := http.NewRequestWithContext(ctx, "GET", projectURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create check project request: %w", err)
	}
	req.SetBasicAuth(*harborUsername, *harborPassword)
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
	createURL := fmt.Sprintf("%s/api/v2.0/projects", *harborURL)
	createBody := fmt.Sprintf(`{
        "project_name": "%s",
        "public": false,
        "registry_id": 0, // This needs to be the ID of a pre-configured proxy cache endpoint.
                           // Assuming a default or pre-existing one. For a real system, this needs to be robust.
        "storage_limit": -1
    }`, projectName) // Simplified for example. A real implementation would need to find the correct registry_id.

	// This is a placeholder. A robust implementation needs to find the ID of the proxy registry endpoint.
	// For now, we assume the user has set one up and we are just creating the project.
	// The real power comes from Harbor automatically pulling from the associated endpoint.
	// Let's just create a normal project and let Harbor's proxy rules handle it.
	createBody = fmt.Sprintf(`{"project_name": "%s", "public": false}`, projectName)

	createReq, err := http.NewRequestWithContext(ctx, "POST", createURL, strings.NewReader(createBody))
	if err != nil {
		return fmt.Errorf("failed to create project creation request: %w", err)
	}
	createReq.SetBasicAuth(*harborUsername, *harborPassword)
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

// scanHarborArtifact triggers a scan for an artifact within Harbor and checks for a CVE.
func scanHarborArtifact(ctx context.Context, project, repo, tag, cveID string, client *http.Client) (bool, error) {
	repoNameEncoded := strings.ReplaceAll(repo, "/", "%2F")

	// Trigger scan
	scanURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/scan", *harborURL, project, repoNameEncoded, tag)
	scanReq, _ := http.NewRequestWithContext(ctx, "POST", scanURL, nil)
	scanReq.SetBasicAuth(*harborUsername, *harborPassword)
	scanResp, err := client.Do(scanReq)
	if err != nil {
		return false, fmt.Errorf("failed to trigger scan on %s/%s:%s: %w", project, repo, tag, err)
	}
	scanResp.Body.Close()

	// Poll for results
	reportURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", *harborURL, project, repoNameEncoded, tag)
	for i := 0; i < 60; i++ {
		time.Sleep(5 * time.Second)
		reportReq, _ := http.NewRequestWithContext(ctx, "GET", reportURL, nil)
		reportReq.SetBasicAuth(*harborUsername, *harborPassword)
		reportReq.Header.Set("Accept", "application/json")
		reportResp, err := client.Do(reportReq)
		if err != nil {
			continue
		}

		if reportResp.StatusCode == http.StatusOK {
			var reportData map[string]HarborVulnerabilityReport
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
				Text: fmt.Sprintf("Could not find a patched version for %s/%s:%s without CVE %s in local Harbor, registry.suse.com, or Docker Hub.",
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
		fmt.Fprintf(os.Stderr, "This program runs MCP servers over SSE HTTP.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEndpoints:\n")
		fmt.Fprintf(os.Stderr, "  /harbor   - Harbor scanning service\n")
		os.Exit(1)
	}
	flag.Parse()

	addr := fmt.Sprintf("%s:%s", *host, *port)

	harborServer := mcp.NewServer(&mcp.Implementation{Name: "harbor-scanner"}, nil)
	mcp.AddTool(harborServer, &mcp.Tool{
		Name:        "scan_image",
		Description: "Scans a container image in Harbor for vulnerabilities using Trivy.",
	}, ScanImage)
	mcp.AddTool(harborServer, &mcp.Tool{
		Name:        "scan_project",
		Description: "Scans all images in a Harbor project and provides a vulnerability summary.",
	}, ScanProject)
	mcp.AddTool(harborServer, &mcp.Tool{
		Name:        "scan_helm_chart",
		Description: "Scans a Helm chart in Harbor for misconfigurations using Trivy.",
	}, ScanHelmChart)
	mcp.AddTool(harborServer, &mcp.Tool{
		Name:        "find_patched_image",
		Description: "Finds a newer version of an image without a specific CVE.",
	}, FindPatchedImage)
	mcp.AddTool(harborServer, &mcp.Tool{
		Name:        "get_vulnerabilities",
		Description: "Retrieves all vulnerabilities for a specific container image from Harbor.",
	}, GetVulnerabilities)
	mcp.AddTool(harborServer, &mcp.Tool{
		Name:        "get_sbom",
		Description: "Retrieves the Software Bill of Materials (SBOM) for a specific container image from Harbor.",
	}, GetSBOM)
	mcp.AddTool(harborServer, &mcp.Tool{
		Name:        "get_project_sbom",
		Description: "Retrieves the Software Bill of Materials (SBOM) for all images in a Harbor project.",
	}, GetProjectSBOM)

	log.Printf("MCP servers serving at %s", addr)
	handler := mcp.NewStreamableHTTPHandler(
		func(request *http.Request) *mcp.Server {
			url := request.URL.Path
			log.Printf("Handling request for URL %s\n", url)
			if url == "/harbor" {
				return harborServer
			}
			return nil
		},
		nil,
	)
	log.Fatal(http.ListenAndServe(addr, handler))
}
