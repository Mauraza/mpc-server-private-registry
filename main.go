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
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	host           = flag.String("host", "localhost", "host to listen on")
	port           = flag.String("port", "8080", "port to listen on")
	harborURL      = flag.String("harbor-url", "http://localhost:8081", "Harbor instance URL")
	harborUsername = flag.String("harbor-username", "admin", "Harbor username for API access")
	harborPassword = flag.String("harbor-password", "", "Harbor password for API access")
)

type SayHiParams struct {
	Name string `json:"name"`
}

func SayHi(ctx context.Context, req *mcp.CallToolRequest, args SayHiParams) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "Hi " + args.Name},
		},
	}, nil, nil
}

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

// HarborVulnerabilityReport represents the structure of the vulnerability report
// object returned by Harbor, which contains the list of vulnerabilities.
type HarborVulnerabilityReport struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// ScanImage is a tool handler that triggers a vulnerability scan in Harbor for a given
// container image and returns the results.
func ScanImage(ctx context.Context, req *mcp.CallToolRequest, args ScanImageParams) (*mcp.CallToolResult, ScanResult, error) {
	if *harborPassword == "" {
		return nil, ScanResult{}, fmt.Errorf("harbor-password flag is not set")
	}

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

	httpReq, err := http.NewRequestWithContext(ctx, "POST", scanURL, nil)
	if err != nil {
		return nil, ScanResult{}, fmt.Errorf("failed to create scan request: %w", err)
	}
	httpReq.SetBasicAuth(*harborUsername, *harborPassword)

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
	for i := 0; i < 10; i++ { // Poll up to 10 times
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

// ScanProject scans all images in a given Harbor project and returns a summary of vulnerabilities.
func ScanProject(ctx context.Context, req *mcp.CallToolRequest, args ScanProjectParams) (*mcp.CallToolResult, ScanProjectResult, error) {
	if *harborPassword == "" {
		return nil, ScanProjectResult{}, fmt.Errorf("harbor-password flag is not set")
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Allow insecure TLS
			},
		},
	}

	// 1. List repositories in the project
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

	var allSummaries []ImageVulnerabilitySummary

	// 2. For each repository, list artifacts and get vulnerability summaries
	for _, repo := range repositories {
		// Harbor repo names include the project, e.g., "my-project/my-repo". We need the part after the slash.
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

		// 3. For each artifact, get its summary
		for _, artifact := range artifacts {
			if len(artifact.Tags) == 0 {
				continue // Skip artifacts with no tags
			}
			tag := artifact.Tags[0].Name // Use the first tag to identify the image

			// We can reuse the single-image scan logic, but we'll call it directly.
			// This is a simplified version that doesn't re-trigger scans, just fetches reports.
			reportURL := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities",
				*harborURL, args.Project, repoNameEncoded, tag)

			reportReq, err := http.NewRequestWithContext(ctx, "GET", reportURL, nil)
			if err != nil {
				log.Printf("Error creating report request for %s:%s: %v", repo.Name, tag, err)
				continue
			}
			reportReq.SetBasicAuth(*harborUsername, *harborPassword)
			reportReq.Header.Set("Accept", "application/json")

			reportResp, err := httpClient.Do(reportReq)
			if err != nil {
				log.Printf("Error getting report for %s:%s: %v", repo.Name, tag, err)
				continue
			}

			summary := ImageVulnerabilitySummary{ImageName: fmt.Sprintf("%s:%s", repo.Name, tag)}
			if reportResp.StatusCode == http.StatusOK {
				var reportData map[string]HarborVulnerabilityReport
				if err := json.NewDecoder(reportResp.Body).Decode(&reportData); err == nil {
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
				}
			}
			reportResp.Body.Close()
			allSummaries = append(allSummaries, summary)
		}
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Found summaries for %d images in project %s.", len(allSummaries), args.Project)}},
	}, ScanProjectResult{Images: allSummaries}, nil
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "This program runs MCP servers over SSE HTTP.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEndpoints:\n")
		fmt.Fprintf(os.Stderr, "  /greeter1 - Greeter 1 service\n")
		fmt.Fprintf(os.Stderr, "  /harbor   - Harbor scanning service\n")
		fmt.Fprintf(os.Stderr, "  /greeter2 - Greeter 2 service\n")
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

	log.Printf("MCP servers serving at %s", addr)
	handler := mcp.NewStreamableHTTPHandler(func(request *http.Request) *mcp.Server {
		url := request.URL.Path
		log.Printf("Handling request for URL %s\n", url)
		switch url {
		case "/harbor":
			return harborServer
		default:
			return nil
		}
	}, nil)
	log.Fatal(http.ListenAndServe(addr, handler))
}
