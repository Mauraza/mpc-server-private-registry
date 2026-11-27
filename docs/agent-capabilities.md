# Private Registry Scanner - Agent Capabilities

## Quick Reference

This document provides a concise reference for the 17 tools available in the private-registry-scanner server.

## Capability Summary

| Tool | Category | Purpose | Example requests |
|------|----------|---------|--------------|
| scan_image | Security | Scan single image for vulnerabilities | "scan", "security", "image vulnerability" |
| scan_project | Security | Scan all project images | "scan project", "project security" |
| get_vulnerabilities | Security | Get detailed vulnerability list | "vulnerabilities", "cves", "image security" |
| find_patched_image | Remediation | Find patched image version | "patch", "upgrade", "fix vulnerability" |
| get_sbom | Compliance | Get SBOM for image | "sbom", "bill of materials", "compliance" |
| get_project_sbom | Compliance | Get SBOMs for project images | "sbom project", "compliance audit" |
| list_projects | Inventory | List all registry projects | "list projects", "show projects" |
| list_repositories | Inventory | List project repositories | "list repositories", "show images" |
| list_tags | Inventory | List image tags/versions | "list tags", "image versions" |
| get_project | Inventory | Get project details | "project info", "project details" |
| get_project_summary | Inventory | Get project summary | "project summary", "overview" |
| search | Inventory | Search for images | "search images", "find image" |
| list_charts | Inventory | List Helm charts | "helm charts", "list charts" |
| list_chart_versions | Inventory | List chart versions | "chart versions", "helm versions" |
| create_project | Provisioning | Create new project | "create project", "new project" |
| get_health | Monitoring | Check registry health | "registry health", "status" |
| list_quotas | Monitoring | List resource quotas | "quotas", "storage quota" |

## Detailed Capability Descriptions

### Security Tools

#### scan_image
**Domain:** Container Image Security  
**Input:** project, repository, tag  
**Output:** List of vulnerabilities with severity levels

Perform a detailed security scan of a single container image for known vulnerabilities. Uses Trivy scanner integrated with the registry.

**When to use:** You need detailed vulnerability information for a specific image version.

```
Example: Scan image myrepo/myapp:v1.2.3 in project production
Returns: [
  {ID: "CVE-2024-1234", Severity: "HIGH", PackageName: "openssl", Version: "1.1.1", FixVersion: "1.1.1w"},
  {ID: "CVE-2024-5678", Severity: "CRITICAL", PackageName: "libc", ...}
]
```

---

#### scan_project
**Domain:** Container Image Security  
**Input:** project name  
**Output:** Vulnerability summary per image

Scan all container images in a registry project and provide a summary of vulnerabilities found.

**When to use:** You need a quick security posture assessment for all images in a project.

```
Example: Scan all images in production project
Returns: [
  {ImageName: "myapp:v1.0", CriticalCount: 1, HighCount: 3, MediumCount: 5},
  {ImageName: "myapp:v2.0", CriticalCount: 0, HighCount: 1, MediumCount: 2}
]
```

---

#### get_vulnerabilities
**Domain:** Container Image Security  
**Input:** project, repository, tag  
**Output:** Detailed vulnerability list with package info

Retrieve a comprehensive list of all vulnerabilities detected for a specific image, including package names, versions, and available fixes.

**When to use:** You need to analyze specific vulnerabilities or generate a vulnerability report.

```
Example: Get vulnerabilities for app:latest
Returns: {
  ImageName: "app:latest",
  TotalCount: 12,
  Vulnerabilities: [
    {ID: "CVE-2024-1234", Severity: "HIGH", PackageName: "openssl", Description: "..."}
  ]
}
```

---

#### find_patched_image
**Domain:** Vulnerability Remediation  
**Input:** project, repository, tag, CVE ID  
**Output:** Patched image location or no-patch status

Find a newer version of an image without a specific CVE vulnerability. Useful for patching strategies.

**When to use:** You need to identify patched versions for vulnerability remediation.

```
Example: Find app version without CVE-2024-1234
Returns: {
  Found: true,
  Image: "app:v2.1.0",
  Location: "https://registry.example.com/app/app/v2.1.0",
  CriticalCount: 0,
  HighCount: 1
}
```

---

### Compliance Tools

#### get_sbom
**Domain:** Software Supply Chain  
**Input:** project, repository, tag  
**Output:** Software Bill of Materials data and URL

Retrieve the Software Bill of Materials (SBOM) for a specific container image. Includes all software components, versions, and licenses.

**When to use:** You need compliance data, license tracking, or supply chain verification for a specific image.

```
Example: Get SBOM for app:v1.0
Returns: {
  ImageName: "app:v1.0",
  SBOM: {
    "components": [
      {"name": "openssl", "version": "1.1.1", "licenses": ["Apache-2.0"]},
      {"name": "curl", "version": "7.68.0", "licenses": ["MIT"]}
    ]
  },
  SBOMURL: "https://registry.example.com/sbom/app-v1.0.spdx"
}
```

---

#### get_project_sbom
**Domain:** Software Supply Chain  
**Input:** project name  
**Output:** SBOMs for all project images

Retrieve Software Bills of Materials for all container images in a registry project. Batch operation for compliance audits.

**When to use:** You need to audit all software components across all images in a project.

```
Example: Get SBOMs for production project
Returns: [
  {ImageName: "app:v1.0", ScanStatus: "Success", SBOMURL: "..."},
  {ImageName: "app:v2.0", ScanStatus: "Success", SBOMURL: "..."}
]
```

---

### Inventory Tools

#### list_projects
**Domain:** Registry Inventory  
**Input:** None  
**Output:** List of all projects

List all projects available in the private registry.

**When to use:** You need to discover available projects or get an inventory overview.

```
Example: List all projects
Returns: [
  {Name: "production", RepoCount: 5, CreationTime: "2024-01-15T10:30:00Z"},
  {Name: "staging", RepoCount: 3, CreationTime: "2024-01-10T14:20:00Z"}
]
```

---

#### list_repositories
**Domain:** Registry Inventory  
**Input:** project name  
**Output:** List of repositories in project

List all repositories within a specific registry project.

**When to use:** You need to see all image repositories in a project.

```
Example: List repositories in production project
Returns: [
  {Name: "production/backend"},
  {Name: "production/frontend"},
  {Name: "production/database"}
]
```

---

#### list_tags
**Domain:** Registry Inventory  
**Input:** project, repository  
**Output:** List of image tags

List all available tags (versions) for a specific image repository.

**When to use:** You need to find available versions of an image.

```
Example: List tags for production/backend
Returns: ["latest", "v2.1.0", "v2.0.5", "v1.9.8", "canary"]
```

---

#### get_project
**Domain:** Registry Inventory  
**Input:** project name  
**Output:** Detailed project information

Retrieve detailed metadata about a specific registry project.

**When to use:** You need detailed project information and statistics.

```
Example: Get production project details
Returns: {
  Name: "production",
  RepoCount: 5,
  CreationTime: "2024-01-15T10:30:00Z",
  Public: false,
  Description: "Production container images"
}
```

---

#### get_project_summary
**Domain:** Registry Inventory  
**Input:** project name  
**Output:** Quick project summary

Get a quick summary of a project without triggering long-running scans.

**When to use:** You need quick project statistics without waiting for vulnerability scans.

```
Example: Get production project summary
Returns: {
  Name: "production",
  RepoCount: 5,
  ArtifactCount: 23,
  CreationTime: "2024-01-15T10:30:00Z"
}
```

---

#### search
**Domain:** Registry Inventory  
**Input:** query string  
**Output:** Matching projects and repositories

Search for projects and repositories by name.

**When to use:** You need to find specific images in a large registry.

```
Example: Search for "app"
Returns: [
  {Type: "Project", Name: "production"},
  {Type: "Repository", Name: "production/myapp"},
  {Type: "Repository", Name: "staging/myapp-backend"}
]
```

---

#### list_charts
**Domain:** Registry Inventory  
**Input:** project name  
**Output:** List of Helm charts

List Helm charts available in a registry project.

**Note:** Requires chart repository support enabled in Harbor (may not be available in Harbor 2.11+).

**When to use:** You need to discover Helm charts in the registry.

```
Example: List charts in production project
Returns: ["nginx", "postgresql", "redis"]
```

---

#### list_chart_versions
**Domain:** Registry Inventory  
**Input:** project, chart name  
**Output:** List of chart versions

List available versions of a specific Helm chart.

**When to use:** You need to find available versions for Helm chart upgrades.

```
Example: List versions of nginx chart
Returns: ["1.2.0", "1.1.5", "1.1.0", "1.0.0"]
```

---

### Provisioning Tools

#### create_project
**Domain:** Registry Management  
**Input:** project name, public (boolean)  
**Output:** Created project details

Create a new project in the registry. Projects are private by default.

**When to use:** You need to set up a new namespace for container images.

```
Example: Create public project "myapp"
Returns: {
  Project: "myapp",
  Public: true,
  CreationTime: "2024-10-30T19:55:00Z"
}
```

---

### Monitoring Tools

#### get_health
**Domain:** System Monitoring  
**Input:** None  
**Output:** Health status of registry components

Check the overall health of the registry and its components (database, Redis, etc.).

**When to use:** You need to verify registry availability and component health.

```
Example: Check registry health
Returns: {
  Status: "healthy",
  Components: [
    {Name: "core", Status: "healthy"},
    {Name: "jobservice", Status: "healthy"},
    {Name: "registry", Status: "healthy"}
  ]
}
```

---

#### list_quotas
**Domain:** System Monitoring  
**Input:** Optional project name filter  
**Output:** Storage and artifact quotas

List storage and artifact-count quotas for projects.

**When to use:** You need to monitor storage usage or plan capacity.

```
Example: List quotas
Returns: [
  {Project: "production", StorageQuota: "100GB", StorageUsed: "75GB", ArtifactQuota: "unlimited"},
  {Project: "staging", StorageQuota: "50GB", StorageUsed: "12GB", ArtifactQuota: "1000"}
]
```

---

## Tool Categories

### Security Category
Focus: Vulnerability detection and assessment
- scan_image
- scan_project
- get_vulnerabilities
- find_patched_image

**Example triggers:** "scan", "vulnerability", "cve", "security", "exposure"

### Compliance Category
Focus: Software supply chain and compliance
- get_sbom
- get_project_sbom

**Example triggers:** "sbom", "compliance", "audit", "bill of materials", "license"

### Inventory Category
Focus: Discovery and metadata
- list_projects
- list_repositories
- list_tags
- get_project
- get_project_summary
- search
- list_charts
- list_chart_versions

**Example triggers:** "list", "show", "find", "search", "discover", "inventory"

### Provisioning Category
Focus: Infrastructure management
- create_project

**Example triggers:** "create", "provision", "setup", "new project"

### Monitoring Category
Focus: Health and capacity
- get_health
- list_quotas

**Example triggers:** "health", "status", "quota", "capacity", "monitoring"

## Usage Patterns

### Pattern 1: Security Audit
```
Query: "Check security of production images"
Workflow: list_projects → get_project_summary → scan_project → analyze results
```

### Pattern 2: Patch Management
```
Query: "Find patches for CVE-2024-1234 in production"
Workflow: scan_project → find_patched_image (for affected images) → report available patches
```

### Pattern 3: Compliance Reporting
```
Query: "Generate compliance report for platform project"
Workflow: get_project → get_project_sbom → compile report
```

### Pattern 4: Image Inventory
```
Query: "Show all images in production"
Workflow: get_project → list_repositories → list_tags → format results
```

## Performance Characteristics

| Tool | Typical Duration | Parallel Safe | Cancellable |
|------|------------------|---------------|------------|
| scan_image | 30s - 2m | No (1 at a time) | Yes |
| scan_project | 2m - 30m | No (1 at a time) | Yes |
| get_vulnerabilities | < 1s | Yes | N/A |
| find_patched_image | 1m - 5m | No | Yes |
| get_sbom | 10s - 1m | Yes | N/A |
| get_project_sbom | 1m - 10m | Partial | Yes |
| list_projects | < 1s | Yes | N/A |
| list_repositories | < 1s | Yes | N/A |
| list_tags | < 1s | Yes | N/A |
| get_project | < 1s | Yes | N/A |
| get_project_summary | < 1s | Yes | N/A |
| search | < 1s | Yes | N/A |
| list_charts | < 1s | Yes | N/A |
| list_chart_versions | < 1s | Yes | N/A |
| create_project | 1s - 3s | No | N/A |
| get_health | < 1s | Yes | N/A |
| list_quotas | < 1s | Yes | N/A |

## Error Handling

Each tool provides descriptive error messages:
- **Authentication errors:** Suggests credential verification
- **Network errors:** Suggests connectivity troubleshooting
- **Registry errors:** Includes registry error message details
- **Timeout errors:** Suggests increasing timeout or trying smaller scopes

Clients can use these error details when handling failures.

## Related Information

- See main README for individual tool parameter details
- See main.go for implementation details
