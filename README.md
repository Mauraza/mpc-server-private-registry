# MPC-server Private Registry based on Harbor

This project lets you use an AI assistant to scan your Harbor private registry for security vulnerabilities. It acts as a bridge, allowing any AI that "speaks" the Model-Context Protocol (MCP) to find security issues in your container images.

Think of it like asking a smart assistant: *"Hey, are there any critical vulnerabilities in my `production/api-server:v1.2` image?"* This server gives the AI the tools it needs to answer that question.

## Overview

This project runs a simple web server that listens for requests on the `/harbor` endpoint. When an AI assistant sends a request, the server translates it into actions for your Harbor registry, like starting a vulnerability scan or checking for patched images.

The server relies on command-line flags for its configuration, including Harbor's URL and credentials.

The Model-Context Protocol (MCP) is an open standard designed to create a universal way for AI models to connect with external data sources, tools, and environments. [1, 2, 7] Often described as a "USB-C for AI applications," its goal is to replace the need for custom, one-off integrations with a single, standardized protocol. [1, 3, 5, 11]

MCP establishes a client-server architecture where an AI assistant (the "client") can discover and use tools exposed by an MCP "server". [2, 4] This project implements an MCP server that provides tools for interacting with a Harbor registry. By doing so, it allows any MCP-compatible AI client to perform security scans and other tasks without needing to understand the specifics of the Harbor API.

## Features & Tools

The server exposes several tools that can be called via the MCP protocol:

### 1. `scan_image`

* **What it does**: Scans a single container image for security vulnerabilities.
* **Process**:
    1. Triggers a scan for the specified image (`project/repository:tag`) using the Harbor API.
    2. Polls the API until the vulnerability report is available.
    3. Returns a list of vulnerabilities found.
* **Parameters**: `project`, `repository`, `tag`.

### 2. `scan_project`

* **What it does**: Scans every container image in an entire Harbor project.
* **Process**:
    1. Lists all repositories in the project.
    2. For each repository, it iterates through all image artifacts.
    3. It triggers a scan for each image and polls for the results.
    4. Returns a summary for each image, including counts of critical, high, medium, and low severity vulnerabilities.
* **Parameters**: `project`.

### 3. `find_patched_image`

* **What it does**: Finds a newer, patched version of an image that fixes a specific vulnerability (CVE).
* **Process**:
    1. Lists all artifacts (images) in the specified repository.
    2. Identifies images that are newer than the given tag based on their push time.
    3. For each newer image, it fetches its vulnerability report.
    4. It checks if the specified `cve_id` is present in the report.
    5. Returns the first newer image found that doesn't have the CVE.
* **Parameters**: `project`, `repository`, `tag`, `cve_id`.

## Setup and Usage

### Prerequisites

* **Go**: Version 1.18 or newer.
* **cURL**: Used for testing and interacting with the MCP server from the command line.
* **Crane**: A command-line tool for interacting with container registries. It's useful for managing images outside the MCP server.

The required Go packages will be downloaded automatically when you build or run the application for the first time.

To run the server, you need to provide the Harbor instance details via command-line flags.

```bash
# Example of running the server
go run main.go \
  --harbor-url "https://your-harbor-instance.com" \
  --harbor-username "your-user" \
  --harbor-password "your-password"
```

The server will start on `localhost:8080` by default. The MCP endpoint will be available at `http://localhost:8080/harbor`.

## Examples

You can interact with the MCP server using cURL or any MCP-compatible client. Below are examples of how to call each tool using cURL.

### Get SBOM for a specific image

```bash
curl -X POST http://localhost:8080/harbor \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "get_sbom",
      "arguments": {
        "project": "library",
        "repository": "valkey",
        "tag": "8.0.2"
      }
    }
  }'
```

### Get vulnerabilities for a specific image

```bash
curl -X POST http://localhost:8080/harbor \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "get_vulnerabilities",
      "arguments": {
        "project": "library",
        "repository": "valkey",
        "tag": "8.0.2"
      }
    }
  }'
```

### Scan a single image for vulnerabilities

```bash
curl -X POST http://localhost:8080/harbor \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "scan_image",
      "arguments": {
        "project": "library",
        "repository": "valkey",
        "tag": "8.0.2"
      }
    }
  }'
```

### Scan all images in a project

```bash
curl -X POST http://localhost:8080/harbor \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "scan_project",
      "arguments": {
        "project": "library"
      }
    }
  }'
```

### Get SBOM for all images in a project

```bash
curl -X POST http://localhost:8080/harbor \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "tools/call",
    "params": {
      "name": "get_project_sbom",
      "arguments": {
        "project": "library"
      }
    }
  }'
```

### Scan a Helm chart for misconfigurations

```bash
curl -X POST http://localhost:8080/harbor \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 6,
    "method": "tools/call",
    "params": {
      "name": "scan_helm_chart",
      "arguments": {
        "project": "library",
        "repository": "my-helm-chart",
        "tag": "1.0.0"
      }
    }
  }'
```

### Find a patched image without a specific CVE

```bash
curl -X POST http://localhost:8080/harbor \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 7,
    "method": "tools/call",
    "params": {
      "name": "find_patched_image",
      "arguments": {
        "project": "library",
        "repository": "valkey",
        "tag": "8.0.1",
        "cve_id": "CVE-2023-12345"
      }
    }
  }'
```
