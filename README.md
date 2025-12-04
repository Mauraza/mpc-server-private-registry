# MPC-server Private Registry based on Harbor

This project implements a server that exposes the Model-Context Protocol (MCP) to interact with a Harbor private registry. It provides a set of tools for scanning container images and Helm charts for vulnerabilities and misconfigurations, as well as finding patched image versions.

## Overview

The `main.go` file sets up an HTTP server that listens for MCP requests on the `/harbor` endpoint. This server is designed to act as a bridge between an MCP-compatible client (like an AI agent) and a Harbor registry, allowing the client to perform security-related tasks.

The server relies on command-line flags for its configuration, including Harbor's URL and credentials.

## What is the Model-Context Protocol (MCP)?

The Model-Context Protocol (MCP) is an open standard designed to create a universal way for AI models to connect with external data sources, tools, and environments. [1, 2, 7] Often described as a "USB-C for AI applications," its goal is to replace the need for custom, one-off integrations with a single, standardized protocol. [1, 3, 5, 11]

MCP establishes a client-server architecture where an AI assistant (the "client") can discover and use tools exposed by an MCP "server". [2, 4] This project implements an MCP server that provides tools for interacting with a Harbor registry. By doing so, it allows any MCP-compatible AI client to perform security scans and other tasks without needing to understand the specifics of the Harbor API.

## Features & Tools

The server exposes several tools that can be called via the MCP protocol:

### `scan_image`

* **Description**: Scans a specific container image within Harbor for vulnerabilities.
* **Process**:
    1. Triggers a scan for the specified image (`project/repository:tag`) using the Harbor API.
    2. Polls the API until the vulnerability report is available.
    3. Returns a list of vulnerabilities found.
* **Parameters**: `project`, `repository`, `tag`.

### `scan_project`

* **Description**: Scans all container images within a specified Harbor project.
* **Process**:
    1. Lists all repositories in the project.
    2. For each repository, it iterates through all image artifacts.
    3. It triggers a scan for each image and polls for the results.
    4. Returns a summary for each image, including counts of critical, high, medium, and low severity vulnerabilities.
* **Parameters**: `project`.

### `find_patched_image`

* **Description**: Finds a newer version of a container image in Harbor that does not contain a specific CVE.
* **Process**:
    1. Lists all artifacts (images) in the specified repository.
    2. Identifies images that are newer than the given tag based on their push time.
    3. For each newer image, it fetches its vulnerability report.
    4. It checks if the specified `cve_id` is present in the report.
    5. The first newer image found without the CVE is returned as the "patched" version.
* **Parameters**: `project`, `repository`, `tag`, `cve_id`.

## Setup and Usage

To run the server, you need to provide the Harbor instance details via command-line flags.

```bash
# Example of running the server
go run main.go \
  --harbor-url "https://your-harbor-instance.com" \
  --harbor-username "your-user" \
  --harbor-password "your-password"
```

The server will start on `localhost:8080` by default. The MCP endpoint will be available at `http://localhost:8080/harbor`.
