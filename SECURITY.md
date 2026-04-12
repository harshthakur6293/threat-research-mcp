# Security Policy

## Scope

This repository supports **defensive** security workflows only.

## Reporting

Please report security vulnerabilities **before** public disclosure so they can be triaged and fixed responsibly.

**GitHub (preferred):** If you are viewing this repository on GitHub, use **Security → Report a vulnerability** to open a **private** security advisory. Repository maintainers should enable **Private vulnerability reporting** under the repository’s **Settings → Security**.

**Other cases:** If GitHub advisories are not available (for example, a private mirror), contact the maintainers through a **private** channel they publish for this project (for example, an email address in the repository README or an organization security contact).

## Operational hardening (for operators)

### Ingestion and file paths

Tools **`ingest_sources`**, **`intel_to_analysis_product`**, and the CLI flag **`--sources`** read **local paths** from the machine running the MCP server or CLI. Treat source YAML/JSON as **trusted configuration**:

- Only point `path` / `url` / `api_root` at **authorized** feeds and directories.
- Prefer **read-only** service accounts for TAXII and HTTP-backed sources.
- **Path traversal**: do not expose unvalidated user-supplied strings as filesystem paths in automation.

### Secrets

- Do **not** commit API keys. Use environment variables or your MCP host’s secret store for TAXII basic auth, API keys, etc.
- VirusTotal / OTX and similar: if you use a separate enrichment MCP, keys live in **that** server’s config; this project does not ship vendor API clients by default.

### Network egress

RSS, HTML, and TAXII adapters perform **outbound HTTPS** from the host running this server. Restrict egress with your corporate firewall policies if required.

### Multi-MCP

When running **multiple MCP servers** in Cursor (or another host), each process has its own trust boundary. Review each server’s documentation before enabling it in production analyst environments.

### Local SQLite persistence (`THREAT_RESEARCH_MCP_DB`)

If you set **`THREAT_RESEARCH_MCP_DB`** to a file path, the process may create or grow a SQLite database on that host. Treat the file like any other sensitive analyst artifact:

- **Contents** can include **ingested intel** (titles, URLs, normalized bodies), **workflow input previews**, **full workflow JSON**, and **`AnalysisProduct`** payloads (narratives, IOCs, draft rules, review notes).
- **Placement**: use a path on encrypted disk, with OS file permissions restricted to the MCP/CLI service account; avoid world-readable locations.
- **Retention and backup**: define lifecycle (rotation, deletion, backup policy) according to your org’s data-handling rules for threat intel and detection drafts.
- **Omit the variable** if you want no local persistence from these features (tools that search history will report that the database is not configured).
