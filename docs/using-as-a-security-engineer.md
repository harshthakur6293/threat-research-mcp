# Using Threat Research MCP as a security engineer (another organization)

This page explains **how the server behaves end-to-end** and how to get the most value when your org already uses **Anomali**, **OTX**, **VirusTotal**, and other intel platforms.

## Mock walkthrough: you just found this on GitHub

**Persona:** Alex, a security engineer at **Contoso**, skimming open-source MCP servers for defensive workflows.

### Step 1 — Decide it fits, then clone

Alex reads the **README** and **`SECURITY.md`**: defensive scope, local paths for ingestion, optional SQLite, no mandatory vendor APIs. That matches a lab laptop and a read-only threat feed export.

```bash
cd /path/to/src   # any directory you use for clones (e.g. ~/src or C:\Users\you\src)
git clone https://github.com/harshdthakur6293/threat-research-mcp.git   # upstream; use your fork URL if you forked
cd threat-research-mcp
python3 -m venv .venv   # Windows: py -3 -m venv .venv
# Windows (cmd/PowerShell): .venv\Scripts\activate
# macOS / Linux: source .venv/bin/activate
python -m pip install -e ".[dev]"
```

**Optional sanity check:** `python -m threat_research_mcp --workflow threat_research --text "Phishing email with zip and PowerShell -enc"` prints JSON to the terminal (same orchestration the MCP uses, without Cursor).

### Step 2 — Register the server in your MCP client

Alex configures their MCP host (**Cursor**, **VS Code**, **Cline**, or any client that supports **stdio** MCP servers) so it starts this repo’s Python module. Cursor users open **Settings → MCP**; VS Code users often use **`.vscode/mcp.json`** or the MCP settings UI (see [VS Code MCP configuration](https://code.visualstudio.com/docs/copilot/reference/mcp-configuration)). They set (see **Example `mcp.json`** below):

- **`command` / `args`**: Python from **this repo’s venv** and `-m threat_research_mcp.server`.
- **`cwd`**: absolute path to the clone (so relative paths in source configs resolve predictably).
- **`THREAT_RESEARCH_MCP_DB`**: optional path to e.g. `data/db/runs.sqlite` for run history and search tools; omit for no disk persistence.

They **restart MCP** or reload the window so the new server starts.

### Step 3 — First chat turn (text-only “paste”)

In the **MCP-connected chat** (Cursor, VS Code Copilot chat, Cline, etc.), Alex pastes an internal one-paragraph incident note and asks for a **structured handoff** for hunt and detection. The assistant should call the MCP tool **`analysis_product`** with that text (and optionally `workflow`, default `threat_research`).

**What comes back (conceptually):** one JSON object matching **`AnalysisProduct`**: `narrative_summary`, `extracted_iocs`, `technique_alignments`, `hunt_pack`, `detection_bundle` (Sigma / KQL / SPL drafts where applicable), `review_status`, and `provenance`. Alex copies that JSON into a ticket, a wiki, or a downstream automation that expects the schema in **`docs/canonical-schemas.md`**.

*Mock fragment (illustrative, not live output):*

```json
{
  "product_id": "9f3e…",
  "schema_version": "1.0",
  "narrative_summary": "…",
  "extracted_iocs": [ { "type": "ipv4", "value": "203.0.113.10" } ],
  "technique_alignments": [ { "technique_id": "T1059", "technique_name": "…", "evidence": "…" } ],
  "hunt_pack": { "opportunities": [], "summary": "" },
  "detection_bundle": { "rules": [], "notes": [] }
}
```

### Step 4 — Normalize intel from a file (ingestion)

Alex drops a vendor PDF text export into `C:\Intel\reports\campaign_notes.txt` and creates a tiny **`my-sources.yaml`** in the repo (or any trusted directory) pointing at that file using the `local_file` type (see **`configs/sources.example.yaml`** and **`docs/ingestion.md`**).

They ask the assistant to call **`ingest_sources`** with the **absolute path** to `my-sources.yaml`.

**What comes back:** JSON with `count` and `documents[]`—each item is a **`NormalizedDocument`** (title, `normalized_text`, `fingerprint`, `source_name`, etc.). No workflow yet; this is “bring intel to a common shape.”

If **`THREAT_RESEARCH_MCP_DB`** is set, those documents are also **stored** for later search via **`search_ingested_intel`**.

### Step 5 — One tool: merged intel → full product

Alex wants **both** their paragraph and the ingested file in one run. They ask the assistant to call **`intel_to_analysis_product`** with:

- `text`: short analyst context (“Prioritize exfil indicators; customer is healthcare.”).
- `sources_config_path`: absolute path to the same `my-sources.yaml`.
- `workflow`: e.g. `threat_research` (or another supported workflow name).

**What comes back:** a single **`AnalysisProduct`** JSON again, but **`provenance`** should list **feed/file lineage** (source name, fingerprint, title) in addition to the workflow row—so hunt/detection consumers know which normalized documents drove the run.

### Step 6 — Optional: prove persistence

With SQLite enabled, Alex runs **`search_analysis_product_history`** with `text_query` set to a distinctive string from an earlier narrative, or **`search_ingested_intel`** with `source_name` matching their YAML `name`. They use **`get_stored_analysis_product`** with a `row_id` from the search result to pull the **full** stored product JSON.

### Step 7 — What Alex does Monday

- Pairs this MCP with **mitre-attack-mcp** in the same Cursor project for deeper technique lookups (see below).
- Keeps **secrets out of YAML**; uses env-injected credentials only where TAXII/API sources are approved.
- Treats the SQLite file as **sensitive**: path, permissions, retention per org policy (**`SECURITY.md`**).

---

## How this MCP works (step by step)

1. **You connect an MCP client** (e.g. Cursor) to the server process: `python -m threat_research_mcp.server` over **stdio**.
2. The client calls **tools** (functions with typed inputs/outputs). Each tool returns **text** (usually JSON as a string).
3. **Intel enters** in one of two ways:
   - **Paste / `text`**: analyst narrative, paste of a report, log snippet, etc.
   - **Ingestion**: a **YAML or JSON** file lists sources (`local_file`, `rss`, `html`, `stix_bundle`, `taxii`). The tool **`ingest_sources`** returns normalized documents; **`intel_to_analysis_product`** merges those bodies with optional `text`, then runs the workflow.
4. The **orchestrator** runs defensive workflows (`threat_research`, `hunt_generation`, …): research → (optional) hunting → (optional) detection → review.
5. The primary bundle for downstream teams is **`AnalysisProduct`** (JSON): IOCs, technique alignments, hunt pack, Sigma + KQL + SPL drafts, data-source hints, provenance.

You do **not** need to import Python modules in the IDE—the MCP tools are the interface.

## Example `mcp.json` (Cursor-style)

Adjust **`command`**, **`cwd`**, and optional **`env`** to your machine. Use the **Python interpreter from this repo’s venv** (the same environment where you ran `pip install -e ".[dev]"`). On Windows, forward slashes in JSON paths are fine (e.g. `C:/path/to/.venv/Scripts/python.exe`).

```json
{
  "mcpServers": {
    "threat-research-mcp": {
      "command": "/path/to/threat-research-mcp/.venv/bin/python",
      "args": ["-m", "threat_research_mcp.server"],
      "cwd": "/path/to/threat-research-mcp",
      "env": {
        "THREAT_RESEARCH_MCP_DB": "/path/to/threat-research-mcp/data/db/runs.sqlite"
      }
    }
  }
}
```

**VS Code** uses a similar layout under `"servers"` in `mcp.json`, often with `"type": "stdio"`; see the [MCP configuration reference](https://code.visualstudio.com/docs/copilot/reference/mcp-configuration). **Cline** stores servers in `cline_mcp_settings.json` (see the Cline docs for the file location on your OS); fields map to the same `command` / `args` / `cwd` / `env` idea.

- **`THREAT_RESEARCH_MCP_DB`**: optional; enables SQLite for workflow runs, ingested documents, and analysis products, plus MCP history search tools (see README **Optional: SQLite persistence** and `SECURITY.md`). Omit if you do not want local SQLite files.
- **Python 3.10+** is recommended if you rely on the `mcp` package; the repo also supports older Python for CLI-only use.

## Getting the best from first-party intel (Anomali, OTX, VT, …)

This MCP **does not embed** Anomali or VirusTotal SDKs by default. Integrate **the way your org already moves intel**:

| Platform | Practical pattern with this MCP |
|----------|----------------------------------|
| **AlienVault OTX** | Export or sync pulses to **JSON/STIX** on disk or a **TAXII** collection; ingest via `stix_bundle` / `taxii` / `local_file`. Or use an RSS/HTML export if your team has one. |
| **Anomali / ThreatStream** | Export reports or indicators to **files** (STIX, CSV, HTML) on a **trusted path**; use `local_file` or `html_report`. If the product exposes **TAXII 2.1**, use the `taxii` source type with `api_root` + `collection_id` + auth. |
| **VirusTotal** (and similar) | Best as **IOC enrichment after extraction**: run `extract_iocs` or use `AnalysisProduct`, then enrich in a **peer MCP** (e.g. fastmcp-threatintel) or your SOAR. Keeps API keys and rate limits out of this repo. |
| **Internal blogs / Confluence** | **RSS** or **HTML** `url` sources if reachable from the host running the MCP server. |

**Tip:** Build one **`sources.yaml`** per environment (lab vs prod) with only approved URLs and paths; store it in git **without secrets**, and inject credentials via environment variables expanded in your deployment layer—not committed literals.

## Better ATT&CK: using **mitre-attack-mcp** with this server

Today, **this** server’s `attack_map` is **keyword-based** for offline use. For **full matrix** lookups (any technique, tactics, Navigator layers):

1. Add **[mitre-attack-mcp](https://github.com/MHaggis/mitre-attack-mcp)** to the **same** Cursor `mcp.json` (second server entry).
2. In the assistant, chain work explicitly, e.g.  
   “Call `attack_map` / `analysis_product` on this report, then use mitre-attack-mcp `get_technique` / `search_techniques` for each ID and suggest detection refinements.”

**Calling mitre-attack-mcp from inside this Python process** (one server calling another) is possible as a **future embedded bridge** (subprocess + MCP client), but it adds deployment, auth, and failure-mode complexity. For most organizations, **host-level composition** (two MCPs + clear analyst prompts) is the right first step.

## Persistence: SQLite vs graph (Neo4j, Vertex Synapse)

- **SQLite** (already optional for workflow runs) is the **simplest** durable store: audit trail, replay, local-first.
- **Neo4j (Cypher)** or **Vertex Synapse** are a strong fit when you need **relationship-centric** intel (actor → campaign → indicator → technique) and graph queries. They are **not required** to get value from this MCP.
- A sensible **evolution** is: normalize here → **export** STIX/JSON or bulk-load into your graph platform → keep this MCP as the **ingestion + drafting** edge. The repo already has **placeholder** packages under `integrations/neo4j` and `integrations/synapse` for future work.

Choose graph when your **query patterns** are inherently relational; choose SQLite + files when you need **low ops** and fast adoption.

## Quick reference — high-value tools

| Goal | Tool |
|------|------|
| One JSON handoff for hunt + detection | `intel_to_analysis_product` or `analysis_product` |
| Normalize feeds only | `ingest_sources` |
| Validate a Sigma string | `validate_sigma` |
| Quick IOCs / summary / map | `extract_iocs`, `summarize`, `attack_map` |

For deeper background, see **`docs/architecture.md`**, **`docs/organization-adoption.md`**, and **`docs/ingestion.md`**.
