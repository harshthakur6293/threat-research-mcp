from __future__ import annotations

from pathlib import Path
from textwrap import dedent


ROOT = Path(__file__).resolve().parents[1]


def write(rel: str, content: str) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(content).lstrip("\n"), encoding="utf-8")


def touch(rel: str) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("", encoding="utf-8")


def main() -> None:
    files = {
        "README.md": """
            # Threat Research MCP

            Threat Research MCP is an open-source MCP server and orchestration framework for defensive security research, threat hunting, and detection engineering.

            ## Core capabilities

            - IOC extraction from unstructured text
            - Threat report summarization and ATT&CK keyword mapping
            - Hunt hypothesis generation
            - Sigma detection draft generation
            - Timeline reconstruction and log explanation
            - Coverage gap analysis primitives

            ## Safety scope

            This project is defensive-only and intended for authorized environments.

            ## Quickstart

            ```bash
            python -m pip install -e .[dev]
            python -m threat_research_mcp --workflow threat_research --text "Phishing campaign using encoded PowerShell"
            pytest -q
            ```
        """,
        "LICENSE": """
            MIT License

            Copyright (c) 2026

            Permission is hereby granted, free of charge, to any person obtaining a copy
            of this software and associated documentation files (the "Software"), to deal
            in the Software without restriction, including without limitation the rights
            to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
            copies of the Software, and to permit persons to whom the Software is
            furnished to do so, subject to the following conditions:

            The above copyright notice and this permission notice shall be included in all
            copies or substantial portions of the Software.

            THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
            IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
            FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
            AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
            LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
            OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
            SOFTWARE.
        """,
        "CONTRIBUTING.md": """
            # Contributing

            Thank you for contributing to Threat Research MCP.

            ## Requirements

            - Keep changes defensive-only
            - Add or update tests
            - Avoid committing secrets
            - Keep PRs scoped and reviewable
        """,
        "CODE_OF_CONDUCT.md": """
            # Code of Conduct

            Be respectful, constructive, and professional in all interactions.
        """,
        "SECURITY.md": """
            # Security Policy

            ## Scope

            This repository supports defensive security workflows only.

            ## Reporting

            Please report vulnerabilities privately to the maintainer before public disclosure.
        """,
        "CHANGELOG.md": """
            # Changelog

            ## 0.1.0

            - Initial project scaffold for Threat Research MCP
            - Core tools, agent stubs, and orchestrator workflow
            - CI, security, and build workflows
        """,
        ".gitignore": """
            __pycache__/
            *.pyc
            .pytest_cache/
            .ruff_cache/
            .mypy_cache/
            .venv/
            venv/
            .env
            dist/
            build/
            *.egg-info/
            data/artifacts/
            data/cache/
            data/db/
        """,
        ".env.example": """
            OPENAI_API_KEY=
            MODEL_NAME=
        """,
        "pyproject.toml": """
            [build-system]
            requires = ["setuptools>=68", "wheel"]
            build-backend = "setuptools.build_meta"

            [project]
            name = "threat-research-mcp"
            version = "0.1.0"
            description = "Defensive security MCP server with multi-agent orchestration."
            readme = "README.md"
            requires-python = ">=3.10"
            license = { text = "MIT" }
            authors = [{ name = "Harsh Thakur" }]
            dependencies = ["mcp>=1.8.0", "pydantic>=2.7.0"]

            [project.optional-dependencies]
            dev = [
              "pytest>=8.0.0",
              "pytest-cov>=5.0.0",
              "ruff>=0.8.0",
              "mypy>=1.10.0",
              "bandit>=1.7.9",
              "pip-audit>=2.7.3",
              "build>=1.2.1",
              "twine>=5.1.1",
            ]

            [project.scripts]
            threat-research-mcp = "threat_research_mcp.cli:main"

            [tool.setuptools.packages.find]
            where = ["src"]

            [tool.pytest.ini_options]
            testpaths = ["tests"]
            pythonpath = ["src"]

            [tool.ruff]
            line-length = 100
            target-version = "py311"
        """,
        "Makefile": """
            .PHONY: lint test build security

            lint:
	python -m ruff check .
	python -m ruff format --check .

            test:
	python -m pytest -q

            build:
	python -m build

            security:
	python -m bandit -r src
	python -m pip_audit
        """,
        "src/threat_research_mcp/__init__.py": """
            __version__ = "0.1.0"
        """,
        "src/threat_research_mcp/__main__.py": """
            from threat_research_mcp.cli import main

            if __name__ == "__main__":
                main()
        """,
        "src/threat_research_mcp/config.py": """
            from pydantic import BaseModel


            class AppConfig(BaseModel):
                app_name: str = "Threat Research MCP"
                default_transport: str = "stdio"
        """,
        "src/threat_research_mcp/cli.py": """
            from __future__ import annotations

            import argparse
            from threat_research_mcp.orchestrator.workflow import run_workflow


            def main() -> None:
                parser = argparse.ArgumentParser(prog="threat-research-mcp")
                parser.add_argument("--workflow", default="threat_research")
                parser.add_argument("--text", default="")
                args = parser.parse_args()
                print(run_workflow(args.workflow, args.text))
        """,
        "src/threat_research_mcp/server.py": """
            from __future__ import annotations

            from threat_research_mcp.tools.extract_iocs import extract_iocs_json
            from threat_research_mcp.tools.summarize_threat_report import summarize_threat_report
            from threat_research_mcp.tools.map_attack import map_attack
            from threat_research_mcp.tools.generate_sigma import generate_sigma
            from threat_research_mcp.tools.explain_log import explain_log
            from threat_research_mcp.tools.reconstruct_timeline import reconstruct_timeline
            from threat_research_mcp.tools.generate_hunt_hypothesis import generate_hunt_hypothesis
            from threat_research_mcp.tools.detection_gap_analysis import detection_gap_analysis

            try:
                from mcp.server.fastmcp import FastMCP
            except Exception:
                FastMCP = None


            if FastMCP:
                mcp = FastMCP("Threat Research MCP")

                @mcp.tool()
                def extract_iocs(text: str) -> str:
                    return extract_iocs_json(text)

                @mcp.tool()
                def summarize(text: str) -> str:
                    return summarize_threat_report(text)

                @mcp.tool()
                def attack_map(text: str) -> str:
                    return map_attack(text)

                @mcp.tool()
                def sigma(title: str, behavior: str, logsource: str = "process_creation") -> str:
                    return generate_sigma(title, behavior, logsource)

                @mcp.tool()
                def explain(text: str) -> str:
                    return explain_log(text)

                @mcp.tool()
                def timeline(text: str) -> str:
                    return reconstruct_timeline(text)

                @mcp.tool()
                def hunt(text: str) -> str:
                    return generate_hunt_hypothesis(text)

                @mcp.tool()
                def coverage(techniques_csv: str, detections_csv: str) -> str:
                    return detection_gap_analysis(techniques_csv, detections_csv)


            def main() -> None:
                if FastMCP is None:
                    raise RuntimeError("mcp package not available. Install dependencies.")
                mcp.run(transport="stdio")
        """,
        "src/threat_research_mcp/schemas/__init__.py": """
            from .workflow import WorkflowState
            from .detection import DetectionRule
            from .hunt import HuntHypothesis
            from .coverage import CoverageRecord
        """,
        "src/threat_research_mcp/schemas/workflow.py": """
            from pydantic import BaseModel, Field


            class WorkflowState(BaseModel):
                workflow_type: str
                input_text: str
                extracted_iocs: dict = Field(default_factory=dict)
                summary: str = ""
                attack_mapping: list[dict] = Field(default_factory=list)
                hunt_hypothesis: str = ""
                sigma_draft: str = ""
                reviewer_notes: list[str] = Field(default_factory=list)
        """,
        "src/threat_research_mcp/schemas/detection.py": """
            from pydantic import BaseModel, Field


            class DetectionRule(BaseModel):
                title: str
                rule_type: str = "sigma"
                logic: str
                false_positives: list[str] = Field(default_factory=list)
        """,
        "src/threat_research_mcp/schemas/hunt.py": """
            from pydantic import BaseModel, Field


            class HuntHypothesis(BaseModel):
                title: str
                hypothesis: str
                related_techniques: list[str] = Field(default_factory=list)
        """,
        "src/threat_research_mcp/schemas/coverage.py": """
            from pydantic import BaseModel


            class CoverageRecord(BaseModel):
                technique_id: str
                coverage_status: str
        """,
        "src/threat_research_mcp/tools/extract_iocs.py": """
            from __future__ import annotations

            import json
            import re

            _IPV4 = re.compile(
                r"\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
                r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"
            )
            _HASH = re.compile(r"\\b(?:[a-fA-F\\d]{32}|[a-fA-F\\d]{40}|[a-fA-F\\d]{64})\\b")
            _EMAIL = re.compile(r"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b")
            _DOMAIN = re.compile(
                r"\\b(?=[a-zA-Z0-9.-]{4,253}\\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+"
                r"[a-zA-Z]{2,63}\\b"
            )
            _URL = re.compile(r"\\bhttps?://[^\\s<>\"{}|\\^`\\[\\]]+", re.IGNORECASE)


            def _unique(items: list[str]) -> list[str]:
                seen: set[str] = set()
                out: list[str] = []
                for item in items:
                    val = item.strip()
                    if val and val not in seen:
                        seen.add(val)
                        out.append(val)
                return out


            def extract_iocs_from_text(text: str) -> dict:
                if not text or not text.strip():
                    return {
                        "ips": [],
                        "domains": [],
                        "urls": [],
                        "hashes": [],
                        "emails": [],
                        "notes": "empty input",
                    }

                ips = _unique(_IPV4.findall(text))
                urls = _unique(_URL.findall(text))
                hashes = _unique(_HASH.findall(text))
                emails = _unique(_EMAIL.findall(text))
                domain_hits = _unique(_DOMAIN.findall(text))
                domains = [d for d in domain_hits if d not in ips and not any(d in u for u in urls)]

                return {
                    "ips": ips,
                    "domains": _unique(domains),
                    "urls": urls,
                    "hashes": hashes,
                    "emails": emails,
                    "notes": "heuristic extraction; verify before action",
                }


            def extract_iocs_json(text: str) -> str:
                return json.dumps(extract_iocs_from_text(text), indent=2)
        """,
        "src/threat_research_mcp/tools/summarize_threat_report.py": """
            def summarize_threat_report(text: str) -> str:
                cleaned = " ".join(text.split())
                if not cleaned:
                    return "Empty input report."
                return f"Summary: {cleaned[:400]}"
        """,
        "src/threat_research_mcp/tools/map_attack.py": """
            import json

            KEYWORDS = {
                "powershell": ("T1059.001", "PowerShell"),
                "phishing": ("T1566.001", "Spearphishing Attachment"),
                "scheduled task": ("T1053.005", "Scheduled Task"),
                "javascript": ("T1059.007", "JavaScript"),
            }


            def map_attack(text: str) -> str:
                out = []
                low = text.lower()
                for token, (tid, name) in KEYWORDS.items():
                    if token in low:
                        out.append({"id": tid, "name": name, "evidence": token})
                return json.dumps({"techniques": out}, indent=2)
        """,
        "src/threat_research_mcp/tools/generate_sigma.py": """
            def generate_sigma(title: str, behavior: str, logsource: str = "process_creation") -> str:
                return (
                    f"title: {title}\\n"
                    "status: experimental\\n"
                    "logsource:\\n"
                    f"  category: {logsource}\\n"
                    "  product: windows\\n"
                    "detection:\\n"
                    "  selection:\\n"
                    f"    CommandLine|contains: '{behavior}'\\n"
                    "  condition: selection\\n"
                    "level: medium\\n"
                )
        """,
        "src/threat_research_mcp/tools/explain_log.py": """
            def explain_log(event_text: str) -> str:
                return (
                    "Log explanation: review event context, process lineage, command line, and "
                    f"network behavior. Input excerpt: {event_text[:180]}"
                )
        """,
        "src/threat_research_mcp/tools/reconstruct_timeline.py": """
            def reconstruct_timeline(text: str) -> str:
                lines = [line.strip() for line in text.splitlines() if line.strip()]
                return "\\n".join(sorted(lines))
        """,
        "src/threat_research_mcp/tools/generate_hunt_hypothesis.py": """
            import json


            def generate_hunt_hypothesis(text: str) -> str:
                return json.dumps(
                    {
                        "title": "Generated Hunt Hypothesis",
                        "hypothesis": "Potential suspicious behavior should be validated across telemetry.",
                        "evidence": text[:220],
                        "required_telemetry": ["process_creation", "network_connections"],
                    },
                    indent=2,
                )
        """,
        "src/threat_research_mcp/tools/generate_detection_ideas.py": """
            import json


            def generate_detection_ideas(text: str) -> str:
                return json.dumps(
                    {
                        "input_excerpt": text[:180],
                        "ideas": [
                            "Detect suspicious parent-child process relationships",
                            "Correlate command line anomalies with outbound network",
                            "Flag persistence artifacts shortly after suspicious execution",
                        ],
                    },
                    indent=2,
                )
        """,
        "src/threat_research_mcp/tools/map_data_sources.py": """
            import json

            MAPPING = {
                "T1059.001": ["process_creation", "powershell_script_block"],
                "T1053.005": ["scheduled_task_events"],
                "T1566.001": ["email_gateway", "endpoint_process_events"],
            }


            def map_data_sources(technique_id: str) -> str:
                return json.dumps({"technique_id": technique_id, "data_sources": MAPPING.get(technique_id, [])}, indent=2)
        """,
        "src/threat_research_mcp/tools/detection_gap_analysis.py": """
            import json


            def detection_gap_analysis(techniques_csv: str, detections_csv: str) -> str:
                techniques = [x.strip() for x in techniques_csv.split(",") if x.strip()]
                detections = [x.strip() for x in detections_csv.split(",") if x.strip()]
                gaps = [t for t in techniques if t not in detections]
                return json.dumps({"techniques": techniques, "detections": detections, "gaps": gaps}, indent=2)
        """,
        "src/threat_research_mcp/agents/research_agent.py": """
            from threat_research_mcp.tools.extract_iocs import extract_iocs_from_text
            from threat_research_mcp.tools.summarize_threat_report import summarize_threat_report
            from threat_research_mcp.tools.map_attack import map_attack


            def run_research(text: str) -> dict:
                return {
                    "summary": summarize_threat_report(text),
                    "iocs": extract_iocs_from_text(text),
                    "attack": map_attack(text),
                }
        """,
        "src/threat_research_mcp/agents/hunting_agent.py": """
            from threat_research_mcp.tools.generate_hunt_hypothesis import generate_hunt_hypothesis
            from threat_research_mcp.tools.explain_log import explain_log
            from threat_research_mcp.tools.reconstruct_timeline import reconstruct_timeline


            def run_hunting(text: str) -> dict:
                return {
                    "hypothesis": generate_hunt_hypothesis(text),
                    "timeline": reconstruct_timeline(text),
                    "log_explanation": explain_log(text),
                }
        """,
        "src/threat_research_mcp/agents/detection_agent.py": """
            from threat_research_mcp.tools.generate_sigma import generate_sigma
            from threat_research_mcp.tools.generate_detection_ideas import generate_detection_ideas


            def run_detection(text: str) -> dict:
                return {
                    "sigma": generate_sigma("Generated Detection", text[:80]),
                    "ideas": generate_detection_ideas(text),
                }
        """,
        "src/threat_research_mcp/agents/reviewer_agent.py": """
            def run_review(research: dict, hunting: dict, detection: dict) -> dict:
                notes = []
                if not research.get("summary"):
                    notes.append("Missing research summary")
                if "sigma" not in detection:
                    notes.append("Missing sigma draft")
                return {"status": "pass_with_notes" if notes else "pass", "notes": notes, "confidence": "medium"}
        """,
        "src/threat_research_mcp/orchestrator/router.py": """
            def route_workflow(workflow: str) -> str:
                allowed = {
                    "threat_research",
                    "hunt_generation",
                    "detection_generation",
                    "timeline_reconstruction",
                    "log_explanation",
                    "coverage_analysis",
                    "report_comparison",
                }
                return workflow if workflow in allowed else "threat_research"
        """,
        "src/threat_research_mcp/orchestrator/state.py": """
            from threat_research_mcp.schemas.workflow import WorkflowState


            def init_state(workflow_type: str, input_text: str) -> WorkflowState:
                return WorkflowState(workflow_type=workflow_type, input_text=input_text)
        """,
        "src/threat_research_mcp/orchestrator/policy.py": """
            def defensive_policy_ok(text: str) -> bool:
                blocked = ["autonomous exploitation", "deploy malware", "credential theft"]
                low = text.lower()
                return not any(token in low for token in blocked)
        """,
        "src/threat_research_mcp/orchestrator/formatter.py": """
            import json


            def format_output(data: dict) -> str:
                return json.dumps(data, indent=2)
        """,
        "src/threat_research_mcp/orchestrator/approvals.py": """
            def requires_human_approval(action: str) -> bool:
                return action not in {"analyze", "summarize", "draft"}
        """,
        "src/threat_research_mcp/orchestrator/trace.py": """
            def record_trace(step: str, payload: dict) -> dict:
                return {"step": step, "keys": sorted(payload.keys())}
        """,
        "src/threat_research_mcp/orchestrator/workflow.py": """
            from threat_research_mcp.agents.research_agent import run_research
            from threat_research_mcp.agents.hunting_agent import run_hunting
            from threat_research_mcp.agents.detection_agent import run_detection
            from threat_research_mcp.agents.reviewer_agent import run_review
            from threat_research_mcp.orchestrator.router import route_workflow
            from threat_research_mcp.orchestrator.policy import defensive_policy_ok
            from threat_research_mcp.orchestrator.formatter import format_output


            def run_workflow(workflow: str, text: str) -> str:
                routed = route_workflow(workflow)
                if not defensive_policy_ok(text):
                    return format_output({"status": "blocked", "reason": "defensive policy violation"})

                research = run_research(text)
                hunting = run_hunting(text) if routed in {"hunt_generation", "timeline_reconstruction", "log_explanation", "coverage_analysis"} else {}
                detection = run_detection(text) if routed in {"threat_research", "detection_generation", "coverage_analysis"} else {}
                review = run_review(research, hunting, detection)

                return format_output({
                    "workflow": routed,
                    "research": research,
                    "hunting": hunting,
                    "detection": detection,
                    "review": review,
                })
        """,
        "tests/test_extract_iocs.py": """
            from threat_research_mcp.tools.extract_iocs import extract_iocs_from_text


            def test_extracts_ip_and_hash() -> None:
                text = "Beacon to 203.0.113.10 and hash deadbeefdeadbeefdeadbeefdeadbeef"
                r = extract_iocs_from_text(text)
                assert "203.0.113.10" in r["ips"]
                assert any(h.lower() == "deadbeefdeadbeefdeadbeefdeadbeef" for h in r["hashes"])


            def test_empty_input() -> None:
                r = extract_iocs_from_text("")
                assert r["ips"] == []
                assert "empty" in r["notes"].lower()
        """,
        "tests/test_workflow.py": """
            from threat_research_mcp.orchestrator.workflow import run_workflow


            def test_workflow_contains_expected_keys() -> None:
                out = run_workflow("threat_research", "Phishing led to PowerShell execution")
                assert "workflow" in out
                assert "research" in out
                assert "review" in out
        """,
        ".github/CODEOWNERS": """
            * @harshdthakur6293
            .github/workflows/* @harshdthakur6293
            src/threat_research_mcp/orchestrator/* @harshdthakur6293
            src/threat_research_mcp/integrations/* @harshdthakur6293
            SECURITY.md @harshdthakur6293
        """,
        ".github/PULL_REQUEST_TEMPLATE.md": """
            ## Summary

            ## Checklist
            - [ ] Defensive-only scope
            - [ ] Tests added or updated
            - [ ] No secrets committed
            - [ ] Documentation updated where needed
        """,
        ".github/workflows/ci.yml": """
            name: ci

            on:
              push:
                branches: [main]
              pull_request:

            jobs:
              test:
                runs-on: ubuntu-latest
                strategy:
                  matrix:
                    python-version: ["3.11", "3.12"]
                steps:
                  - uses: actions/checkout@v4
                  - uses: actions/setup-python@v5
                    with:
                      python-version: ${{ matrix.python-version }}
                      cache: pip
                  - run: python -m pip install --upgrade pip
                  - run: python -m pip install -e .[dev]
                  - run: python -m ruff check .
                  - run: python -m ruff format --check .
                  - run: python -m pytest -q --maxfail=1 --cov=src/threat_research_mcp --cov-fail-under=70
        """,
        ".github/workflows/security.yml": """
            name: security

            on:
              pull_request:
              push:
                branches: [main]
              schedule:
                - cron: "0 4 * * 1"

            jobs:
              checks:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - uses: actions/setup-python@v5
                    with:
                      python-version: "3.11"
                  - run: python -m pip install --upgrade pip
                  - run: python -m pip install -e .[dev]
                  - run: python -m bandit -r src
                  - run: python -m pip_audit
        """,
        ".github/workflows/build.yml": """
            name: build

            on:
              pull_request:
              push:
                branches: [main]

            jobs:
              package:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - uses: actions/setup-python@v5
                    with:
                      python-version: "3.11"
                  - run: python -m pip install --upgrade pip
                  - run: python -m pip install build twine
                  - run: python -m build
                  - run: python -m twine check dist/*
        """,
    }

    for rel, content in files.items():
        write(rel, content)

    placeholders = [
        "src/threat_research_mcp/tools/__init__.py",
        "src/threat_research_mcp/agents/__init__.py",
        "src/threat_research_mcp/orchestrator/__init__.py",
        "src/threat_research_mcp/ingestion/__init__.py",
        "src/threat_research_mcp/ingestion/base.py",
        "src/threat_research_mcp/ingestion/manager.py",
        "src/threat_research_mcp/ingestion/registry.py",
        "src/threat_research_mcp/ingestion/parser.py",
        "src/threat_research_mcp/ingestion/normalizer.py",
        "src/threat_research_mcp/ingestion/deduper.py",
        "src/threat_research_mcp/ingestion/adapters/__init__.py",
        "src/threat_research_mcp/ingestion/adapters/local_file_adapter.py",
        "src/threat_research_mcp/ingestion/adapters/rss_adapter.py",
        "src/threat_research_mcp/ingestion/adapters/taxii_adapter.py",
        "src/threat_research_mcp/ingestion/adapters/html_report_adapter.py",
        "src/threat_research_mcp/ingestion/adapters/base_http_adapter.py",
        "src/threat_research_mcp/memory/__init__.py",
        "src/threat_research_mcp/memory/session_store.py",
        "src/threat_research_mcp/memory/artifact_store.py",
        "src/threat_research_mcp/memory/retriever.py",
        "src/threat_research_mcp/memory/summarizer.py",
        "src/threat_research_mcp/memory/policy.py",
        "src/threat_research_mcp/storage/__init__.py",
        "src/threat_research_mcp/storage/sqlite.py",
        "src/threat_research_mcp/storage/models.py",
        "src/threat_research_mcp/storage/migrations.py",
        "src/threat_research_mcp/storage/repositories/__init__.py",
        "src/threat_research_mcp/storage/repositories/documents.py",
        "src/threat_research_mcp/storage/repositories/artifacts.py",
        "src/threat_research_mcp/storage/repositories/sessions.py",
        "src/threat_research_mcp/storage/repositories/sources.py",
        "src/threat_research_mcp/storage/repositories/detections.py",
        "src/threat_research_mcp/storage/repositories/hunts.py",
        "src/threat_research_mcp/storage/repositories/coverage.py",
        "src/threat_research_mcp/providers/__init__.py",
        "src/threat_research_mcp/providers/base.py",
        "src/threat_research_mcp/providers/openai_provider.py",
        "src/threat_research_mcp/providers/mock_provider.py",
        "src/threat_research_mcp/resources/__init__.py",
        "src/threat_research_mcp/resources/mitre_reference.py",
        "src/threat_research_mcp/resources/attack_data_sources.py",
        "src/threat_research_mcp/resources/sigma_style_guide.py",
        "src/threat_research_mcp/resources/detection_notes.py",
        "src/threat_research_mcp/resources/analyst_playbooks.py",
        "src/threat_research_mcp/resources/source_trust_registry.py",
        "src/threat_research_mcp/prompts/threat_research.md",
        "src/threat_research_mcp/prompts/hunt_generation.md",
        "src/threat_research_mcp/prompts/detection_engineering.md",
        "src/threat_research_mcp/prompts/reviewer.md",
        "src/threat_research_mcp/prompts/timeline_analysis.md",
        "src/threat_research_mcp/prompts/source_ingestion_review.md",
        "src/threat_research_mcp/prompts/detection_review.md",
        "src/threat_research_mcp/prompts/coverage_review.md",
        "src/threat_research_mcp/hunt/__init__.py",
        "src/threat_research_mcp/hunt/hypothesis_generator.py",
        "src/threat_research_mcp/hunt/hunt_planner.py",
        "src/threat_research_mcp/hunt/telemetry_mapper.py",
        "src/threat_research_mcp/hunt/hunt_formatter.py",
        "src/threat_research_mcp/hunt/hunt_prioritizer.py",
        "src/threat_research_mcp/hunt/templates/encoded_powershell.yaml",
        "src/threat_research_mcp/hunt/templates/suspicious_rundll32.yaml",
        "src/threat_research_mcp/hunt/templates/rare_outbound_connections.yaml",
        "src/threat_research_mcp/detection/__init__.py",
        "src/threat_research_mcp/detection/rule_generator.py",
        "src/threat_research_mcp/detection/rule_validator.py",
        "src/threat_research_mcp/detection/rule_optimizer.py",
        "src/threat_research_mcp/detection/detection_formatter.py",
        "src/threat_research_mcp/detection/detection_inventory.py",
        "src/threat_research_mcp/detection/logic_analyzer.py",
        "src/threat_research_mcp/detection/rule_templates/sigma/suspicious_powershell.yml",
        "src/threat_research_mcp/detection/rule_templates/sigma/rundll32_temp.yml",
        "src/threat_research_mcp/detection/rule_templates/sigma/scheduled_task_persistence.yml",
        "src/threat_research_mcp/detection/rule_templates/yara/README.md",
        "src/threat_research_mcp/detection/rule_templates/kql/README.md",
        "src/threat_research_mcp/detection/rule_templates/spl/README.md",
        "src/threat_research_mcp/detection/rule_templates/eql/README.md",
        "src/threat_research_mcp/coverage/__init__.py",
        "src/threat_research_mcp/coverage/attack_coverage_map.py",
        "src/threat_research_mcp/coverage/gap_analysis.py",
        "src/threat_research_mcp/coverage/datasource_mapper.py",
        "src/threat_research_mcp/coverage/telemetry_gaps.py",
        "src/threat_research_mcp/coverage/reporting.py",
        "src/threat_research_mcp/integrations/__init__.py",
        "src/threat_research_mcp/integrations/synapse/README.md",
        "src/threat_research_mcp/integrations/synapse/client.py",
        "src/threat_research_mcp/integrations/synapse/mapper.py",
        "src/threat_research_mcp/integrations/synapse/storm_queries.py",
        "src/threat_research_mcp/integrations/synapse/ingestion_bridge.py",
        "src/threat_research_mcp/integrations/neo4j/README.md",
        "src/threat_research_mcp/integrations/neo4j/client.py",
        "src/threat_research_mcp/integrations/neo4j/schema.py",
        "src/threat_research_mcp/integrations/neo4j/queries.py",
        "src/threat_research_mcp/integrations/opencti/README.md",
        "src/threat_research_mcp/integrations/opencti/client.py",
        "src/threat_research_mcp/integrations/opencti/mapper.py",
        "src/threat_research_mcp/integrations/misp/README.md",
        "src/threat_research_mcp/integrations/misp/client.py",
        "src/threat_research_mcp/integrations/misp/mapper.py",
        "src/threat_research_mcp/retrieval/exact.py",
        "src/threat_research_mcp/retrieval/semantic.py",
        "src/threat_research_mcp/retrieval/graph.py",
        "src/threat_research_mcp/retrieval/hybrid.py",
        "src/threat_research_mcp/retrieval/ranking.py",
        "src/threat_research_mcp/graph/ontology.py",
        "src/threat_research_mcp/graph/entities.py",
        "src/threat_research_mcp/graph/relationships.py",
        "src/threat_research_mcp/observability/__init__.py",
        "src/threat_research_mcp/observability/metrics.py",
        "src/threat_research_mcp/observability/tracing.py",
        "src/threat_research_mcp/observability/audit.py",
        "src/threat_research_mcp/tenancy/__init__.py",
        "src/threat_research_mcp/tenancy/workspace.py",
        "src/threat_research_mcp/tenancy/isolation.py",
        "src/threat_research_mcp/policy/source_trust.py",
        "src/threat_research_mcp/policy/data_retention.py",
        "src/threat_research_mcp/policy/redaction.py",
        "src/threat_research_mcp/policy/reviewer_thresholds.py",
        "src/threat_research_mcp/utils/__init__.py",
        "src/threat_research_mcp/utils/text.py",
        "src/threat_research_mcp/utils/yaml_utils.py",
        "src/threat_research_mcp/utils/validation.py",
        "src/threat_research_mcp/utils/time_utils.py",
        "src/threat_research_mcp/utils/ids.py",
        "src/threat_research_mcp/utils/hashing.py",
        "src/threat_research_mcp/utils/files.py",
        "docs/architecture.md",
        "docs/roadmap.md",
        "docs/safety-model.md",
        "docs/tool-contracts.md",
        "docs/agent-design.md",
        "docs/ingestion.md",
        "docs/memory-model.md",
        "docs/storage.md",
        "docs/evaluation.md",
        "docs/detection-engineering.md",
        "docs/threat-hunting.md",
        "docs/coverage-analysis.md",
        "docs/organization-adoption.md",
        "docs/quickstart-local.md",
        "docs/quickstart-docker.md",
        "docs/integration-opencti.md",
        "docs/integration-misp.md",
        "docs/integration-synapse.md",
        "docs/integration-neo4j.md",
        "docs/security-hardening.md",
        "docs/governance.md",
        "configs/sources.example.yaml",
        "configs/app.example.yaml",
        "configs/prompts.example.yaml",
        "configs/memory.example.yaml",
        "configs/policies.example.yaml",
        "configs/hunts.example.yaml",
        "configs/detections.example.yaml",
        "examples/sample_inputs/phishing_report.txt",
        "examples/sample_inputs/suspicious_command.txt",
        "examples/sample_inputs/timeline_notes.txt",
        "examples/sample_inputs/hunt_request.txt",
        "examples/expected_outputs/phishing_report_output.json",
        "examples/expected_outputs/sigma_rule.yml",
        "examples/expected_outputs/hunt_hypothesis.json",
        "examples/expected_outputs/coverage_report.json",
        "examples/run_local_workflow.py",
        "examples/run_ingestion_demo.py",
        "examples/run_compare_reports.py",
        "examples/run_hunt_generation.py",
        "examples/example_client_openai.py",
        "tests/conftest.py",
        "tests/fixtures/phishing_report.txt",
        "tests/fixtures/powershell_case.txt",
        "tests/fixtures/html_report_sample.html",
        "tests/fixtures/rss_feed_sample.xml",
        "tests/fixtures/taxii_sample.json",
        "tests/fixtures/hunt_case.json",
        "tests/fixtures/detection_inventory.json",
        "evals/benchmark_cases.json",
        "evals/score.py",
        "evals/run_evals.py",
        "evals/rubrics/ioc_extraction.json",
        "evals/rubrics/attack_mapping.json",
        "evals/rubrics/sigma_generation.json",
        "evals/rubrics/hunt_generation.json",
        "evals/rubrics/coverage_analysis.json",
        "evals/expected/ioc_extraction.json",
        "evals/expected/attack_mapping.json",
        "evals/expected/sigma_generation.yml",
        "evals/expected/hunt_generation.json",
        "evals/expected/coverage_analysis.json",
        "scripts/dev.sh",
        "scripts/lint.sh",
        "scripts/test.sh",
        "scripts/run_server.sh",
        "scripts/init_db.sh",
        "scripts/seed_examples.sh",
        "deployment/docker/Dockerfile",
        "deployment/docker/docker-compose.yml",
        "deployment/kubernetes/README.md",
        "deployment/systemd/README.md",
        ".github/ISSUE_TEMPLATE/bug_report.md",
        ".github/ISSUE_TEMPLATE/feature_request.md",
        ".github/ISSUE_TEMPLATE/new-source-adapter.md",
        ".github/ISSUE_TEMPLATE/new-tool.md",
        ".github/ISSUE_TEMPLATE/new-hunt-template.md",
        ".github/ISSUE_TEMPLATE/new-detection-template.md",
    ]
    for rel in placeholders:
        touch(rel)


if __name__ == "__main__":
    main()
