from __future__ import annotations

from pathlib import Path


ROOT = Path("src/threat_research_mcp")

MODULE_DESCRIPTIONS = {
    "coverage": "Detection coverage analysis helpers.",
    "detection": "Detection engineering helpers and rule utilities.",
    "graph": "Graph-model placeholders for future CTI relationship reasoning.",
    "hunt": "Threat hunting helper modules.",
    "ingestion": "Threat intelligence ingestion pipeline components.",
    "integrations": "External integration placeholders.",
    "memory": "Memory and context retention helpers.",
    "observability": "Logging, metrics, and tracing helpers.",
    "policy": "Policy and governance helpers.",
    "providers": "LLM/provider abstraction helpers.",
    "resources": "Static knowledge/resource placeholders.",
    "retrieval": "Retrieval strategy helpers.",
    "storage": "Persistence layer helpers.",
    "tenancy": "Workspace/tenant isolation helpers.",
    "tools": "Reusable MCP tool implementations.",
    "utils": "Utility helper functions.",
    "agents": "Agent role implementations for workflow orchestration.",
    "orchestrator": "Workflow routing and orchestration components.",
    "schemas": "Data contracts and schema models.",
}


def infer_desc(path: Path) -> str:
    parts = path.parts
    if len(parts) >= 3 and parts[0] == "src" and parts[1] == "threat_research_mcp":
        domain = parts[2]
        base = MODULE_DESCRIPTIONS.get(domain, "Project module placeholder.")
        if len(parts) >= 5 and domain == "integrations":
            return f"Integration placeholder for {parts[3]}."
        return base
    return "Project module placeholder."


def content_for(path: Path) -> str:
    desc = infer_desc(path)
    if path.name == "__init__.py":
        return f'"""{desc}"""\n\n__all__ = []\n'

    module_name = path.stem
    status_fn = f"get_{module_name}_status" if module_name.isidentifier() else "get_module_status"
    return (
        f'"""{desc}\n\n'
        "This module is scaffolded and intentionally minimal.\n"
        "Expand this file as features are implemented.\n"
        '"""\n\n'
        f"def {status_fn}() -> str:\n"
        '    """Return implementation status for this scaffold module."""\n'
        '    return "scaffolded"\n'
    )


def main() -> None:
    written = 0
    for py_file in ROOT.rglob("*.py"):
        if py_file.stat().st_size == 0:
            py_file.write_text(content_for(py_file), encoding="utf-8")
            written += 1
    print(f"Populated {written} empty Python files with scaffold stubs.")


if __name__ == "__main__":
    main()
