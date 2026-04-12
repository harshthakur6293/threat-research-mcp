# Canonical schemas (v1)

These models describe the **end state** of the pipeline you are building: **intel → structured IOC/TTP → ATT&CK alignment → hunt pack → multi-format detection bundle**.

## Top-level

| Model | Module | Role |
|-------|--------|------|
| `AnalysisProduct` | `schemas/analysis_product.py` | Single MCP/CLI deliverable for downstream teams. |
| `IntelProvenance` | same | Which feed/file/fingerprint produced the analysis. |

## IOCs

| Model | Module |
|-------|--------|
| `IocObject` (discriminated union) | `schemas/ioc_objects.py` |
| `IocIpv4`, `IocIpv6`, `IocDomain`, `IocUrl`, `IocEmail`, `IocHash`, … | same |

Use `kind` as the discriminator when serializing to JSON.

## ATT&CK / TTP

| Model | Module |
|-------|--------|
| `TechniqueAlignment` | `schemas/ttp_alignment.py` |

Holds `technique_id`, optional name, tactics, procedure hint, evidence, confidence, and `data_source_hints` for log-source mapping.

## Hunt handoff

| Model | Module |
|-------|--------|
| `HuntDeliveryPack` | `schemas/hunt_delivery.py` |
| `HuntOpportunity` | same |
| `HuntQueryArtifact` | same (`language`: kql, spl, sigma, eql, yara, pseudo, other) |

## Detection handoff

| Model | Module |
|-------|--------|
| `DetectionDeliveryBundle` | `schemas/detection_delivery.py` |
| `DetectionRuleArtifact` | same (`rule_format`: sigma, kql, spl, eql, yara, other) |

## Imports

```python
from threat_research_mcp.schemas import AnalysisProduct, IocIpv4, TechniqueAlignment
```

## Versioning

`AnalysisProduct.schema_version` is **"1.0"** today. Bump when making breaking JSON changes and keep release notes.

## Where it appears

- **CLI / `run_workflow`**: the full JSON response includes an **`analysis_product`** key (same schema as `docs/canonical-schemas.md`).
- **MCP**: tool **`analysis_product`** returns that object alone for easy client consumption.
