# Demo: Sapphire Sleet macOS Campaign
**threat-research-mcp** · Raw threat intel → analyst-ready detection package in one conversation

---

## The Story

A threat report lands in your inbox. Sapphire Sleet (DPRK-nexus, BlueNoroff) is targeting
your Web3 company via fake LinkedIn recruiters and a trojanised Zoom installer.

You have 30 minutes before the next standup. Here is what threat-research-mcp produces.

---

## Demo Flow (8 Steps)

```
1. Paste the report                          sapphire_sleet_input.txt
2. run_pipeline → full analysis              sapphire_sleet_pipeline.json
3. 7 ATT&CK techniques mapped with evidence
4. 10 hunt hypotheses (SPL / KQL / Elastic)
5. Sigma rule bundle generated               sapphire_sleet_sigma_bundle.yml
6. ATT&CK Navigator layer exported          sapphire_sleet_navigator_layer.json
7. Interactive HTML report generated         sapphire_sleet_report.html
8. Campaign tracker updated
```

---

## Results Summary

| Metric | Value |
|---|---|
| IOCs extracted | 6 (IPs, domains, hash, email) |
| ATT&CK techniques | 7 mapped |
| Hunt hypotheses | 10 (SPL + KQL + Elastic) |
| Sigma rules | 1 curated + 6 with community links |
| Navigator layer | Ready to drag into attack.mitre.org |
| Detection package | HTML report + YAML bundle + IOC CSV |

---

## Techniques Detected

| ID | Name | Tactic | Confidence |
|---|---|---|---|
| T1059.002 | AppleScript / osascript | execution | HIGH |
| T1543.001 | Launch Agent persistence | persistence | HIGH |
| T1548.006 | TCC database manipulation | defense-evasion | HIGH |
| T1555.001 | Keychain credential access | credential-access | HIGH |
| T1539 | Steal web session cookie | credential-access | MEDIUM |
| T1567.002 | Exfiltration via Telegram Bot API | exfiltration | HIGH |
| T1204.002 | User execution: malicious file | execution | MEDIUM |

---

## Demo Script

### Step 1 — Run the pipeline

```
run_pipeline_tool
  text: <paste sapphire_sleet_input.txt>
```

### Step 2 — Show the techniques with evidence

Point to the `techniques` array. Each technique shows:
- ATT&CK ID and name
- Confidence score and label (HIGH / MEDIUM / LOW)
- Evidence keywords that triggered the match

### Step 3 — Generate the Navigator layer

```
navigator_layer_from_map_attack
  map_attack_json: <paste techniques block>
```

Open `sapphire_sleet_navigator_layer.json` at:
https://mitre-attack.github.io/attack-navigator/

### Step 4 — Show hunt hypotheses

Each hypothesis includes:
- Specific hunt query (SPL, KQL, Elastic)
- The exact log source to query
- Actionable hypothesis statement

### Step 5 — Generate the HTML report

```
generate_threat_report
  pipeline_json: <pipeline output>
  title: "Sapphire Sleet macOS Campaign"
```

Open `sapphire_sleet_report.html` in any browser. No server needed.

### Step 6 — Key talking point

> "The other MCPs are excellent specialist tools.
> threat-research-mcp is the analyst workflow layer —
> it turns unstructured intel into an evidence-backed detection package."

---

## Output Files

| File | Description |
|---|---|
| `sapphire_sleet_input.txt` | Raw threat intelligence text |
| `sapphire_sleet_pipeline.json` | Full pipeline output (JSON) |
| `sapphire_sleet_report.html` | Interactive HTML report (D3 graph + hunt queries + Sigma) |
| `sapphire_sleet_navigator_layer.json` | ATT&CK Navigator layer |
| `sapphire_sleet_sigma_bundle.yml` | Sigma detection rules |
| `sapphire_sleet_iocs.csv` | IOC table with confidence scores |

---

## Companion MCPs (add to claude_desktop_config.json)

```json
{
  "mcpServers": {
    "threat-research-mcp": {
      "command": "uvx",
      "args": ["threat-research-mcp"]
    },
    "mitre-attack-mcp": {
      "command": "uvx",
      "args": ["mitre-attack-mcp"]
    },
    "security-detections-mcp": {
      "command": "uvx",
      "args": ["security-detections-mcp"]
    }
  }
}
```

With all three: Claude maps techniques → looks up full ATT&CK descriptions →
searches 8,200+ existing community rules → fills gaps with new detections.
