import sys
import json

sys.path.insert(0, "src")
from threat_research_mcp.tools.run_pipeline import run_pipeline

articles = {
    "Microsoft — AI as Tradecraft (DPRK)": (
        "Source: https://www.microsoft.com/en-us/security/blog/2025/05/14/north-korean-threat-actors-ai/ "
        "North Korean threat actors Jasper Sleet Coral Sleet Emerald Sleet Sapphire Sleet Moonstone Sleet "
        "operationalize AI across attack workflows. AI-generated malware with emoji markers. "
        "Coral Sleet OtterCookie malware. Persona fabrication deepfake faceswap voice-changing software. "
        "Phishing infrastructure SOCKS5 OpenVPN reverse proxy. "
        "Microsoft Teams phishing lures. Spearphishing attachment with malicious file. "
        "PowerShell download cradle invoke-expression encodedcommand. Reflective code loading fileless in-memory execution. "
        "Credential dumping lsass mimikatz sekurlsa. Pass-the-hash lateral movement. "
        "Cobalt Strike beacon C2 HTTPS command and control. DNS tunneling exfiltration. "
        "Supply chain compromise malicious package pypi. GitHub Actions ci/cd malicious workflow. "
        "Stolen credentials valid accounts cloud account. Data theft exfiltrat. "
        "BEC fraud phishing spearphishing link malicious link."
    ),
    "Google Mandiant — UNC6692 Snow Flurries": (
        "Source: https://cloud.google.com/blog/topics/threat-intelligence/unc6692-snow-flurries "
        "UNC6692 Snow Flurries campaign. Microsoft Teams phishing impersonating it helpdesk teams lure. "
        "AutoHotkey scripts downloaded from AWS S3 bucket. "
        "Phishing domain service-page-25144.s3.us-west-2.amazonaws.com "
        "SNOWBELT browser extension backdoor AES-GCM encrypted C2 communications WebSocket command and control. "
        "C2 cloudfront-021.s3.us-west-2.amazonaws.com screenshot command execution file exfil payload. "
        "SHA256 7f1d71e1e079f3244a69205588d504ed830d4c473747bb1b5c520634cc5a2477 "
        "SNOWGLAZE Python tunneler WebSocket C2 wss://sad4w7h913-b4a57f9c36eb.herokuapp.com:443/ws "
        "SOCKS proxy json base64 data. SHA256 2fa987b9ed6ec6d09c7451abd994249dfaba1c5a7da1c22b8407c461e62f7e49 "
        "SNOWBASIN Python backdoor cmd.exe remote shell execution screenshot file exfiltration SSL bypass. "
        "SHA256 c8940de8cb917abe158a826a1d08f1083af517351d01642e6c7f324d0bba1eb8 "
        "lsass credential dump LSASS memory pass-the-hash lateral movement FTK Imager. "
        "Exfiltration via LimeWire C2 channel. Black Basta ransomware affiliate. "
        "T1566.004 T1059.001 T1003.001 T1550.002 T1071.001 T1041"
    ),
    "Google Mandiant — DarkSword iOS Exploit Chain": (
        "Source: https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain "
        "DarkSword iOS full-chain exploit chain targeting iOS zero-day. "
        "CVE-2025-31277 JavaScriptCore JIT. CVE-2026-20700 dyld PAC bypass zero-day. "
        "CVE-2025-43529 JavaScriptCore DFG zero-day. CVE-2025-14174 ANGLE WebGL zero-day. "
        "CVE-2025-43510 XNU copy-on-write. CVE-2025-43520 XNU VFS race condition. "
        "Exploit public-facing application deserialization heap spray buffer overflow RCE. "
        "UNC6748 Saudi Arabia snapshare.chat watering hole drive-by compromise. "
        "GHOSTKNIFE malware account exfiltration message theft screen capture screenshots audio recording. "
        "C2 IPs 62.72.21.10 72.60.98.48 "
        "PARS Defense commercial spyware sahibndn.io e5.malaymoil.com "
        "GHOSTSABER malware SQLite query execution device discovery file discovery. "
        "UNC6353 Russia static.cdncounter.net watering hole injection. "
        "GHOSTBLADE malware exfiltrates iMessage Telegram WhatsApp location history "
        "WiFi passwords cryptocurrency wallet crypto wallet health data. "
        "Exfiltration domain sqwas.shapelie.com "
        "SHA256 2e5a56beb63f21d9347310412ae6efb29fd3db2d3a3fc0798865a29a3c578d35 "
        "Sandbox escape PAC manipulation ROP gadget native code execution. "
        "Session cookie theft session hijack. Data from local system file collection. "
        "Memory manipulation process injection. Active November 2025 through March 2026."
    ),
}

DIV = "=" * 72

for name, text in articles.items():
    result = json.loads(run_pipeline(text=text))
    s = result["summary"]
    techs = result.get("techniques", {}).get("techniques", [])
    suppressed = result.get("techniques", {}).get("suppressed", [])
    iocs = result.get("iocs", {})
    hunts = result.get("hunt_hypotheses", {}).get("hypotheses", [])
    sigma_rules = result.get("detections", {}).get("sigma", {}).get("rules", [])

    ip_vals = [i["value"] if isinstance(i, dict) else i for i in iocs.get("ips", [])]
    dom_vals = [d["value"] if isinstance(d, dict) else d for d in iocs.get("domains", [])]
    hash_vals = [h["value"] if isinstance(h, dict) else h for h in iocs.get("hashes", [])]

    sq = result.get("source_quality_used") or s.get("source_quality", "unknown")
    print(DIV)
    print(f"  {name}  [{sq}]")
    print(DIV)

    print(f"\n  IOCs  ({s['iocs_extracted']} total)")
    if ip_vals:
        print(f"    IPs:     {ip_vals}")
    if dom_vals:
        print(f"    Domains: {dom_vals}")
    if hash_vals:
        print(f"    Hashes:  {[h[:20] + '...' for h in hash_vals]}")

    print(f"\n  ATT&CK Techniques  ({len(techs)} above threshold, {len(suppressed)} suppressed)")
    for t in techs:
        ev = ", ".join(t.get("evidence", [])[:3])
        print(f"    {t['id']:14} [{t['confidence_label']:6} {t['confidence']:.2f}]  {t['name']}")
        print(f"                     evidence: {ev}")

    print(
        f"\n  Hunts: {s['hunt_hypotheses_generated']}   Sigma rules: {s['sigma_rules_generated']}",
        end="",
    )
    curated = sum(1 for r in sigma_rules if r.get("status") == "curated")
    stubs = sum(1 for r in sigma_rules if r.get("status") == "no_curated_rule")
    print(f"  (curated={curated}, no_rule={stubs})")
    print()
