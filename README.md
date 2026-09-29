# Securiscan
# Securiscan

**Securiscan** is a robust, lightweight, and native standard-library security triage engine built to analyze vulnerabilities across **Web Applications, APIs, LLMs, and Mobile Packages** completely using Python standard built-ins.

## 🚀 Core Execution Modes

### 1. Passive External Inspection (Default Safest Mode)
Performs a native read-only standard-library GET request to analyze server cookies, session configurations, and missing header matrices (`CSP`, `HSTS`, `X-Frame-Options`) without sending attack payloads.
```bash
python securiscan.py -w "https://example.com"
```

### 2. Explicit Active Canary Probing (Authorized Scope Only)
Fires targeted, benign payloads to evaluate input-reflection (`XSS`, `SSTI`, `SQLi`) and path traversal bounds. This flag will **fail closed** if directed at private subnets or loopbacks without an accompanying authorization flag.
```bash
# Scan a verified public asset
python securiscan.py -w "https://example.com" --active

# Scan an authorized internal lab network
python securiscan.py -w "http://10.0.1" --active --allow-private-target "10.0.1.45"
```

### 3. Static Air-Gapped Code Diagnostics
Analyzes directories, dependency files, or configuration contexts 100% offline.
```bash
python securiscan.py -w ./source_code_dir --no-fetch --pdf triage_output.pdf
```

## 📋 Finding Policy Validation States
* **POTENTIAL:** Heuristic candidate matches found via static text patterns. Requires manual context inspection.
* **OBSERVED:** Direct structural configuration anomalies confirmed on live headers or server objects.
* **CONFIRMED:** Vulnerability reproduced actively via baseline-aware canary payload evaluation.
