# Dashboard Screenshot Evidence

**Purpose:** Show that the Streamlit dashboard runs against the committed results and model files. Every screenshot came from a real local run; no values were mocked or edited. The report itself is not covered here.

## 1. Captured screens

All files are in `results/figures/` and are full-page captures at 1680x1050, without browser chrome.

| File | Screen | Content |
|---|---|---|
| `dashboard_overview.png` | A. Triage overview | KPI cards, alert sources, risk distribution, recent high-risk alerts |
| `dashboard_alert_queue.png` | B. Alert queue | Filterable queue with risk, decision, review flag, process, rule ids, and ATT&CK |
| `dashboard_alert_detail.png` | C. Alert detail | Command line, process context, rule matches, ATT&CK, model probability, and risk reasons |
| `dashboard_rules_attack.png` | D. Rules and ATT&CK | Rule catalogue, severity and ATT&CK mapping, per-rule hits |
| `dashboard_model_experiments.png` | E. Model and experiments | E1-E5 metrics, saved threshold and fusion settings, PR curve, confusion matrix |
| `dashboard_vm_validation.png` | F. VM external validation | VM results, scenario summary, and the transfer caveat |
| `dashboard_manual_scorer.png` | G. Manual event scorer | Manual form, live `score_event` result, risk reasons, and calibration caveat |
| `dashboard_method_limitations.png` | H. Method and limitations | Method summary and the limitations from `docs/artifact_index.md` |

## 2. Capture details

| Item | Value |
|---|---|
| Capture time | 2026-11-10, 21:30 local (UTC+4) |
| Repository state | Working tree based on `c0ba2a3bd0487cab1272e40d96b40260df9b6071`; Deliverable-2 changes were uncommitted at capture |
| OS | Windows 11 (10.0.26200) |
| Python | 3.15.1 (`.venv\Scripts\python.exe`) |
| Streamlit | 1.66.1 |
| Theme | `dashboard/.streamlit/config.toml`: dark theme, background `#050608`, sidebar `#12141a`, accent `#ff3b3b` |
| Browser | Microsoft Edge 157.0.4341.42 through Playwright, headless |
| Viewport | 1680x1050, device scale factor 1, full page |
| Server | `streamlit run app.py` on port 8599, headless |
| After capture | Server stopped; nothing listening on port 8599 |

The PNGs were also checked programmatically. Each is a valid 1680x1050 image of roughly 215-285 KB, and an 80x80 luminance downsample gives a mean of 16-24 and a standard deviation of 16-32. That is consistent with a populated dark page rather than a blank render.

## 3. Reproducing the screenshots

The captures need the files under `results/` and the theme file above. From the repository root:

```powershell
Set-Location dashboard
..\.venv\Scripts\streamlit.exe run app.py --server.port 8599 --server.headless true
```

In another terminal, run this helper from the repository root. It waits for the overview metrics, selects each screen by its sidebar label, and writes the PNG.

```python
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path.cwd() / "results" / "figures"
OUT.mkdir(parents=True, exist_ok=True)
SCREENS = {
    "A. Triage overview": "overview",
    "B. Alert queue": "alert_queue",
    "C. Alert detail": "alert_detail",
    "D. Rules and ATT&CK": "rules_attack",
    "E. Model and experiments": "model_experiments",
    "F. VM external validation": "vm_validation",
    "G. Manual event scorer": "manual_scorer",
    "H. Method and limitations": "method_limitations",
}

with sync_playwright() as p:
    browser = p.chromium.launch(channel="msedge", headless=True)
    page = browser.new_page(
        viewport={"width": 1680, "height": 1050},
        device_scale_factor=1,
        reduced_motion="reduce",
    )
    page.goto("http://127.0.0.1:8599", wait_until="networkidle", timeout=120000)
    page.wait_for_selector('[data-testid="stMetric"]', timeout=120000)
    page.wait_for_timeout(2500)
    for label, slug in SCREENS.items():
        page.get_by_text(label, exact=True).first.click()
        page.wait_for_timeout(2200)
        page.screenshot(path=str(OUT / f"dashboard_{slug}.png"), full_page=True)
    browser.close()
```

If Playwright is missing, install it with `..\.venv\Scripts\pip.exe install playwright`. No browser download is needed when using the installed Edge channel.

Stop Streamlit with `Ctrl+C` afterwards, or close the process listening on port 8599. CSS-only edits reload when the file is saved; theme changes need a restart.

## 4. Scope

- The dashboard reads the committed result tables and model files, so the screenshots show the same numbers as `results/master_results.csv` and the evaluation documents.
- Screenshots are presentation evidence, not a replacement for the metric files.
- The manual scorer demonstrates the out-of-distribution triage aid. It is not part of the offline evaluation.
- The VM screen shows the 32-event external check, not a real-world performance estimate.
- `results/figures/` is deliberately excluded from the `.gitignore` rules so these images are committed with the other evidence.
