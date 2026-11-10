# Reproducibility and Dependencies

**Owners:** Hamdan Al Sabahi (Integration & quality) and Saif Abed (Data & ML)
**Purpose:** Record the environment, seeds, saved thresholds, and commands needed to reproduce the reported results.

## 1. Environment

| Item | Value |
|---|---|
| OS | Windows 11 (10.0.26200) |
| Python | 3.15.1 (MSC v.1951 64-bit) |
| Interpreter | `.venv\Scripts\python.exe` |
| Locked dependencies | `requirements-lock.txt` (from `pip freeze` on 2026-11-10) |
| Broad requirements | `requirements.txt` (version ranges for fresh installs) |

Key versions: `pandas 3.1.0`, `numpy 2.5.4`, `scikit-learn 1.9.1`, `xgboost 3.4.1`, `pyarrow 26.0.0`, `matplotlib 3.11.2`, `streamlit 1.66.1`, `fastapi 0.162.3`, `uvicorn 0.54.0`, and `pytest 9.2.0`.

The encoder branch also needs `transformers`, `tokenizers`, and `torch` (listed in `requirements.txt`). Those packages are not installed in the final scoring environment because the SecureBERT embeddings were produced on the training machine. The exact encoder-run package versions were not recorded; this is a known limitation. The saved encoder artifacts remain in `results/models/encoder_*.joblib`, and the checkpoint is recorded in `results/encoder_config.json` (`cisco-ai/SecureBERT2.0-base`).

## 2. Seeds and saved settings

| Setting | Value | Source |
|---|---|---|
| Split and sampling seed | 42 | `data/splits/manifest.json`, scripts |
| XGBoost threshold | 0.55 | `results/chosen_threshold.json` |
| XGBoost threshold selection | Validation F1; ties go to the lower threshold | `results/chosen_threshold.json` |
| Fusion weights | `w_xgb=0.4`, `w_encoder=0.6` | `results/fusion_config.json` |
| Fusion threshold | 0.50 (validation F1; ties go to lower FPR) | `results/fusion_config.json` |
| Encoder threshold | 0.20 (validation F1) | `results/encoder_config.json` |
| Held-out techniques | 15 ids, 8,122 malicious rows | `data/splits/manifest.json` |
| Benign-heavy prevalence | 1:100 | `results/benign_heavy_results.csv` |
| VM threshold | 0.55, not tuned on VM data | `docs/vm_results_summary.md` |

Splits use `cmd_normalized` (the command template) as the group key, so variants of the same command cannot cross train, validation, and test. Holdout rows whose template already appeared in another split were removed (`holdout_template_overlap_dropped=352`).

## 3. Commands

Run these from the repository root with the virtual environment active.

```powershell
# Audit the raw features export, then rebuild splits from the 100k working sample
python src/audit_dataset.py
python src/make_splits.py

# Tabular baseline (preprocessor is fitted on train only)
python src/preprocess.py
python src/train_xgb.py

# Encoder branch (needs transformers/torch and raw text; not run in final env)
python src/encode_securebert.py
python src/train_encoder.py

# Fusion, ablation, holdout, benign-heavy, thresholds, and confidence intervals
python src/hybrid_fusion.py
python src/ablation_e3.py
python src/eval_holdout.py
python src/benign_heavy_test.py
python src/threshold_and_uncertainty.py

# Rules baseline (E1) and hybrid-with-rules (E5)
python rules/run_rules.py --datasets test holdout
python src/hybrid_rules.py

# Consolidated tables and Deliverable-2 artifacts
python src/build_master_table.py
python src/export_artifacts.py

# VM external check and alert records (requires vm_adapted.parquet)
python src/score_vm.py --adapted data/processed/vm_adapted.parquet --out-dir results
python src/alert_scoring.py --input data/processed/vm_adapted.parquet --prefix vm_alerts

# Demo alert samples
python src/alert_scoring.py --input results/test_event_outcomes.csv `
    --proba-col proba --label-col true --per-outcome 8 --prefix sample_alerts

# Dashboard, API, and tests
streamlit run dashboard/app.py
uvicorn api.main:app --port 8000
python -m pytest tests rules/tests -q
```

## 4. Inputs not committed

- `data/raw/` - WinLOLBIN-GT CSV and raw VM Sysmon exports (licence and size).
- `data/processed/securebert*/` - saved embeddings (size).
- `.venv/` - recreate from `requirements-lock.txt`.

The files needed to check the reported numbers without the raw data are committed: split manifests, model artifacts, alert records, metric tables, confusion matrices, the PR curve, and the adapted VM table.

## 5. Evidence map

See `docs/artifact_index.md` for the file behind each Deliverable-2 artifact.
