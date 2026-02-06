from __future__ import annotations

import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd


# -------------------------------
# Models container + loader
# -------------------------------
@dataclass
class Models:
    brute_force: Any
    powershell: Any
    privilege_escalation: Any
    service_installation: Any


def load_models(models_dir: str | Path = None) -> Models:
    if models_dir is None:
        models_dir = Path(__file__).resolve().parent.parent / "models"
    else:
        models_dir = Path(models_dir)

    def _load(filename: str):
        path = models_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Missing model file: {path}")
        with open(path, "rb") as f:
            return pickle.load(f)

    return Models(
        brute_force=_load("brute_force_model.pkl"),
        powershell=_load("powershell_suspicious_model.pkl"),
        privilege_escalation=_load("privilege_escalation_model.pkl"),
        service_installation=_load("service_installation_model.pkl"),
    )


# -------------------------------
# CSV loading (with shift-left repair)
# -------------------------------
def _load_csv(path: str | Path, name: str) -> pd.DataFrame:
    """
    Loads Event Viewer-exported CSV and repairs the common "shift-left" issue.

    Your observed layout is often:
      Level         -> timestamp
      Date and Time -> Source name
      Source        -> numeric event id
      Event ID      -> task/category text
      Task Category -> message/body text

    We repair by:
      Date and Time := Level
      Event ID      := Source
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"{name} file not found: {path}")

    print(f"\n[DEBUG] Loading {name} from: {path}")

    df = pd.read_csv(path, sep=",", encoding="utf-8", engine="python", on_bad_lines="skip")
    df.columns = df.columns.str.strip()

    print(f"[DEBUG] {name} columns: {list(df.columns)}")
    if len(df) > 0:
        print(f"[DEBUG] {name} first row: {df.iloc[0].to_dict()}")

    level_parsed = pd.to_datetime(df["Level"].astype(str).head(20), errors="coerce")
    source_numeric = pd.to_numeric(df["Source"].astype(str).head(20), errors="coerce")

    is_shifted = (level_parsed.notna().sum() >= 5) and (source_numeric.notna().sum() >= 5)
    if is_shifted:
        print(f"[DEBUG] {name}: detected shifted CSV layout. Repairing columns...")
        df["Date and Time"] = df["Level"]
        df["Event ID"] = df["Source"]

    if "Date and Time" not in df.columns or "Event ID" not in df.columns:
        raise ValueError(f"{name}: missing required columns after repair. Found: {list(df.columns)}")

    df["Date and Time"] = pd.to_datetime(
        df["Date and Time"].astype(str),
        format="%m/%d/%Y %I:%M:%S %p",
        errors="coerce",
    )
    df = df.dropna(subset=["Date and Time"]).copy()

    
    df["Event ID"] = pd.to_numeric(df["Event ID"], errors="coerce")
    df = df.dropna(subset=["Event ID"]).copy()
    df["Event ID"] = df["Event ID"].astype(int)

    df = df.sort_values("Date and Time").reset_index(drop=True)
    return df


# -------------------------------
# Feature extraction
# -------------------------------
def _add_time_window(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["time_window"] = df["Date and Time"].dt.floor("5min")
    return df


def _count_events_per_window(df: pd.DataFrame, event_ids: List[int]) -> pd.DataFrame:
    df = _add_time_window(df)

    grouped = df.groupby(["time_window", "Event ID"]).size().unstack(fill_value=0)

    for eid in event_ids:
        if eid not in grouped.columns:
            grouped[eid] = 0

    grouped = grouped[event_ids].sort_index()
    grouped.columns = [f"event_{eid}" for eid in event_ids]
    return grouped.reset_index()


# -------------------------------
# Prediction helper + explainability
# -------------------------------
def _predict_windows(model, features_df: pd.DataFrame, threshold: float) -> dict:
    X = features_df.drop(columns=["time_window"])
    time_windows = features_df["time_window"].astype(str).tolist()

    proba = model.predict_proba(X)

    classes = list(model.classes_)
    if 1 in classes:
        idx = classes.index(1)
    else:
        idx = classes.index(max(classes))

    suspicious_probs = proba[:, idx]
    flagged = suspicious_probs >= threshold

    window_scores = [
        {"time_window": tw, "suspicious_prob": float(p)}
        for tw, p in zip(time_windows, suspicious_probs)
    ]
    top = sorted(window_scores, key=lambda x: x["suspicious_prob"], reverse=True)[:5]

    top_with_features = []
    for item in top:
        tw = item["time_window"]
        row = features_df[features_df["time_window"].astype(str) == tw].drop(columns=["time_window"])
        if not row.empty:
            item["features"] = row.iloc[0].to_dict()
        top_with_features.append(item)

    return {
        "threshold": threshold,
        "triggered_raw": bool(flagged.any()),
        "num_windows": len(features_df),
        "num_flagged_windows_raw": int(flagged.sum()),
        "top_windows": top_with_features,
        
    }


def _apply_heuristic_adjustments(features_df: pd.DataFrame, model_result: dict, detector_type: str) -> dict:
    
    result = model_result.copy()
    X = features_df.drop(columns=["time_window"])
    
    if detector_type == "brute_force":
        total_failures = X["event_4625"].sum()
        total_successes = X["event_4624"].sum()
        max_failures_per_window = X["event_4625"].max()
        
        
        total_logins = total_successes + total_failures
        failure_rate = total_failures / total_logins if total_logins > 0 else 0
        
        
        if total_failures < 3:
            result["triggered_raw"] = False
            result["num_flagged_windows_raw"] = 0
            result["heuristic_note"] = f"Minimal failed logins detected (failures: {total_failures}). Normal login activity."
        elif failure_rate < 0.10 and max_failures_per_window < 5:
            result["triggered_raw"] = False
            result["num_flagged_windows_raw"] = 0
            result["heuristic_note"] = f"Low failure rate detected ({failure_rate:.1%}). Likely benign login activity."
            
    elif detector_type == "powershell":
        total_4104 = X["event_4104"].sum()
        total_4103 = X["event_4103"].sum()
        max_4104_per_window = X["event_4104"].max()
        
        if total_4104 < 5 and total_4103 < 5:
            result["triggered_raw"] = False
            result["num_flagged_windows_raw"] = 0
            result["heuristic_note"] = f"Minimal PowerShell activity (4104: {total_4104}, 4103: {total_4103}). Normal operational usage."
        elif max_4104_per_window < 15 and total_4104 < 30:
            result["triggered_raw"] = False
            result["num_flagged_windows_raw"] = 0
            result["heuristic_note"] = f"Low PowerShell activity detected (total: {total_4104}, max per window: {max_4104_per_window}). Normal usage."
            
    elif detector_type == "privilege_escalation":
        total_4672 = X["event_4672"].sum()
        total_4624 = X["event_4624"].sum()
        max_4672_per_window = X["event_4672"].max()
        
    
        if total_4672 < 2:
            result["triggered_raw"] = False
            result["num_flagged_windows_raw"] = 0
            result["heuristic_note"] = f"Minimal privilege token usage (4672: {total_4672}). Normal activity."
        elif total_4624 > 0 and total_4672 / total_4624 < 0.3:
            result["triggered_raw"] = False
            result["num_flagged_windows_raw"] = 0
            result["heuristic_note"] = f"Normal privilege-to-login ratio ({total_4672}/{total_4624}). Routine administrative operations."
            
    elif detector_type == "service_installation":
        total_7045 = X["event_7045"].sum()
        max_7045_per_window = X["event_7045"].max()
        
        if total_7045 <= 1:
            result["triggered_raw"] = False
            result["num_flagged_windows_raw"] = 0
            result["heuristic_note"] = f"Single service installation detected. Likely software update or maintenance."
        elif max_7045_per_window <= 1 and total_7045 < 3:
            result["triggered_raw"] = False
            result["num_flagged_windows_raw"] = 0
            result["heuristic_note"] = f"Sporadic service installations ({total_7045} total). Normal system maintenance."
    
    return result


def _max_feature_value(top_windows: list, feature_name: str) -> int:
    max_val = 0
    for w in top_windows:
        feats = w.get("features", {})
        v = feats.get(feature_name, 0)
        try:
            v = int(v)
        except Exception:
            v = 0
        if v > max_val:
            max_val = v
    return max_val


# -------------------------------
# MAIN
# -------------------------------
def analyze(
    security_csv_path: str | Path,
    system_csv_path: str | Path,
    powershell_csv_path: str | Path,
) -> Dict[str, Any]:
    """
    Load CSVs → extract window features → run model predictions → apply rules overlay → return verdict.
    """
    models = load_models()

    security_df = _load_csv(security_csv_path, "Security.csv")
    system_df = _load_csv(system_csv_path, "System.csv")
    powershell_df = _load_csv(powershell_csv_path, "PowerShell.csv")

    # Feature extraction
    brute_force_features = _count_events_per_window(security_df, [4624, 4625])
    priv_esc_features = _count_events_per_window(security_df, [4624, 4672])
    powershell_features = _count_events_per_window(powershell_df, [4104, 4103])

    service_features = _count_events_per_window(system_df, [7045])
    service_features["has_service_install"] = (service_features["event_7045"] > 0).astype(int)

    # Verify feature alignment (optional but useful)
    def _expected_features(model):
        return list(getattr(model, "feature_names_in_", []))

    print("\n[DEBUG] brute_force expected:", _expected_features(models.brute_force))
    print("[DEBUG] brute_force actual:  ", [c for c in brute_force_features.columns if c != "time_window"])
    print("\n[DEBUG] powershell expected:", _expected_features(models.powershell))
    print("[DEBUG] powershell actual:  ", [c for c in powershell_features.columns if c != "time_window"])
    print("\n[DEBUG] priv_esc expected:", _expected_features(models.privilege_escalation))
    print("[DEBUG] priv_esc actual:  ", [c for c in priv_esc_features.columns if c != "time_window"])
    print("\n[DEBUG] service expected:", _expected_features(models.service_installation))
    print("[DEBUG] service actual:  ", [c for c in service_features.columns if c != "time_window"])

    
    THRESH = 0.65
    brute_force = _predict_windows(models.brute_force, brute_force_features, THRESH)
    powershell = _predict_windows(models.powershell, powershell_features, THRESH)
    privilege_escalation = _predict_windows(models.privilege_escalation, priv_esc_features, THRESH)
    service_installation = _predict_windows(models.service_installation, service_features, THRESH)

    
    brute_force = _apply_heuristic_adjustments(brute_force_features, brute_force, "brute_force")
    powershell = _apply_heuristic_adjustments(powershell_features, powershell, "powershell")
    privilege_escalation = _apply_heuristic_adjustments(priv_esc_features, privilege_escalation, "privilege_escalation")
    service_installation = _apply_heuristic_adjustments(service_features, service_installation, "service_installation")

    
    notes: List[str] = []
    
    # Add heuristic notes if present
    for detector_name, detector_result in [("Brute Force", brute_force), ("PowerShell", powershell), 
                                            ("Privilege Escalation", privilege_escalation), 
                                            ("Service Installation", service_installation)]:
        if "heuristic_note" in detector_result:
            notes.append(f"{detector_name}: {detector_result['heuristic_note']}")

    svc_max_7045 = _max_feature_value(service_installation["top_windows"], "event_7045")
    service_installation["gate_event_7045_min"] = 2
    service_installation["max_event_7045_in_top"] = svc_max_7045
    service_installation["triggered"] = bool(service_installation["triggered_raw"] and (svc_max_7045 >= 2))
    if service_installation["triggered_raw"] and not service_installation["triggered"] and "heuristic_note" not in service_installation:
        notes.append("Service-install model fired, but event_7045 was only a single occurrence; treating as non-suspicious (likely benign install/update).")

    
    brute_force["triggered"] = bool(brute_force["triggered_raw"])
    powershell["triggered"] = bool(powershell["triggered_raw"])

    
    privilege_escalation["triggered"] = bool(privilege_escalation["triggered_raw"])

    other_triggered = brute_force["triggered"] or powershell["triggered"] or service_installation["triggered"]
    overall_suspicious = (
        brute_force["triggered"]
        or powershell["triggered"]
        or service_installation["triggered"]
        or (privilege_escalation["triggered"] and other_triggered)
    )

    if privilege_escalation["triggered"] and not overall_suspicious:
        notes.append("Privilege-escalation indicators detected but not corroborated by other detectors; not marking overall verdict as suspicious.")

    verdict = "Suspicious" if overall_suspicious else "Benign"

    return {
        "status": "ok",
        "csv_summary": {
            "security_rows": len(security_df),
            "system_rows": len(system_df),
            "powershell_rows": len(powershell_df),
            "security_time_range": (str(security_df["Date and Time"].min()), str(security_df["Date and Time"].max())),
            "system_time_range": (str(system_df["Date and Time"].min()), str(system_df["Date and Time"].max())),
            "powershell_time_range": (str(powershell_df["Date and Time"].min()), str(powershell_df["Date and Time"].max())),
        },
        "feature_summary": {
            "brute_force_rows": len(brute_force_features),
            "priv_esc_rows": len(priv_esc_features),
            "powershell_rows": len(powershell_features),
            "service_rows": len(service_features),
            "brute_force_columns": list(brute_force_features.columns),
            "priv_esc_columns": list(priv_esc_features.columns),
            "powershell_columns": list(powershell_features.columns),
            "service_columns": list(service_features.columns),
        },
        "predictions": {
            "overall_verdict": verdict,
            "notes": notes,
            "brute_force": brute_force,
            "powershell": powershell,
            "privilege_escalation": privilege_escalation,
            "service_installation": service_installation,
        },
    }
