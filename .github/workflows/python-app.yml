import io
import os
import io
import re
import csv
import json
import shutil
import platform
import subprocess
import smtplib
import mimetypes
import zipfile
from email.message import EmailMessage
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import psutil
import streamlit as st

APP_DIR = Path(__file__).resolve().parent
REPORT_DIR = APP_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

st.set_page_config(page_title="AWANISH IT/OPS Testing", page_icon="🛠️", layout="wide")

st.markdown("""
<style>
  :root { --awi-navy: #071a2e; --awi-blue: #0b4ea2; --awi-accent: #1677ff; }
  [data-testid="stAppViewContainer"] { background: linear-gradient(180deg, #edf4fc 0%, #f6f8fc 360px); }
  [data-testid="stHeader"] { background: rgba(246,248,252,.88); }
  [data-testid="stSidebar"] { background: linear-gradient(180deg, #071a2e 0%, #102e50 100%); }
  [data-testid="stSidebar"] * { color: #eaf2ff; }
  [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color: #d6e5f8; }
  .block-container { padding-top: 1.35rem; padding-bottom: 2.5rem; max-width: 1680px; }
  [data-testid="stMetric"] { background: #fff; border: 1px solid #dce6f2; padding: 15px 16px; border-radius: 14px; box-shadow: 0 4px 16px rgba(15,48,86,.055); }
  [data-testid="stMetricLabel"] { color: #52657d; font-weight: 650; }
  [data-testid="stTabs"] button[role="tab"] { font-weight: 650; padding: 11px 14px; }
  div.stButton > button, div.stFormSubmitButton > button, div.stDownloadButton > button { border-radius: 10px; font-weight: 650; min-height: 2.65rem; }
  div[data-testid="stDataFrame"] { border: 1px solid #dce6f2; border-radius: 12px; overflow: hidden; }
  div[data-testid="stAlert"] { border-radius: 12px; }
  div[data-testid="stVerticalBlockBorderWrapper"] { border-color: #dce6f2; border-radius: 14px; }
  h1 { letter-spacing: -.035em; color: #0b2440; }
  h2, h3 { color: #102e50; }
  .awi-hero { padding: 24px 26px; border-radius: 18px; color: white; background: linear-gradient(120deg,#071a2e 0%,#0b4ea2 68%,#1677ff 100%); margin: 0 0 18px 0; box-shadow: 0 10px 28px rgba(7,26,46,.17); }
  .awi-hero h2 { color: white; margin: 0 0 6px 0; }
  .awi-hero p { color: #d9e9ff; margin: 0; }
  .awi-section { font-size: 1.05rem; font-weight: 750; color: #102e50; padding: 4px 0 8px 0; }
</style>
""", unsafe_allow_html=True)


def now_str():
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

def safe_read_text(uploaded_file, max_bytes=25 * 1024 * 1024):
    raw = uploaded_file.getvalue()
    if len(raw) > max_bytes:
        raise ValueError("File is larger than 25 MB. Please split it into smaller files.")
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")

def normalize_line(line):
    line = line.strip()
    # Normalize timestamps, GUIDs, long numeric IDs, and memory addresses to reduce noise.
    line = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b", "<TIMESTAMP>", line)
    line = re.sub(r"\b\d{1,2}/\d{1,2}/\d{2,4}[ T]\d{1,2}:\d{2}:\d{2}\b", "<TIMESTAMP>", line)
    line = re.sub(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b", "<GUID>", line)
    line = re.sub(r"\b0x[0-9a-fA-F]+\b", "<HEX>", line)
    line = re.sub(r"\b\d{5,}\b", "<ID>", line)
    return line.lower()

def classify_line(line):
    s = line.lower()
    if any(x in s for x in ("critical", "fatal", "panic", "bugcheck", "blue screen", "bsod")):
        return "Critical"
    if any(x in s for x in ("error", "failed", "failure", "exception", "crash", "corrupt", "timeout", "timed out")):
        return "Error"
    if any(x in s for x in ("warning", "degraded", "retry", "low disk", "almost full")):
        return "Warning"
    return "Info"

def compare_logs(old_text, new_text):
    old_lines = [x.strip() for x in old_text.splitlines() if x.strip()]
    new_lines = [x.strip() for x in new_text.splitlines() if x.strip()]
    old_counts = Counter(normalize_line(x) for x in old_lines)
    new_counts = Counter(normalize_line(x) for x in new_lines)
    rows = []
    for norm, count in (new_counts - old_counts).items():
        example = next((x for x in new_lines if normalize_line(x) == norm), norm)
        rows.append({
            "Severity": classify_line(example),
            "New occurrences": count,
            "Log line": example[:2000],
        })
    severity_order = {"Critical": 0, "Error": 1, "Warning": 2, "Info": 3}
    rows.sort(key=lambda r: (severity_order.get(r["Severity"], 4), -r["New occurrences"]))
    return old_lines, new_lines, rows

def run_powershell(command, timeout=20):
    if platform.system() != "Windows":
        return None, "This check is available only on Windows."
    try:
        p = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-Command", command],
            capture_output=True, text=True, timeout=timeout, errors="replace"
        )
        if p.returncode != 0:
            return p.stdout.strip(), (p.stderr.strip() or f"PowerShell returned code {p.returncode}")
        return p.stdout.strip(), None
    except Exception as e:
        return None, str(e)

def get_local_event_logs(hours, max_events):
    if platform.system() != "Windows":
        return [], "Local Event Viewer collection requires Windows."
    since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    # Read-only Get-WinEvent. Limit events to keep the app responsive.
    cmd = (
        f"$start=[datetime]'{since}'; "
        f"Get-WinEvent -FilterHashtable @{{LogName='System'; StartTime=$start}} -MaxEvents {int(max_events)} "
        "-ErrorAction SilentlyContinue | "
        "Where-Object { $_.Level -in @(1,2,3) -or $_.Id -in @(41,1074,6005,6006,6008,1001) } | "
        "Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | ConvertTo-Json -Depth 3"
    )
    out, err = run_powershell(cmd, timeout=45)
    if err:
        return [], err
    if not out:
        return [], None
    try:
        parsed = json.loads(out)
        if isinstance(parsed, dict):
            parsed = [parsed]
        return parsed, None
    except json.JSONDecodeError:
        return [], "Could not parse PowerShell output. Try running the app from a normal Windows PowerShell session."

def disk_usage_rows():
    rows = []
    if platform.system() == "Windows":
        cmd = "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID,VolumeName,@{N='SizeGB';E={[math]::Round($_.Size/1GB,2)}},@{N='FreeGB';E={[math]::Round($_.FreeSpace/1GB,2)}},@{N='FreePercent';E={if($_.Size){[math]::Round($_.FreeSpace/$_.Size*100,1)}else{0}}} | ConvertTo-Json"
        out, err = run_powershell(cmd, timeout=20)
        if not err and out:
            try:
                parsed = json.loads(out)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                return parsed, None
            except Exception:
                pass
        # fallback to Python drive probing
        import string
        for letter in string.ascii_uppercase:
            root = f"{letter}:\\"
            if os.path.exists(root):
                try:
                    u = shutil.disk_usage(root)
                    rows.append({"DeviceID": root, "VolumeName": "", "SizeGB": round(u.total/1e9, 2),
                                 "FreeGB": round(u.free/1e9, 2), "FreePercent": round(u.free/u.total*100, 1)})
                except Exception:
                    pass
        return rows, err
    try:
        u = shutil.disk_usage("/")
        return [{"DeviceID": "/", "VolumeName": "", "SizeGB": round(u.total/1e9, 2),
                 "FreeGB": round(u.free/1e9, 2), "FreePercent": round(u.free/u.total*100, 1)}], None
    except Exception as e:
        return [], str(e)

def get_temp_candidates():
    roots = []
    for key in ("TEMP", "TMP"):
        val = os.environ.get(key)
        if val:
            p = Path(val)
            if p.exists() and p.is_dir() and p not in roots:
                roots.append(p)
    # Never automatically traverse Windows system temp folders; use only current-user TEMP/TMP.
    candidates = []
    for root in roots:
        try:
            for p in root.iterdir():
                try:
                    if p.is_file():
                        stt = p.stat()
                        candidates.append({"path": str(p), "size": stt.st_size, "modified": datetime.fromtimestamp(stt.st_mtime)})
                    elif p.is_dir():
                        # Report folder but don't recursively delete it.
                        candidates.append({"path": str(p), "size": None, "modified": datetime.fromtimestamp(p.stat().st_mtime)})
                except (PermissionError, FileNotFoundError, OSError):
                    continue
        except (PermissionError, OSError):
            continue
    return candidates

def event_interpretation(ev):
    eid = str(ev.get("Id", ""))
    provider = str(ev.get("ProviderName", ""))
    msg = str(ev.get("Message", "") or "")
    mapping = {
        "41": "Kernel-Power: Windows reports that the system restarted without a clean shutdown. This does not by itself prove a PSU or hardware fault.",
        "6008": "Unexpected shutdown recorded. Correlate with nearby events and logs.",
        "1074": "A process or user initiated a shutdown/restart. Inspect the event message for the initiator and reason.",
        "6005": "Event Log service started; can help identify boot time.",
        "6006": "Event Log service stopped cleanly; can help identify a normal shutdown.",
        "1001": "BugCheck/WER event may indicate a system crash or bugcheck. Inspect the message and any dump files."
    }
    if eid in mapping:
        return mapping[eid]
    if "disk" in provider.lower() or "stor" in provider.lower() or "ntfs" in provider.lower():
        return "Storage-related event. Check the full message, disk health, controller/RAID logs and event IDs."
    if "whea" in provider.lower():
        return "WHEA hardware error report. Investigate the detailed message and vendor diagnostics."
    return classify_line(msg) + ": review full event details and correlate with nearby timestamps."



# SCTE Excel report generator adapted from the user's Scte-logs-updated(2).py.
# It preserves the user's state lists, required columns, event detection,
# duplicate removal, and two-panel Excel report layout.
def build_scte_report(uploaded_files):
    all_data = []
    file_messages = []
    skmamp2 = ["GJ", "PH", "OA", "NE", "KN", "KL", "BN", "TN"]
    skmamp1 = ["IN", "CN", "UP", "MP", "RJ", "BH", "JK"]
    all_states = skmamp2 + skmamp1

    for uploaded in uploaded_files:
        try:
            raw = uploaded.getvalue()
            with pd.ExcelFile(io.BytesIO(raw)) as xls:
                for sheet in xls.sheet_names:
                    try:
                        sheet_df = pd.read_excel(xls, sheet_name=sheet)
                        sheet_df.columns = [str(col).strip() for col in sheet_df.columns]
                        required_columns = ["Time", "Producer Name", "SCTE Payload"]
                        missing = [col for col in required_columns if col not in sheet_df.columns]
                        if missing:
                            file_messages.append(
                                f"SKIPPED: {uploaded.name} | {sheet} — missing columns: " + ", ".join(missing)
                            )
                            continue
                        sheet_df["SCTE Payload"] = (
                            sheet_df["SCTE Payload"].fillna("").astype(str).str.strip()
                        )
                        all_data.append(sheet_df)
                        file_messages.append(
                            f"READ: {uploaded.name} | Sheet: {sheet} | Rows: {len(sheet_df)}"
                        )
                    except Exception as exc:
                        file_messages.append(f"SHEET ERROR: {uploaded.name} | {sheet} | {exc}")
        except Exception as exc:
            file_messages.append(f"FILE ERROR: {uploaded.name} | {exc}")

    if not all_data:
        raise ValueError(
            "No usable sheets found. Input Excel files must contain columns named "
            "'Time', 'Producer Name', and 'SCTE Payload'."
        )

    df = pd.concat(all_data, ignore_index=True)
    imported_rows = len(df)
    df = df.drop_duplicates(subset=["Time", "Producer Name", "SCTE Payload"]).copy()

    df["State"] = (
        df["Producer Name"].fillna("").astype(str)
        .str.extract(
            r"(?:KEY-|Playout-)([A-Z]{2})(?=\s|$|-|\.)",
            flags=re.IGNORECASE,
            expand=False
        )
        .str.upper()
    )

    df["Type"] = ""
    payload = df["SCTE Payload"].fillna("").astype(str)
    df.loc[payload.str.contains("StartImmediate", case=False, na=False), "Type"] = "START"
    df.loc[payload.str.contains("EndImmediate", case=False, na=False), "Type"] = "END"
    df = df[df["Type"] != ""].copy()
    recognized_events = len(df)

    df = df.sort_values("Time", kind="stable")
    df = df.drop_duplicates(subset=["State", "Time", "Type"]).copy()

    result_dict = {}
    for state in all_states:
        group = (
            df[df["State"] == state]
            .sort_values("Time", kind="stable")
            .reset_index(drop=True)
        )
        temp = []
        for i in range(1, len(group)):
            curr = group.iloc[i]
            prev = group.iloc[i - 1]
            if curr["Type"] == prev["Type"]:
                temp.extend([prev, curr])
        if temp:
            temp_df = pd.DataFrame(temp).drop_duplicates(subset=["State", "Time", "Type"])
        else:
            temp_df = group.iloc[0:0].copy()
        result_dict[state] = temp_df

    def build_block(states):
        rows = []
        for state in states:
            rows.append([state, "", ""])
            data = result_dict.get(state)
            if not df["State"].eq(state).any():
                rows.append(["", "SHEET MISSING NEED TO DOWNLOAD", ""])
            elif data is None or data.empty:
                rows.append(["", "OK", ""])
            else:
                for _, row in data.iterrows():
                    rows.append([row["Time"], row["Type"], ""])
            rows.append(["", "", ""])
        return rows

    left = build_block(skmamp2)
    right = build_block(skmamp1)
    max_len = max(len(left), len(right))
    left.extend([["", "", ""]] * (max_len - len(left)))
    right.extend([["", "", ""]] * (max_len - len(right)))

    final = [["SKMAMP-2", "", "", "", "SKMAMP-1", "", ""]]
    for i in range(max_len):
        final.append(left[i] + [""] + right[i])

    output = io.BytesIO()
    pd.DataFrame(final).to_excel(output, index=False, header=False, engine="openpyxl")
    output.seek(0)
    stats = {
        "files_uploaded": len(uploaded_files),
        "rows_imported_before_exact_dedup": imported_rows,
        "recognized_start_end_events_before_state_dedup": recognized_events,
        "states_detected": sorted(df["State"].dropna().unique().tolist()),
        "messages": file_messages,
    }
    return output.getvalue(), stats



# SCTE command validation helpers: compare Asrun TXT commands against SCTE export events.
SCTE_START_COMMANDS = ["SCTE-IN", "SQ-KL-EFFECT-4-IN", "SW-KL-BRK-ON", "BRK-ON"]
SCTE_END_COMMANDS = ["SW-KL-BRK-OFF", "SQ-KL-EFFECT-4-OUT", "BRK-OFF", "SCTE-OUT"]

def parse_asrun_commands(text):
    """Parse standard AMPP Asrun text rows into timestamp/command/status records."""
    rows = []
    stamp_re = re.compile(
        r"^\s*(\d{1,2}/\d{1,2}/\d{2,4}\s+\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\S+)(.*)$"
    )
    known = set(SCTE_START_COMMANDS + SCTE_END_COMMANDS)
    for line in text.splitlines():
        m = stamp_re.match(line)
        if not m:
            continue
        stamp_text, command, rest = m.groups()
        command = command.strip()
        # AMPP Asrun fixed-width columns truncate this long macro ID; infer direction
        # from the adjacent Title column ("...-4-I" / "...-4-O").
        if command == "SQ-KL-EFFECT-":
            if re.search(r"SQ-KL-EFFECT-4-I", rest, re.I):
                command = "SQ-KL-EFFECT-4-IN"
            elif re.search(r"SQ-KL-EFFECT-4-O", rest, re.I):
                command = "SQ-KL-EFFECT-4-OUT"
        if command not in known:
            continue
        try:
            ts = pd.to_datetime(stamp_text, dayfirst=True, errors="coerce")
        except Exception:
            ts = pd.NaT
        if pd.isna(ts):
            continue
        status_match = re.search(r"\b(Done|Partial|Failed|Error|Pending)\b", rest, re.I)
        status = status_match.group(1).title() if status_match else "Unknown"
        rows.append({"Asrun Time": ts, "Command": command, "Asrun Status": status, "Source Line": line.strip()})
    if not rows:
        raise ValueError(
            "No SCTE command rows were detected in the Asrun TXT. Expected rows like "
            "'15/10/26 00:53:57.21 SCTE-IN ... Done'."
        )
    return pd.DataFrame(rows).sort_values("Asrun Time", kind="stable").reset_index(drop=True)

def parse_scte_export_excel(uploaded_file):
    """Read SCTE export workbook rows and extract StartImmediate/EndImmediate events."""
    raw = uploaded_file.getvalue()
    with pd.ExcelFile(io.BytesIO(raw)) as xls:
        frames = []
        for sheet in xls.sheet_names:
            try:
                frame = pd.read_excel(xls, sheet_name=sheet)
                frame.columns = [str(c).strip() for c in frame.columns]
                if "Time" in frame.columns and "SCTE Payload" in frame.columns:
                    if "Producer Name" not in frame.columns:
                        frame["Producer Name"] = ""
                    frames.append(frame[["Time", "Producer Name", "SCTE Payload"]].copy())
            except Exception:
                continue
    if not frames:
        raise ValueError("SCTE Excel export must contain columns: Time and SCTE Payload (Producer Name is recommended).")
    raw_df = pd.concat(frames, ignore_index=True)
    rows = []
    for _, row in raw_df.iterrows():
        payload = str(row.get("SCTE Payload", "") or "")
        if "StartImmediate" not in payload and "EndImmediate" not in payload:
            continue
        kind = "START" if "StartImmediate" in payload else "END"
        time_value = str(row.get("Time", "") or "").strip()
        # Excel exports may contain strings such as "Thu Oct 15 2026 04:57:54 GMT+0530 (India Standard Time)".
        cleaned_time = re.sub(r"\s+GMT[+-]\d{4}.*$", "", time_value)
        ts = pd.to_datetime(cleaned_time, errors="coerce", utc=False)
        if pd.isna(ts):
            continue
        producer = str(row.get("Producer Name", "") or "")
        state_match = re.search(r"(?:KEY-|Playout-)([A-Z]{2})(?=\s|$|-|\.)", producer, re.I)
        rows.append({
            "Export Time": ts,
            "Export Type": kind,
            "Export State": state_match.group(1).upper() if state_match else "",
            "Producer Name": producer,
            "SCTE Payload": payload[:1200],
        })
    if not rows:
        raise ValueError("No StartImmediate/EndImmediate SCTE events found in the Excel export.")
    return pd.DataFrame(rows).sort_values("Export Time", kind="stable").reset_index(drop=True)

def parse_scte_export_txt(text):
    """Parse row-oriented SCTE TXT/CSV exports; each event row should include time and payload."""
    rows = []
    # Typical export rows contain a readable date/time plus a JSON payload on the same line.
    time_patterns = [
        re.compile(r"(?P<time>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
        re.compile(r"(?P<time>(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)"),
        re.compile(r"(?P<time>\d{1,2}/\d{1,2}/\d{2,4}\s+\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)"),
    ]
    for line in text.splitlines():
        if "StartImmediate" not in line and "EndImmediate" not in line:
            continue
        match = next((p.search(line) for p in time_patterns if p.search(line)), None)
        if not match:
            continue
        ts = pd.to_datetime(match.group("time"), errors="coerce", dayfirst=True)
        if pd.isna(ts):
            continue
        kind = "START" if "StartImmediate" in line else "END"
        producer_match = re.search(r"((?:skm-plx\S*|KEY-[A-Z]{2}|Playout-[A-Z]{2})[^,\t|]*)", line, re.I)
        producer = producer_match.group(1).strip() if producer_match else ""
        state_match = re.search(r"(?:KEY-|Playout-)([A-Z]{2})(?=\s|$|-|\.)", producer, re.I)
        rows.append({
            "Export Time": ts,
            "Export Type": kind,
            "Export State": state_match.group(1).upper() if state_match else "",
            "Producer Name": producer,
            "SCTE Payload": line[:1200],
        })
    if not rows:
        raise ValueError(
            "Could not detect SCTE events in this TXT. It should have one event per line with a timestamp "
            "and StartImmediate or EndImmediate. If the TXT is a multi-line JSON dump, upload the XLSX export instead."
        )
    return pd.DataFrame(rows).sort_values("Export Time", kind="stable").reset_index(drop=True)

def compare_scte_sources(asrun_df, export_df, tolerance_seconds=1.0):
    """Match each Asrun SCTE-IN/OUT marker to the closest same-type export event."""
    markers = asrun_df[asrun_df["Command"].isin(["SCTE-IN", "SCTE-OUT"])].copy()
    used_export = set()
    output = []
    for _, marker in markers.iterrows():
        expected_type = "START" if marker["Command"] == "SCTE-IN" else "END"
        candidates = export_df[export_df["Export Type"] == expected_type].copy()
        candidates = candidates[~candidates.index.isin(used_export)]
        if candidates.empty:
            output.append({
                "Asrun Time": marker["Asrun Time"], "SCTE Command": marker["Command"],
                "Expected Export Event": expected_type, "Matched Export Time": None,
                "Difference (seconds)": None, "Asrun Status": marker["Asrun Status"],
                "Result": "MISSING EXPORT EVENT", "Producer": "", "Export Payload": ""
            })
            continue
        candidates["Difference (seconds)"] = (
            candidates["Export Time"].apply(lambda x: abs((pd.Timestamp(x).replace(tzinfo=None) - pd.Timestamp(marker["Asrun Time"]).replace(tzinfo=None)).total_seconds()))
        )
        best_idx = candidates["Difference (seconds)"].idxmin()
        best = candidates.loc[best_idx]
        diff = float(best["Difference (seconds)"])
        if diff <= tolerance_seconds:
            used_export.add(best_idx)
            result = "MATCH" if marker["Asrun Status"] == "Done" else f"MATCH - ASRUN {marker['Asrun Status'].upper()}"
        else:
            result = "TIME MISMATCH"
        output.append({
            "Asrun Time": marker["Asrun Time"], "SCTE Command": marker["Command"],
            "Expected Export Event": expected_type, "Matched Export Time": best["Export Time"],
            "Difference (seconds)": round(diff, 3), "Asrun Status": marker["Asrun Status"],
            "Result": result, "Producer": best["Producer Name"], "Export Payload": best["SCTE Payload"]
        })
    return pd.DataFrame(output)


def check_command_sequences(asrun_df, window_seconds=2.0):
    """Validate all four commands per SCTE event, assigning each command row only once.

    START event = SCTE-IN + SQ-KL-EFFECT-4-IN + SW-KL-BRK-ON + BRK-ON.
    END event   = SCTE-OUT + SW-KL-BRK-OFF + SQ-KL-EFFECT-4-OUT + BRK-OFF.
    A command row cannot satisfy more than one marker; every required command must be Done
    and within the selected time window. This is the Asrun-side sequence check. The export
    workbook separately confirms SCTE-IN/OUT against StartImmediate/EndImmediate payloads.
    """
    rows = []
    markers = asrun_df[asrun_df["Command"].isin(["SCTE-IN", "SCTE-OUT"])].copy()
    used_rows = set()
    for marker_idx, marker in markers.iterrows():
        is_start = marker["Command"] == "SCTE-IN"
        event_label = "START" if is_start else "END"
        required = (["SCTE-IN", "SQ-KL-EFFECT-4-IN", "SW-KL-BRK-ON", "BRK-ON"] if is_start else
                    ["SW-KL-BRK-OFF", "SQ-KL-EFFECT-4-OUT", "BRK-OFF", "SCTE-OUT"])
        # The marker itself is the first/last command in the four-command sequence and
        # must be Done too. Do not let one marker row satisfy another event.
        for command in required:
            if command == marker["Command"]:
                status = "OK" if str(marker["Asrun Status"]).lower() == "done" else f"ASRUN {str(marker['Asrun Status']).upper()}"
                rows.append({
                    "Event #": int(markers.index.get_loc(marker_idx)) + 1,
                    "Event": event_label, "SCTE Marker": marker["Command"],
                    "Marker Time": marker["Asrun Time"], "Required Command": command,
                    "Command Time": marker["Asrun Time"], "Difference (seconds)": 0.0,
                    "Asrun Status": marker["Asrun Status"], "Status": status
                })
                used_rows.add(marker_idx)
                continue
            candidates = asrun_df[(asrun_df["Command"] == command) & (~asrun_df.index.isin(used_rows))].copy()
            if candidates.empty:
                rows.append({
                    "Event #": int(markers.index.get_loc(marker_idx)) + 1,
                    "Event": event_label, "SCTE Marker": marker["Command"],
                    "Marker Time": marker["Asrun Time"], "Required Command": command,
                    "Command Time": None, "Difference (seconds)": None,
                    "Asrun Status": "Missing", "Status": "MISSING COMMAND"
                })
                continue
            candidates["Difference (seconds)"] = candidates["Asrun Time"].apply(
                lambda x: abs((pd.Timestamp(x).replace(tzinfo=None) -
                               pd.Timestamp(marker["Asrun Time"]).replace(tzinfo=None)).total_seconds())
            )
            candidates = candidates[candidates["Difference (seconds)"] <= window_seconds]
            if candidates.empty:
                # Show the nearest row to make the reason diagnosable, but don't consume it.
                all_candidates = asrun_df[asrun_df["Command"] == command].copy()
                all_candidates["Difference (seconds)"] = all_candidates["Asrun Time"].apply(
                    lambda x: abs((pd.Timestamp(x).replace(tzinfo=None) -
                                   pd.Timestamp(marker["Asrun Time"]).replace(tzinfo=None)).total_seconds())
                )
                best = all_candidates.loc[all_candidates["Difference (seconds)"].idxmin()]
                status = "OUTSIDE WINDOW"
            else:
                best = candidates.loc[candidates["Difference (seconds)"].idxmin()]
                used_rows.add(best.name)
                status = "OK" if str(best["Asrun Status"]).lower() == "done" else f"ASRUN {str(best['Asrun Status']).upper()}"
            rows.append({
                "Event #": int(markers.index.get_loc(marker_idx)) + 1,
                "Event": event_label, "SCTE Marker": marker["Command"],
                "Marker Time": marker["Asrun Time"], "Required Command": command,
                "Command Time": best["Asrun Time"], "Difference (seconds)": round(float(best["Difference (seconds)"]), 3),
                "Asrun Status": best["Asrun Status"], "Status": status
            })
    return pd.DataFrame(rows)


def collect_system_monitor(hours=24, driver_age_years=2):
    """Collect a read-only snapshot of utilization, application crashes/hangs,
    hardware-related Windows events, driver age, and antivirus status."""
    result = {"checked_at": now_str(), "utilization": {}, "top_processes": [],
              "application_events": [], "hung_processes": [], "hardware_events": [], "drivers_to_review": [],
              "antivirus": {}, "warnings": []}

    # Cross-platform utilization snapshot (Windows is the primary target).
    try:
        result["utilization"] = {
            "CPU percent": round(psutil.cpu_percent(interval=1), 1),
            "RAM used percent": round(psutil.virtual_memory().percent, 1),
            "RAM total GB": round(psutil.virtual_memory().total / (1024**3), 2),
            "RAM available GB": round(psutil.virtual_memory().available / (1024**3), 2),
            "Boot time": datetime.fromtimestamp(psutil.boot_time()).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        }
        disk_rows = []
        for part in psutil.disk_partitions(all=False):
            if platform.system() == "Windows" and not part.device:
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disk_rows.append({"Drive": part.device or part.mountpoint,
                                  "Mount": part.mountpoint,
                                  "Total GB": round(usage.total/(1024**3), 2),
                                  "Used GB": round(usage.used/(1024**3), 2),
                                  "Free GB": round(usage.free/(1024**3), 2),
                                  "Used percent": round(usage.percent, 1)})
            except (PermissionError, OSError):
                continue
        result["disks"] = disk_rows
        procs = []
        for proc in psutil.process_iter(["pid", "name", "memory_info"]):
            try:
                info = proc.info
                procs.append({"PID": info.get("pid"), "Process": info.get("name") or "Unknown",
                              "Memory MB": round((info.get("memory_info").rss if info.get("memory_info") else 0)/(1024**2), 1),
                              "_proc": proc})
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        for row in procs:
            try:
                row["CPU percent"] = row["_proc"].cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                row["CPU percent"] = 0.0
        psutil.cpu_percent(interval=0.4)
        for row in procs:
            try:
                row["CPU percent"] = round(row["_proc"].cpu_percent(interval=None), 1)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                row["CPU percent"] = 0.0
            row.pop("_proc", None)
        result["top_processes"] = sorted(procs, key=lambda r: (r["CPU percent"], r["Memory MB"]), reverse=True)[:15]
    except Exception as exc:
        result["warnings"].append(f"Utilization/process snapshot: {exc}")
        result.setdefault("disks", [])

    if platform.system() != "Windows":
        result["warnings"].append("Windows Event Viewer, driver-age and antivirus checks require the portal to run on Windows.")
        return result

    # Application Error (1000), Windows Error Reporting (1001), Application Hang (1002).
    since = (datetime.now() - timedelta(hours=int(hours))).strftime("%Y-%m-%dT%H:%M:%S")
    app_cmd = (
        f"$start=[datetime]'{since}'; "
        "Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$start; Id=@(1000,1001,1002)} "
        "-MaxEvents 300 -ErrorAction SilentlyContinue | "
        "Select-Object @{N='Time';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}},Id,ProviderName,LevelDisplayName,Message | ConvertTo-Json -Depth 3"
    )
    out, err = run_powershell(app_cmd, timeout=60)
    if err:
        result["warnings"].append("Application crash/hang events: " + err)
    elif out:
        try:
            obj = json.loads(out); obj = obj if isinstance(obj, list) else [obj]
            for ev in obj:
                msg = str(ev.get("Message") or "")
                result["application_events"].append({"Time": ev.get("Time", ""), "Event ID": ev.get("Id", ""),
                    "Source": ev.get("ProviderName", ""), "Level": ev.get("LevelDisplayName", ""),
                    "Finding": {"1000": "Application crash", "1001": "Windows Error Reporting", "1002": "Application not responding / hang"}.get(str(ev.get("Id")), "Application event"),
                    "Message": msg[:2500]})
        except Exception as exc:
            result["warnings"].append(f"Could not parse application events: {exc}")

    # Current processes Windows reports as not responding (snapshot only).
    hung_cmd = (
        "Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Responding -eq $false } | "
        "Select-Object @{N='Process';E={$_.ProcessName}},Id,Responding,CPU,StartTime | ConvertTo-Json -Depth 2"
    )
    out, err = run_powershell(hung_cmd, timeout=30)
    if err:
        result["warnings"].append("Current not-responding process check: " + err)
    elif out:
        try:
            obj = json.loads(out); obj = obj if isinstance(obj, list) else [obj]
            result["hung_processes"] = [{"Process": ev.get("Process", ""), "PID": ev.get("Id", ""),
                "Responding": ev.get("Responding", False), "CPU seconds": ev.get("CPU", ""),
                "Start time": ev.get("StartTime", "")} for ev in obj]
        except Exception as exc:
            result["warnings"].append(f"Could not parse not-responding process list: {exc}")

    # Hardware/storage indicators from System log. Events are clues, not a final diagnosis.
    sys_cmd = (
        f"$start=[datetime]'{since}'; "
        "Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$start} -MaxEvents 600 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Id -in @(7,11,15,17,18,19,20,41,51,55,129,153,157,6008) -or $_.ProviderName -match 'WHEA|Disk|Ntfs|storport|stornvme|iaStor|Kernel-Power|volmgr' } | "
        "Select-Object @{N='Time';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}},Id,ProviderName,LevelDisplayName,Message | ConvertTo-Json -Depth 3"
    )
    out, err = run_powershell(sys_cmd, timeout=60)
    if err:
        result["warnings"].append("Hardware/System events: " + err)
    elif out:
        try:
            obj = json.loads(out); obj = obj if isinstance(obj, list) else [obj]
            for ev in obj:
                provider = str(ev.get("ProviderName") or "")
                eid = str(ev.get("Id", ""))
                msg = str(ev.get("Message") or "")
                result["hardware_events"].append({"Time": ev.get("Time", ""), "Event ID": eid,
                    "Source": provider, "Level": ev.get("LevelDisplayName", ""),
                    "Finding": "Unexpected restart" if eid in ("41", "6008") else ("WHEA hardware error" if "whea" in provider.lower() else "Storage / hardware event"),
                    "Message": msg[:2500]})
        except Exception as exc:
            result["warnings"].append(f"Could not parse hardware events: {exc}")

    # Driver age is only a review signal; an old date alone does not prove a driver is outdated.
    driver_cmd = (
        "Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DriverDate -ne $null -and $_.DeviceName } | "
        "Select-Object DeviceName,Manufacturer,DriverVersion,DriverDate,InfName | ConvertTo-Json -Depth 3"
    )
    out, err = run_powershell(driver_cmd, timeout=60)
    cutoff = datetime.now() - timedelta(days=int(driver_age_years * 365.25))
    if err:
        result["warnings"].append("Driver inventory: " + err)
    elif out:
        try:
            obj = json.loads(out); obj = obj if isinstance(obj, list) else [obj]
            for dr in obj:
                raw_date = dr.get("DriverDate")
                try:
                    d = pd.to_datetime(raw_date, errors="coerce")
                    if pd.isna(d):
                        continue
                    if d.tzinfo is not None:
                        d = d.tz_localize(None)
                    if d.to_pydatetime() < cutoff:
                        result["drivers_to_review"].append({"Device": dr.get("DeviceName", ""),
                            "Manufacturer": dr.get("Manufacturer", ""), "Driver version": dr.get("DriverVersion", ""),
                            "Driver date": d.strftime("%Y-%m-%d"), "INF": dr.get("InfName", ""),
                            "Review note": f"Older than {driver_age_years:g} years — verify against OEM/Windows Update; age alone is not proof of outdated driver."})
                except Exception:
                    continue
            result["drivers_to_review"] = sorted(result["drivers_to_review"], key=lambda r: r["Driver date"])
        except Exception as exc:
            result["warnings"].append(f"Could not parse driver inventory: {exc}")

    # Antivirus: prefer Defender health plus Security Center registered products.
    av_cmd = (
        "$products=@(); try {$products=Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | "
        "Select-Object displayName,productState,pathToSignedProductExe} catch {}; "
        "$defender=$null; try {$defender=Get-MpComputerStatus -ErrorAction Stop | "
        "Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,AntivirusSignatureAge} catch {}; "
        "[pscustomobject]@{RegisteredProducts=@($products); Defender=$defender} | ConvertTo-Json -Depth 4"
    )
    out, err = run_powershell(av_cmd, timeout=45)
    if err:
        result["antivirus"] = {"Status": "Unknown", "Details": err}
        result["warnings"].append("Antivirus status could not be confirmed; verify in Windows Security or your corporate endpoint console.")
    elif out:
        try:
            obj = json.loads(out)
            products = obj.get("RegisteredProducts") or []
            if isinstance(products, dict): products = [products]
            defender = obj.get("Defender")
            details = []
            if products:
                details.append("Security Center registered: " + ", ".join(str(x.get("displayName", "Unknown")) for x in products))
            if isinstance(defender, dict):
                enabled = defender.get("AntivirusEnabled") is True and defender.get("AMServiceEnabled") is True
                rtp = defender.get("RealTimeProtectionEnabled") is True
                details.append(f"Microsoft Defender service/AV enabled: {enabled}; real-time protection: {rtp}; signature age: {defender.get('AntivirusSignatureAge', 'Unknown')} day(s)")
                if enabled and rtp:
                    status = "Defender enabled"
                elif products:
                    status = "Registered antivirus found — verify active protection"
                else:
                    status = "Review: Defender protection not confirmed"
            elif products:
                status = "Registered antivirus found — active protection not confirmed"
            else:
                status = "Unknown — no product registered in this query"
                details.append("SecurityCenter2 may be unavailable on Windows Server or managed endpoints. Confirm with the organization’s antivirus/EDR console before declaring antivirus missing.")
            result["antivirus"] = {"Status": status, "Details": " | ".join(details) or "No status details returned."}
        except Exception as exc:
            result["antivirus"] = {"Status": "Unknown", "Details": str(exc)}
    else:
        result["antivirus"] = {"Status": "Unknown", "Details": "No antivirus status returned. Verify with Windows Security or corporate endpoint management."}
    return result


def collect_remote_systems(hosts, hours=24, driver_age_years=2):
    '''Read-only multi-host diagnostics through configured PowerShell Remoting/WinRM.

    Requires approved credentials and WinRM/PowerShell remoting configured by IT. No
    credentials are collected or stored by this helper. Failed hosts are returned as rows.
    '''
    if platform.system() != "Windows":
        raise RuntimeError("Remote Windows checks require the portal to run on Windows with PowerShell.")
    clean_hosts = []
    for host in hosts:
        host = host.strip()
        if not host:
            continue
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,255}", host):
            raise ValueError(f"Invalid computer name: {host!r}. Use a hostname or FQDN only.")
        if host.lower() not in {x.lower() for x in clean_hosts}:
            clean_hosts.append(host)
    if not clean_hosts:
        return []
    host_literals = ",".join("'" + h.replace("'", "''") + "'" for h in clean_hosts)
    ps = r'''
$ErrorActionPreference = 'Stop'
$targets = @(__HOSTS__)
$hours = __HOURS__
$driverAge = __DRIVERAGE__
$results = foreach ($computer in $targets) {
  try {
    Invoke-Command -ComputerName $computer -ErrorAction Stop -ScriptBlock {
      param($hours, $driverAge)
      $cpu = $null; $ram = $null; $ramTotal = $null; $ramFree = $null
      try { $cpu = [math]::Round((Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime,1) } catch {}
      try { $os = Get-CimInstance Win32_OperatingSystem; $ramTotal=[math]::Round($os.TotalVisibleMemorySize/1MB,2); $ramFree=[math]::Round($os.FreePhysicalMemory/1MB,2); if ($os.TotalVisibleMemorySize) { $ram=[math]::Round(100*(1-$os.FreePhysicalMemory/$os.TotalVisibleMemorySize),1) } } catch {}
      $disks = @(); try { $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { if ($_.Size -gt 0) { [pscustomobject]@{Drive=$_.DeviceID; SizeGB=[math]::Round($_.Size/1GB,2); FreeGB=[math]::Round($_.FreeSpace/1GB,2); UsedPercent=[math]::Round(100*(1-$_.FreeSpace/$_.Size),1)} } }) } catch {}
      $top = @(); $hung = @(); try { $procs = @(Get-Process -ErrorAction SilentlyContinue); $top = @($procs | Sort-Object CPU -Descending | Select-Object -First 10 @{N='Process';E={$_.ProcessName}},Id,@{N='CPUSeconds';E={$_.CPU}},@{N='MemoryMB';E={[math]::Round($_.WorkingSet64/1MB,1)}}); $hung = @($procs | Where-Object { $_.Responding -eq $false } | Select-Object @{N='Process';E={$_.ProcessName}},Id,Responding) } catch {}
      $start = (Get-Date).AddHours(-$hours)
      $appEvents = @(); try { $appEvents = @(Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$start; Id=@(1000,1001,1002)} -MaxEvents 100 -ErrorAction SilentlyContinue | Select-Object @{N='Time';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}},Id,ProviderName,Message) } catch {}
      $hwEvents = @(); try { $hwEvents = @(Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$start} -MaxEvents 250 -ErrorAction SilentlyContinue | Where-Object { $_.Id -in @(7,11,17,18,19,41,51,55,129,153,157,6008) -or $_.ProviderName -match 'WHEA|Disk|Ntfs|storport|stornvme|Kernel-Power|volmgr' } | Select-Object @{N='Time';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}},Id,ProviderName,Message) } catch {}
      $drivers = @(); try { $cutoff=(Get-Date).AddYears(-$driverAge); $drivers = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.DriverDate -and $_.DeviceName -and ([datetime]$_.DriverDate) -lt $cutoff } | Select-Object -First 200 DeviceName,Manufacturer,DriverVersion,DriverDate,InfName) } catch {}
      $avNames = @(); try { $avNames = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Select-Object -ExpandProperty displayName) } catch {}
      $defender = 'Unknown'; try { $d=Get-MpComputerStatus -ErrorAction Stop; if ($d.AntivirusEnabled -and $d.RealTimeProtectionEnabled) { $defender='Enabled' } else { $defender='Review - not fully enabled' } } catch {}
      [pscustomobject]@{ComputerName=$env:COMPUTERNAME; Reachable=$true; CPUPercent=$cpu; RAMUsedPercent=$ram; RAMTotalGB=$ramTotal; RAMFreeGB=$ramFree; Disks=@($disks); TopProcesses=@($top); HungProcesses=@($hung); ApplicationEvents=@($appEvents); HardwareEvents=@($hwEvents); DriversToReview=@($drivers); AntivirusNames=@($avNames); DefenderStatus=$defender}
    } -ArgumentList $hours,$driverAge
  } catch {
    [pscustomobject]@{ComputerName=$computer; Reachable=$false; Error=$_.Exception.Message}
  }
}
$results | ConvertTo-Json -Depth 7 -Compress
'''.replace('__HOSTS__', host_literals).replace('__HOURS__', str(int(hours))).replace('__DRIVERAGE__', str(int(driver_age_years)))
    proc = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-Command", ps],
                         capture_output=True, text=True, timeout=max(90, len(clean_hosts)*45), errors="replace")
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(proc.stderr.strip() or f"PowerShell returned code {proc.returncode}")
    if not proc.stdout.strip():
        raise RuntimeError(proc.stderr.strip() or "No output returned. Verify WinRM/PowerShell Remoting and permissions.")
    try:
        data = json.loads(proc.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError("Could not parse remote diagnostics output. Check PowerShell remoting output/errors.") from exc
    if isinstance(data, dict):
        data = [data]
    return data



def diagnose_winrm_hosts(hosts):
    """Read-only WinRM reachability test from this portal computer."""
    if platform.system() != "Windows":
        return [{"ComputerName": h, "Result": "Unavailable", "Details": "WinRM tests require this portal to run on Windows."} for h in hosts]
    clean_hosts = []
    for host in hosts:
        host = host.strip()
        if host and re.fullmatch(r"[A-Za-z0-9._-]{1,255}", host) and host.lower() not in {x.lower() for x in clean_hosts}:
            clean_hosts.append(host)
    if not clean_hosts:
        return []
    hosts_literal = ",".join("'" + h.replace("'", "''") + "'" for h in clean_hosts)
    ps = r"""
$targets=@(__HOSTS__)
$results=foreach($computer in $targets) {
  $port5985=$false; $port5986=$false; $wsman=$false; $detail=''
  try { $port5985=(Test-NetConnection -ComputerName $computer -Port 5985 -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction SilentlyContinue) } catch {}
  try { $port5986=(Test-NetConnection -ComputerName $computer -Port 5986 -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction SilentlyContinue) } catch {}
  try { Test-WSMan -ComputerName $computer -ErrorAction Stop | Out-Null; $wsman=$true; $detail='Test-WSMan succeeded using the default HTTP endpoint.' }
  catch { $detail=$_.Exception.Message }
  [pscustomobject]@{ComputerName=$computer; Port5985=$port5985; Port5986=$port5986; TestWSMan=$wsman; Details=$detail}
}
$results | ConvertTo-Json -Depth 4 -Compress
""".replace("__HOSTS__", hosts_literal)
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-Command", ps],
        capture_output=True, text=True, timeout=max(45, len(clean_hosts) * 15), errors="replace"
    )
    if not proc.stdout.strip():
        raise RuntimeError(proc.stderr.strip() or f"No diagnostic output returned (exit {proc.returncode}).")
    result = json.loads(proc.stdout.strip())
    return [result] if isinstance(result, dict) else result


def open_local_driver_tools(tool):
    """Open the built-in Windows UI; no driver is installed automatically."""
    if platform.system() != "Windows":
        raise RuntimeError("Driver update UI is available only when the portal runs on Windows.")
    if tool == "windows_update":
        subprocess.Popen(["cmd.exe", "/c", "start", "", "ms-settings:windowsupdate"], shell=False)
    elif tool == "device_manager":
        subprocess.Popen(["mmc.exe", "devmgmt.msc"], shell=False)
    else:
        raise ValueError("Unknown driver tool.")


def run_powershell_admin_tool(host, action, port=443, timeout=45):
    """Run a fixed, read-only local or remote PowerShell diagnostic action."""
    if platform.system() != "Windows":
        raise RuntimeError("PowerShell tools require the portal to run on Windows.")
    host = (host or "").strip()
    if not host or not re.fullmatch(r"[A-Za-z0-9._-]{1,255}", host):
        raise ValueError("Enter a valid computer hostname or IP address.")
    if not (1 <= int(port) <= 65535):
        raise ValueError("Port must be between 1 and 65535.")

    target_q = "'" + host.replace("'", "''") + "'"
    actions = {
        "Ping (4 packets)": f"Test-Connection -ComputerName {target_q} -Count 4 -ErrorAction SilentlyContinue | Select-Object ComputerName,Address,Status,ResponseTime",
        "Test TCP port": f"Test-NetConnection -ComputerName {target_q} -Port {int(port)} -WarningAction SilentlyContinue | Select-Object ComputerName,RemoteAddress,RemotePort,TcpTestSucceeded",
        "Test WinRM": f"Test-WSMan -ComputerName {target_q} -ErrorAction Stop | Select-Object ComputerName,ProductVersion,ProtocolVersion",
        "Remote hostname": f"Invoke-Command -ComputerName {target_q} -ErrorAction Stop -ScriptBlock {{ hostname }}",
        "Remote OS and last boot": f"Invoke-Command -ComputerName {target_q} -ErrorAction Stop -ScriptBlock {{ Get-CimInstance Win32_OperatingSystem | Select-Object CSName,Caption,Version,LastBootUpTime }}",
        "Remote top processes": f"Invoke-Command -ComputerName {target_q} -ErrorAction Stop -ScriptBlock {{ Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 ProcessName,Id,CPU,WorkingSet64 }}",
        "Remote services (running)": f"Invoke-Command -ComputerName {target_q} -ErrorAction Stop -ScriptBlock {{ Get-Service | Where-Object Status -eq 'Running' | Select-Object -First 40 Name,DisplayName,Status }}",
        "Remote disk space": f"Invoke-Command -ComputerName {target_q} -ErrorAction Stop -ScriptBlock {{ Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID,VolumeName,@{{N='SizeGB';E={{[math]::Round($_.Size/1GB,2)}}}},@{{N='FreeGB';E={{[math]::Round($_.FreeSpace/1GB,2)}}}} }}",
        "Remote application errors (last 24h)": f"Invoke-Command -ComputerName {target_q} -ErrorAction Stop -ScriptBlock {{ Get-WinEvent -FilterHashtable @{{LogName='Application'; StartTime=(Get-Date).AddHours(-24)}} -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {{ $_.Level -in @(1,2,3) -or $_.Id -in @(1000,1001,1002) }} | Select-Object -First 50 TimeCreated,Id,LevelDisplayName,ProviderName,Message }}",
    }
    if action not in actions:
        raise ValueError("Choose one of the supported read-only diagnostics.")
    command = actions[action] + " | ConvertTo-Json -Depth 4 -Compress"
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-Command", command],
        capture_output=True, text=True, timeout=timeout, errors="replace"
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(proc.stderr.strip() or f"PowerShell returned code {proc.returncode}.")
    output = proc.stdout.strip()
    if proc.stderr.strip():
        output += "\n\nSTDERR:\n" + proc.stderr.strip()
    return output or "(No output returned. This may mean the host is unreachable or no matching events were found.)"

def send_report_email(smtp_host, smtp_port, username, password, sender, recipients, subject, body, attachment_name, attachment_bytes):
    '''Send a user-requested report via SMTP with TLS; never writes credentials to disk.'''
    if not smtp_host.strip() or not sender.strip() or not recipients.strip():
        raise ValueError("SMTP server, sender email, and recipient email are required.")
    msg = EmailMessage()
    msg["Subject"] = subject.strip() or "AWANISH IT/OPS System Monitor Report"
    msg["From"] = sender.strip()
    msg["To"] = recipients.strip()
    msg.set_content(body)
    guessed_type, _ = mimetypes.guess_type(attachment_name)
    if guessed_type:
        maintype, subtype = guessed_type.split("/", 1)
    else:
        maintype, subtype = "application", "octet-stream"
    msg.add_attachment(attachment_bytes, maintype=maintype, subtype=subtype, filename=attachment_name)
    if int(smtp_port) == 465:
        with smtplib.SMTP_SSL(smtp_host.strip(), int(smtp_port), timeout=30) as server:
            if username.strip():
                server.login(username.strip(), password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(smtp_host.strip(), int(smtp_port), timeout=30) as server:
            server.ehlo()
            if server.has_extn("starttls"):
                server.starttls()
                server.ehlo()
            if username.strip():
                server.login(username.strip(), password)
            server.send_message(msg)

st.title("AWANISH IT/OPS Testing")
st.caption("Dark-blue operations dashboard • Read-only diagnostics by default • Human approval required for cleanup or disruptive actions")

with st.sidebar:
    st.markdown("## 🛠️ AWANISH IT/OPS")
    st.caption("TESTING • OPERATIONS CONSOLE")
    st.divider()
    st.markdown("**CURRENT WORKSTATION**")
    st.write(f"🖥️  {platform.node() or 'Unknown'}")
    st.caption(platform.system() + " • " + platform.release())
    st.caption(f"Session started: {now_str()}")
    st.divider()
    st.markdown("**DIAGNOSTIC SETTINGS**")
    event_hours = st.selectbox("Event log lookback", [6, 12, 24, 48, 168], index=2, format_func=lambda x: f"Last {x} hours" if x < 168 else "Last 7 days")
    max_events = st.slider("Maximum events to inspect", min_value=100, max_value=3000, value=500, step=100)
    st.divider()
    st.caption("Read-only checks by default. Cleanup and disruptive actions require explicit review/approval.")

tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10 = st.tabs([
    "Overview", "Log Compare", "Restart & Events", "Hardware Checks", "Temp Cleanup",
    "SCTE Excel Report", "SCTE Command Match", "System Monitor", "Multi-System & Email",
    "PowerShell & Remote Access"
])

with tab1:
    st.markdown("""
    <div class="awi-hero">
      <h2>IT Operations Command Center</h2>
      <p>Live workstation health • SCTE validation • event investigation • multi-system diagnostics</p>
    </div>
    """, unsafe_allow_html=True)
    # Lightweight live local metrics. These are collected at page render and are not remote-system values.
    cpu_now = psutil.cpu_percent(interval=0.25)
    mem_now = psutil.virtual_memory()
    try:
        boot_dt = datetime.fromtimestamp(psutil.boot_time()).astimezone().strftime("%d %b %Y, %H:%M")
    except Exception:
        boot_dt = "Unavailable"
    try:
        root_path = os.environ.get("SystemDrive", "C:") + "\\" if platform.system() == "Windows" else "/"
        disk_now = shutil.disk_usage(root_path)
        disk_used = (disk_now.used / disk_now.total * 100) if disk_now.total else 0
        disk_free_gb = disk_now.free / (1024 ** 3)
    except Exception:
        disk_used, disk_free_gb = 0, 0
    event_count = len(st.session_state.get("events", []) or [])
    scte_ready = "Ready" if st.session_state.get("scte_report_bytes") or st.session_state.get("scte_report_data") else "Upload required"
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("CPU Utilization", f"{cpu_now:.0f}%", help="Live local workstation sample")
    m2.metric("Memory Used", f"{mem_now.percent:.0f}%", f"{mem_now.used / (1024**3):.1f} / {mem_now.total / (1024**3):.1f} GB")
    m3.metric("System Disk Used", f"{disk_used:.0f}%", f"{disk_free_gb:.1f} GB free")
    m4.metric("Last Event Scan", f"{event_count} events" if "events" in st.session_state else "Not run", help="Events from your last manual scan")

    # Lightweight trend history: one sample per Streamlit rerun, kept in this browser session.
    # This is not a background polling service; values update when the app reruns.
    sample = {
        "Time": datetime.now().strftime("%H:%M:%S"),
        "CPU %": round(float(cpu_now), 1),
        "Memory %": round(float(mem_now.percent), 1),
        "Disk %": round(float(disk_used), 1),
    }
    if "overview_health_history" not in st.session_state:
        st.session_state["overview_health_history"] = []
    history = st.session_state["overview_health_history"]
    if not history or history[-1].get("Time") != sample["Time"]:
        history.append(sample)
        st.session_state["overview_health_history"] = history[-30:]
    with st.expander("Resource utilization trend", expanded=True):
        st.caption("Local workstation samples from this session. The chart updates when the app reruns; it does not poll in the background.")
        trend_df = pd.DataFrame(st.session_state["overview_health_history"])
        if not trend_df.empty:
            st.line_chart(trend_df.set_index("Time"), y=["CPU %", "Memory %", "Disk %"], height=230)

    if cpu_now >= 90:
        st.error("High CPU usage detected on this workstation. Review System Monitor and top processes.")
    elif mem_now.percent >= 90:
        st.warning("Memory usage is high. Review running applications before taking action.")
    if disk_used >= 90:
        st.error("System disk usage is critically high. Review disk details; no files have been deleted.")
    elif disk_used >= 80:
        st.warning("System disk usage is elevated. Review the Hardware Checks and Temp Cleanup tabs.")

    st.markdown('<div class="awi-section">Quick actions</div>', unsafe_allow_html=True)
    q1, q2, q3, q4 = st.columns(4)
    with q1:
        if st.button("🔎 Run System Check", type="primary", use_container_width=True, key="overview_system_check"):
            st.session_state["overview_quick_result"] = {"time": now_str(), "cpu": psutil.cpu_percent(interval=0.5), "memory": psutil.virtual_memory().percent, "disk": disk_used, "free_gb": disk_free_gb, "boot": boot_dt}
    with q2:
        if st.button("💽 Check Disk Space", use_container_width=True, key="overview_disk_check"):
            rows, err = disk_usage_rows()
            st.session_state["overview_disk_rows"] = rows
            st.session_state["overview_disk_error"] = err
    with q3:
        if st.button("🧾 Scan Temp Files", use_container_width=True, key="overview_temp_scan"):
            st.session_state["temp_candidates"] = get_temp_candidates()
            st.session_state["temp_scan_time"] = now_str()
            st.session_state["temp_approved"] = False
            st.session_state["overview_temp_scanned"] = True
    with q4:
        if st.button("📄 Open Report Folder", use_container_width=True, key="overview_report_folder"):
            st.session_state["overview_report_folder_requested"] = True
    if st.session_state.get("overview_quick_result"):
        qr = st.session_state["overview_quick_result"]
        st.success(f"System check completed at {qr['time']} • CPU {qr['cpu']:.0f}% • Memory {qr['memory']:.0f}% • Disk {qr['disk']:.0f}% used • Boot: {qr['boot']}")
    if "overview_disk_rows" in st.session_state:
        if st.session_state["overview_disk_rows"]:
            st.dataframe(pd.DataFrame(st.session_state["overview_disk_rows"]), use_container_width=True, hide_index=True)
        else:
            st.warning(st.session_state.get("overview_disk_error") or "No disk information returned.")
    if st.session_state.get("overview_temp_scanned"):
        candidates = st.session_state.get("temp_candidates", [])
        st.info(f"Temp scan complete: {len(candidates)} top-level items found. Review candidates in the Temp Cleanup tab; nothing was deleted.")
    if st.session_state.get("overview_report_folder_requested"):
        st.info(f"Report folder: {REPORT_DIR}  •  Use the report download buttons in each module to save reports. The portal will not open folders automatically.")

    st.markdown('<div class="awi-section">Operational shortcuts</div>', unsafe_allow_html=True)
    s1, s2, s3 = st.columns(3)
    with s1:
        with st.container(border=True):
            st.markdown("**📡 System monitoring**")
            st.caption("CPU, memory, disks, crashes, hardware, drivers and antivirus review.")
            st.caption("Use the System Monitor and Hardware Checks tabs.")
    with s2:
        with st.container(border=True):
            st.markdown("**📺 SCTE validation**")
            st.caption("Generate the Excel report and validate command/timestamp matching.")
            st.caption("Use SCTE Excel Report and SCTE Command Match.")
    with s3:
        with st.container(border=True):
            st.markdown("**✉️ Reports & remote checks**")
            st.caption("Email reports using approved SMTP settings and run approved read-only remote diagnostics.")
            st.caption("Use Multi-System & Email and PowerShell & Remote Access.")

    st.markdown('<div class="awi-section">Reports & email shortcuts</div>', unsafe_allow_html=True)
    e1, e2, e3 = st.columns(3)
    with e1:
        with st.container(border=True):
            st.markdown("**SCTE Excel report**")
            st.caption("Generate and download FINAL_REPORT.xlsx, then use the email form in the SCTE Excel Report tab.")
    with e2:
        with st.container(border=True):
            st.markdown("**SCTE command match**")
            st.caption("Run batch validation and download the CSV results; email the report from the command-match section.")
    with e3:
        with st.container(border=True):
            st.markdown("**Multi-system report**")
            st.caption("Check multiple approved hosts, download the consolidated report and send it using your approved SMTP relay.")

    with st.expander("Recent alerts and notifications", expanded=True):
        alerts = []
        if cpu_now >= 90: alerts.append(("Critical", "CPU utilization is at or above 90%"))
        if mem_now.percent >= 90: alerts.append(("Warning", "Memory utilization is at or above 90%"))
        if disk_used >= 90: alerts.append(("Critical", "System disk usage is at or above 90%"))
        elif disk_used >= 80: alerts.append(("Warning", "System disk usage is at or above 80%"))
        if st.session_state.get("comparison", {}).get("rows"):
            alerts.append(("Review", f"Log comparison found {len(st.session_state['comparison']['rows'])} new/changed patterns"))
        if st.session_state.get("temp_candidates") is not None:
            alerts.append(("Review", f"Temporary-file scan found {len(st.session_state.get('temp_candidates', []))} top-level items; approval required before cleanup"))
        if not alerts:
            st.success("No threshold alerts from the current local snapshot. Run module-specific checks for deeper diagnostics.")
        else:
            st.dataframe(pd.DataFrame(alerts, columns=["Severity", "Alert"]), use_container_width=True, hide_index=True)

    with st.expander("Resource utilization chart"):
        chart_df = pd.DataFrame({"Resource": ["CPU", "Memory", "System disk"], "Used %": [cpu_now, mem_now.percent, disk_used]})
        st.bar_chart(chart_df.set_index("Resource"), y="Used %", use_container_width=True)
        st.caption(f"Last boot: {boot_dt} • Chart shows a local snapshot, not historical monitoring.")

with tab2:
    st.subheader("Compare old and new logs")
    st.write("Upload two text/log files. The comparison normalizes common timestamps and IDs to reduce noise.")
    old_file = st.file_uploader("Previous log (baseline)", type=None, key="old_log")
    new_file = st.file_uploader("Current log", type=None, key="new_log")
    if st.button("Compare logs", type="primary", key="compare_btn"):
        if not old_file or not new_file:
            st.error("Upload both the previous and current log files.")
        else:
            try:
                old_text = safe_read_text(old_file)
                new_text = safe_read_text(new_file)
                old_lines, new_lines, rows = compare_logs(old_text, new_text)
                st.session_state["comparison"] = {
                    "created": now_str(), "old_name": old_file.name, "new_name": new_file.name,
                    "old_line_count": len(old_lines), "new_line_count": len(new_lines), "rows": rows
                }
            except Exception as e:
                st.error(f"Could not compare files: {e}")
    result = st.session_state.get("comparison")
    if result:
        a, b, c = st.columns(3)
        a.metric("Baseline lines", result["old_line_count"])
        b.metric("Current lines", result["new_line_count"])
        c.metric("New/changed patterns", len(result["rows"]))
        st.caption(f'{result["old_name"]} → {result["new_name"]} • {result["created"]}')
        if result["rows"]:
            df = pd.DataFrame(result["rows"])
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.download_button("Download comparison CSV", df.to_csv(index=False).encode("utf-8-sig"),
                               file_name="awi_log_comparison.csv", mime="text/csv")
        else:
            st.success("No new normalized log patterns were found.")
        report = {
            "generated_at": result["created"], "baseline_file": result["old_name"],
            "current_file": result["new_name"], "baseline_lines": result["old_line_count"],
            "current_lines": result["new_line_count"], "new_patterns": result["rows"]
        }
        st.download_button("Download comparison JSON report", json.dumps(report, indent=2).encode("utf-8"),
                           file_name="awi_log_comparison_report.json", mime="application/json")

with tab3:
    st.subheader("Windows restart and system events")
    st.write("Reads the local computer's Windows System event log. For a remote server, export the System log as EVTX or CSV and analyze it as a file in a future version.")
    if platform.system() != "Windows":
        st.warning("Local Event Viewer collection is available only when this app runs on Windows.")
    if st.button("Read local System events", type="primary"):
        events, err = get_local_event_logs(event_hours, max_events)
        if err:
            st.error(f"Could not read events: {err}")
            st.caption("Some event logs may require appropriate Windows permissions.")
        else:
            cooked = []
            for ev in events:
                cooked.append({
                    "Time": str(ev.get("TimeCreated", "")),
                    "Event ID": ev.get("Id", ""),
                    "Level": ev.get("LevelDisplayName", ""),
                    "Source": ev.get("ProviderName", ""),
                    "Interpretation": event_interpretation(ev),
                    "Message": str(ev.get("Message", "") or "")[:4000],
                })
            st.session_state["events"] = cooked
            st.session_state["events_generated"] = now_str()
    events = st.session_state.get("events")
    if events is not None:
        st.caption(f'Last checked: {st.session_state.get("events_generated", "")}')
        if events:
            df = pd.DataFrame(events)
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.download_button("Download events CSV", df.to_csv(index=False).encode("utf-8-sig"),
                               file_name="awi_windows_events.csv", mime="text/csv")
        else:
            st.success("No matching critical, error, warning, or selected restart events were returned for the chosen time range.")

with tab4:
    st.subheader("Basic hardware and storage indicators")
    if st.button("Run read-only hardware checks", type="primary"):
        disks, err = disk_usage_rows()
        st.session_state["disk_rows"] = disks
        st.session_state["disk_error"] = err
        if platform.system() == "Windows":
            # Read-only commands; SMART availability varies by device, driver and permissions.
            smart_out, smart_err = run_powershell(
                "Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue | "
                "Select-Object InstanceName,PredictFailure,Reason | ConvertTo-Json", timeout=20)
            st.session_state["smart_out"] = smart_out
            st.session_state["smart_err"] = smart_err
            os_out, os_err = run_powershell(
                "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,LastBootUpTime,FreePhysicalMemory,TotalVisibleMemorySize | ConvertTo-Json",
                timeout=20)
            st.session_state["os_out"] = os_out
            st.session_state["os_err"] = os_err
    disks = st.session_state.get("disk_rows")
    if disks is not None:
        if disks:
            df = pd.DataFrame(disks)
            st.dataframe(df, use_container_width=True, hide_index=True)
            for row in disks:
                try:
                    pct = float(row.get("FreePercent", 100))
                    if pct < 10:
                        st.error(f'{row.get("DeviceID", "Disk")}: critically low free space ({pct}% free).')
                    elif pct < 20:
                        st.warning(f'{row.get("DeviceID", "Disk")}: low free space ({pct}% free).')
                except Exception:
                    pass
        else:
            st.warning(st.session_state.get("disk_error") or "No disk information returned.")
        if platform.system() == "Windows":
            st.markdown("**Windows storage health prediction (if exposed by the device/driver)**")
            smart_out = st.session_state.get("smart_out")
            if smart_out:
                st.code(smart_out)
                if "true" in smart_out.lower():
                    st.warning("A device may report predicted failure. Confirm with vendor diagnostics; this is not a complete hardware test.")
            else:
                st.caption("No SMART prediction data returned. This is common on some NVMe, RAID, USB and vendor-managed controllers.")
            st.markdown("**Operating system / memory information**")
            if st.session_state.get("os_out"):
                st.code(st.session_state["os_out"])
            else:
                st.caption(st.session_state.get("os_err") or "OS details were unavailable.")
    st.warning("These are screening indicators, not a definitive hardware diagnosis. For Dell RAID/server health, confirm through iDRAC/OpenManage or the approved vendor utility.")

with tab5:
    st.subheader("Temporary-file scan and approval")
    st.write("Scans only the current user's TEMP/TMP top-level entries. It does not recursively delete folders, Windows system files, browser data, or application logs.")
    if st.button("Scan temporary files", type="primary"):
        st.session_state["temp_candidates"] = get_temp_candidates()
        st.session_state["temp_scan_time"] = now_str()
        st.session_state["temp_approved"] = False
    candidates = st.session_state.get("temp_candidates")
    if candidates is not None:
        st.caption(f'Last scan: {st.session_state.get("temp_scan_time", "")}')
        files_only = [x for x in candidates if x["size"] is not None]
        total_bytes = sum(x["size"] for x in files_only)
        st.metric("Top-level files found", len(files_only))
        st.metric("Potential file size", f"{total_bytes / (1024**2):.1f} MB")
        if candidates:
            df = pd.DataFrame([{
                "Path": x["path"],
                "Size (MB)": round(x["size"]/(1024**2), 3) if x["size"] is not None else "Folder (not eligible)",
                "Last modified": x["modified"].strftime("%Y-%m-%d %H:%M:%S"),
                "Eligible": "File only" if x["size"] is not None else "Not eligible"
            } for x in candidates])
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.warning("Review the list carefully. Some temp files may be in use. Only individually selected files can be deleted.")
            eligible = [x["path"] for x in files_only]
            selected = st.multiselect("Select exact files to delete", eligible, default=[])
            st.checkbox("I reviewed the selected paths and approve deleting only these selected files.", key="confirm_cleanup")
            if st.button("Delete selected files", type="secondary"):
                if not st.session_state.get("confirm_cleanup"):
                    st.error("Tick the approval checkbox first.")
                elif not selected:
                    st.error("Select at least one file.")
                else:
                    deleted, skipped = [], []
                    allowed = set(eligible)
                    for item in selected:
                        if item not in allowed:
                            skipped.append(item + " (not in scan)")
                            continue
                        try:
                            p = Path(item)
                            # Guard against changed environment and directories.
                            if not p.is_file():
                                skipped.append(item + " (no longer a file)")
                                continue
                            p.unlink()
                            deleted.append(item)
                        except Exception as e:
                            skipped.append(item + f" ({e})")
                    st.session_state["cleanup_result"] = {"deleted": deleted, "skipped": skipped, "time": now_str()}
                    st.session_state["temp_candidates"] = get_temp_candidates()
                    st.session_state["confirm_cleanup"] = False
                    st.rerun()
        else:
            st.success("No top-level temporary entries were found in the current user's TEMP/TMP paths.")
    cleanup_result = st.session_state.get("cleanup_result")
    if cleanup_result:
        st.markdown("**Last cleanup result**")
        st.write(f'Time: {cleanup_result["time"]}')
        st.write(f'Deleted files: {len(cleanup_result["deleted"])}')
        if cleanup_result["deleted"]:
            st.code("\n".join(cleanup_result["deleted"]))
        if cleanup_result["skipped"]:
            st.warning("Skipped items:\n" + "\n".join(cleanup_result["skipped"]))

st.divider()
st.caption("AWANISH IT/OPS Testing • Local diagnostic helper • Always verify findings with approved vendor tools before maintenance.")



with tab6:
    st.subheader("SCTE Logs → Excel Report")
    st.write(
        "Upload one or more downloaded Excel log files (.xlsx or .xlsm). "
        "This runs your SCTE StartImmediate/EndImmediate detection logic and creates FINAL_REPORT.xlsx."
    )
    st.info(
        "Required columns on each usable worksheet: Time, Producer Name, SCTE Payload. "
        "The original state lists and report layout are retained."
    )
    scte_files = st.file_uploader(
        "Select SCTE Excel log files",
        type=["xlsx", "xlsm"],
        accept_multiple_files=True,
        key="scte_excel_uploads"
    )
    if st.button("Generate FINAL_REPORT.xlsx", type="primary", key="generate_scte_report"):
        if not scte_files:
            st.error("Please upload at least one Excel log file.")
        else:
            try:
                report_bytes, report_stats = build_scte_report(scte_files)
                st.session_state["scte_report_bytes"] = report_bytes
                st.session_state["scte_report_stats"] = report_stats
                st.session_state["scte_report_time"] = now_str()
                st.success("SCTE report generated successfully.")
            except Exception as exc:
                st.error(f"Could not generate SCTE report: {exc}")

    report_stats = st.session_state.get("scte_report_stats")
    if report_stats:
        a, b, c = st.columns(3)
        a.metric("Excel files uploaded", report_stats["files_uploaded"])
        b.metric("Rows imported", report_stats["rows_imported_before_exact_dedup"])
        c.metric("Recognized START/END events", report_stats["recognized_start_end_events_before_state_dedup"])
        st.caption("Generated: " + st.session_state.get("scte_report_time", ""))
        st.write("Detected states:", ", ".join(report_stats["states_detected"]) or "None")

        # Preview the exact generated Excel workbook in the portal.
        # This reads the report bytes only; it does not rerun or alter SCTE validation.
        st.subheader("SCTE Report Preview")
        report_bytes = st.session_state.get("scte_report_bytes")
        if report_bytes:
            try:
                with pd.ExcelFile(io.BytesIO(report_bytes), engine="openpyxl") as workbook:
                    for sheet_name in workbook.sheet_names:
                        st.markdown(f"**Worksheet: {sheet_name}**")
                        preview_df = pd.read_excel(
                            workbook,
                            sheet_name=sheet_name,
                            header=None,
                            dtype=object,
                        )
                        st.dataframe(
                            preview_df,
                            use_container_width=True,
                            hide_index=True,
                        )
            except Exception as exc:
                st.error(f"Could not preview the generated SCTE Excel report: {exc}")
                st.caption("The original Excel download remains available below.")

        st.download_button(
            "Download FINAL_REPORT.xlsx",
            data=st.session_state["scte_report_bytes"],
            file_name="FINAL_REPORT.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            key="download_scte_report"
        )
        st.divider()
        st.subheader("Email FINAL_REPORT.xlsx")
        st.caption("Send the generated SCTE Excel report as an email attachment using your organization's approved SMTP relay.")
        with st.form("scte_excel_email_form"):
            se1, se2 = st.columns(2)
            with se1:
                scte_smtp_host = st.text_input("SMTP server / relay", key="scte_email_smtp_host", placeholder="smtp.company.com")
                scte_smtp_port = st.number_input("SMTP port", min_value=1, max_value=65535, value=587, step=1, key="scte_email_smtp_port")
                scte_smtp_user = st.text_input("SMTP username (if required)", key="scte_email_smtp_user")
                scte_smtp_password = st.text_input("SMTP password / app password", type="password", key="scte_email_smtp_password")
            with se2:
                scte_sender = st.text_input("From email", key="scte_email_sender", placeholder="it-ops@company.com")
                scte_recipients = st.text_input("To email(s), comma-separated", key="scte_email_recipients", placeholder="helpdesk@company.com")
                scte_subject = st.text_input("Email subject", value="SCTE FINAL_REPORT.xlsx", key="scte_email_subject")
            scte_body = st.text_area("Email message", value="Please find attached the generated SCTE FINAL_REPORT.xlsx for review.", key="scte_email_body")
            send_scte_email = st.form_submit_button("Send SCTE Excel Report", type="primary")
        if send_scte_email:
            try:
                send_report_email(
                    scte_smtp_host, int(scte_smtp_port), scte_smtp_user, scte_smtp_password,
                    scte_sender, scte_recipients, scte_subject, scte_body,
                    "FINAL_REPORT.xlsx", st.session_state["scte_report_bytes"]
                )
                st.success("SCTE Excel report email sent successfully.")
            except Exception as exc:
                st.error(f"SCTE report email was not sent: {exc}. Verify SMTP settings and sender permissions with IT.")

        with st.expander("Processing details"):
            for message in report_stats["messages"]:
                st.text(message)

with tab7:
    st.subheader("SCTE Command Match — Batch Asrun TXT vs SCTE Export")
    st.write(
        "Upload multiple AMPP Asrun TXT files and multiple SCTE export files. "
        "Choose the matching export for each Asrun file, then run the batch comparison."
    )
    st.info(
        "Each pair is checked independently. START requires SCTE-IN, SQ-KL-EFFECT-4-IN, "
        "SW-KL-BRK-ON, BRK-ON. END requires SW-KL-BRK-OFF, SQ-KL-EFFECT-4-OUT, "
        "BRK-OFF, SCTE-OUT. Every required Asrun command must be Done, within the selected "
        "time window, and a command row cannot be reused. SCTE-IN/OUT are also matched against "
        "StartImmediate/EndImmediate events in the selected export."
    )

    asrun_uploads = st.file_uploader(
        "Upload one or more AMPP Asrun TXT files",
        type=["txt", "log", "csv"],
        accept_multiple_files=True,
        key="scte_match_asrun_uploads"
    )
    export_uploads = st.file_uploader(
        "Upload one or more SCTE exports (Excel or TXT)",
        type=["xlsx", "xlsm", "txt", "csv", "log"],
        accept_multiple_files=True,
        key="scte_match_export_uploads"
    )

    export_names = [f.name for f in (export_uploads or [])]
    pair_map = {}
    if asrun_uploads and export_uploads:
        st.markdown("**Match each Asrun file to its corresponding SCTE export**")
        for idx, asrun_file in enumerate(asrun_uploads):
            asrun_stem = Path(asrun_file.name).stem.lower()
            # Prefer a filename with shared tokens; otherwise use the same upload position if available.
            tokens = [t for t in re.split(r"[^a-z0-9]+", asrun_stem) if len(t) > 2]
            scored = []
            for ex_idx, ex_file in enumerate(export_uploads):
                ex_stem = Path(ex_file.name).stem.lower()
                score = sum(1 for t in tokens if t in ex_stem)
                scored.append((score, ex_idx))
            best_score = max((s for s, _ in scored), default=0)
            best_idx = next((j for s, j in scored if s == best_score), idx if idx < len(export_uploads) else 0)
            if best_score == 0 and idx < len(export_uploads):
                best_idx = idx
            default_name = export_uploads[best_idx].name
            chosen_name = st.selectbox(
                f"Export for {asrun_file.name}",
                options=export_names,
                index=export_names.index(default_name),
                key=f"scte_pair_map_{idx}"
            )
            pair_map[asrun_file.name] = chosen_name

    tolerance = st.select_slider(
        "Allowed timestamp difference for SCTE export match",
        options=[0.0, 0.25, 0.5, 1.0, 2.0, 5.0],
        value=1.0,
        format_func=lambda x: "Exact (0 sec)" if x == 0 else f"{x:g} sec",
        key="scte_match_tolerance_batch"
    )
    command_window = st.select_slider(
        "Allowed time window for macro commands around SCTE-IN/OUT",
        options=[0.5, 1.0, 2.0, 3.0, 5.0],
        value=2.0,
        format_func=lambda x: f"{x:g} sec",
        key="scte_command_window_batch"
    )

    if st.button("Run Batch SCTE Command Test", type="primary", key="run_scte_command_match_batch"):
        if not asrun_uploads or not export_uploads:
            st.error("Upload at least one Asrun TXT and one SCTE export file.")
        else:
            match_frames, sequence_frames, asrun_frames, export_frames, errors = [], [], [], [], []
            export_lookup = {f.name: f for f in export_uploads}
            for asrun_file in asrun_uploads:
                export_name = pair_map.get(asrun_file.name)
                export_file = export_lookup.get(export_name)
                if export_file is None:
                    errors.append(f"{asrun_file.name}: no matching export selected.")
                    continue
                try:
                    asrun_df = parse_asrun_commands(safe_read_text(asrun_file))
                    if export_file.name.lower().endswith((".xlsx", ".xlsm")):
                        export_df = parse_scte_export_excel(export_file)
                    else:
                        export_df = parse_scte_export_txt(safe_read_text(export_file))

                    match_df = compare_scte_sources(asrun_df, export_df, tolerance)
                    sequence_df = check_command_sequences(asrun_df, command_window)

                    match_df.insert(0, "Asrun File", asrun_file.name)
                    match_df.insert(1, "Export File", export_file.name)
                    sequence_df.insert(0, "Asrun File", asrun_file.name)
                    sequence_df.insert(1, "Export File", export_file.name)
                    asrun_df.insert(0, "Asrun File", asrun_file.name)
                    export_df.insert(0, "Export File", export_file.name)

                    match_frames.append(match_df)
                    sequence_frames.append(sequence_df)
                    asrun_frames.append(asrun_df)
                    export_frames.append(export_df)
                except Exception as exc:
                    errors.append(f"{asrun_file.name} → {export_name}: {exc}")

            if match_frames:
                all_matches = pd.concat(match_frames, ignore_index=True)
                all_sequences = pd.concat(sequence_frames, ignore_index=True)
                all_asrun = pd.concat(asrun_frames, ignore_index=True)
                all_export = pd.concat(export_frames, ignore_index=True)
                st.session_state["scte_command_match"] = all_matches
                st.session_state["scte_command_sequence"] = all_sequences
                st.session_state["scte_command_asrun"] = all_asrun
                st.session_state["scte_command_export"] = all_export
                st.session_state["scte_command_match_meta"] = {
                    "asrun_names": [f.name for f in asrun_uploads],
                    "export_names": list(dict.fromkeys(pair_map.values())),
                    "pair_map": pair_map,
                    "tolerance": tolerance,
                    "command_window": command_window,
                    "created": now_str(),
                    "pair_count": len(match_frames)
                }
                st.session_state["scte_command_errors"] = errors
            else:
                st.session_state.pop("scte_command_match", None)
                st.session_state["scte_command_errors"] = errors
                st.error("No file pairs could be processed. Check the errors below.")
            for error in errors:
                st.error(error)

    match_df = st.session_state.get("scte_command_match")
    if match_df is not None:
        meta = st.session_state.get("scte_command_match_meta", {})
        total = len(match_df)
        matched = int(match_df["Result"].astype(str).eq("MATCH").sum())
        failures = total - matched
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("File pairs processed", meta.get("pair_count", 0))
        c2.metric("SCTE-IN / OUT markers", total)
        c3.metric("Matched", matched)
        c4.metric("Need review", failures)
        st.caption(
            f'Asrun files: {len(meta.get("asrun_names", []))} • '
            f'Exports selected: {len(meta.get("export_names", []))} • '
            f'Tolerance: {meta.get("tolerance", 1.0):g} sec • {meta.get("created", "")}'
        )
        with st.expander("File pair mapping", expanded=True):
            st.dataframe(
                pd.DataFrame([{"Asrun File": a, "SCTE Export File": e}
                              for a, e in meta.get("pair_map", {}).items()]),
                use_container_width=True, hide_index=True
            )
        if failures:
            st.warning("Some SCTE events are missing, outside the allowed time window, or have a non-Done Asrun status.")
        else:
            st.success("All SCTE-IN/OUT markers matched their corresponding export events within the selected time window.")

        display_df = match_df.copy()
        for col in ("Asrun Time", "Matched Export Time"):
            if col in display_df.columns:
                display_df[col] = display_df[col].apply(
                    lambda x: x.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    if pd.notna(x) and hasattr(x, "strftime") else x
                )
        st.dataframe(display_df, use_container_width=True, hide_index=True)
        marker_csv_bytes = match_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "Download Batch SCTE Marker Match CSV",
            data=marker_csv_bytes,
            file_name="SCTE_Batch_Command_Match_Report.csv",
            mime="text/csv",
            key="download_scte_command_match_batch"
        )

        sequence_df = st.session_state.get("scte_command_sequence")
        sequence_csv_bytes = sequence_df.to_csv(index=False).encode("utf-8-sig") if sequence_df is not None else b""
        st.subheader("Email SCTE Command Match Report")
        with st.form("scte_command_email_form"):
            ce1, ce2 = st.columns(2)
            with ce1:
                cmd_smtp_host = st.text_input("SMTP server / relay", key="cmd_email_smtp_host", placeholder="smtp.company.com")
                cmd_smtp_port = st.number_input("SMTP port", min_value=1, max_value=65535, value=587, step=1, key="cmd_email_smtp_port")
                cmd_smtp_user = st.text_input("SMTP username (if required)", key="cmd_email_smtp_user")
                cmd_smtp_password = st.text_input("SMTP password / app password", type="password", key="cmd_email_smtp_password")
            with ce2:
                cmd_sender = st.text_input("From email", key="cmd_email_sender", placeholder="it-ops@company.com")
                cmd_recipients = st.text_input("To email(s), comma-separated", key="cmd_email_recipients", placeholder="helpdesk@company.com")
                cmd_subject = st.text_input("Email subject", value="SCTE Command Match Batch Report", key="cmd_email_subject")
            cmd_body = st.text_area("Email message", value="Please find attached the batch SCTE command match results.", key="cmd_email_body")
            send_cmd_email = st.form_submit_button("Send SCTE Command Match Report", type="primary")
        if send_cmd_email:
            try:
                send_report_email(
                    cmd_smtp_host, int(cmd_smtp_port), cmd_smtp_user, cmd_smtp_password,
                    cmd_sender, cmd_recipients, cmd_subject, cmd_body,
                    "SCTE_Batch_Command_Match_Report.csv", marker_csv_bytes
                )
                st.success("SCTE command match report email sent successfully.")
            except Exception as exc:
                st.error(f"SCTE command report email was not sent: {exc}. Verify SMTP settings and sender permissions with IT.")

        if sequence_df is not None:
            st.subheader("All 4 required commands per SCTE START/END event")
            seq_failures = int((sequence_df["Status"] != "OK").sum())
            s1, s2, s3 = st.columns(3)
            s1.metric("Required command checks", len(sequence_df))
            s2.metric("Passed", len(sequence_df) - seq_failures)
            s3.metric("Need review", seq_failures)
            st.caption(
                f'Command window: {meta.get("command_window", 2.0):g} sec. '
                "Each START/END event requires all 4 commands; each Asrun row can be used only once."
            )
            if seq_failures:
                st.warning("One or more required commands are missing, outside the time window, or not marked Done.")
            else:
                st.success("All required commands are present and marked Done within the selected window.")
            st.dataframe(sequence_df, use_container_width=True, hide_index=True)
            st.download_button(
                "Download Batch 4-Command Sequence CSV",
                data=sequence_df.to_csv(index=False).encode("utf-8-sig"),
                file_name="SCTE_Batch_4_Command_Sequence_Report.csv",
                mime="text/csv",
                key="download_scte_macro_sequence_batch"
            )

        with st.expander("All detected Asrun commands"):
            st.dataframe(st.session_state["scte_command_asrun"], use_container_width=True, hide_index=True)
        with st.expander("All detected SCTE export events"):
            st.dataframe(st.session_state["scte_command_export"], use_container_width=True, hide_index=True)

    for error in st.session_state.get("scte_command_errors", []):
        st.warning(error)


with tab8:
    st.subheader("System Monitor — crashes, utilization, hardware, drivers & antivirus")
    st.write("Read-only diagnostic snapshot for the computer running this portal. It does not install drivers, change settings, or disable security controls.")
    m1, m2 = st.columns(2)
    with m1:
        monitor_hours = st.selectbox("Look back for crash / hardware events", [6, 12, 24, 48, 168], index=2,
                                     format_func=lambda x: f"Last {x} hours" if x < 168 else "Last 7 days", key="monitor_hours")
    with m2:
        driver_age = st.selectbox("Flag drivers for age review", [1, 2, 3, 4, 5], index=1,
                                  format_func=lambda x: f"Older than {x} year(s)", key="monitor_driver_age")
    st.caption("Driver age is only a review hint, not proof of an outdated driver. Antivirus detection can be limited on Windows Server or centrally managed endpoints.")
    if st.button("Run System Monitor Check", type="primary", key="run_system_monitor"):
        with st.spinner("Collecting utilization and read-only Windows diagnostic information..."):
            st.session_state["system_monitor_result"] = collect_system_monitor(monitor_hours, driver_age)
    mon = st.session_state.get("system_monitor_result")
    if mon:
        st.caption("Checked: " + mon.get("checked_at", ""))
        util = mon.get("utilization", {})
        if util:
            a, b, c, d = st.columns(4)
            a.metric("CPU", f"{util.get('CPU percent', 'N/A')}%")
            b.metric("RAM used", f"{util.get('RAM used percent', 'N/A')}%")
            c.metric("RAM available", f"{util.get('RAM available GB', 'N/A')} GB")
            d.metric("Disks checked", len(mon.get("disks", [])))
            if util.get("CPU percent", 0) >= 90:
                st.warning("CPU utilization is high in this snapshot. Repeat during the slowdown and inspect the top processes.")
            if util.get("RAM used percent", 0) >= 90:
                st.warning("RAM utilization is high. Check the top processes and memory pressure during the incident.")
        if mon.get("disks"):
            st.markdown("**Disk utilization**")
            disk_df = pd.DataFrame(mon["disks"])
            st.dataframe(disk_df, use_container_width=True, hide_index=True)
            if (disk_df["Used percent"] >= 90).any():
                st.warning("One or more mounted drives are at least 90% used.")
        if mon.get("top_processes"):
            st.markdown("**Top processes (snapshot)**")
            st.dataframe(pd.DataFrame(mon["top_processes"]), use_container_width=True, hide_index=True)
        st.markdown("**Currently not-responding processes (snapshot)**")
        hung = mon.get("hung_processes", [])
        if hung:
            st.warning(f"Windows currently reports {len(hung)} process(es) as not responding. Check the application name/PID and correlate with logs.")
            st.dataframe(pd.DataFrame(hung), use_container_width=True, hide_index=True)
        else:
            st.success("No currently not-responding processes were returned by Windows at the time of this snapshot.")
        st.markdown("**Application crashes / not responding (Event Viewer history)**")
        app_events = mon.get("application_events", [])
        if app_events:
            st.warning(f"Found {len(app_events)} relevant Application log event(s). Review timestamps and messages around the reported issue.")
            st.dataframe(pd.DataFrame(app_events), use_container_width=True, hide_index=True)
        else:
            st.success("No matching Application Error / WER / Application Hang events were returned for this time range, or event collection was unavailable.")
        st.markdown("**Hardware / storage / unexpected restart events**")
        hw_events = mon.get("hardware_events", [])
        if hw_events:
            st.dataframe(pd.DataFrame(hw_events), use_container_width=True, hide_index=True)
            st.warning("These event records are diagnostic clues. Confirm with OEM hardware tools, RAID/iDRAC, and full event details before concluding hardware failure.")
        else:
            st.info("No matching hardware/storage events returned for the selected period, or event collection was unavailable.")
        st.markdown("**Drivers to review by age**")
        drivers = mon.get("drivers_to_review", [])
        if drivers:
            st.caption(f"{len(drivers)} driver record(s) are older than the selected age threshold. Verify current versions with the PC/server OEM or approved Windows Update source before updating.")
            st.dataframe(pd.DataFrame(drivers), use_container_width=True, hide_index=True)
        else:
            st.success("No driver records older than the selected age threshold were returned, or the inventory query was unavailable. This does not guarantee every driver is current.")
        st.markdown("**Antivirus / endpoint protection**")
        av = mon.get("antivirus", {})
        st.write("**Status:** " + str(av.get("Status", "Unknown")))
        st.caption(str(av.get("Details", "No details returned.")))
        if str(av.get("Status", "")).lower().startswith(("unknown", "review")):
            st.warning("Do not declare antivirus missing based only on this result. Confirm the endpoint agent and last check-in in your organization’s approved antivirus/EDR console.")
        if mon.get("warnings"):
            with st.expander("Collection warnings / limitations"):
                for warning in mon["warnings"]:
                    st.write("- " + warning)
        report = {
            "Checked at": mon.get("checked_at", ""),
            "Utilization": mon.get("utilization", {}),
            "Disks": mon.get("disks", []),
            "Top processes": mon.get("top_processes", []),
            "Current not-responding processes": mon.get("hung_processes", []),
            "Application events": mon.get("application_events", []),
            "Hardware events": mon.get("hardware_events", []),
            "Drivers to review": mon.get("drivers_to_review", []),
            "Antivirus": mon.get("antivirus", {}),
            "Warnings": mon.get("warnings", []),
        }
        st.download_button("Download System Monitor JSON report", data=json.dumps(report, indent=2, default=str).encode("utf-8"),
                           file_name="AWANISH_System_Monitor_Report.json", mime="application/json", key="download_system_monitor_json")
        csv_rows = []
        for section in ("hung_processes", "application_events", "hardware_events", "drivers_to_review", "disks", "top_processes"):
            for item in mon.get(section, []):
                csv_rows.append({"Section": section, **item})
        if csv_rows:
            st.download_button("Download System Monitor details CSV", data=pd.DataFrame(csv_rows).to_csv(index=False).encode("utf-8-sig"),
                               file_name="AWANISH_System_Monitor_Details.csv", mime="text/csv", key="download_system_monitor_csv")

with tab9:
    st.subheader("Multi-System Monitor & Email Report")
    st.write("Check this computer and other Windows computers through PowerShell Remoting. Reports can be emailed directly from this portal using your approved SMTP relay.")
    st.warning("Remote checks require IT-approved PowerShell Remoting/WinRM and permissions on each target. Driver updates can cause downtime; this portal opens the approved Windows update tools but does not silently install drivers.")
    st.subheader("WinRM connection troubleshooting")
    st.write("If a remote host reports ‘The client cannot connect to the destination specified in the request’, test the WinRM endpoint before retrying remote monitoring.")
    winrm_targets_text = st.text_input(
        "Computer names to test for WinRM",
        value="CP1-ANIM01.tv18.com",
        key="winrm_test_hosts",
        help="Enter one or more hostnames separated by commas."
    )
    if st.button("Test WinRM Connectivity", key="test_winrm_button"):
        targets = [x.strip() for x in re.split(r"[,;]+", winrm_targets_text) if x.strip()]
        try:
            winrm_results = diagnose_winrm_hosts(targets)
            st.session_state["winrm_diagnostic_results"] = winrm_results
        except Exception as exc:
            st.session_state["winrm_diagnostic_error"] = str(exc)
    if st.session_state.get("winrm_diagnostic_error"):
        st.error(st.session_state.pop("winrm_diagnostic_error"))
    if st.session_state.get("winrm_diagnostic_results"):
        wr_df = pd.DataFrame(st.session_state["winrm_diagnostic_results"])
        st.dataframe(wr_df, use_container_width=True, hide_index=True)
        st.caption("Port 5985 is commonly WinRM HTTP; 5986 is commonly HTTPS. A reachable port alone does not prove authentication/authorization works.")
    with st.expander("WinRM fix checklist for the destination computer"):
        st.markdown("""
        Run these commands **on the destination PC/server in an elevated PowerShell window**, only with your IT team's approval:

        ```powershell
        Get-Service WinRM
        winrm quickconfig
        Enable-PSRemoting -Force
        Test-WSMan localhost
        ```

        Then test from the portal computer:

        ```powershell
        Test-WSMan CP1-ANIM01.tv18.com
        Test-NetConnection CP1-ANIM01.tv18.com -Port 5985
        ```

        If the service is running but remote access still fails, ask IT to verify Windows Firewall rules, DNS, domain/trust, authentication, listener configuration, and the account's remote-management permissions. Do not enable Basic authentication or TrustedHosts broadly as a workaround.
        """)
    st.divider()
    st.subheader("Driver update options")
    st.write("For the computer running this portal, open Windows Update or Device Manager. Review the model, current driver version, OEM recommendation and maintenance window before installing.")
    du1, du2 = st.columns(2)
    with du1:
        if st.button("Open Windows Update", key="open_windows_update"):
            try:
                open_local_driver_tools("windows_update")
                st.success("Opened Windows Update on the computer running this portal.")
            except Exception as exc:
                st.error(str(exc))
    with du2:
        if st.button("Open Device Manager", key="open_device_manager"):
            try:
                open_local_driver_tools("device_manager")
                st.success("Opened Device Manager on the computer running this portal.")
            except Exception as exc:
                st.error(str(exc))
    st.info("Remote driver inventory is included in the system check below. Remote driver installation is not started until WinRM works and the correct OEM-approved package/maintenance window is confirmed.")
    include_local = st.checkbox("Also check the computer running this portal", value=True, key="multi_include_local")
    remote_text = st.text_area("Other computer names (one per line or comma-separated)", placeholder="PCR-ANIM-01\nPCR-ANIM-02\nserver01.domain.local", key="multi_remote_hosts")
    r1, r2 = st.columns(2)
    with r1:
        remote_hours = st.selectbox("Remote event lookback", [6, 12, 24, 48, 168], index=2, format_func=lambda x: f"Last {x} hours" if x < 168 else "Last 7 days", key="multi_remote_hours")
    with r2:
        remote_driver_age = st.selectbox("Flag driver dates older than", [1, 2, 3, 4, 5], index=1, format_func=lambda x: f"{x} year(s)", key="multi_driver_age")
    if st.button("Check Selected Systems", type="primary", key="multi_run_systems"):
        combined = {"checked_at": now_str(), "local_systems": [], "remote_systems": [], "warnings": []}
        if include_local:
            try:
                local = collect_system_monitor(remote_hours, remote_driver_age)
                local["ComputerName"] = platform.node() or "LOCAL"
                local["Reachable"] = True
                combined["local_systems"].append(local)
            except Exception as exc:
                combined["warnings"].append(f"Local check failed: {exc}")
        host_list = [h.strip() for h in re.split(r"[,\r\n]+", remote_text) if h.strip()]
        if host_list:
            try:
                combined["remote_systems"] = collect_remote_systems(host_list, remote_hours, remote_driver_age)
            except Exception as exc:
                combined["warnings"].append(f"Remote checks failed: {exc}")
        if not include_local and not host_list:
            st.error("Select the local computer or enter at least one remote computer name.")
        else:
            st.session_state["multi_system_report"] = combined
            st.success("System checks finished. Review each host status below.")
    multi = st.session_state.get("multi_system_report")
    if multi:
        st.caption("Checked: " + multi.get("checked_at", ""))
        local_rows = multi.get("local_systems", [])
        remote_rows = multi.get("remote_systems", [])
        all_rows = []
        for item in local_rows:
            u = item.get("utilization", {})
            all_rows.append({"Computer": item.get("ComputerName", "Local"), "Reachable": True,
                             "CPU %": u.get("CPU percent", "N/A"), "RAM used %": u.get("RAM used percent", "N/A"),
                             "Disk count": len(item.get("disks", [])), "Hung processes": len(item.get("hung_processes", [])),
                             "App crash/hang events": len(item.get("application_events", [])),
                             "Hardware events": len(item.get("hardware_events", [])),
                             "Drivers to review": len(item.get("drivers_to_review", [])),
                             "Antivirus": item.get("antivirus", {}).get("Status", "Unknown"), "Error": ""})
        for item in remote_rows:
            all_rows.append({"Computer": item.get("ComputerName", "Unknown"), "Reachable": item.get("Reachable", False),
                             "CPU %": item.get("CPUPercent", "N/A"), "RAM used %": item.get("RAMUsedPercent", "N/A"),
                             "Disk count": len(item.get("Disks") or []), "Hung processes": len(item.get("HungProcesses") or []),
                             "App crash/hang events": len(item.get("ApplicationEvents") or []),
                             "Hardware events": len(item.get("HardwareEvents") or []),
                             "Drivers to review": len(item.get("DriversToReview") or []),
                             "Antivirus": (", ".join(item.get("AntivirusNames") or []) + " / " + str(item.get("DefenderStatus", "Unknown"))).strip(" /"),
                             "Error": item.get("Error", "")})
        if all_rows:
            st.subheader("System summary")
            st.dataframe(pd.DataFrame(all_rows), use_container_width=True, hide_index=True)
        for warning in multi.get("warnings", []):
            st.warning(warning)
        with st.expander("Detailed results by computer", expanded=True):
            for item in local_rows:
                st.markdown(f"**Local: {item.get('ComputerName', 'This computer')}**")
                if item.get("hung_processes"):
                    st.write("Not responding processes")
                    st.dataframe(pd.DataFrame(item["hung_processes"]), use_container_width=True, hide_index=True)
                if item.get("application_events"):
                    st.write("Application crash/hang events")
                    st.dataframe(pd.DataFrame(item["application_events"]), use_container_width=True, hide_index=True)
                if item.get("hardware_events"):
                    st.write("Hardware/storage events")
                    st.dataframe(pd.DataFrame(item["hardware_events"]), use_container_width=True, hide_index=True)
                if item.get("drivers_to_review"):
                    st.write("Drivers to review")
                    st.dataframe(pd.DataFrame(item["drivers_to_review"]), use_container_width=True, hide_index=True)
                st.write("Antivirus:", item.get("antivirus", {}))
            for item in remote_rows:
                st.markdown(f"**Remote: {item.get('ComputerName', 'Unknown')}**")
                if not item.get("Reachable"):
                    st.error(item.get("Error", "Remote system unavailable or permission denied."))
                    continue
                for label, key in (("Not responding processes", "HungProcesses"), ("Application crash/hang events", "ApplicationEvents"),
                                   ("Hardware/storage events", "HardwareEvents"), ("Drivers to review", "DriversToReview"),
                                   ("Top processes", "TopProcesses"), ("Disk usage", "Disks")):
                    data = item.get(key) or []
                    if data:
                        st.write(label)
                        st.dataframe(pd.DataFrame(data), use_container_width=True, hide_index=True)
                st.write("Antivirus registered:", item.get("AntivirusNames", []), "| Defender:", item.get("DefenderStatus", "Unknown"))
        report_bytes = json.dumps(multi, indent=2, default=str).encode("utf-8")
        st.download_button("Download Multi-System JSON Report", data=report_bytes, file_name="AWANISH_Multi_System_Report.json",
                           mime="application/json", key="download_multi_system_json")
        if all_rows:
            st.download_button("Download System Summary CSV", data=pd.DataFrame(all_rows).to_csv(index=False).encode("utf-8-sig"),
                               file_name="AWANISH_Multi_System_Summary.csv", mime="text/csv", key="download_multi_system_csv")
        st.divider()
        st.subheader("Send report by email")
        st.caption("Use your organization's approved SMTP relay or mail gateway. SMTP settings/password are used only for this send attempt and are not written to a file by this app.")
        with st.form("multi_system_email_form"):
            e1, e2 = st.columns(2)
            with e1:
                smtp_host = st.text_input("SMTP server / relay", placeholder="smtp.company.com")
                smtp_port = st.number_input("SMTP port", min_value=1, max_value=65535, value=587, step=1)
                smtp_user = st.text_input("SMTP username (if required)")
                smtp_password = st.text_input("SMTP password / app password", type="password")
            with e2:
                sender = st.text_input("From email", placeholder="it-ops@company.com")
                recipients = st.text_input("To email(s), comma-separated", placeholder="helpdesk@company.com, itlead@company.com")
                email_subject = st.text_input("Email subject", value="AWANISH IT/OPS Multi-System Monitor Report")
            email_body = st.text_area("Email message", value="Please find attached the AWANISH IT/OPS system monitoring report. Review unreachable systems and any reported crash, hardware, driver or antivirus findings.")
            send_clicked = st.form_submit_button("Send Monitoring Report", type="primary")
        if send_clicked:
            try:
                send_report_email(smtp_host, int(smtp_port), smtp_user, smtp_password, sender, recipients,
                                  email_subject, email_body, "AWANISH_Multi_System_Report.json", report_bytes)
                st.success("Email sent successfully through the configured SMTP server.")
            except Exception as exc:
                st.error(f"Email was not sent: {exc}. Verify the SMTP relay, port/TLS, sender permissions and credentials with IT.")



with tab10:
    st.subheader("PowerShell & Remote Access")
    st.write("Run common read-only network and Windows diagnostics from the portal. Remote actions use the Windows account running Streamlit and require approved access on the target computer.")
    st.warning("This is a controlled diagnostic console, not an unrestricted PowerShell terminal. Only the listed read-only commands are available. Remote Invoke-Command requires WinRM, firewall access, and authorization.")
    p1, p2 = st.columns([2, 1])
    with p1:
        ps_host = st.text_input("Target computer (hostname or IP)", value="CP1-ANIM01.tv18.com", key="portal_ps_target")
    with p2:
        ps_port = st.number_input("TCP port (for port test)", min_value=1, max_value=65535, value=5985, step=1, key="portal_ps_port")
    ps_action = st.selectbox(
        "PowerShell action",
        [
            "Ping (4 packets)", "Test TCP port", "Test WinRM", "Remote hostname",
            "Remote OS and last boot", "Remote top processes", "Remote services (running)",
            "Remote disk space", "Remote application errors (last 24h)"
        ],
        key="portal_ps_action"
    )
    if st.button("Run PowerShell Diagnostic", type="primary", key="portal_ps_run"):
        with st.spinner(f"Running {ps_action} against {ps_host}..."):
            try:
                output = run_powershell_admin_tool(ps_host, ps_action, int(ps_port))
                st.session_state["portal_ps_last_result"] = {
                    "host": ps_host, "action": ps_action, "time": now_str(), "output": output
                }
            except Exception as exc:
                st.session_state["portal_ps_last_result"] = {
                    "host": ps_host, "action": ps_action, "time": now_str(), "output": f"ERROR: {exc}"
                }
    ps_result = st.session_state.get("portal_ps_last_result")
    if ps_result:
        st.caption(f'{ps_result["time"]} • {ps_result["host"]} • {ps_result["action"]}')
        st.code(ps_result["output"], language="powershell")
        st.download_button(
            "Download PowerShell diagnostic output",
            data=ps_result["output"].encode("utf-8", errors="replace"),
            file_name=f'PowerShell_{re.sub(r"[^A-Za-z0-9._-]", "_", ps_result["host"])}_diagnostic.txt',
            mime="text/plain",
            key="portal_ps_download"
        )
    with st.expander("What to do if remote access fails"):
        st.markdown("""
        1. Test `Ping (4 packets)` and `Test TCP port` first.
        2. Run `Test WinRM`. A port may be open even if WinRM authentication fails.
        3. For remote OS/process/service/disk/event checks, ask the target-system administrator to confirm WinRM/PowerShell Remoting is configured and your account is authorized.
        4. On the target, an authorized administrator can review `Get-Service WinRM`, `winrm quickconfig`, and firewall policy. Follow company change control; do not weaken authentication settings or enable broad TrustedHosts as a shortcut.
        """)
