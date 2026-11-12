from __future__ import annotations

import csv
from pathlib import Path

import pandas as pd

from triage.config import LABELS, REQUIRED_RAW_COLUMNS

RAW_LABEL = {
    "true_positive": "TruePositive",
    "benign_positive": "BenignPositive",
    "false_positive": "FalsePositive",
}

CATEGORIES = ("InitialAccess", "Execution", "Exfiltration", "Discovery")
ENTITY_TYPES = ("Account", "Device", "Ip", "Url")
EVIDENCE_ROLES = ("Actor", "Target", "Related")


def _label_for(index: int) -> str:
    bucket = index % 10
    if bucket < 4:
        return "true_positive"
    if bucket < 7:
        return "benign_positive"
    return "false_positive"


def _int_code(base: int, index: int, width: int = 6) -> str:
    return str((base + index) % (10**width))


def _incident_rows(
    index: int,
    incident_id: int,
    org_id: int,
    label: str,
    start: pd.Timestamp,
) -> list[dict[str, str]]:
    row_count = 2 + (index % 4)
    alert_count = 1 + (index % 2)
    rows: list[dict[str, str]] = []
    for row_index in range(row_count):
        evidence_id = incident_id * 100 + row_index
        alert_id = incident_id * 10 + (row_index % alert_count)
        timestamp = start + pd.Timedelta(minutes=row_index * 3)
        true_positive = label == "true_positive"
        benign = label == "benign_positive"
        row = {
            "Id": str(evidence_id),
            "OrgId": str(org_id),
            "IncidentId": str(incident_id),
            "AlertId": str(alert_id),
            "Timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "DetectorId": str(1 + (index % 20)),
            "AlertTitle": str(1 + (index % 12)),
            "Category": CATEGORIES[index % len(CATEGORIES)],
            "MitreTechniques": "T1078" if true_positive else "",
            "IncidentGrade": RAW_LABEL[label],
            "ActionGrouped": "",
            "ActionGranular": "",
            "EntityType": ENTITY_TYPES[(index + row_index) % len(ENTITY_TYPES)],
            "EvidenceRole": EVIDENCE_ROLES[(index + row_index) % len(EVIDENCE_ROLES)],
            "Sha256": _int_code(500_000, evidence_id),
            "IpAddress": _int_code(600_000, evidence_id),
            "Url": _int_code(700_000, evidence_id),
            "AccountSid": _int_code(800_000, evidence_id),
            "AccountUpn": _int_code(810_000, evidence_id),
            "AccountObjectId": _int_code(820_000, evidence_id),
            "AccountName": _int_code(830_000, evidence_id),
            "DeviceName": _int_code(840_000, evidence_id),
            "NetworkMessageId": _int_code(850_000, evidence_id),
            "EmailClusterId": _int_code(860_000, evidence_id),
            "RegistryKey": _int_code(870_000, evidence_id),
            "RegistryValueName": _int_code(880_000, evidence_id),
            "RegistryValueData": _int_code(890_000, evidence_id),
            "ApplicationId": _int_code(900_000, evidence_id),
            "ApplicationName": _int_code(910_000, evidence_id),
            "OAuthApplicationId": _int_code(920_000, evidence_id),
            "ThreatFamily": "Malware" if true_positive else "",
            "FileName": _int_code(930_000, evidence_id),
            "FolderPath": _int_code(940_000, evidence_id),
            "ResourceIdName": _int_code(950_000, evidence_id),
            "ResourceType": "Device",
            "Roles": "Victim",
            "OSFamily": "Windows",
            "OSVersion": "10.0",
            "AntispamDirection": "",
            "SuspicionLevel": "Suspicious" if (true_positive or benign) else "",
            "LastVerdict": "Malicious" if true_positive else ("Suspicious" if benign else ""),
            "CountryCode": str(1 + (index % 5)),
            "State": str(1 + (index % 7)),
            "City": str(1 + (index % 11)),
            "DeviceId": _int_code(960_000, evidence_id),
        }
        rows.append(row)
    return rows


def _write_split(
    path: Path,
    count: int,
    incident_id_start: int,
    start: pd.Timestamp,
    include_usage: bool,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for index in range(count):
        incident_id = incident_id_start + index
        org_id = 1 + (index % 7)
        label = _label_for(index)
        incident_rows = _incident_rows(
            index, incident_id, org_id, label, start + pd.Timedelta(hours=index)
        )
        if include_usage:
            for row in incident_rows:
                row["Usage"] = "Evaluation"
        rows.extend(incident_rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = list(REQUIRED_RAW_COLUMNS) + (["Usage"] if include_usage else [])
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    return rows


def write_fixture(
    raw_dir: Path,
    train_incidents: int = 80,
    test_incidents: int = 40,
) -> dict[str, str]:
    raw_dir = Path(raw_dir)
    train_path = raw_dir / "GUIDE_Train.csv"
    test_path = raw_dir / "GUIDE_Test.csv"
    _write_split(
        train_path,
        count=train_incidents,
        incident_id_start=10_000,
        start=pd.Timestamp("2024-01-01 00:00:00"),
        include_usage=False,
    )
    _write_split(
        test_path,
        count=test_incidents,
        incident_id_start=20_000,
        start=pd.Timestamp("2024-03-01 00:00:00"),
        include_usage=True,
    )
    return {
        "train_path": str(train_path),
        "test_path": str(test_path),
        "train_incidents": str(train_incidents),
        "test_incidents": str(test_incidents),
        "labels": ",".join(LABELS),
    }
