from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
MANIFEST_DIR = DATA_DIR / "manifests"
REPORTS_DIR = ROOT / "reports"

SEED = 42
SAMPLE_SIZE = 100_000

LABELS = ("true_positive", "benign_positive", "false_positive")

LABEL_MAP = {
    "truepositive": "true_positive",
    "true_positive": "true_positive",
    "tp": "true_positive",
    "benignpositive": "benign_positive",
    "benign_positive": "benign_positive",
    "bp": "benign_positive",
    "falsepositive": "false_positive",
    "false_positive": "false_positive",
    "fp": "false_positive",
}

# GUIDE_Train.csv and GUIDE_Test.csv are denormalized at the alert/evidence
# row grain. These are the columns the ETL expects in both files.
REQUIRED_RAW_COLUMNS = (
    "Id",
    "OrgId",
    "IncidentId",
    "AlertId",
    "Timestamp",
    "DetectorId",
    "AlertTitle",
    "Category",
    "MitreTechniques",
    "IncidentGrade",
    "ActionGrouped",
    "ActionGranular",
    "EntityType",
    "EvidenceRole",
    "Sha256",
    "IpAddress",
    "Url",
    "AccountSid",
    "AccountUpn",
    "AccountObjectId",
    "AccountName",
    "DeviceName",
    "NetworkMessageId",
    "EmailClusterId",
    "RegistryKey",
    "RegistryValueName",
    "RegistryValueData",
    "ApplicationId",
    "ApplicationName",
    "OAuthApplicationId",
    "ThreatFamily",
    "FileName",
    "FolderPath",
    "ResourceIdName",
    "ResourceType",
    "Roles",
    "OSFamily",
    "OSVersion",
    "AntispamDirection",
    "SuspicionLevel",
    "LastVerdict",
    "CountryCode",
    "State",
    "City",
    "DeviceId",
)

NUMERIC_FEATURES = (
    "alert_count",
    "evidence_count",
    "detector_count",
    "entity_type_count",
    "alert_title_count",
    "category_count",
    "evidence_role_count",
    "has_mitre",
    "suspicious_count",
    "verdict_count",
    "malicious_count",
    "sha256_count",
    "ip_count",
    "url_count",
    "account_count",
    "device_count",
    "registry_count",
    "file_count",
    "email_count",
    "event_hour",
    "event_day_of_week",
)
