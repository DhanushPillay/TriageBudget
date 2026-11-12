from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb

from triage.config import (
    LABEL_MAP,
    LABELS,
    REQUIRED_RAW_COLUMNS,
    ROOT,
    SEED,
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_ids(ids: list[str]) -> str:
    digest = hashlib.sha256()
    for incident_id in sorted(ids):
        digest.update(incident_id.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _sql_path(path: Path) -> str:
    return path.resolve().as_posix().replace("'", "''")


def _relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def find_raw_files(raw_dir: Path) -> tuple[list[Path], list[Path]]:
    raw_dir = Path(raw_dir)
    files = sorted(
        path
        for path in raw_dir.rglob("*.csv")
        if path.is_file() and "queue" not in path.name.lower() and "rank" not in path.name.lower()
    )
    if not files:
        raise FileNotFoundError(f"No incident CSV files found under {raw_dir}")

    def named(name: str) -> list[Path]:
        return [path for path in files if path.name.lower() == name]

    train = named("guide_train.csv") or [path for path in files if "train" in path.name.lower()]
    test = named("guide_test.csv") or [path for path in files if "test" in path.name.lower()]
    if not train:
        if len(files) == 1:
            train = files
        else:
            raise FileNotFoundError(
                f"Could not identify a train CSV under {raw_dir}. "
                "Expected GUIDE_Train.csv or a single CSV."
            )
    return train, test


def _label_sql(column: str = "IncidentGrade") -> str:
    return f"""
        CASE lower(replace(trim({column}), ' ', '_'))
            WHEN 'truepositive' THEN 'true_positive'
            WHEN 'true_positive' THEN 'true_positive'
            WHEN 'tp' THEN 'true_positive'
            WHEN 'benignpositive' THEN 'benign_positive'
            WHEN 'benign_positive' THEN 'benign_positive'
            WHEN 'bp' THEN 'benign_positive'
            WHEN 'falsepositive' THEN 'false_positive'
            WHEN 'false_positive' THEN 'false_positive'
            WHEN 'fp' THEN 'false_positive'
            ELSE NULL
        END
    """


def normalize_label(value: str | None) -> str | None:
    if value is None:
        return None
    return LABEL_MAP.get(str(value).strip().lower().replace(" ", "_"))


def run_etl(
    raw_dir: Path,
    out_path: Path,
    stats_path: Path | None = None,
) -> dict[str, Any]:
    """Aggregate GUIDE alert/evidence rows to one row per incident."""
    raw_dir = Path(raw_dir)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    train_files, test_files = find_raw_files(raw_dir)
    all_files = train_files + test_files

    con = duckdb.connect()
    try:
        temp_dir = out_path.parent / ".duckdb_tmp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        con.execute("SET preserve_insertion_order = false")
        con.execute("SET memory_limit = '10GB'")
        con.execute("SET threads = 4")
        con.execute(f"SET temp_directory = '{_sql_path(temp_dir)}'")

        file_list = ", ".join(f"'{_sql_path(path)}'" for path in all_files)
        con.execute(
            f"""
            CREATE VIEW raw AS
            SELECT *
            FROM read_csv(
                [{file_list}],
                all_varchar = true,
                header = true,
                union_by_name = true,
                filename = 'source_file'
            )
            """
        )

        columns = {row[0] for row in con.execute("DESCRIBE SELECT * FROM raw").fetchall()}
        missing = sorted(set(REQUIRED_RAW_COLUMNS) - columns)
        if missing:
            raise ValueError(f"Raw GUIDE files are missing required columns: {missing}")

        con.execute(
            f"""
            CREATE TABLE incidents AS
            WITH base AS (
                SELECT
                    CASE
                        WHEN lower(source_file) LIKE '%guide_train.csv' THEN 'train'
                        WHEN lower(source_file) LIKE '%guide_test.csv' THEN 'test'
                        WHEN lower(source_file) LIKE '%train%' THEN 'train'
                        WHEN lower(source_file) LIKE '%test%' THEN 'test'
                        ELSE 'train'
                    END AS source_split,
                    COALESCE(NULLIF(trim(OrgId), ''), 'unknown') AS org_id,
                    NULLIF(trim(IncidentId), '') AS incident_id_raw,
                    NULLIF(trim(AlertId), '') AS alert_id,
                    NULLIF(trim(Id), '') AS evidence_id,
                    try_cast(NULLIF(trim(Timestamp), '') AS TIMESTAMP) AS created_at,
                    {_label_sql()} AS triage_label,
                    NULLIF(trim(IncidentGrade), '') AS triage_label_raw,
                    NULLIF(trim(AlertTitle), '') AS alert_title,
                    NULLIF(trim(Category), '') AS category,
                    NULLIF(trim(MitreTechniques), '') AS mitre_techniques,
                    NULLIF(trim(EntityType), '') AS entity_type,
                    NULLIF(trim(EvidenceRole), '') AS evidence_role,
                    NULLIF(trim(SuspicionLevel), '') AS suspicion_level,
                    NULLIF(trim(LastVerdict), '') AS last_verdict,
                    NULLIF(trim(ResourceType), '') AS resource_type,
                    NULLIF(trim(Roles), '') AS role_code,
                    NULLIF(trim(AntispamDirection), '') AS antispam_direction,
                    NULLIF(trim(ThreatFamily), '') AS threat_family,
                    NULLIF(trim(DetectorId), '') AS detector_id,
                    NULLIF(trim(Sha256), '') AS sha256,
                    NULLIF(trim(IpAddress), '') AS ip_address,
                    NULLIF(trim(Url), '') AS url,
                    NULLIF(trim(AccountSid), '') AS account_sid,
                    NULLIF(trim(AccountUpn), '') AS account_upn,
                    NULLIF(trim(AccountObjectId), '') AS account_object_id,
                    NULLIF(trim(AccountName), '') AS account_name,
                    NULLIF(trim(DeviceName), '') AS device_name,
                    NULLIF(trim(NetworkMessageId), '') AS network_message_id,
                    NULLIF(trim(EmailClusterId), '') AS email_cluster_id,
                    NULLIF(trim(RegistryKey), '') AS registry_key,
                    NULLIF(trim(RegistryValueName), '') AS registry_value_name,
                    NULLIF(trim(RegistryValueData), '') AS registry_value_data,
                    NULLIF(trim(ApplicationId), '') AS application_id,
                    NULLIF(trim(ApplicationName), '') AS application_name,
                    NULLIF(trim(OAuthApplicationId), '') AS oauth_application_id,
                    NULLIF(trim(FileName), '') AS file_name,
                    NULLIF(trim(FolderPath), '') AS folder_path,
                    NULLIF(trim(ResourceIdName), '') AS resource_id_name,
                    NULLIF(trim(OSFamily), '') AS os_family,
                    NULLIF(trim(OSVersion), '') AS os_version,
                    NULLIF(trim(CountryCode), '') AS country_code,
                    NULLIF(trim(State), '') AS state_code,
                    NULLIF(trim(City), '') AS city
                FROM raw
                WHERE NULLIF(trim(IncidentId), '') IS NOT NULL
            ),
            aggregated AS (
                SELECT
                    org_id || ':' || incident_id_raw AS incident_id,
                    org_id,
                    incident_id_raw,
                    min(created_at) AS created_at,
                    max(source_split) AS source_split,
                    count(DISTINCT source_split) AS split_variants,
                    max(triage_label) AS triage_label,
                    max(triage_label_raw) AS triage_label_raw,
                    count(DISTINCT triage_label) FILTER (WHERE triage_label IS NOT NULL)
                        AS label_variants,
                    max(alert_title) AS title,
                    max(alert_title) AS alert_title,
                    count(DISTINCT alert_id) AS alert_count,
                    count(*) AS evidence_count,
                    count(DISTINCT detector_id) AS detector_count,
                    count(DISTINCT entity_type) AS entity_type_count,
                    count(DISTINCT alert_title) AS alert_title_count,
                    count(DISTINCT category) AS category_count,
                    count(DISTINCT evidence_role) AS evidence_role_count,
                    max(CASE WHEN mitre_techniques IS NOT NULL THEN 1 ELSE 0 END) AS has_mitre,
                    count(*) FILTER (WHERE lower(suspicion_level) = 'suspicious')
                        AS suspicious_count,
                    count(*) FILTER (
                        WHERE lower(last_verdict) IN ('malicious', 'suspicious')
                    ) AS verdict_count,
                    count(*) FILTER (WHERE lower(last_verdict) = 'malicious')
                        AS malicious_count,
                    count(DISTINCT sha256) FILTER (WHERE sha256 IS NOT NULL) AS sha256_count,
                    count(DISTINCT ip_address) FILTER (WHERE ip_address IS NOT NULL)
                        AS ip_count,
                    count(DISTINCT url) FILTER (WHERE url IS NOT NULL) AS url_count,
                    count(DISTINCT account_sid) FILTER (WHERE account_sid IS NOT NULL)
                        AS account_count,
                    count(DISTINCT device_name) FILTER (WHERE device_name IS NOT NULL)
                        AS device_count,
                    count(DISTINCT registry_key) FILTER (WHERE registry_key IS NOT NULL)
                        AS registry_count,
                    count(DISTINCT file_name) FILTER (WHERE file_name IS NOT NULL)
                        AS file_count,
                    count(DISTINCT email_cluster_id) FILTER (
                        WHERE email_cluster_id IS NOT NULL
                    ) AS email_count,
                    array_to_string(
                        list_sort(list(DISTINCT category) FILTER (WHERE category IS NOT NULL)),
                        ' '
                    ) AS categories,
                    array_to_string(
                        list_sort(
                            list(DISTINCT mitre_techniques)
                            FILTER (WHERE mitre_techniques IS NOT NULL)
                        ),
                        ' '
                    ) AS mitre_techniques,
                    array_to_string(
                        list_sort(
                            list(DISTINCT entity_type) FILTER (WHERE entity_type IS NOT NULL)
                        ),
                        ' '
                    ) AS entity_types,
                    array_to_string(
                        list_sort(
                            list(DISTINCT evidence_role) FILTER (WHERE evidence_role IS NOT NULL)
                        ),
                        ' '
                    ) AS evidence_roles,
                    array_to_string(
                        list_sort(
                            list(DISTINCT suspicion_level)
                            FILTER (WHERE suspicion_level IS NOT NULL)
                        ),
                        ' '
                    ) AS suspicion_levels,
                    array_to_string(
                        list_sort(
                            list(DISTINCT last_verdict) FILTER (WHERE last_verdict IS NOT NULL)
                        ),
                        ' '
                    ) AS last_verdicts,
                    array_to_string(
                        list_sort(
                            list(DISTINCT resource_type) FILTER (WHERE resource_type IS NOT NULL)
                        ),
                        ' '
                    ) AS resource_types,
                    array_to_string(
                        list_sort(list(DISTINCT role_code) FILTER (WHERE role_code IS NOT NULL)),
                        ' '
                    ) AS roles,
                    array_to_string(
                        list_sort(
                            list(DISTINCT antispam_direction)
                            FILTER (WHERE antispam_direction IS NOT NULL)
                        ),
                        ' '
                    ) AS antispam_directions,
                    array_to_string(
                        list_sort(
                            list(DISTINCT threat_family) FILTER (WHERE threat_family IS NOT NULL)
                        ),
                        ' '
                    ) AS threat_families,
                    array_to_string(
                        list_sort(
                            list(DISTINCT alert_title) FILTER (WHERE alert_title IS NOT NULL)
                        ),
                        ' '
                    ) AS alert_titles,
                    list_sort(
                        list(DISTINCT alert_id) FILTER (WHERE alert_id IS NOT NULL)
                    ) AS alert_ids,
                    list_sort(
                        list(DISTINCT evidence_id) FILTER (WHERE evidence_id IS NOT NULL)
                    ) AS evidence_ids
                FROM base
                GROUP BY org_id, incident_id_raw
            )
            SELECT
                incident_id,
                org_id,
                incident_id_raw,
                created_at,
                source_split AS split,
                triage_label,
                triage_label_raw,
                CASE WHEN label_variants > 1 THEN TRUE ELSE FALSE END AS label_conflict,
                CASE WHEN split_variants > 1 THEN TRUE ELSE FALSE END AS split_conflict,
                title,
                alert_title,
                alert_count,
                evidence_count,
                detector_count,
                entity_type_count,
                alert_title_count,
                category_count,
                evidence_role_count,
                has_mitre,
                suspicious_count,
                verdict_count,
                malicious_count,
                sha256_count,
                ip_count,
                url_count,
                account_count,
                device_count,
                registry_count,
                file_count,
                email_count,
                extract(hour FROM created_at) AS event_hour,
                extract(dow FROM created_at) AS event_day_of_week,
                categories,
                mitre_techniques,
                entity_types,
                evidence_roles,
                suspicion_levels,
                last_verdicts,
                resource_types,
                roles,
                antispam_directions,
                threat_families,
                alert_titles,
                concat_ws(
                    ' ',
                    categories,
                    mitre_techniques,
                    entity_types,
                    evidence_roles,
                    suspicion_levels,
                    last_verdicts,
                    resource_types,
                    roles,
                    antispam_directions,
                    threat_families,
                    alert_titles
                ) AS summary,
                alert_ids,
                evidence_ids
            FROM aggregated
            """
        )

        con.execute(
            f"""
            COPY (SELECT * FROM incidents ORDER BY incident_id)
            TO '{_sql_path(out_path)}'
            (FORMAT PARQUET, COMPRESSION ZSTD)
            """
        )

        file_rows = {
            str(row[0]): int(row[1])
            for row in con.execute(
                "SELECT source_file, count(*) FROM raw GROUP BY source_file ORDER BY source_file"
            ).fetchall()
        }
        split_counts = {
            str(row[0]): int(row[1])
            for row in con.execute(
                "SELECT split, count(*) FROM incidents GROUP BY split ORDER BY split"
            ).fetchall()
        }
        label_counts = {
            f"{row[0]}|{row[1] or 'missing'}": int(row[2])
            for row in con.execute(
                """
                SELECT split, triage_label, count(*)
                FROM incidents
                GROUP BY split, triage_label
                ORDER BY split, triage_label
                """
            ).fetchall()
        }
        conflicts = int(
            con.execute("SELECT count(*) FROM incidents WHERE label_conflict").fetchone()[0]
        )
        split_conflicts = int(
            con.execute("SELECT count(*) FROM incidents WHERE split_conflict").fetchone()[0]
        )
        null_timestamps = int(
            con.execute("SELECT count(*) FROM incidents WHERE created_at IS NULL").fetchone()[0]
        )

        stats = {
            "generated_at": datetime.now(UTC).isoformat(),
            "raw_files": [
                {
                    "path": _relative(path),
                    "sha256": sha256_file(path),
                    "rows": file_rows.get(path.resolve().as_posix(), 0),
                }
                for path in all_files
            ],
            "incidents_parquet": {
                "path": _relative(out_path),
                "sha256": sha256_file(out_path),
                "rows": int(
                    con.execute("SELECT count(*) FROM incidents").fetchone()[0]
                ),
            },
            "split_counts": split_counts,
            "label_counts": label_counts,
            "label_conflicts": conflicts,
            "split_conflicts": split_conflicts,
            "null_timestamps": null_timestamps,
        }
    finally:
        con.close()

    if stats_path is not None:
        stats_path = Path(stats_path)
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        stats_path.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    return stats


def _count_by_label(con: duckdb.DuckDBPyConnection, table: str) -> dict[str, int]:
    rows = con.execute(
        f"""
        SELECT triage_label, count(*)
        FROM {table}
        WHERE triage_label IS NOT NULL
        GROUP BY triage_label
        ORDER BY triage_label
        """
    ).fetchall()
    counts = {label: 0 for label in LABELS}
    for label, count in rows:
        counts[str(label)] = int(count)
    return counts


def _table_ids(con: duckdb.DuckDBPyConnection, table: str) -> list[str]:
    return [
        str(row[0])
        for row in con.execute(f"SELECT incident_id FROM {table} ORDER BY incident_id").fetchall()
    ]


def _write_table(con: duckdb.DuckDBPyConnection, table: str, path: Path) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    con.execute(
        f"""
        COPY (SELECT * FROM {table} ORDER BY incident_id)
        TO '{_sql_path(path)}'
        (FORMAT PARQUET, COMPRESSION ZSTD)
        """
    )
    ids = _table_ids(con, table)
    return {
        "path": _relative(path),
        "rows": len(ids),
        "label_counts": _count_by_label(con, table),
        "ids_sha256": sha256_ids(ids),
        "file_sha256": sha256_file(path),
    }


def build_manifest(
    incidents_path: Path,
    out_dir: Path,
    manifest_path: Path,
    sample_size: int = 100_000,
    seed: int = SEED,
    force: bool = False,
) -> dict[str, Any]:
    incidents_path = Path(incidents_path)
    out_dir = Path(out_dir)
    manifest_path = Path(manifest_path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    if manifest_path.exists() and not force:
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        validation = validate_manifest(manifest_path)
        if validation["passed"]:
            return existing
        raise FileExistsError(
            f"Manifest exists at {manifest_path} but does not validate. "
            "Use --force only when intentionally rebuilding the frozen split."
        )

    con = duckdb.connect()
    try:
        con.execute(
            f"CREATE VIEW inc AS SELECT * FROM read_parquet('{_sql_path(incidents_path)}')"
        )
        test_total, test_labeled = con.execute(
            "SELECT count(*), count(triage_label) FROM inc WHERE split = 'test'"
        ).fetchone()
        test_labeled = int(test_labeled or 0)
        test_total = int(test_total or 0)
        use_official_test = test_total > 0 and (test_labeled / test_total) >= 0.5
        test_source = "official" if use_official_test else "local_carve_out"

        if use_official_test:
            con.execute(
                "CREATE VIEW base AS SELECT *, split AS base_split FROM inc"
            )
        else:
            con.execute(
                f"""
                CREATE VIEW base AS
                SELECT *,
                    CASE
                        WHEN split = 'test' THEN 'unused'
                        WHEN triage_label IS NULL THEN 'excluded'
                        WHEN label_conflict THEN 'excluded'
                        WHEN split_conflict THEN 'excluded'
                        WHEN hash(incident_id || ':carve_test:{seed}') % 100 < 20 THEN 'test'
                        ELSE 'train'
                    END AS base_split
                FROM inc
                """
            )

        con.execute(
            """
            CREATE VIEW eligible AS
            SELECT *
            FROM base
            WHERE base_split = 'train'
              AND triage_label IS NOT NULL
              AND NOT label_conflict
              AND NOT split_conflict
            """
        )
        eligible_count = int(con.execute("SELECT count(*) FROM eligible").fetchone()[0])
        if eligible_count == 0:
            raise ValueError("No labelled, non-conflicting train incidents are available")

        warnings: list[str] = []
        unlabeled_train = int(
            con.execute(
                "SELECT count(*) FROM inc WHERE split = 'train' AND triage_label IS NULL"
            ).fetchone()[0]
        )
        if unlabeled_train:
            warnings.append(
                f"{unlabeled_train} train incidents without a triage label were excluded."
            )
        conflicting_train = int(
            con.execute(
                """
                SELECT count(*)
                FROM inc
                WHERE split = 'train' AND (label_conflict OR split_conflict)
                """
            ).fetchone()[0]
        )
        if conflicting_train:
            warnings.append(
                f"{conflicting_train} train incidents with label or split conflicts "
                "were excluded."
            )

        if sample_size is None or sample_size >= eligible_count:
            con.execute("CREATE TABLE train_sample AS SELECT * FROM eligible")
        else:
            con.execute(
                f"""
                CREATE TABLE train_sample AS
                WITH ranked AS (
                    SELECT *,
                        row_number() OVER (
                            PARTITION BY triage_label
                            ORDER BY hash(incident_id || ':sample:{seed}')
                        ) AS rn,
                        count(*) OVER (PARTITION BY triage_label) AS n_label,
                        count(*) OVER () AS n_total
                    FROM eligible
                )
                SELECT * EXCLUDE (rn, n_label, n_total)
                FROM ranked
                WHERE rn <= greatest(1, round({sample_size} * n_label::DOUBLE / n_total))
                """
            )

        train_sample_count = int(
            con.execute("SELECT count(*) FROM train_sample").fetchone()[0]
        )
        if train_sample_count >= 100:
            con.execute(
                f"""
                CREATE TABLE dev AS
                WITH ranked AS (
                    SELECT *,
                        row_number() OVER (
                            PARTITION BY triage_label
                            ORDER BY hash(incident_id || ':dev:{seed}')
                        ) AS rn,
                        count(*) OVER (PARTITION BY triage_label) AS n_label
                    FROM train_sample
                )
                SELECT * EXCLUDE (rn, n_label)
                FROM ranked
                WHERE rn <= greatest(1, round(0.1 * n_label))
                """
            )
        else:
            con.execute("CREATE TABLE dev AS SELECT * FROM train_sample WHERE FALSE")

        con.execute(
            """
            CREATE TABLE train AS
            SELECT *
            FROM train_sample
            WHERE incident_id NOT IN (SELECT incident_id FROM dev)
            """
        )
        con.execute(
            """
            CREATE TABLE test AS
            SELECT *
            FROM base
            WHERE base_split = 'test'
              AND triage_label IS NOT NULL
              AND NOT label_conflict
              AND NOT split_conflict
            """
        )

        con.execute("CREATE TABLE train_out AS SELECT * EXCLUDE (base_split) FROM train")
        con.execute("CREATE TABLE dev_out AS SELECT * EXCLUDE (base_split) FROM dev")
        con.execute("CREATE TABLE test_out AS SELECT * EXCLUDE (base_split) FROM test")

        splits = {
            "train": _write_table(con, "train_out", out_dir / "train.parquet"),
            "dev": _write_table(con, "dev_out", out_dir / "dev.parquet"),
            "test": _write_table(con, "test_out", out_dir / "test.parquet"),
        }

        unused_count = 0
        if not use_official_test:
            unused_count = int(
                con.execute("SELECT count(*) FROM base WHERE base_split = 'unused'").fetchone()[0]
            )

        if not use_official_test:
            warnings.append(
                "Official test labels were missing or below 50 percent. "
                "The test split was carved from the official train split and must be "
                "reported as local_carve_out."
            )
        if unused_count:
            warnings.append(
                f"{unused_count} official test incidents without labels were excluded."
            )
        if test_labeled and not use_official_test:
            warnings.append(
                f"Official test file contained {test_labeled} labelled rows, but coverage "
                f"was below 50 percent of {test_total}."
            )

        manifest = {
            "manifest_version": 1,
            "dataset": "Microsoft GUIDE",
            "dataset_version": "kaggle-v2",
            "created_at": datetime.now(UTC).isoformat(),
            "source": {
                "incidents_parquet": {
                    "path": _relative(incidents_path),
                    "sha256": sha256_file(incidents_path),
                    "rows": int(con.execute("SELECT count(*) FROM inc").fetchone()[0]),
                }
            },
            "sampling": {
                "seed": seed,
                "max_train_incidents": sample_size,
                "strategy": "label_stratified_hash",
                "dev_fraction": 0.1 if train_sample_count >= 100 else 0.0,
            },
            "test_source": test_source,
            "splits": splits,
            "warnings": warnings,
        }
    finally:
        con.close()

    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    validation = validate_manifest(manifest_path)
    if not validation["passed"]:
        raise ValueError(f"Generated manifest failed validation: {validation['checks']}")
    return manifest


def _resolve_manifest_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (ROOT / path)


def validate_manifest(manifest_path: Path) -> dict[str, Any]:
    manifest_path = Path(manifest_path)
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    if not manifest_path.exists():
        add("manifest exists", False, str(manifest_path))
        return {"passed": False, "checks": checks}

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    source = manifest.get("source", {}).get("incidents_parquet", {})
    source_path = _resolve_manifest_path(source.get("path", ""))
    source_ok = source_path.exists() and sha256_file(source_path) == source.get("sha256")
    add(
        "source hash matches",
        source_ok,
        f"{source_path} expected {source.get('sha256')}",
    )

    split_ids: dict[str, set[str]] = {}
    con = duckdb.connect()
    try:
        for split_name, split in manifest.get("splits", {}).items():
            path = _resolve_manifest_path(split.get("path", ""))
            file_ok = path.exists() and sha256_file(path) == split.get("file_sha256")
            add(f"{split_name} file hash matches", file_ok, str(path))
            if not file_ok:
                continue
            con.execute(
                f"CREATE OR REPLACE VIEW split_{split_name} AS "
                f"SELECT * FROM read_parquet('{_sql_path(path)}')"
            )
            rows = int(con.execute(f"SELECT count(*) FROM split_{split_name}").fetchone()[0])
            add(f"{split_name} row count matches", rows == split.get("rows"), f"{rows} rows")
            ids = _table_ids(con, f"split_{split_name}")
            split_ids[split_name] = set(ids)
            add(
                f"{split_name} incident id hash matches",
                sha256_ids(ids) == split.get("ids_sha256"),
                f"{len(ids)} ids",
            )
            add(
                f"{split_name} label counts match",
                _count_by_label(con, f"split_{split_name}") == split.get("label_counts"),
                str(_count_by_label(con, f"split_{split_name}")),
            )
    finally:
        con.close()

    names = sorted(split_ids)
    for index, left in enumerate(names):
        for right in names[index + 1 :]:
            overlap = split_ids[left] & split_ids[right]
            add(
                f"{left} and {right} disjoint",
                not overlap,
                f"{len(overlap)} shared incident ids",
            )

    return {"passed": all(check["passed"] for check in checks), "checks": checks}


def quality_report(
    incidents_path: Path,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    incidents_path = Path(incidents_path)
    checks: list[dict[str, Any]] = []
    warnings: list[str] = []

    def add(name: str, passed: bool, detail: str, warning: bool = False) -> None:
        checks.append(
            {"name": name, "passed": bool(passed), "detail": detail, "warning": warning}
        )
        if warning and not passed:
            warnings.append(f"{name}: {detail}")

    con = duckdb.connect()
    try:
        con.execute(
            f"CREATE VIEW inc AS SELECT * FROM read_parquet('{_sql_path(incidents_path)}')"
        )
        total, unique_ids = con.execute(
            "SELECT count(*), count(DISTINCT incident_id) FROM inc"
        ).fetchone()
        add("incident id unique", total == unique_ids, f"{total} rows, {unique_ids} ids")

        unknown_labels = int(
            con.execute(
                f"""
                SELECT count(*)
                FROM inc
                WHERE triage_label IS NOT NULL
                  AND triage_label NOT IN ({", ".join("'" + label + "'" for label in LABELS)})
                """
            ).fetchone()[0]
        )
        add("label values known", unknown_labels == 0, f"{unknown_labels} unknown labels")

        bad_splits = int(
            con.execute(
                "SELECT count(*) FROM inc WHERE split NOT IN ('train', 'test')"
            ).fetchone()[0]
        )
        add("split values known", bad_splits == 0, f"{bad_splits} invalid split values")

        mixed = int(
            con.execute(
                """
                SELECT count(*)
                FROM (
                    SELECT incident_id
                    FROM inc
                    GROUP BY incident_id
                    HAVING count(DISTINCT split) > 1
                )
                """
            ).fetchone()[0]
        )
        add("split disjoint by incident", mixed == 0, f"{mixed} incidents in both splits")

        conflicts = int(
            con.execute("SELECT count(*) FROM inc WHERE label_conflict").fetchone()[0]
        )
        add(
            "label conflicts",
            conflicts == 0,
            f"{conflicts} incidents with conflicting labels",
            True,
        )

        split_conflicts = int(
            con.execute("SELECT count(*) FROM inc WHERE split_conflict").fetchone()[0]
        )
        add(
            "split conflicts",
            split_conflicts == 0,
            f"{split_conflicts} incidents in multiple source files",
            True,
        )

        null_timestamps = int(
            con.execute("SELECT count(*) FROM inc WHERE created_at IS NULL").fetchone()[0]
        )
        add(
            "timestamps parse",
            null_timestamps == 0,
            f"{null_timestamps} null or invalid timestamps",
            True,
        )

        missing_labels = int(
            con.execute("SELECT count(*) FROM inc WHERE triage_label IS NULL").fetchone()[0]
        )
        add(
            "labels present",
            missing_labels == 0,
            f"{missing_labels} incidents without a triage label",
            True,
        )

        sparse = int(
            con.execute(
                "SELECT count(*) FROM inc WHERE summary IS NULL OR trim(summary) = ''"
            ).fetchone()[0]
        )
        add("incident text present", sparse == 0, f"{sparse} incidents with empty text", True)
    finally:
        con.close()

    if manifest_path is not None:
        validation = validate_manifest(manifest_path)
        checks.extend(validation["checks"])

    return {
        "passed": all(check["passed"] for check in checks if not check.get("warning")),
        "checks": checks,
        "warnings": warnings,
    }
