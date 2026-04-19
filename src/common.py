from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
from dateutil import parser as dt_parser

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"
SCHEMA_FILE = BASE_DIR / "json_schema.json"

SQLITE_CVES_URL = "https://www.sqlite.org/cves.html"
CVE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
CVE_RECORD_URL = "https://www.cve.org/CVERecord?id={cve_id}"
CVE_LIST_RAW_URL = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/"
    "cves/{year}/{bucket}/{cve_id}.json"
)
CWE_API_URL = "https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_number}"

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
CPE_RE = re.compile(r"cpe:2\.3:[aho]:[^\s\"'<>]+", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


class DataCollectionError(RuntimeError):
    """Ошибка получения/обработки данных."""


_SESSION = requests.Session()
_SESSION.headers.update(
    {
        "User-Agent": (
            "SQLite-CVE-Lab/1.0 "
            "(educational project; contact: local-user@example.invalid)"
        )
    }
)


def ensure_results_dir() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)



def request_text(url: str, timeout: int = 30) -> str:
    response = _SESSION.get(url, timeout=timeout)
    response.raise_for_status()
    return response.text



def request_json(url: str, timeout: int = 30) -> dict[str, Any] | list[Any]:
    response = _SESSION.get(url, timeout=timeout)
    response.raise_for_status()
    return response.json()



def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)



def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)



def normalize_iso_datetime(value: str | None) -> str | None:
    if value in (None, ""):
        return None
    try:
        parsed = dt_parser.isoparse(value)
    except (TypeError, ValueError):
        try:
            parsed = dt_parser.parse(value)
        except (TypeError, ValueError):
            return value
    return parsed.isoformat()



def normalize_iso_date(value: str | None) -> str | None:
    if value in (None, ""):
        return None
    if DATE_RE.fullmatch(value):
        return value
    try:
        parsed = dt_parser.parse(value)
        return parsed.date().isoformat()
    except (TypeError, ValueError):
        return value



def make_absolute_url(base_url: str, maybe_relative: str | None) -> str:
    if not maybe_relative:
        return base_url
    return urljoin(base_url, maybe_relative)



def cve_bucket_from_id(cve_id: str) -> tuple[str, str]:
    match = re.fullmatch(r"CVE-(\d{4})-(\d+)", cve_id, re.IGNORECASE)
    if not match:
        raise ValueError(f"Некорректный CVE-ID: {cve_id}")
    year, number = match.groups()
    prefix = number[:-3] if len(number) > 3 else "0"
    bucket = f"{prefix}xxx"
    return year, bucket



def fetch_cve_record(cve_id: str) -> dict[str, Any]:
    """
    Сначала пытаемся получить запись из CVE Services API.
    Если API недоступно, используем официальный репозиторий CVE List V5,
    который синхронизируется с официальным API.
    """
    api_url = CVE_API_URL.format(cve_id=cve_id)
    try:
        data = request_json(api_url)
        if isinstance(data, dict) and data:
            return data
    except Exception:
        pass

    year, bucket = cve_bucket_from_id(cve_id)
    fallback_url = CVE_LIST_RAW_URL.format(year=year, bucket=bucket, cve_id=cve_id)
    data = request_json(fallback_url)
    if not isinstance(data, dict) or not data:
        raise DataCollectionError(f"Не удалось получить CVE record для {cve_id}")
    return data



def fetch_cwe_info(cwe_id: str) -> dict[str, str]:
    match = CWE_RE.fullmatch(cwe_id)
    if not match:
        return {"name": "Unknown", "description": "Unknown"}

    cwe_number = match.group(1)
    url = CWE_API_URL.format(cwe_number=cwe_number)
    try:
        data = request_json(url)
    except Exception:
        return {"name": "Unknown", "description": "Unknown"}

    if not isinstance(data, dict):
        return {"name": "Unknown", "description": "Unknown"}

    weaknesses = data.get("Weaknesses") or []
    if not weaknesses:
        return {"name": "Unknown", "description": "Unknown"}

    weakness = weaknesses[0]
    name = (weakness.get("Name") or "Unknown").strip()
    description = (weakness.get("Description") or "Unknown").strip()
    return {"name": name, "description": description}



def first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None



def find_english_description(record: dict[str, Any]) -> str | None:
    containers = record.get("containers", {})
    for container_name in ("cna", "adp"):
        container = containers.get(container_name)
        if not isinstance(container, dict):
            continue
        descriptions = container.get("descriptions", [])
        for item in descriptions:
            if not isinstance(item, dict):
                continue
            if item.get("lang") == "en" and item.get("value"):
                return str(item["value"]).strip()
        for item in descriptions:
            if isinstance(item, dict) and item.get("value"):
                return str(item["value"]).strip()
    return None



def extract_cvss_list(record: dict[str, Any]) -> list[dict[str, Any]]:
    containers = record.get("containers", {})
    result: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    def normalize_version(metric_key: str) -> str:
        cleaned = metric_key.replace("_", "").lower()
        return cleaned

    for container_name in ("cna", "adp"):
        container = containers.get(container_name)
        if not isinstance(container, dict):
            continue
        metrics = container.get("metrics", [])
        if not isinstance(metrics, list):
            continue

        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            for key, value in metric.items():
                if not key.lower().startswith("cvss") or not isinstance(value, dict):
                    continue

                version = normalize_version(key)
                score = first_non_empty(
                    value.get("baseScore"),
                    value.get("environmentalScore"),
                    value.get("temporalScore"),
                )
                vector = first_non_empty(value.get("vectorString"), value.get("vector"))
                severity = first_non_empty(
                    value.get("baseSeverity"),
                    value.get("environmentalSeverity"),
                    value.get("temporalSeverity"),
                )

                if score is None and vector is None and severity is None:
                    continue

                row = {
                    "version": version,
                    "score": score,
                    "vector": vector,
                    "severity": severity,
                }
                signature = (row["version"], row["score"], row["vector"], row["severity"])
                if signature not in seen:
                    seen.add(signature)
                    result.append(row)

    return result



def walk_json(value: Any):
    if isinstance(value, dict):
        for inner in value.values():
            yield from walk_json(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from walk_json(inner)
    else:
        yield value



def extract_cpe_list(record: dict[str, Any]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for item in walk_json(record):
        if not isinstance(item, str):
            continue
        for match in CPE_RE.findall(item):
            normalized = match.strip()
            if normalized not in seen:
                seen.add(normalized)
                found.append(normalized)
    return found



def extract_cwe_ids(record: dict[str, Any]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    containers = record.get("containers", {})

    for container in containers.values():
        if not isinstance(container, dict):
            continue
        problem_types = container.get("problemTypes", [])
        if not isinstance(problem_types, list):
            continue
        for problem_type in problem_types:
            if not isinstance(problem_type, dict):
                continue
            descriptions = problem_type.get("descriptions", [])
            if not isinstance(descriptions, list):
                continue
            for item in descriptions:
                if not isinstance(item, dict):
                    continue
                direct_cwe_id = item.get("cweId")
                if isinstance(direct_cwe_id, str) and CWE_RE.fullmatch(direct_cwe_id):
                    if direct_cwe_id not in seen:
                        seen.add(direct_cwe_id)
                        found.append(direct_cwe_id)
                text = " ".join(
                    str(item.get(field, "")) for field in ("description", "value", "name")
                )
                for match in CWE_RE.findall(text):
                    cwe_id = f"CWE-{match}"
                    if cwe_id not in seen:
                        seen.add(cwe_id)
                        found.append(cwe_id)
    return found



def current_timestamp() -> str:
    return datetime.now().isoformat(timespec="seconds")
