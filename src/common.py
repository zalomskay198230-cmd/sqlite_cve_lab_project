from __future__ import annotations

import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator
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
            "SQLite-CVE-Lab/1.1 "
            "(educational project; contact: local-user@example.invalid)"
        )
    }
)


def ensure_results_dir() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)



def request_text(url: str, timeout: int = 30, retries: int = 3, backoff: float = 1.5) -> str:
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            response = _SESSION.get(url, timeout=timeout)
            response.raise_for_status()
            return response.text
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt == retries:
                break
            time.sleep(backoff * attempt)
    raise DataCollectionError(f"Не удалось получить текст по URL {url}: {last_error}")



def request_json(
    url: str,
    timeout: int = 30,
    retries: int = 3,
    backoff: float = 1.5,
) -> dict[str, Any] | list[Any]:
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            response = _SESSION.get(url, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt == retries:
                break
            time.sleep(backoff * attempt)
    raise DataCollectionError(f"Не удалось получить JSON по URL {url}: {last_error}")



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



def iter_container_objects(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    containers = record.get("containers", {})
    if not isinstance(containers, dict):
        return

    for value in containers.values():
        if isinstance(value, dict):
            yield value
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield item



def fetch_cwe_info(
    cwe_id: str,
    fallback: dict[str, str] | None = None,
    retries: int = 3,
) -> dict[str, str]:
    default_fallback = fallback or {"name": "Unknown", "description": "Unknown"}

    match = CWE_RE.fullmatch(cwe_id)
    if not match:
        return default_fallback

    cwe_number = match.group(1)
    url = CWE_API_URL.format(cwe_number=cwe_number)

    for attempt in range(1, retries + 1):
        try:
            data = request_json(url, retries=1)
        except Exception:
            if attempt == retries:
                return default_fallback
            time.sleep(1.5 * attempt)
            continue

        if not isinstance(data, dict):
            if attempt == retries:
                return default_fallback
            time.sleep(1.5 * attempt)
            continue

        weaknesses = data.get("Weaknesses") or []
        if not weaknesses:
            if attempt == retries:
                return default_fallback
            time.sleep(1.5 * attempt)
            continue

        weakness = weaknesses[0]
        name = str(weakness.get("Name") or "").strip()
        description = str(weakness.get("Description") or "").strip()
        if name and description:
            return {"name": name, "description": description}

        if attempt < retries:
            time.sleep(1.5 * attempt)

    return default_fallback



def extract_cwe_fallbacks(record: dict[str, Any]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}

    for container in iter_container_objects(record):
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

                cwe_id = item.get("cweId")
                if not isinstance(cwe_id, str) or not CWE_RE.fullmatch(cwe_id):
                    text = " ".join(str(item.get(field, "")) for field in ("description", "value", "name"))
                    match = CWE_RE.search(text)
                    if not match:
                        continue
                    cwe_id = f"CWE-{match.group(1)}"

                text = " ".join(str(item.get(field, "")) for field in ("description", "value", "name")).strip()
                name = text
                if text.upper().startswith(cwe_id.upper()):
                    name = text[len(cwe_id):].strip(" :-") or text

                result[cwe_id] = {
                    "name": name or default_name_from_cwe_id(cwe_id),
                    "description": text or default_name_from_cwe_id(cwe_id),
                }

    return result



def default_name_from_cwe_id(cwe_id: str) -> str:
    return cwe_id



def first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None



def find_english_description(record: dict[str, Any]) -> str | None:
    for container in iter_container_objects(record):
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
    result: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    def normalize_version(metric_key: str) -> str:
        cleaned = metric_key.replace("_", "").lower()
        return cleaned

    for container in iter_container_objects(record):
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



def normalize_cpe_component(value: str) -> str:
    cleaned = value.strip().lower().replace(" ", "_")
    cleaned = cleaned.replace("/", "_")
    return cleaned or "*"



def is_concrete_version(value: str | None) -> bool:
    if not value:
        return False
    text = value.strip()
    if not text:
        return False
    forbidden_fragments = ("<", ">", "=", " ", "*", ",", "||")
    forbidden_values = {"all", "n/a", "na", "unspecified", "unknown", "none"}
    lowered = text.lower()
    if lowered in forbidden_values:
        return False
    return not any(fragment in text for fragment in forbidden_fragments)



def build_synthetic_cpe(vendor: str, product: str, version: str) -> str:
    return (
        f"cpe:2.3:a:{normalize_cpe_component(vendor)}:"
        f"{normalize_cpe_component(product)}:{normalize_cpe_component(version)}:*:*:*:*:*:*:*"
    )



def extract_cpe_list(record: dict[str, Any]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    def add_cpe(value: str) -> None:
        normalized = value.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            found.append(normalized)

    # 1. Сначала собираем готовые CPE, если они явно есть в записи.
    for item in walk_json(record):
        if not isinstance(item, str):
            continue
        for match in CPE_RE.findall(item):
            add_cpe(match)

    # 2. Если готовых CPE нет или в них не хватает конкретных версий,
    #    дополнительно синтезируем CPE из affected/vendor/product/versions.
    for container in iter_container_objects(record):
        affected_list = container.get("affected", [])
        if not isinstance(affected_list, list):
            continue

        for affected in affected_list:
            if not isinstance(affected, dict):
                continue

            vendor = str(affected.get("vendor") or "sqlite").strip()
            product = str(affected.get("product") or "sqlite").strip()

            cpes = affected.get("cpes", [])
            if isinstance(cpes, list):
                for cpe in cpes:
                    if isinstance(cpe, str):
                        add_cpe(cpe)

            versions = affected.get("versions", [])
            if not isinstance(versions, list):
                continue

            for version_item in versions:
                if not isinstance(version_item, dict):
                    continue
                version_value = str(version_item.get("version") or "").strip()
                if is_concrete_version(version_value):
                    add_cpe(build_synthetic_cpe(vendor, product, version_value))

    return found



def extract_cwe_ids(record: dict[str, Any]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    for container in iter_container_objects(record):
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
