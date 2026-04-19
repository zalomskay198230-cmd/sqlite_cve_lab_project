from __future__ import annotations

from pathlib import Path

from common import (
    CVE_RECORD_URL,
    RESULTS_DIR,
    ensure_results_dir,
    extract_cpe_list,
    extract_cwe_ids,
    extract_cvss_list,
    fetch_cve_record,
    fetch_cwe_info,
    find_english_description,
    load_json,
    normalize_iso_datetime,
    save_json,
)

INPUT_FILE = RESULTS_DIR / "result_task_1.json"
OUTPUT_FILE = RESULTS_DIR / "result_task_2.json"



def enrich_records(task1_records: list[dict]) -> list[dict]:
    enriched: list[dict] = []

    for item in task1_records:
        cve_id = item["ID"]
        record = fetch_cve_record(cve_id)
        metadata = record.get("cveMetadata", {})

        cwe_map: dict[str, dict[str, str]] = {}
        for cwe_id in extract_cwe_ids(record):
            cwe_map[cwe_id] = fetch_cwe_info(cwe_id)

        enriched.append(
            {
                "ID": cve_id,
                "vendor_release_date": item.get("vendor_release_date"),
                "vendor_release_url": item.get("vendor_release_url"),
                "url": CVE_RECORD_URL.format(cve_id=cve_id),
                "published_date": normalize_iso_datetime(metadata.get("datePublished")),
                "updated_date": normalize_iso_datetime(metadata.get("dateUpdated")),
                "description": find_english_description(record),
                "cvss_list": extract_cvss_list(record),
                "cpe_list": extract_cpe_list(record),
                "cwe": cwe_map,
            }
        )

    return enriched



def main() -> None:
    ensure_results_dir()
    task1_records = load_json(INPUT_FILE)
    data = enrich_records(task1_records)
    save_json(OUTPUT_FILE, data)
    print(f"Обогащено записей: {len(data)}")
    print(f"Файл сохранён: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
