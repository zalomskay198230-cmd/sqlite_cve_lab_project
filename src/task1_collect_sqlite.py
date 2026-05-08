from __future__ import annotations

import re

from bs4 import BeautifulSoup

from common import DATE_RE, RESULTS_DIR, SQLITE_CVES_URL, ensure_results_dir, request_text, save_json

OUTPUT_FILE = RESULTS_DIR / "result_task_1.json"

EXCLUDE_MARKERS = (
    "duplicate of",
    "not a bug in sqlite",
    "not a bug in the core sqlite library",
    "this cve is misinformation",
    "does not affect sqlite itself",
    "this is a bug in the sqlite jdbc library",
    "this is not a bug in sqlite",
    "has nothing whatsoever to do with sqlite",
)


def should_keep_sqlite_cve(comment_text: str) -> bool:
    normalized = " ".join(comment_text.lower().split())
    return not any(marker in normalized for marker in EXCLUDE_MARKERS)



def parse_status_section(status_text: str) -> list[dict[str, str | None]]:
    lines = [line.strip() for line in status_text.splitlines() if line.strip()]

    start_index = 0
    for index, line in enumerate(lines):
        if line.startswith("CVE Number Fix Comments"):
            start_index = index + 1
            break

    result: list[dict[str, str | None]] = []
    current_cve: str | None = None
    current_buffer: list[str] = []

    def flush_current() -> None:
        nonlocal current_cve, current_buffer
        if not current_cve:
            return

        comment_text = " ".join(part for part in current_buffer if part).strip()
        if should_keep_sqlite_cve(comment_text):
            date_match = DATE_RE.search(comment_text)
            vendor_release_date = date_match.group(0) if date_match else None
            result.append(
                {
                    "ID": current_cve,
                    "vendor_release_date": vendor_release_date,
                    "vendor_release_url": SQLITE_CVES_URL,
                }
            )

        current_cve = None
        current_buffer = []

    for line in lines[start_index:]:
        match = re.match(r"^(CVE-\d{4}-\d+)\b(.*)$", line, re.IGNORECASE)
        if match:
            flush_current()
            current_cve = match.group(1).upper()
            tail = match.group(2).strip()
            if tail:
                current_buffer.append(tail)
            continue

        if current_cve:
            current_buffer.append(line)

    flush_current()
    return result



def collect_sqlite_cves() -> list[dict[str, str | None]]:
    html = request_text(SQLITE_CVES_URL)
    soup = BeautifulSoup(html, "html.parser")
    full_text = soup.get_text("\n", strip=True)

    section_start = full_text.find("Status Of Recent SQLite CVEs")
    if section_start != -1:
        full_text = full_text[section_start:]

    return parse_status_section(full_text)



def main() -> None:
    ensure_results_dir()
    data = collect_sqlite_cves()
    save_json(OUTPUT_FILE, data)
    print(f"Собрано применимых записей: {len(data)}")
    print(f"Файл сохранён: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
