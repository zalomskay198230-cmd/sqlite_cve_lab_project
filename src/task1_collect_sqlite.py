from __future__ import annotations

import re
from pathlib import Path

from bs4 import BeautifulSoup

from common import (
    CVE_ID_RE,
    DATE_RE,
    RESULTS_DIR,
    SQLITE_CVES_URL,
    ensure_results_dir,
    request_text,
    save_json,
)

OUTPUT_FILE = RESULTS_DIR / "result_task_1.json"



def collect_sqlite_cves() -> list[dict[str, str | None]]:
    html = request_text(SQLITE_CVES_URL)
    soup = BeautifulSoup(html, "html.parser")

    result: list[dict[str, str | None]] = []
    seen: set[str] = set()

    # Ищем все ссылки с CVE-ID на странице SQLite.
    for anchor in soup.find_all("a", string=re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)):
        cve_id = anchor.get_text(strip=True).upper()
        if cve_id in seen:
            continue

        # На странице SQLite каждая запись обычно лежит в строке таблицы.
        # Если строки таблицы нет, берём ближайший родительский блок.
        context_node = anchor.find_parent("tr") or anchor.find_parent(["p", "li", "div", "td"]) or anchor
        context_text = context_node.get_text(" ", strip=True)

        date_match = DATE_RE.search(context_text)
        vendor_release_date = date_match.group(0) if date_match else None

        result.append(
            {
                "ID": cve_id,
                # Для SQLite все CVE опубликованы на одной официальной странице.
                "vendor_release_date": vendor_release_date,
                "vendor_release_url": SQLITE_CVES_URL,
            }
        )
        seen.add(cve_id)

    return result



def main() -> None:
    ensure_results_dir()
    data = collect_sqlite_cves()
    save_json(OUTPUT_FILE, data)
    print(f"Собрано записей: {len(data)}")
    print(f"Файл сохранён: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
