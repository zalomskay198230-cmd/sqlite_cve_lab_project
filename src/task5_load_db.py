from __future__ import annotations

import os
from datetime import datetime

import psycopg

from common import RESULTS_DIR, load_json

INPUT_FILE = RESULTS_DIR / "result_task_2.json"

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "sqlite_cve_lab")
DB_USER = os.getenv("DB_USER", "lab_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "lab_password")



def to_datetime(value: str | None):
    if not value:
        return None
    return datetime.fromisoformat(value)



def main() -> None:
    data = load_json(INPUT_FILE)

    conn = psycopg.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )

    with conn:
        with conn.cursor() as cur:
            for item in data:
                cur.execute(
                    """
                    INSERT INTO vulnerabilities (
                        cve_id,
                        vendor_release_date,
                        vendor_release_url,
                        cve_url,
                        published_date,
                        updated_date,
                        description
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        vendor_release_date = EXCLUDED.vendor_release_date,
                        vendor_release_url = EXCLUDED.vendor_release_url,
                        cve_url = EXCLUDED.cve_url,
                        published_date = EXCLUDED.published_date,
                        updated_date = EXCLUDED.updated_date,
                        description = EXCLUDED.description
                    RETURNING id
                    """,
                    (
                        item["ID"],
                        item.get("vendor_release_date"),
                        item["vendor_release_url"],
                        item["url"],
                        to_datetime(item.get("published_date")),
                        to_datetime(item.get("updated_date")),
                        item.get("description") or "",
                    ),
                )
                vulnerability_id = cur.fetchone()[0]

                cur.execute("DELETE FROM cvss_metrics WHERE vulnerability_id = %s", (vulnerability_id,))
                cur.execute("DELETE FROM vulnerability_cpes WHERE vulnerability_id = %s", (vulnerability_id,))
                cur.execute("DELETE FROM vulnerability_cwes WHERE vulnerability_id = %s", (vulnerability_id,))

                for metric in item.get("cvss_list", []):
                    cur.execute(
                        """
                        INSERT INTO cvss_metrics (vulnerability_id, version, score, vector, severity)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (vulnerability_id, version, vector) DO NOTHING
                        """,
                        (
                            vulnerability_id,
                            metric.get("version") or "unknown",
                            metric.get("score"),
                            metric.get("vector") or "unknown",
                            metric.get("severity") or "unknown",
                        ),
                    )

                for cpe in item.get("cpe_list", []):
                    cur.execute(
                        """
                        INSERT INTO cpes (cpe)
                        VALUES (%s)
                        ON CONFLICT (cpe) DO UPDATE SET cpe = EXCLUDED.cpe
                        RETURNING id
                        """,
                        (cpe,),
                    )
                    cpe_id_row = cur.fetchone()
                    if cpe_id_row is None:
                        cur.execute("SELECT id FROM cpes WHERE cpe = %s", (cpe,))
                        cpe_id = cur.fetchone()[0]
                    else:
                        cpe_id = cpe_id_row[0]

                    cur.execute(
                        """
                        INSERT INTO vulnerability_cpes (vulnerability_id, cpe_id)
                        VALUES (%s, %s)
                        ON CONFLICT DO NOTHING
                        """,
                        (vulnerability_id, cpe_id),
                    )

                for cwe_id, cwe_data in item.get("cwe", {}).items():
                    cur.execute(
                        """
                        INSERT INTO cwes (cwe_id, name, description)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (cwe_id) DO UPDATE SET
                            name = EXCLUDED.name,
                            description = EXCLUDED.description
                        RETURNING id
                        """,
                        (
                            cwe_id,
                            cwe_data.get("name") or "Unknown",
                            cwe_data.get("description") or "Unknown",
                        ),
                    )
                    cwe_ref_id = cur.fetchone()[0]

                    cur.execute(
                        """
                        INSERT INTO vulnerability_cwes (vulnerability_id, cwe_ref_id)
                        VALUES (%s, %s)
                        ON CONFLICT DO NOTHING
                        """,
                        (vulnerability_id, cwe_ref_id),
                    )

    print("Данные успешно загружены в БД.")


if __name__ == "__main__":
    main()
