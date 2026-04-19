from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET
from xml.dom import minidom

from common import RESULTS_DIR, load_json

INPUT_FILE = RESULTS_DIR / "result_task_2.json"
OUTPUT_FILE = RESULTS_DIR / "result_task_3.xml"



def build_xml(data: list[dict]) -> ET.Element:
    root = ET.Element("vulnerabilities")

    for item in data:
        vulnerability = ET.SubElement(root, "vulnerability")

        for field in (
            "ID",
            "vendor_release_date",
            "vendor_release_url",
            "url",
            "published_date",
            "updated_date",
            "description",
        ):
            element = ET.SubElement(vulnerability, field)
            value = item.get(field)
            element.text = "" if value is None else str(value)

        cvss_list_element = ET.SubElement(vulnerability, "cvss_list")
        for cvss in item.get("cvss_list", []):
            cvss_element = ET.SubElement(cvss_list_element, "cvss")
            cvss_element.set("version", str(cvss.get("version", "")))
            cvss_element.set("score", "" if cvss.get("score") is None else str(cvss.get("score")))
            cvss_element.set("severity", "" if cvss.get("severity") is None else str(cvss.get("severity")))
            cvss_element.text = "" if cvss.get("vector") is None else str(cvss.get("vector"))

        cpe_list_element = ET.SubElement(vulnerability, "cpe_list")
        for cpe in item.get("cpe_list", []):
            cpe_element = ET.SubElement(cpe_list_element, "cpe")
            cpe_element.text = str(cpe)

        cwe_list_element = ET.SubElement(vulnerability, "cwe_list")
        for cwe_id, cwe_data in item.get("cwe", {}).items():
            cwe_element = ET.SubElement(cwe_list_element, "cwe")
            cwe_element.set("id", str(cwe_id))
            cwe_element.set("name", str(cwe_data.get("name", "")))
            cwe_element.text = str(cwe_data.get("description", ""))

    return root



def main() -> None:
    data = load_json(INPUT_FILE)
    root = build_xml(data)
    xml_bytes = ET.tostring(root, encoding="utf-8")
    pretty_xml = minidom.parseString(xml_bytes).toprettyxml(indent="  ")
    OUTPUT_FILE.write_text(pretty_xml, encoding="utf-8")
    print(f"Файл сохранён: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
