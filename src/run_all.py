from task1_collect_sqlite import main as task1_main
from task2_enrich_from_mitre import main as task2_main
from task3_json_to_xml import main as task3_main
from task4_validate_json import main as task4_main


def main() -> None:
    task1_main()
    task2_main()
    task3_main()
    task4_main()


if __name__ == "__main__":
    main()
