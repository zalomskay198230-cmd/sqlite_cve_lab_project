from __future__ import annotations

from pathlib import Path

from jsonschema import Draft202012Validator

from common import RESULTS_DIR, SCHEMA_FILE, load_json

INPUT_FILE = RESULTS_DIR / "result_task_2.json"



def main() -> None:
    data = load_json(INPUT_FILE)
    schema = load_json(SCHEMA_FILE)

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda error: list(error.path))

    if not errors:
        print("Валидация прошла успешно.")
        return

    print("Обнаружены ошибки валидации:")
    for index, error in enumerate(errors, start=1):
        path = "/".join(str(part) for part in error.path) or "<root>"
        print(f"{index}. {path}: {error.message}")


if __name__ == "__main__":
    main()
