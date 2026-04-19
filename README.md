# Лабораторная работа №2 — SQLite CVE

Вариант: официальный ресурс SQLite `https://www.sqlite.org/cves.html`.

## Что делает проект

- **Задача 1** — собирает все CVE-ID со страницы SQLite и сохраняет `result_task_1.json`.
- **Задача 2** — обогащает записи данными из MITRE/CVE и CWE, сохраняет `result_task_2.json`.
- **Задача 3** — преобразует JSON из задания 2 в XML `result_task_3.xml`.
- **Задача 4** — валидирует `result_task_2.json` по `json_schema.json`.
- **Задача 5** — создаёт PostgreSQL в Docker и загружает нормализованные данные в БД.

## Структура проекта

```text
sqlite_cve_lab_project/
├── db/
│   ├── Dockerfile
│   └── init.sql
├── results/
├── src/
│   ├── common.py
│   ├── run_all.py
│   ├── task1_collect_sqlite.py
│   ├── task2_enrich_from_mitre.py
│   ├── task3_json_to_xml.py
│   ├── task4_validate_json.py
│   └── task5_load_db.py
├── docker-compose.yml
├── json_schema.json
├── README.md
└── requirements.txt
```

## Установка

```bash
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

## Запуск задач 1–4

Из корня проекта:

```bash
python src/run_all.py
```

Или по отдельности:

```bash
python src/task1_collect_sqlite.py
python src/task2_enrich_from_mitre.py
python src/task3_json_to_xml.py
python src/task4_validate_json.py
```

## Запуск БД для задания 5

```bash
docker compose up -d --build
```

После поднятия контейнера загрузить данные:

```bash
python src/task5_load_db.py
```

## Параметры БД

По умолчанию используются:

- `DB_HOST=localhost`
- `DB_PORT=5432`
- `DB_NAME=sqlite_cve_lab`
- `DB_USER=lab_user`
- `DB_PASSWORD=lab_password`

При необходимости их можно переопределить через переменные окружения.

## Примечания по выбранному источнику

1. SQLite публикует CVE на одной общей странице, поэтому в `vendor_release_url` сохраняется одна и та же ссылка: `https://www.sqlite.org/cves.html`.
2. Часть записей на странице может быть помечена как **duplicate** или **not a bug in SQLite** — это особенность самого источника.
3. Для получения CVE record скрипт сначала использует CVE Services API `cveawg.mitre.org`, а если он недоступен — официальный `cvelistV5`, который синхронизируется с официальным API.
4. Для имени и описания CWE используется официальный **CWE REST API** от MITRE.

## Что написать в отчёте

Для каждого задания удобно указать:

- какие библиотеки использовались;
- какие сложности были;
- как решались проблемы;
- фрагмент итогового файла;
- особенности данных SQLite (общая страница, дубликаты, записи не про ядро SQLite, возможное отсутствие части полей в CVE record).
