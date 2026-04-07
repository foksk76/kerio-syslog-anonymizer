Language: [English](README.md) | [Русский](README.ru.md)

# Kerio Syslog Anonymizer

Детерминированная анонимизация текстовых Kerio Connect syslog-файлов для безопасной публикации, примеров и повторяемой проверки парсеров.

> **Статус проекта:** Утилита для подготовки реальных Kerio syslog-примеров перед публичным или полупубличным использованием.

> **Языковая политика:** `README.md` является основным английским README. `README.ru.md` является основной русской версией для лабораторной работы и быстрого входа в проект. Сохраняйте переключатель языка первой строкой в обоих файлах.

## Зачем нужен этот репозиторий

Реальный Kerio Connect syslog может содержать чувствительные значения: email-адреса, имена пользователей, внутренние IP-адреса, домены, темы писем, display names и ФИО.

Этот репозиторий обрабатывает исходный текстовый файл syslog, заменяет поддерживаемые чувствительные значения на детерминированные вымышленные значения и сохраняет таблицу соответствий, чтобы повторные запуски сохраняли связи между событиями. Это помогает публиковать примеры, воспроизводить поведение парсеров и делиться наборами данных для разбора проблем без раскрытия исходных данных.

## Семейство проектов

Этот репозиторий входит в семейство проектов **Kerio Connect Monitoring & Logging**:

1. [kerio-connect](https://github.com/foksk76/kerio-connect) - воспроизводимая лабораторная среда Kerio Connect
2. [kerio-logstash-project](https://github.com/foksk76/kerio-logstash-project) - pipeline для parsing, normalization и validation Kerio syslog в ELK
3. [kerio-syslog-anonymizer](https://github.com/foksk76/kerio-syslog-anonymizer) - детерминированная анонимизация реальных логов для безопасной публикации и повторяемой корреляции

## Место репозитория в общей схеме

Этот репозиторий подготавливает raw Kerio syslog перед коммитом в публичный репозиторий, использованием в parser tests или передачей другому инженеру.

```text
Kerio Connect -> raw syslog TXT -> kerio-syslog-anonymizer -> anonymized TXT -> Logstash / Elasticsearch / Kibana / documentation
```

Связанные репозитории дополняют друг друга:

- `kerio-connect` предоставляет воспроизводимую лабораторную среду Kerio Connect.
- `kerio-logstash-project` разбирает, нормализует, обогащает и проверяет Kerio syslog в ELK.
- `kerio-syslog-anonymizer` подготавливает реальные логи для безопасной публикации, сохраняя повторяемую корреляцию.

## Основной сценарий использования

1. Экспортируйте или скопируйте raw Kerio syslog text file.
2. Запустите `kerio_anonymizer.py`, указав input file, output file и mapping file.
3. Скрипт определит или использует заданную кодировку входного файла.
4. Поддерживаемые чувствительные значения будут заменены на детерминированные фейковые значения.
5. Анонимизированный output и `mapping.json` будут записаны для повторного использования и проверки.

## Для кого это

- Администраторы Kerio Connect, которым нужно безопасно делиться примерами логов.
- DevOps, observability и SecOps инженеры, которые готовят fixtures для парсеров и dashboards.
- Контрибьюторы проекта, которым нужны реалистичные анонимизированные данные для повторяемой проверки.

## Архитектура / Роли компонентов

1. **Source system** создаёт raw Kerio Connect syslog text.
2. **Anonymizer script** читает text file и применяет детерминированные замены.
3. **Mapping store** сохраняет fake values в `mapping.json` с ключами `sha256(category:value)`.
4. **Output artifact** содержит anonymized syslog text для тестов, документации или ELK ingestion.
5. **Verification commands** подтверждают наличие output-файлов и hashed mapping keys.

## Требования

### Программное обеспечение

- OS: Windows, Linux или другая ОС с поддержкой Python.
- Python: рекомендуется 3.11 или новее.
- Python dependencies: устанавливаются из `requirements.txt`.

### Аппаратные ресурсы

- CPU: 1 vCPU достаточно для малых и средних файлов.
- RAM: минимум 512 MB, рекомендуется 1 GB для больших файлов.
- Disk: свободное место для input file, output file и mapping file.

### Проверенные версии

| Компонент | Версия | Примечания |
|---|---|---|
| Python | 3.11.9 | Проверено в локальной Windows-среде |
| Python | 3.12.3 | Проверено в Ubuntu 24.04 test container |
| Faker | Из `requirements.txt` | Используется для генерации fake data |

## Структура репозитория

- `kerio_anonymizer.py` содержит CLI anonymizer.
- `requirements.txt` содержит runtime dependencies Python.
- `.env.example` описывает optional Kerio Connect API settings.
- `mapping.json` хранит детерминированные fake values с hashed real keys.
- `README.md` и `README.ru.md` описывают onboarding на английском и русском.
- `CHANGELOG.md`, `HANDOFF.md` и `NEXT_STEPS.md` описывают состояние проекта и следующие шаги.
- `RELEASE_NOTES.md` содержит текущий черновик GitHub Release Notes.
- `CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md` и `LICENSE` описывают governance.
- `CHANGES.md` сохранён как legacy release notes; canonical release history находится в `CHANGELOG.md`.

## Языковая политика документации

- `README.md` является основным английским источником.
- `README.ru.md` является основной русской версией для lab work и quick onboarding.
- Первая строка обоих README-файлов является переключателем языка:

```md
Language: [English](README.md) | [Русский](README.ru.md)
```

- Русский README следует английскому README и не описывает отдельное поведение.
- Если английский README меняется, обновляйте `README.ru.md` в том же релизе, когда это возможно.
- `CHANGELOG.md` ведётся на английском.
- `CONTRIBUTING.md` ведётся на английском; изменения русского README приветствуются, если сохраняют смысл английской версии.

## Быстрый старт

Короткий путь: создать локальное Python-окружение, анонимизировать один syslog text file и убедиться, что output и mapping файлы созданы.

План работы:

- подготовить Python virtual environment;
- установить зависимости из `requirements.txt`;
- запустить anonymizer для одного input text file;
- проверить output file и mapping file;
- посмотреть первые анонимизированные строки.

### 1. Клонируйте репозиторий

```bash
git clone https://github.com/foksk76/kerio-syslog-anonymizer.git
cd kerio-syslog-anonymizer
```

Если всё хорошо:

- текущая директория является корнем репозитория;
- файлы `kerio_anonymizer.py`, `requirements.txt` и `README.md` присутствуют.

### 2. Подготовьте окружение

PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python kerio_anonymizer.py --help
```

Bash:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python kerio_anonymizer.py --help
```

**Что можно менять**

- Значение `--input`: путь к исходному syslog text file.
- Значение `--output`: путь к anonymized output file.
- Значение `--mapping`: путь к mapping JSON file.
- Значение `--input-encoding`: используйте `cp1251` или `cp866`, если источник не UTF-8.
- Значение `--seed`: optional deterministic seed для fake generation.

**Что важно**

- Используйте тот же `mapping.json`, когда нужны стабильные fake values между запусками.
- Не публикуйте mapping file, если вы осознанно не принимаете, что он содержит replacement history.
- `127.0.0.1` намеренно сохраняется и не анонимизируется.

### 3. Запустите проект

Создайте или скопируйте исходный текстовый syslog-файл с именем `input.txt` в корень репозитория, затем выполните:

```powershell
python kerio_anonymizer.py --input input.txt --output output.txt --mapping mapping.json
```

Если input file использует не UTF-8 кодировку, выполните:

```powershell
python kerio_anonymizer.py --input input.txt --output output.txt --mapping mapping.json --input-encoding cp1251
```

Если всё хорошо:

- команда завершится с `Done.`;
- будет напечатан output path;
- будет напечатан mapping path;
- после запуска появятся `output.txt` и `mapping.json`.

Для этого quick start не нужен live Kerio Connect server. Можно использовать сохранённый text file или минимальное событие ниже.

Чтобы получить исходный лог через Kerio Connect API вместо чтения `input.txt`, скопируйте пример окружения и отредактируйте его:

```powershell
Copy-Item .env.example .env
notepad .env
```

Задайте в `.env` как минимум эти значения:

- `KERIO_API_URL`: адрес Kerio Connect Admin API JSON-RPC, например `https://kerio.example.local:4040/admin/api/jsonrpc/`.
- `KERIO_API_USER`: учётная запись Kerio, которой разрешено читать или экспортировать логи.
- `KERIO_API_PASSWORD`: пароль этой учётной записи.
- `KERIO_LOG_NAME`: лог для экспорта, например `mail`.

Затем выполните:

```powershell
python kerio_anonymizer.py --kerio-fetch-log --output output.txt --mapping mapping.json
```

Если всё хорошо:

- скрипт войдёт в Kerio Connect API;
- выбранный лог будет экспортирован как plain text;
- `output.txt` и `mapping.json` будут созданы или обновлены.

### 4. Проверьте результат

Проверьте, что output и mapping файлы существуют:

```powershell
python -c "from pathlib import Path; print(Path('output.txt').exists(), Path('mapping.json').exists())"
```

Если всё хорошо:

- команда напечатает `True True`.

Проверьте, что mapping keys являются hashed:

```powershell
python -c "import json; data=json.load(open('mapping.json', encoding='utf-8')); category=next(iter(data.values()), {}); first=next(iter(category), 'empty'); print(first)"
```

Если всё хорошо:

- напечатанный ключ начинается с `sha256:`;
- или команда печатает `empty`, если input не содержал поддерживаемых sensitive fields.

Посмотрите первые строки anonymized file:

```powershell
Get-Content output.txt -TotalCount 5
```

Если всё хорошо:

- поддерживаемые sensitive values заменены на fake values;
- `127.0.0.1` остаётся без изменений, если он есть в source file.

### 5. Зафиксируйте итог

После шагов выше:

- `output.txt` содержит anonymized syslog text;
- `mapping.json` содержит deterministic fake values по hashed real values;
- повторные запуски с тем же mapping сохраняют correlation stable.

## Проверка Audit Matrix

В этом репозитории нет отдельного audit или protocol matrix runner.

Используйте verification commands из Quick Start. Audit и protocol validation относятся к более широким Kerio lab и ELK pipeline репозиториям, когда они присутствуют.

## Минимальный пример события

```text
<22>1 2026-04-01T14:59:32+07:00 mx01.example.local audit - - - IMAP: User john.doe@example.local authenticated from IP address 10.150.90.11
```

Сохраните его как `input.txt`, чтобы выполнить Quick Start без реального export file.

## Нормализованный результат

Точные fake values зависят от mapping file и seed, но результат должен сохранять форму события и заменять поддерживаемые sensitive values:

```text
<22>1 2026-04-01T14:59:32+07:00 domain-7707198324.example.invalid audit - - - IMAP: User pamela_roberts@domain-8f60ae24ab.example.invalid authenticated from IP address 10.205.220.170
```

## Чеклист проверки

- [ ] Репозиторий успешно клонирован
- [ ] Окружение подготовлено
- [ ] Зависимости установлены из `requirements.txt`
- [ ] `python kerio_anonymizer.py --help` завершился успешно
- [ ] `output.txt` создан
- [ ] `mapping.json` создан или обновлён
- [ ] Mapping keys начинаются с `sha256:`
- [ ] Повторные запуски сохраняют deterministic replacements
- [ ] Русский README остаётся согласованным с английским README при изменении поведения

## Устранение неполадок

### Проблема: требуется пакет `Faker`

**Симптомы**

- скрипт завершается до обработки input file;
- ошибка упоминает `Faker`.

**Что проверить**

- virtual environment активирован;
- зависимости из `requirements.txt` установлены.

**Как исправить**

```powershell
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Проблема: input text выглядит повреждённым или нечитаемым

**Симптомы**

- кириллица или другой non-ASCII text отображается некорректно;
- subjects или names читаются не так, как ожидалось.

**Что проверить**

- исходный файл может быть не в UTF-8.

**Как исправить**

```powershell
python kerio_anonymizer.py --input input.txt --output output.txt --mapping mapping.json --input-encoding cp1251
```

Если проблема остаётся, попробуйте `--input-encoding cp866`.

### Проблема: PowerShell блокирует activation virtual environment

**Симптомы**

- `.venv\Scripts\Activate.ps1` блокируется execution policy.

**Что проверить**

- execution policy текущего процесса PowerShell.

**Как исправить**

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.venv\Scripts\Activate.ps1
```

### Проблема: старый mapping file всё ещё содержит plain-text keys

**Симптомы**

- старый `mapping.json` содержит исходные значения вместо `sha256:` keys.

**Что проверить**

- файл мог быть создан до добавления hashed-key normalization.

**Как исправить**

```powershell
python kerio_anonymizer.py --input input.txt --output output.txt --mapping mapping.json
```

Если всё хорошо:

- mapping нормализуется при сохранении, а будущие ключи используют формат `sha256(category:value)`.

## Что проект не делает

- Не разворачивает Kerio Connect.
- Не запускает Logstash, Elasticsearch, Kibana или Grafana.
- Не предоставляет streaming syslog listener.
- Не выполняет полное обнаружение всех возможных PII в произвольном тексте.
- В текущем виде не ориентирован на IPv6 anonymization.
- Не заменяет vendor documentation или формальную data handling policy.

## Что важно знать

- Deterministic anonymization сделана намеренно: dashboards, parser tests и investigations требуют stable correlation.
- `mapping.json` хранит hashed real keys, но всё равно отражает replacement history и должен проверяться перед публикацией.
- `127.0.0.1` сохраняется без изменений.
- Encoding input file важен для кириллических names и subjects.
- Kerio Connect является proprietary vendor software. Этот репозиторий не распространяет Kerio Connect или vendor-restricted artifacts.

## Roadmap

См. [NEXT_STEPS.md](./NEXT_STEPS.md)

## Changelog

См. [CHANGELOG.md](./CHANGELOG.md)

`CHANGELOG.md` остаётся canonical и English-only, если репозиторий явно не решит иначе.

## Handoff

См. [HANDOFF.md](./HANDOFF.md)

## Участие в проекте

См. [CONTRIBUTING.md](./CONTRIBUTING.md)

Contribution guidelines указывают, что:

- English является основным языком документации и review;
- Russian README updates приветствуются, если они сохраняют смысл English README;
- Russian documentation должна помогать onboarding без изменения описанного поведения.

## GitHub Release Notes

GitHub Release Notes остаются на английском.

Используйте такую структуру для docs-only releases:

```md
## Operational Changes

- Documentation now follows the Kerio project family README template.
- Russian README content was aligned with the English README.
- No runtime behavior changed.

## Validation

- README language switchers were checked in both English and Russian documents.
- README headings were compared against the project template.
- `python kerio_anonymizer.py --help` completed successfully.

## Engineer Notes

- No runtime configuration change is required.
- Use the updated README when onboarding a new engineer or reviewing the anonymization workflow.
```

## Безопасность

См. [SECURITY.md](./SECURITY.md)

## Поддержка

См. [SUPPORT.md](./SUPPORT.md)

## Лицензия

См. [LICENSE](./LICENSE)
