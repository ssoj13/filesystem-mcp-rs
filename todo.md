# Filesystem MCP - Requirements & TODO

> Практические требования на основе реального использования LLM для разработки

## Приоритет 1: Критически нужно

### 1.1 `file_hash` - Хеширование файлов

**Проблема:** Для сравнения файлов приходится читать весь контент или вызывать PowerShell Get-FileHash.

**Параметры:**
```json
{
  "path": "string, required - путь к файлу",
  "algorithm": "string, optional - md5|sha1|sha256|sha512|xxhash64, default: sha256"
}
```

**Возврат:**
```json
{
  "path": "/path/to/file",
  "algorithm": "sha256",
  "hash": "a1b2c3d4...",
  "size": 12345
}
```

**Use cases:**
- Проверка идентичности файлов без чтения контента
- Верификация копирования/экспорта
- Детекция изменений в файлах

---

### 1.2 `file_hash_multiple` - Хеширование нескольких файлов

**Проблема:** При сравнении двух файлов нужно два вызова file_hash.

**Параметры:**
```json
{
  "paths": ["string array, required - список путей"],
  "algorithm": "string, optional, default: sha256"
}
```

**Возврат:**
```json
{
  "results": [
    {"path": "/file1", "hash": "abc...", "size": 100},
    {"path": "/file2", "hash": "abc...", "size": 100}
  ],
  "all_match": true
}
```

---

### 1.3 `compare_files` - Бинарное сравнение файлов

**Проблема:** Нет способа быстро понять где и насколько файлы отличаются.

**Параметры:**
```json
{
  "path1": "string, required",
  "path2": "string, required",
  "max_diffs": "number, optional - макс. кол-во различий для вывода, default: 20",
  "context_bytes": "number, optional - байт контекста вокруг различий, default: 8"
}
```

**Возврат:**
```json
{
  "identical": false,
  "size1": 49964134,
  "size2": 49930475,
  "size_diff": -33659,
  "hash1": "9EDFD4A7...",
  "hash2": "E751A668...",
  "first_diff_offset": 8,
  "total_diff_regions": 2498603,
  "total_diff_bytes": 46278194,
  "match_percentage": 7.38,
  "diff_samples": [
    {
      "offset": 8,
      "length": 3,
      "bytes1_hex": "2e 64 fa",
      "bytes2_hex": "2a e0 f9"
    }
  ]
}
```

**Use cases:**
- Проверка бинарного паритета после экспорта/конвертации
- Поиск различий в бинарных форматах
- Дебаг сериализации

---

## Приоритет 2: Очень полезно

### 2.1 `compare_directories` - Сравнение директорий

**Проблема:** Нет способа сравнить два дерева директорий.

**Параметры:**
```json
{
  "path1": "string, required",
  "path2": "string, required",
  "recursive": "bool, default: true",
  "compare_content": "bool, default: false - сравнивать по хешу или только по имени/размеру",
  "ignore_patterns": ["string array, optional - glob patterns to ignore"]
}
```

**Возврат:**
```json
{
  "identical": false,
  "only_in_first": ["file1.txt", "dir/file2.rs"],
  "only_in_second": ["new_file.txt"],
  "different": [
    {
      "path": "src/main.rs",
      "size1": 1000,
      "size2": 1200,
      "hash1": "abc...",
      "hash2": "def..."
    }
  ],
  "same_count": 150,
  "diff_count": 3
}
```

---

### 2.2 `tail_file` - Чтение конца файла

**Проблема:** read_text_file с tail работает, но нет follow mode для логов.

**Параметры:**
```json
{
  "path": "string, required",
  "lines": "number, optional, default: 10",
  "bytes": "number, optional - альтернатива lines",
  "follow": "bool, optional, default: false",
  "timeout_ms": "number, optional - для follow mode, default: 5000"
}
```

**Возврат:**
```json
{
  "content": "last lines...",
  "lines_returned": 10,
  "file_size": 12345,
  "truncated": false
}
```

**Use cases:**
- Просмотр логов
- Мониторинг output файлов от background процессов
- Дебаг длинных операций

---

### 2.3 `watch_file` - Ожидание изменений

**Проблема:** Нет способа дождаться изменения файла (например, результата билда).

**Параметры:**
```json
{
  "path": "string, required",
  "timeout_ms": "number, optional, default: 30000",
  "events": ["string array, optional - modify|create|delete, default: all"]
}
```

**Возврат:**
```json
{
  "changed": true,
  "event": "modify",
  "new_size": 12345,
  "elapsed_ms": 1523
}
```

---

### 2.4 `read_json` - Чтение JSON с query

**Проблема:** Приходится читать весь JSON и парсить в голове.

**Параметры:**
```json
{
  "path": "string, required",
  "query": "string, optional - JSONPath или jq-like query",
  "pretty": "bool, optional, default: true"
}
```

**Возврат:**
```json
{
  "result": { ... },
  "query_matched": true,
  "total_keys": 15
}
```

---

### 2.5 `read_pdf` - Извлечение текста из PDF

**Проблема:** PDF часто нужно читать для документации.

**Параметры:**
```json
{
  "path": "string, required",
  "pages": "string, optional - '1-5' или '1,3,5' или null для всех",
  "max_chars": "number, optional, default: 50000"
}
```

**Возврат:**
```json
{
  "text": "extracted text...",
  "pages_count": 10,
  "pages_extracted": [1, 2, 3, 4, 5],
  "truncated": false
}
```

---

## Приоритет 3: Nice to have

### 3.1 `archive_extract` - Распаковка архивов

**Параметры:**
```json
{
  "path": "string, required - путь к архиву",
  "destination": "string, required - куда распаковать",
  "format": "string, optional - zip|tar|tar.gz|7z, auto-detect by extension",
  "files": ["string array, optional - конкретные файлы для извлечения"]
}
```

---

### 3.2 `archive_create` - Создание архивов

**Параметры:**
```json
{
  "paths": ["string array, required - что архивировать"],
  "destination": "string, required - путь к архиву",
  "format": "string, optional, default: zip"
}
```

---

### 3.3 `file_stats` - Статистика по файлу/директории

**Параметры:**
```json
{
  "path": "string, required",
  "recursive": "bool, default: true"
}
```

**Возврат:**
```json
{
  "total_files": 1523,
  "total_dirs": 89,
  "total_size": 125000000,
  "total_size_human": "119.2 MB",
  "by_extension": {
    ".rs": {"count": 45, "size": 230000},
    ".toml": {"count": 3, "size": 5000}
  },
  "largest_files": [
    {"path": "data/big.bin", "size": 50000000}
  ]
}
```

---

### 3.4 `find_duplicates` - Поиск дубликатов

**Параметры:**
```json
{
  "path": "string, required",
  "min_size": "number, optional - минимальный размер файла",
  "by_content": "bool, default: true - по хешу или только по размеру"
}
```

**Возврат:**
```json
{
  "duplicate_groups": [
    {
      "hash": "abc123...",
      "size": 12345,
      "files": ["path1", "path2", "path3"]
    }
  ],
  "total_wasted_space": 50000
}
```

---

## Улучшения существующих инструментов

### `grep_files` улучшения
- [ ] Добавить `--invert-match` (показать строки НЕ содержащие паттерн)
- [ ] Добавить `--files-without-match` (файлы без совпадений)
- [ ] Добавить `--count-only` (только количество совпадений на файл)

### `search_files` улучшения  
- [ ] Добавить `--type` фильтр (file/dir/symlink)
- [ ] Добавить `--min-size` / `--max-size`
- [ ] Добавить `--modified-after` / `--modified-before`

### `directory_tree` улучшения
- [ ] Добавить `--max-depth`
- [ ] Добавить `--show-size`
- [ ] Добавить `--show-hash` для файлов

---

## Заметки по реализации

### Библиотеки для Rust:
- Хеширование: `sha2`, `md5`, `xxhash-rust`
- PDF: `pdf-extract` или `lopdf`
- JSON query: `jsonpath-rust` или `serde_json_path`
- Архивы: `zip`, `tar`, `flate2`
- File watching: `notify`

### Приоритет реализации:
1. `file_hash` + `file_hash_multiple` - простое, очень нужное
2. `compare_files` - среднее, очень нужное
3. `read_json` с query - простое, полезное
4. `compare_directories` - среднее, полезное
5. Остальное по мере необходимости

добавить все тесты
убедиться что работает
поправить changelog и readme
