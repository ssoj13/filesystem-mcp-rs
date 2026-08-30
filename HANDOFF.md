# HANDOFF.md — filesystem-mcp-rs + computer-mcp-rs (2026-08-30)

## Состояние: ВСЁ ЗАКОНЧИНО И ЗАПУШЕНО. Чистый старт для любой новой задачи.

## Что это за проекты
- **filesystem-mcp-rs** (публичный): Rust MCP сервер, 131 тул. v0.2.1, HEAD `10ab49e`, main == origin/main.
- **computer-mcp-rs** (ПРИВАТНЫЙ, github ssoj13/computer-mcp-rs): standalone-версия computer-control
  (lib + bin). Паритет с fs-модулем. HEAD `0d889e5`.

## Ключевая архитектура (не переоткрывать)
- Компьютер-контроль живёт в `src/tools/computer/` fs-репо как самодостаточный модуль.
  `driver/mod.rs` = OS-шов: `imp` бэкенд (windows / не-Windows fallback с громким
  `unsupported`), нейтральные типы (Btn/Ease/KeyMod/FocusInfo/WinInfo/WinTarget),
  `Caps` (ctl_caps тул показывает что реально на этой OS).
- Флаги: `computer-tools` = umbrella над `ctl-input`(ядро, тянет screenshot-tools) /
  `ctl-uia`(тянет ctl-input) / `ctl-ocr` / `ctl-notify` / `ctl-clip-files`.
  НЕ в default features.
- rmcp 3.1.4 НЕ умеет cfg-gate #[tool] методы в одном impl (S1 spike) → per-domain
  #[tool_router(router = X, vis = "pub(crate)")] + ToolRouter::merge в FileSystemServer::new.
- 26 ctl-тулов: arm, ctl_caps, monitors, capture, mouse_click/drag/scroll, key_tap,
  key_type, input_macro (${N.path} result refs!), wait (screen_change/window/clipboard/
  color), win_focus/list/geom/close/layout/to_monitor, color, ui/ui_click/ui_get/ui_set,
  ocr (engine: media|ocrs), find_image, notify, clip_files_get/set.

## Верифицированные API-факты (не переоткрывать — всё проверено live/по исходникам)
- windows 0.62: SendInput(&[INPUT], i32); IsWindow(Option<HWND>); GetProcessDpiAwarenessContext
  УДАЛЁН (исп. GetThreadDpiAwarenessContext); HWND = !Send (не возвращать из spawn_blocking);
  GetForegroundWindow/WHEEL_DELTA живут в WindowsAndMessaging, НЕ в KeyboardAndMouse.
- xcap 0.9.8: Window::id() == hwnd.0 as u32; from_hwnd ctor НЕТ (перебор Window::all()).
- uiautomation 0.25: element_from_handle(Handle::from(hwnd)); UIMatcher::new(auto).from(el)
  .depth(d).timeout(ms).find_all(); get_bounding_rectangle() -> f32 Rect; get_automation_id /
  get_classname / is_offscreen / get_pattern::<T>() (Invoke/Toggle/Value/RangeValue/
  ExpandCollapse/SelectionItem/ScrollItem; toggle()/get_toggle_state()/set_value()).
- windows-future 0.3: НЕТ блокирующего .get(); использовать futures::executor::block_on(op.into_future()).
- ocrs 0.13 + rten 0.26: ImageSource::from_bytes(rgb8_raw, dims); engine.recognize_text;
  модели качаются с ocrs-models.s3-accelerate.amazonaws.com (*.rten) атомарно (.part -> rename)
  в %APPDATA%\computer-mcp-rs\ocrs; env override FS_MCP_CTL_OCRS_MODELS_DIR.
- rmcp 3.1.4: с with_structured это СОБСТВЕННЫЙ WithStructured trait fs (main.rs);
  tool_router attr принимает router=/vis=/server_handler=; JsonSchema из schemars,
  НЕ из rmcp::serde.

## ctl-t API quirks (проверено live)
- capture CapTarget принимает ВСЕ формы cursor: {cursor:{size:N}}, {cursor:N}, {size:N},
  {rect:{...}}, {x,y,w,h} — через CursorSize untagged enum (коммит 4813941). 4/4 live.
- key_type: paste mode (default) ~100x быстрее unicode; focus-gated (отказ если фокус ушёл);
  clipboard juggle с interloper-guard (чужой контент не затирается, restored=false).
- chars-режим печати < ~25ms ломает серии (последний символ повторяется, детерминированно) —
  30ms verified; unicode на 3ms роняет символы в Win11 Notepad. Дефолт 30ms.
- ui_click pattern-aware: Invoke -> Toggle -> ExpandCollapse -> SelectionItem -> click;
  offscreen -> scroll_into_view; поиск по имени ИЛИ automation id (id приоритет).
- ui_get — «посмотри прежде чем действовать» (без арма).
- drag: duration_ms (16ms чанки) + ease (linear|out) + hold_ms (settle с зажатой кнопкой).
- input_macro: 40 шагов / 30s wall cap, fail-fast, per-step arm re-check.

## Сторонние баги (не переоткрывать)
1. `omc ask grok` сломан на Windows (DEP0190 + голый -p). Workaround: прямой headless grok.
2. grok 1.0.5 headless `-p` ВИСНЕТ в non-TTY (3x проверено). Интерактивный TUI работает.
3. write_file `content`: canonical = ContentRef object; голая строка толерируется как inline
   (v0.2.1), JSON-encoded ContentRef разворачивается. Ограничение inline/chunk теперь 64 KiB.
4. Win11 Notepad session restore подмешивает старый текст в заголовок после force-kill —
   тестовый харнесс должен чистить %LOCALAPPDATA%\Packages\...\TabState.

## Деплой / сборка
- `cargo build --release --features computer-tools` -> target\release\filesystem-mcp-rs.exe
- Деплой: скопировать в C:\Users\joss1\.cargo\bin\filesystem-mcp-rs.exe. Файл может быть
  залочен живым сервером — тогда rename старый (.old.N) и копировать новый.
- `filesystem-mcp-rs install` регистрирует во все клиентские конфиги + пишет env
  (FS_MCP_CTL_TYPE_MODE=paste|chars, TYPE_INTERVAL_MS=30, ARM_TTL_MS=30000, OPS_PER_MIN=240).
- Тесты: cargo test --features computer-tools (464+4+64, все зелёные). Clippy чист
  (кроме pre-existing line_edit.rs j-loop и integration.rs assert warnings).

## Прожитая сессия (хронология решений)
1. PLAN2.md: computer-control дизайн через 3 planner-агентов + self-critic. Артефакт в корне.
2. P1 (MVP) -> P2 (macro/wait/geom) -> P3 (UIA/OCR) -> всё в computer-mcp-rs, потом FOLDED IN
   в fs как src/tools/computer/ (решение оператора: один крейт, модуль за флагами).
3. driver/mod.rs абстракция — для будущих mac/Linux бэкендов (enigo/AX/AT-SPI — не начинали).
4. mcp-setup-rs integration: install пишет env-переменные (в strict JSON конфигах нельзя
   комментарии — пишутся активными с дефолтами).
5. Макро-записыватель, temp drag, color/wait_color, find_image (coarse-to-fine NCC на luma,
   без OpenCV), ocrs engine — всё сделано и запушено.
6. UIA hardening (последняя волна): auto_id/class/patterns/toggle/value/offscreen в ui,
   pattern-aware ui_click, ui_get тул, поиск по automation id.

## ОСТАВШИЕСЯ ПЛАНЫ (не начаты)
1. **Macro recorder** (следующий по приоритету): глобальные хуки WH_MOUSE_LL/WH_KEYBOARD_LL,
   запись под arm-гейтом, старт/стоп тулами, экспорт в input_macro steps JSON, реплей через
   существующий engine. Хуки требуют message pump на выделенном потоке (Win32).
2. **Enigo-бэкенды mac/Linux**: driver/mod.rs imp уже готов к этому; enigo покрывает ввод,
   xcap уже кроссплатформенный. Wayland — частично (заявлять wlroots + XWayland).
3. **Cross-repo sync**: lib-файлы fs <-> computer-mcp-rs копируются + sed super:: <-> crate::
   (записано в обоих CLAUDE.md). computer-mcp-rs сейчас на 0d889e5 — БЕЗ последних fs-волн
   (UIA hardening, cursor shapes fix). Синкать при следующем касании.
4. Мелочи: annotate tool, mixed-DPI field tests, legacy `find_named` в uia.rs теперь #[cfg(test)].

## Операторские правила (важно!)
- НЕ использовать opus/fable для агентов — только GLM (сессия). Уже в persistent memory.
- Всегда Read перед Edit (hooks падают иначе).
- systemsgo: двойная проверка агентов, системные решения над хаками, git reset ЗАПРЕЩЁН.
- Ответы в чате на русском; код/комменты/файлы — английский.
- Большие файлы в MCP-инструменты: blob_begin/append/finalize или {kind:path}; write_file
  content иногда ломается при двойном JSON-энкодинге (сервер теперь толерантен, но не rely).
