# driver/ — the OS seam of the computer module

**Что это.** Единственная точка контакта модуля computer-control с операционной
системой. Всё, что выше (`safety`, `steps`, `wait`, `capture`, `find`,
`annotate`, `ocrs_local`, `server_*`), портируемо и ходит в ОС только сюда.

**Зачем.** Один и тот же набор из 26 MCP-тулов должен работать на Windows,
Linux (X11 и Wayland) и macOS, не размазывая `#[cfg]` по всему модулю.

**Как устроено.**
- `mod.rs` — портируемые типы, доменные трейты, реестр бэкендов, рантайм-выбор,
  фасад свободных функций (`driver::click(...)` и т.д.), тест-страж шва.
- `portable.rs` — операции, собранные из трейтов и работающие на любой ОС:
  `resolve_target`, `to_monitor`, `layout_save`, `layout_load`.
- `win32/`, `x11/`, `wayland/`, `mac/`, `null` — бэкенды, по каталогу на штуку.

## Доменные трейты

| Трейт | Операции | Кто реализует |
|---|---|---|
| `InputDrv` | move_cursor, click, drag, scroll, key_tap, type_text, cursor_pos, focus | все |
| `WinDrv` | list, focus_window, geom, close, active, alive | все |
| `ScreenDrv` | virtual_screen, color_at | все |
| `ClipDrv` | get_files, set_files, seq | win32; на Unix — позже |
| `NotifyDrv` | notify | win32; на Unix — позже |
| UIA (флаг `has_uia`) | дерево элементов | только win32 |

Отсутствующий домен — это `None`, из которого фасад делает громкий
`unsupported on this platform (<backend>): <что именно>`. Тихих no-op нет
нигде: молчаливый фолбэк порождает «плавающие» баги, которые потом ловятся
днями.

## Матрица бэкендов и статус верификации

| Бэкенд | Ввод | Окна | Экран | Буфер | Тосты | UIA | Статус |
|---|---|---|---|---|---|---|---|
| `win32` | SendInput | HWND/Win32 | GDI + SystemMetrics | CF_HDROP | WinRT toast | UIAutomation | **проверен живьём** |
| `x11` | XTEST (x11rb) | ICCCM/EWMH | RandR | — | — | — | не начат |
| `wayland` | wlr-virtual-\* / libei | wlr-foreign-toplevel | wl_output | — | — | — | не начат |
| `mac` | CGEventPost | CGWindowList + AX | CGDisplay | NSPasteboard | UNUserNotification | AX (`ui_*`) | implemented; live verify pending |
| `null` | — | — | — | — | — | — | громкий unsupported |

`verified_on_hardware` в `Caps` отражает эту колонку и выдаётся тулом
`ctl_caps` — агент видит, доверять ли платформе.

## Как добавить бэкенд

1. Каталог `driver/<name>/mod.rs` со структурой-синглтоном, реализующей `Backend`
   и те доменные трейты, которые платформа реально тянет.
2. Одна ветка в `select()` в `mod.rs`.
3. Одна фича в `Cargo.toml` + target-таблица для системных зависимостей.
4. Строка в матрице выше со статусом верификации.

Больше нигде ничего не меняется — в этом смысл шва.

## Ловушки

- **Выбор бэкенда — рантаймовый, не компайл-таймовый.** На Linux X11 vs Wayland
  решается по живой сессии (`WAYLAND_DISPLAY`/`DISPLAY`). Переопределяется
  переменной `FS_MCP_CTL_BACKEND=win32|x11|wayland|null` — удобно, чтобы
  прогнать unsupported-пути на машине с настоящим десктопом.
- **Координаты везде — физические пиксели виртуального экрана**, origin может
  быть отрицательным. Ни один бэкенд не имеет права молча приводить их к
  логическим.
- **Id окна — `u32`.** На Windows это HWND, на других платформах непрозрачный
  хендл бэкенда. Наружу утекать смысл id не должен.
- **`layout_*` и `to_monitor` — портируемые**, живут в `portable.rs`. Не
  переписывать их в бэкенде: в ОС из них уходят только `geom` и `alive`.
- **Тест-страж `seam_guard`** в `mod.rs` читает исходники портируемых файлов и
  падает, если там появился прямой `windows::`/`x11rb`/`super::win::` и прочее.
  Добавил новый портируемый файл — впиши его в список `PORTABLE`.
