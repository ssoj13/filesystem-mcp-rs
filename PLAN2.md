# PLAN2.md — Computer Control suite

Status: FINAL draft — 3-planner wave + self adversarial critic pass (§10) + resolved forks (§11).

---

## 1. Verdict (architecture)

**Separate repo `cglibs/computer-mcp-rs`, lib + bin in one repo.**

- lib = primitives: `input/`, `win/`, `uia/`, `ocr/`, `capture/`, `steps/`, `safety/` (arm gate lives in the lib so every consumer inherits it).
- bin = thin rmcp MCP server (`srv/`), tool registry only.
- No cross-deps between filesystem-mcp-rs and computer-mcp-rs in v1. ~100 lines of screenshot/window-listing duplication accepted; promote to shared crate only on third-consumer evidence.
- No third `cg-ctl` repo until a second real consumer exists (systemsgo: no speculative artifacts).
- Why not fold into filesystem-mcp-rs: passive capture (existing) vs active input injection are different consent classes; MCP permissions are per-server → separate binary = explicit opt-in; matches repo-per-MCP-server house pattern (flow-mcp-rs).

## 2. Dependencies

| Need | Crate | Note |
|---|---|---|
| SendInput, SetForegroundWindow, win ops, DPI | `windows` crate (KeyboardAndMouse, WindowsAndMessaging, Dwm, HiDpi, Foundation) | no third-party input crates |
| UI Automation | **`uiautomation` 0.25.x** (leexgone) — VERIFIED 2026-08-28, actively maintained | wraps windows-core ^0.62; features: pattern, control, process, event |
| OCR | `windows` WinRT Media_Ocr (+ Graphics_Imaging, Globalization) | OcrWord.BoundingRect native; `IAsyncOperation::get()` blocks — run on blocking pool |
| Toast | `tauri-winrt-notification` (VERIFY AUMID gotcha for unpackaged exe) | reuse an installed AUMID or toast silently vanishes |
| CF_HDROP | `clipboard-win` 5.x | arboard has no file lists; arboard stays for text/image |
| Capture | `xcap` (already house dep) | requires DPI-aware process first |

- No FFI, no custom unsafe (crates own it). No silent fallbacks: missing OCR language packs → explicit error.

## 3. Tool surface — 20 tools

Window target shape everywhere: `id | title (substring) | exe (substring)`. Success = flat JSON carrying next-step state (pos+hover, focus, rect, hash). Failure = `{error:{code,msg,hint}}`; codes: not_armed, no_match, timeout, denied, unsupported.

| Tool | Params (main) | Notes |
|---|---|---|
| `arm` | `on?=true, ttl_ms?=30000` | single gate tool (no pair), TTL auto-expires, no sliding renewal; gates mouse_*/key_*/input_macro/win_geom/win_close/win_layout(load) |
| `capture` | `target: {monitor}\|{win}\|{rect}\|{cursor:{size?400}}`, `save?`, `inline?=false` | replaces capture_screen/region/window + screenshot_list_monitors; returns {path, hash, rect}; never inline by default |
| `monitors` | — | monitor list with rects + scale |
| `mouse_click` | `x?,y?,button?=left,clicks?=1` | clicks:0 = hover/move; returns {pos, hover:{win_id,title}} |
| `mouse_drag` | `from?, to, button?, steps?=10` | interpolated path |
| `mouse_scroll` | `dy, dx?, x?, y?` | dy>0 = down |
| `key_tap` | `key: "ctrl+shift+t", hold_ms?` | returns {focus} — free focus verification |
| `key_type` | `text, paste?=true` | paste = clipboard roundtrip w/ save+restore; synthetic KEYEVENTF_UNICODE fallback; returns {focus, chars} |
| `input_macro` | `steps, gap_ms?=30, stop_on_fail?=true, dry_run?=false` | caps 40 steps / 30s wall; steps = discriminated union (click/key/type/wait/wait_screen/capture/focus/drag/scroll/move); fail-fast; per-step results |
| `wait` | `kind: screen_change\|window\|clipboard, since?: hash, timeout_ms?=3000, poll_ms?` | replaces win_wait/wait_screen_change |
| `ocr` | `target (capture target shape), find? -> bbox mode` | Windows.Media.Ocr; explicit error if no language packs |
| `ui` | `query?, depth?=2, max?=50` | UIA tree, server-side filter mandatory (raw trees are token bombs); depth:0 = element text |
| `ui_click` | `query, idx?=0` | UIA Invoke pattern first, real click fallback |
| `ui_set` | `query, value` | UIA Value pattern |
| `win_list` | `query?:{title?,exe?}, parent?, active flag` | covers win_active/info/children |
| `win_focus` | `target` | foreground-lock workaround internal; returns final focus state |
| `win_geom` | `id, x?,y?,w?,h?, state?:min\|max\|restore` | move+resize+min/max/restore merged |
| `win_close` | `id` | SEPARATE tool name so per-tool allowlists can exclude it |
| `win_layout` | `op: save\|load, name, dry_run(load)=true` | bulk restore defaults dry-run |
| `notify` | `title?, msg, sound?=false` | toast; "needs human" signal |

Clipboard: extend existing `clipboard_read/write` schema with a `files` field (CF_HDROP) — no new tool.

## 4. Safety model

- `arm{on,ttl_ms}` — single gate, TTL auto-expiry, no sliding renewal. Gates input injectors + bulk mutations only; read/explore tools stay ungated.
- dry_run survives only on bulk tools (input_macro, win_layout load).
- Audit: JSONL log of executed input actions while armed.
- Runaway protection: macro caps (40 steps / 30 s), fail-fast, no fire-and-forget chains.

## 5. Blocking model

- ONE dedicated STA COM thread (CoInitializeEx APARTMENTTHREADED) owns ALL UIA ops: mpsc request in, oneshot out; daemon thread.
- `spawn_blocking` for SendInput batches, clipboard, capture, OCR, toast.
- One `std::sync::Mutex` serializing SendInput holds macro key ordering under concurrent calls.
- No CoreDispatcher / message pump anywhere.

## 6. Top risks (ranked)

1. **Foreground lock** — SetForegroundWindow from background fails; chain: minimize→restore → ALT-trick → AttachThreadInput (last resort); verify with GetForegroundWindow poll (~1 s), fail loudly.
2. **Per-monitor DPI** — SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2) as first line of main(), before any hwnd/xcap.
3. **UIPI/elevated targets** — explicit "target elevated" error, never silent no-op.
4. **UAC secure desktop** — detect via OpenInputDesktop failure → error, no retry.
5. **Focus race** — focus-verify loop + 50–100 ms settle before SendInput.
6. **screen_hash** — downscaled 256×144 luma dhash with epsilon (not raw diff); doubles as pre-OCR change gate.
7. **KEYEVENTF_UNICODE rejection** — DirectInput/RDP/IME apps; ASCII→scan codes, unicode only for non-ASCII, paste mode for long text.
8. **Macro timing** — check SendInput return count (partial → retry), ~10 ms inter-key delay, paired down/up.

## 7. Quirks checklist

- Foreground-lock workaround mandatory — plain SetForegroundWindow silently fails from a background process.
- xcap `WindowInfo.id` on Windows ≈ HWND — VERIFY at impl time; else map xcap id↔HWND once in win/.
- Toast AUMID for unpackaged exe.
- Clipboard restore order in key_type paste mode (save → set → paste → restore, even on failure).
- Win11 Notepad is WinUI (different UIA tree) — test with classic notepad.exe canary too.

## 8. Phases

- **P1 MVP (input+focus+capture):** arm, mouse_click, mouse_drag, mouse_scroll, key_tap, key_type, win_focus, win_list, capture, monitors. Acceptance: arm → focus Notepad → click inside → type ASCII+Unicode → capture window → hash changed. ≤3 round trips.
- **P2 (batching + waits):** input_macro, wait, win_geom, win_close, winlayout-save/load, notify, CF_HDROP clipboard files. Acceptance: one-round-trip macro "click→type→Enter→verify via wait_screen".
- **P3 (understanding):** ui, ui_click, ui_set, ocr; find-and-click hierarchy `UIA → OCR → pixels`. Acceptance: click by element name and by on-screen text without pixel coords.

## 9. Testing

- Unit: combo parser, coordinate clamping, macro validation, arm gate.
- Canary: classic notepad.exe — launch → focus+verify → type ASCII+unicode → assert via UIA ValuePattern → OCR ⊇ typed text → screen_hash changed.
- Env-gated `#[ignore]` for interactive-desktop tests (CI session-0 must skip, not fail).
- Elevated/UAC paths: manual checklist.

## 10. Critic findings (self-pass, marked NON-INDEPENDENT)

> Performed by the orchestrator (same model family as 2 of 3 planners) after grok headless proved
> broken in non-TTY (`-p` hangs 3×, zero output; `doctor`/`models` instant). Treat as first-line
> review, not cross-model verification.

CONFIRMED (breaks something):
1. **arm TTL mid-macro** — TTL 30 s can expire inside a 30 s macro → silent refusals. Fix: per-step arm re-check; `arm` returns `armed_until`; `not_armed` error carries `remaining_ms: 0`.
2. **key_type paste:true can paste into the WRONG window** after a failed focus change — worse than slow typing (may leak clipboard into a foreign app). Fix: paste mode gated on focus verification; mismatch → explicit error, no paste; response always reports `{mode_used, clipboard_restored}`. Synthetic-unicode fallback only opt-in (no silent fallback).
3. **STA COM thread lifecycle** — cancelled MCP caller drops the oneshot; result send must be non-fatal (try-send), and the queue forbids nested/re-entrant dispatch.
4. **PER_MONITOR_AWARE_V2 "first line of main()" fails** (E_ACCESSDENIED) when a host app embedding the lib already set awareness. Fix: `ensure_dpi_aware()` = set-if-possible + query actual context; success when already set.
5. **Negative coordinates** — existing `capture_region` rejects x/y < 0, so left/upper monitors are unreachable. New `capture` must use virtual-screen space (negative coords allowed).
6. **WinRT OCR has NO per-word confidence** — drop `conf` from `ocr` output ({text, rect} only).
7. **arboard + clipboard-win both open the clipboard** → one clipboard facade, single Mutex over ALL clipboard ops.

PLAUSIBLE (watch):
- xcap capture is GDI-based — hardware-overlaid video/games may come out black; PrintWindow/PW_RENDERFULLCONTENT fallback for window captures; document, never silent black frames.
- Macro wall cap counts wait timeouts — long macros must be split; document.
- Combo parser must resolve to VK codes (layout-independent), not characters.
- "~100 lines duplication" is really ~300–500 (target resolution + DPI + hash pipeline); acceptable for v1, written once inside computer-mcp-rs.

Amendments folded into plan: A) arm per-step re-check + ops/min runaway cap; B) focus-gated paste;
C) STA queue contract + clipboard facade; D) ensure_dpi_aware + virtual-screen coords; E) win_layout load dry_run=false (save returns preview), ocr without conf.

## 11. Operator forks — RESOLVED

1. **Separate repo `cglibs/computer-mcp-rs`** — confirmed by operator ("можно сделать отдельным крейтом").
2. **arm TTL 30 s** — kept; `armed_until` returned; per-step re-check per critic A.
3. **key_type paste:true default** — kept WITH focus gate per critic B.
4. **arboard stays** (text/image) + clipboard-win (CF_HDROP) behind one facade Mutex; revisit "replace arboard" only if friction appears.
