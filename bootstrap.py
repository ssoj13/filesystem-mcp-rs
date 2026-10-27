#!/usr/bin/env python3
"""
bootstrap.py - Unified local build, check, test and install script for filesystem-mcp-rs.

Cross-platform, Python 3, stdlib only. Same shape as the oh-my-harness and
opengram-rs bootstraps; the commands are this project's.

Commands (short or long, either works):
    reqs  req       install system prerequisites (`reqs [linux|windows|macos]`)
    b     build     build the workspace (release; -d for debug)
    t     test      run every test (-n to see their output)
    c     check     fmt --all --check + clippy --all-targets -- -D warnings
    i     install   cargo install --path . --locked + `filesystem-mcp-rs install`
    cl    clean     cargo clean
    h     help      print this help text
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).parent.resolve()
IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"

LINUX_PACKAGES = [
    "pkg-config",
    "clang",
    "libclang-dev",
    "libgbm-dev",
    "libpipewire-0.3-dev",
    "libspa-0.2-dev",
    "libwayland-dev",
    "libegl1-mesa-dev",
    "libglvnd-dev",
]


class C:
    RST = "\033[0m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YLW = "\033[93m"
    CYN = "\033[96m"
    WHT = "\033[97m"
    DIM = "\033[90m"

    @classmethod
    def init(cls) -> None:
        if IS_WINDOWS:
            os.system("")


def fmt_time(ms: float) -> str:
    if ms < 1000:
        return f"{ms:.0f}ms"
    if ms < 60000:
        return f"{ms / 1000:.1f}s"
    return f"{int(ms // 60000)}m{(ms % 60000) / 1000:.0f}s"


def header(text: str) -> None:
    print(f"\n{C.CYN}{'=' * 60}\n{text}\n{'=' * 60}{C.RST}")


def step(text: str) -> None:
    print(f"  {C.WHT}{text}{C.RST}")


def ok(text: str) -> None:
    print(f"  {C.GRN}[OK] {text}{C.RST}")


def warn(text: str) -> None:
    print(f"  {C.YLW}[WARN] {text}{C.RST}")


def err(text: str) -> None:
    print(f"  {C.RED}[ERR] {text}{C.RST}")


def run(args: list[str], cwd: Path | None = None) -> tuple[int, float]:
    """Run a command from the repository root and report how long it took."""
    start = time.perf_counter()
    print(f"  {C.DIM}$ {' '.join(args)}{C.RST}")
    code = subprocess.run(args, cwd=cwd or ROOT_DIR).returncode
    return code, (time.perf_counter() - start) * 1000


def finish(name: str, code: int, ms: float) -> int:
    if code == 0:
        ok(f"{name} in {fmt_time(ms)}")
    else:
        err(f"{name} failed with exit code {code} after {fmt_time(ms)}")
    return code


def find_cargo() -> str | None:
    found = shutil.which("cargo")
    if found:
        return found
    bin_name = "cargo.exe" if IS_WINDOWS else "cargo"
    cargo_home = Path(os.environ.get("CARGO_HOME") or (Path.home() / ".cargo"))
    candidate = cargo_home / "bin" / bin_name
    if candidate.is_file():
        # Ensure ~/.cargo/bin is on PATH for subprocesses
        os.environ["PATH"] = f"{candidate.parent}{os.pathsep}{os.environ.get('PATH', '')}"
        return str(candidate)
    return None


def check_cargo() -> bool:
    if find_cargo():
        return True
    err("cargo is not on PATH. Install Rust from https://rustup.rs")
    return False


def profile_args(args: argparse.Namespace) -> list[str]:
    return [] if args.debug else ["--release"]


def detect_os(explicit: str | None) -> str | None:
    if explicit:
        norm = explicit.strip().lower()
        if norm in ("linux",):
            return "linux"
        if norm in ("windows", "win", "win32"):
            return "windows"
        if norm in ("macos", "darwin", "mac", "osx"):
            return "macos"
        return None
    sys_name = platform.system().lower()
    if sys_name == "linux":
        return "linux"
    if sys_name == "windows":
        return "windows"
    if sys_name == "darwin":
        return "macos"
    return sys_name


def sudo_prefix() -> list[str]:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return ["sudo"]
    return []


# ─── Commands ────────────────────────────────────────────────────────────────


def cmd_reqs(args: argparse.Namespace) -> int:
    header("Prerequisites")
    explicit = args.rest[0] if args.rest else None
    target_os = detect_os(explicit)
    if target_os is None:
        err(f"unknown OS target: {explicit!r} (expected linux, windows, or macos)")
        return 2

    step(f"Target OS: {target_os}")

    if target_os == "linux":
        prefix = sudo_prefix()
        code, ms1 = run([*prefix, "apt", "update"])
        if code != 0:
            return finish("reqs (apt update)", code, ms1)
        code, ms2 = run([*prefix, "apt", "install", "-y", *LINUX_PACKAGES])
        return finish("reqs", code, ms1 + ms2)

    if target_os == "macos":
        if shutil.which("xcode-select"):
            res = subprocess.run(["xcode-select", "-p"], capture_output=True, text=True)
            if res.returncode == 0:
                ok(f"Xcode Command Line Tools present ({res.stdout.strip()})")
            else:
                warn("Xcode Command Line Tools not found; run: xcode-select --install")
        else:
            step("macOS requires Xcode Command Line Tools (`xcode-select --install`) and Rust (`rustup`).")
        if find_cargo():
            ok("Rust/Cargo present")
        else:
            warn("cargo not found on PATH; install Rust from https://rustup.rs")
        return 0

    if target_os == "windows":
        step("Windows builds require the Rust MSVC toolchain and Visual Studio C++ Build Tools.")
        if find_cargo():
            ok("Rust/Cargo present")
        else:
            warn("cargo not found on PATH; install Rust from https://rustup.rs")
        return 0

    err(f"unsupported OS: {target_os}")
    return 1


def cmd_build(args: argparse.Namespace) -> int:
    header("Build")
    code, ms = run(["cargo", "build", *profile_args(args)])
    return finish("build", code, ms)


def cmd_test(args: argparse.Namespace) -> int:
    header("Test")
    cmd = ["cargo", "test"]
    if args.nocapture:
        cmd += ["--", "--nocapture"]
    code, ms = run(cmd)
    return finish("test", code, ms)


def cmd_check(_args: argparse.Namespace) -> int:
    header("Check")
    step("formatting")
    code, ms1 = run(["cargo", "fmt", "--all", "--check"])
    if code != 0:
        err("formatting differs - run `cargo fmt --all`")
        return finish("check", code, ms1)
    ok(f"formatting in {fmt_time(ms1)}")

    step("clippy, warnings denied")
    code, ms2 = run(["cargo", "clippy", "--all-targets", "--", "-D", "warnings"])
    return finish("check", code, ms1 + ms2)


def cmd_install(args: argparse.Namespace) -> int:
    header("Install")
    cmd = ["cargo", "install", "--path", ".", "--locked"]
    if args.force:
        cmd.append("--force")
    code, ms1 = run(cmd)
    if code != 0:
        return finish("install", code, ms1)

    bin_name = "filesystem-mcp-rs.exe" if IS_WINDOWS else "filesystem-mcp-rs"
    cargo_home = Path(os.environ.get("CARGO_HOME") or (Path.home() / ".cargo"))
    installed_bin = cargo_home / "bin" / bin_name
    exe = str(installed_bin) if installed_bin.is_file() else (shutil.which("filesystem-mcp-rs") or bin_name)

    install_args = list(args.rest)
    if args.force and "--force" not in install_args and "-f" not in install_args:
        install_args.insert(0, "--force")

    step("registering MCP server in coding agents")
    code, ms2 = run([exe, "install", *install_args])
    return finish("install", code, ms1 + ms2)


def cmd_clean(_args: argparse.Namespace) -> int:
    header("Clean")
    code, ms = run(["cargo", "clean"])
    return finish("clean", code, ms)


def cmd_help(_args: argparse.Namespace) -> int:
    print(HELP_TEXT)
    return 0


# ─── Dispatch ────────────────────────────────────────────────────────────────

COMMANDS: list[tuple[str, str, object, str]] = [
    ("reqs", "req", cmd_reqs, "install system prerequisites (`reqs [linux|windows|macos]`)"),
    ("b", "build", cmd_build, "build filesystem-mcp-rs (release; -d for debug)"),
    ("t", "test", cmd_test, "run all tests (-n to show test output)"),
    ("c", "check", cmd_check, "fmt --all --check + clippy --all-targets -- -D warnings"),
    ("i", "install", cmd_install, "cargo install --path . --locked + `filesystem-mcp-rs install`"),
    ("cl", "clean", cmd_clean, "cargo clean"),
    ("h", "help", cmd_help, "print this help text"),
]

ALIASES = {short: handler for short, _long, handler, _help in COMMANDS}
ALIASES.update({long: handler for _short, long, handler, _help in COMMANDS})


def _help_text() -> str:
    lines = [
        "",
        "FILESYSTEM-MCP-RS BUILD SYSTEM",
        "",
        "Unified build, check, test, prerequisite and installation runner.",
        "",
        "COMMANDS",
    ]
    for short, long, _handler, text in COMMANDS:
        lines.append(f"  {short:<5} {long:<8} {text}")
    lines += [
        "",
        "OPTIONS",
        "  -d, --debug       debug profile instead of release (build)",
        "  -n, --nocapture   show test output (test)",
        "  -f, --force       reinstall even if unchanged (install)",
        "",
        "EXAMPLES",
        "  python bootstrap.py reqs         install prerequisites for current OS",
        "  python bootstrap.py reqs linux   install Debian/Ubuntu packages for Linux",
        "  python bootstrap.py b            release build",
        "  python bootstrap.py b -d         debug build",
        "  python bootstrap.py t -n         run test suite with output",
        "  python bootstrap.py c            formatting and clippy gate",
        "  python bootstrap.py i            build, install binary, and register MCP",
        "",
    ]
    return "\n".join(lines)


HELP_TEXT = _help_text()


def parse_cli(argv: list[str] | None = None) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    if argv is None:
        argv = sys.argv[1:]

    if "--" in argv:
        idx = argv.index("--")
        head = argv[:idx]
        after_dashdash = argv[idx + 1 :]
    else:
        head = list(argv)
        after_dashdash = []

    parser = argparse.ArgumentParser(
        prog="bootstrap.py",
        description="filesystem-mcp-rs build system",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command", nargs="?", default="h")
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-n", "--nocapture", action="store_true")
    parser.add_argument("-f", "--force", action="store_true")
    parser.add_argument("-h", "--help", action="store_true", dest="want_help")

    args, unknown = parser.parse_known_args(head)

    if args.want_help:
        args.rest = []
        return parser, args

    handler = ALIASES.get(args.command)
    if handler is None:
        args.rest = []
        return parser, args

    if handler is cmd_reqs:
        flags = [u for u in unknown if u.startswith("-")]
        if flags:
            parser.error(f"unrecognized arguments for {args.command}: {' '.join(flags)}")
        if after_dashdash:
            parser.error(f"unrecognized arguments after '--' for {args.command}: {' '.join(after_dashdash)}")
        if len(unknown) > 1:
            parser.error(f"{args.command} accepts at most 1 OS target, got: {' '.join(unknown)}")
        args.rest = unknown
    elif handler is cmd_install:
        args.rest = unknown + after_dashdash
    else:
        extra = unknown + after_dashdash
        if extra:
            parser.error(f"unrecognized arguments: {' '.join(extra)}")
        args.rest = []

    return parser, args


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    C.init()

    _parser, args = parse_cli(argv)
    if args.want_help:
        print(HELP_TEXT)
        return 0

    handler = ALIASES.get(args.command)
    if handler is None:
        err(f"unknown command: {args.command}")
        print(HELP_TEXT)
        return 2

    if handler not in (cmd_help, cmd_reqs) and not check_cargo():
        return 1
    return handler(args)  # type: ignore[operator]


if __name__ == "__main__":
    sys.exit(main())
