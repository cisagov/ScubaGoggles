#!/usr/bin/env python3
"""
ScubaGoggles UI Launcher

Starts the Streamlit backend and opens the app in a native window via pywebview.
Matches the system light/dark theme unless overridden with --dark or
SCUBAGOGGLES_UI_DARK=1 (see scubaconfigapp for the same env var).
"""

import argparse
import atexit
import ctypes
import importlib.util
import os
import signal
import socket
import subprocess
import sys
import threading
from pathlib import Path

import webview


def _find_free_port() -> int:
    """Find an available port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


def _resolve_app_file() -> Path | None:
    """Return the path to the Streamlit app file."""
    candidate = Path(__file__).parent / "scubaconfigapp.py"
    return candidate if candidate.exists() else None


def _detect_theme() -> str:
    """Return 'dark' or 'light' based on system preference.

    Falls back to light mode if system theme cannot be detected or darkdetect
    is not available.
    """
    try:
        import darkdetect
    except ImportError:
        return "light"

    theme = darkdetect.theme()
    return theme.lower() if theme else "light"


def _env_ui_dark() -> bool:
    """True if SCUBAGOGGLES_UI_DARK requests dark mode (same as config UI)."""
    val = os.environ.get("SCUBAGOGGLES_UI_DARK", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def _is_streamlit_installed() -> bool:
    """Return True if the streamlit package is importable."""
    return importlib.util.find_spec("streamlit") is not None


def main() -> None:
    """Launch the ScubaGoggles UI in a native window."""

    parser = argparse.ArgumentParser(
        description="ScubaGoggles Configuration UI (Streamlit + native window)",
    )
    parser.add_argument(
        "--dark",
        action="store_true",
        help="Force dark theme (ignores system preference)",
    )
    args = parser.parse_args()
    if args.dark:
        os.environ["SCUBAGOGGLES_UI_DARK"] = "1"

    app_to_run = _resolve_app_file()
    if not app_to_run:
        print("No UI application found!")
        print("Please ensure the UI modules are properly installed.")
        sys.exit(1)

    if not _is_streamlit_installed():
        print("Streamlit is not installed!")
        print("Please install requirements:")
        print("  pip install -r requirements.txt")
        sys.exit(1)

    port = _find_free_port()
    url = f"http://localhost:{port}"

    # Detect theme in a background thread while we start Streamlit
    theme_result = {}

    def _bg_detect():
        theme_result["base"] = _detect_theme()

    theme_thread = threading.Thread(target=_bg_detect, daemon=True)
    theme_thread.start()

    # Start Streamlit immediately (theme flag added once detection finishes)
    theme_thread.join()  # typically < 50 ms
    theme_base = theme_result.get("base", "light")
    if _env_ui_dark():
        theme_base = "dark"

    # Keep app-level custom CSS in sync with Streamlit's detected base theme.
    if theme_base == "dark":
        os.environ.setdefault("SCUBAGOGGLES_UI_DARK", "1")

    cmd = [
        sys.executable, "-m", "streamlit", "run",
        str(app_to_run),
        "--server.address", "localhost",
        "--server.port", str(port),
        "--server.headless", "true",
        "--browser.gatherUsageStats", "false",
        "--theme.base", theme_base,
    ]

    def _kill_server(proc: subprocess.Popen) -> None:
        """Forcefully kill the Streamlit process tree to release the port."""
        if proc.poll() is not None:
            return
        try:
            if sys.platform == "win32":
                # /T kills the entire process tree, /F forces it
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            else:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            proc.kill()
        proc.wait(timeout=5)

    # On Windows, create the process in a new process group so we can kill the tree.
    # On Unix, use a new session so os.killpg works.
    popen_kwargs = {}
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True

    with subprocess.Popen(cmd, **popen_kwargs) as server_process:
        # Guarantee cleanup even on unexpected exit (e.g. sys.exit elsewhere)
        atexit.register(_kill_server, server_process)

        def _shutdown() -> None:
            """Tear down server and close all windows."""
            print("\nScubaGoggles UI stopped by user")
            _kill_server(server_process)
            for win in webview.windows:
                try:
                    win.destroy()
                except Exception:
                    pass
            os._exit(0)

        if sys.platform == "win32":
            # On Windows the native GUI loop blocks Python signal handling.
            # Use a Console Control Handler which Windows invokes on its own
            # thread — it works even while pywebview's message loop is running.
            ctrl_c_event = 0
            ctrl_break_event = 1
            ctrl_close_event = 2

            @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)
            def _console_handler(event: int) -> bool:
                if event in (ctrl_c_event, ctrl_break_event, ctrl_close_event):
                    _shutdown()
                    return True
                return False

            ctypes.windll.kernel32.SetConsoleCtrlHandler(_console_handler, True)
        else:
            signal.signal(signal.SIGINT, lambda *_: _shutdown())

        try:
            print(
                "Starting ScubaGoggles Configuration UI "
                f"({theme_base} theme) ...",
            )

            webview.create_window(
                "ScubaGoggles Configuration",
                url,
                width=1280,
                height=900,
                min_size=(900, 600),
            )
            webview.start()
        except KeyboardInterrupt:
            print("\nScubaGoggles UI stopped by user")
        except Exception as exc:
            print(f"Error starting UI: {exc}")
            sys.exit(1)
        finally:
            _kill_server(server_process)


if __name__ == "__main__":
    main()
