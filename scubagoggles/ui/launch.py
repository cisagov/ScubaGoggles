#!/usr/bin/env python3
"""
ScubaGoggles UI Launcher
Starts the Streamlit backend and opens the app in a native window via pywebview.
Automatically matches the system light/dark theme.
"""

import atexit
import os
import signal
import subprocess
import sys
import socket
import threading
from pathlib import Path


def _find_free_port():
    """Find an available port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


def _resolve_app_file():
    """Return the path to the best available Streamlit app file."""
    ui_dir = Path(__file__).parent
    for name in ("scubaconfigapp.py", "config_generator.py"):
        candidate = ui_dir / name
        if candidate.exists():
            return candidate
    return None


def _detect_theme():
    """Return 'dark' or 'light' based on system preference."""
    try:
        import darkdetect
        theme = darkdetect.theme()
        return theme.lower() if theme else "light"
    except Exception:
        return "light"


def main():
    """Launch the ScubaGoggles UI in a native window."""

    app_to_run = _resolve_app_file()
    if not app_to_run:
        print("No UI application found!")
        print("Please ensure the UI modules are properly installed.")
        sys.exit(1)

    try:
        import streamlit  # noqa: F401
    except ImportError:
        print("Streamlit is not installed!")
        print("Please install requirements:")
        print("  pip install -r requirements.txt")
        sys.exit(1)

    try:
        import webview
    except ImportError:
        print("pywebview is not installed!")
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

    cmd = [
        sys.executable, "-m", "streamlit", "run",
        str(app_to_run),
        "--server.address", "localhost",
        "--server.port", str(port),
        "--server.headless", "true",
        "--browser.gatherUsageStats", "false",
        "--theme.base", theme_base,
    ]

    def _kill_server(proc):
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

    server_process = subprocess.Popen(cmd, **popen_kwargs)

    # Guarantee cleanup even on unexpected exit (e.g. sys.exit elsewhere)
    atexit.register(_kill_server, server_process)

    def _shutdown():
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
        import ctypes
        CTRL_C_EVENT = 0
        CTRL_BREAK_EVENT = 1
        CTRL_CLOSE_EVENT = 2

        @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)
        def _console_handler(event):
            if event in (CTRL_C_EVENT, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT):
                _shutdown()
                return True
            return False

        ctypes.windll.kernel32.SetConsoleCtrlHandler(_console_handler, True)
    else:
        signal.signal(signal.SIGINT, lambda *_: _shutdown())

    try:
        print(f"Starting ScubaGoggles Configuration UI ({theme_base} theme) ...")

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
    except Exception as e:
        print(f"Error starting UI: {e}")
        sys.exit(1)
    finally:
        _kill_server(server_process)


if __name__ == "__main__":
    main()