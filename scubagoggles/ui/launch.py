#!/usr/bin/env python3
"""
ScubaGoggles UI Launcher

Starts the Streamlit-based configuration app in the user's default browser.
Dark mode is auto-detected by the browser via CSS media queries.  Use --dark
or SCUBAGOGGLES_UI_DARK=1 to force dark mode for both Streamlit widgets and
the app's custom CSS.
"""

import argparse
import atexit
import importlib.util
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path


def _find_free_port() -> int:
    """Find an available port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]

def _prevent_streamlit_promotion() -> None:

    """Streamlit self-promotes upon initial invocation, which is not
    appropriate particularly for this application.  It can be avoided by
    creating its "credentials" file with an empty email address.  This is
    only done if the file doesn't already exist.
    """

    streamlit_dir = Path('~/.streamlit').expanduser()

    streamlit_dir.mkdir(exist_ok = True)

    streamlit_config = streamlit_dir / 'credentials.toml'

    if not streamlit_config.exists():
        streamlit_config.write_text('[general]\nemail = ""\n')

def _resolve_app_file() -> Path | None:
    """Return the path to the Streamlit app file."""
    candidate = Path(__file__).parent / "scubaconfigapp.py"
    return candidate if candidate.exists() else None


def _is_streamlit_installed() -> bool:
    """Return True if the streamlit package is importable."""
    return importlib.util.find_spec("streamlit") is not None


def _kill_process_tree(pid: int) -> None:
    """Kill a process and all its children by PID."""
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass


def _get_app_to_run() -> Path:
    """Cheks if UI application path and streamlit module exist/is installed
    Returns Application path if so"""
    app_to_run = _resolve_app_file()
    if not app_to_run:
        print("No UI application found!")
        print("Please ensure the UI modules are properly installed.")
        raise SystemExit(1)
    if not _is_streamlit_installed():
        print("Streamlit is not installed!")
        print("Please install requirements:")
        print("  pip install -r requirements.txt")
        raise SystemExit(1)
    return app_to_run


def _build_streamlit_command(app_to_run: Path, force_dark : bool) -> list[str]:
    """Builds the streamlit command needed to launch the UI"""
    # Find availible port
    port = _find_free_port()
    # Build command as list of strings
    cmd = [
        sys.executable, "-m", "streamlit", "run",
        str(app_to_run),
        "--server.address", "localhost",
        "--server.port", str(port),
        "--server.headless", "false",
        "--browser.gatherUsageStats", "false",
    ]
    # add extra option if dark option specified on command line
    if force_dark:
        cmd += ["--theme.base", "dark"]
    return cmd

def _run_server(cmd : list[str], popen_kwargs : dict):
    """Runs the Streamlit server"""
    with subprocess.Popen(cmd, **popen_kwargs) as server_process:
        # Register cleanup so the Streamlit process tree is always killed —
        # even if the terminal window is closed or the parent exits unexpectedly.
        atexit.register(_kill_process_tree, server_process.pid)

        if sys.platform != "win32":
            signal.signal(
                signal.SIGINT,
                lambda *_: (_kill_process_tree(server_process.pid), sys.exit(0)),
            )
        try:
            server_process.wait()
        except KeyboardInterrupt:
            print("\nScubaGoggles UI stopped by user")
        finally:
            _kill_process_tree(server_process.pid)


def main() -> None:
    """Launch the ScubaGoggles UI in the default web browser."""

    parser = argparse.ArgumentParser(
        description="ScubaGoggles Configuration UI (Streamlit)",
    )
    parser.add_argument(
        "--dark",
        action="store_true",
        help="Force dark theme (overrides browser preference)",
    )
    args = parser.parse_args()
    if args.dark:
        os.environ["SCUBAGOGGLES_UI_DARK"] = "1"

    force_dark = os.environ.get(
        "SCUBAGOGGLES_UI_DARK", "",
    ).strip().lower() in ("1", "true", "yes", "on")

    # get the application path
    # check to see it exists and streamlit is installed
    app_to_run = _get_app_to_run()

    cmd = _build_streamlit_command(app_to_run, force_dark)

    _prevent_streamlit_promotion()

    popen_kwargs: dict = {}
    if sys.platform != "win32":
        # On Unix, start a new session so os.killpg can target the group.
        # On Windows we intentionally stay in the same console group so
        # that Ctrl+C propagates naturally to both parent and child.
        popen_kwargs["start_new_session"] = True

    theme_label = "dark (forced)" if force_dark else "auto"
    print(
        "Starting ScubaGoggles Configuration UI "
        f"({theme_label} theme) ...",
    )
    # port number
    port = cmd[cmd.index("--server.port") + 1]
    print(f"Opening http://localhost:{port} in your browser.")
    print("Press Ctrl+C to stop the server.\n")

    _run_server(cmd, popen_kwargs)

if __name__ == "__main__":
    main()
