"""
ScubaGoggles execution and integration utilities for the UI.
"""

import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import streamlit as st
import yaml


class ScubaRunner:
    """Handles execution of ScubaGoggles assessments."""

    def __init__(self) -> None:
        self.process: Optional[subprocess.Popen[str]] = None
        self.output_queue: "queue.Queue[str]" = queue.Queue()
        self.error_queue: "queue.Queue[str]" = queue.Queue()

    def run_assessment(
        self,
        config_dict: Dict[str, Any],
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> bool:
        """Run ScubaGoggles assessment with given configuration."""
        config_path = ""
        try:
            # Create temporary config file
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".yaml",
                delete=False,
            ) as tmp_config:
                yaml.dump(config_dict, tmp_config, default_flow_style=False)
                config_path = tmp_config.name

            # Determine the correct way to run ScubaGoggles
            cmd = self._build_command(config_path)

            if progress_callback:
                progress_callback("Starting ScubaGoggles assessment...")

            # Run ScubaGoggles
            with subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
            ) as process:
                self.process = process

                # Start threads to capture output
                stdout_thread = threading.Thread(
                    target=self._read_output,
                    args=(process.stdout, self.output_queue),
                    daemon=True,
                )
                stderr_thread = threading.Thread(
                    target=self._read_output,
                    args=(process.stderr, self.error_queue),
                    daemon=True,
                )

                stdout_thread.start()
                stderr_thread.start()

                # Monitor progress
                if progress_callback:
                    self._monitor_progress(progress_callback)

                # Wait for completion
                return_code = process.wait()

            return return_code == 0

        except Exception as exc:  # pragma: no cover - defensive logging
            st.error(f"Failed to run ScubaGoggles: {exc}")
            return False
        finally:
            # Cleanup temp config file
            if config_path:
                try:
                    os.unlink(config_path)
                except OSError:
                    # Best-effort cleanup; ignore filesystem errors
                    pass

    def _build_command(self, config_path: str) -> List[str]:
        """Build the command to execute ScubaGoggles."""
        return [sys.executable, "-m", "scubagoggles.main", "--config", config_path]

    def _read_output(self, stream, output_queue: "queue.Queue[str]") -> None:
        """Read output from subprocess stream."""
        try:
            for line in iter(stream.readline, ""):
                if line:
                    output_queue.put(line.strip())
        except OSError:
            # Ignore I/O issues while reading process output
            pass
        finally:
            stream.close()

    def _monitor_progress(self, progress_callback: Callable[[str], None]) -> None:
        """Monitor progress and update callback."""
        progress_indicators = [
            "Initializing",
            "Loading baselines",
            "Connecting to APIs",
            "Gathering data",
            "Running policy checks",
            "Generating reports",
        ]

        step_patterns: list[tuple[int, tuple[str, ...]]] = [
            (1, ("baseline",)),
            (2, ("connect", "auth")),
            (3, ("gather", "fetch")),
            (4, ("policy", "check")),
            (5, ("report", "generate")),
        ]

        current_step = 0

        while self.process and self.process.poll() is None:
            # Get output messages
            try:
                while True:
                    output = self.output_queue.get_nowait()
                    lowered = output.lower()

                    for step, tokens in step_patterns:
                        if any(token in lowered for token in tokens):
                            current_step = max(current_step, step)

                    if current_step < len(progress_indicators):
                        progress_callback(progress_indicators[current_step])

            except queue.Empty:
                pass

            time.sleep(0.5)

    def get_output(self) -> List[str]:
        """Get all captured output"""
        output_lines = []
        try:
            while True:
                line = self.output_queue.get_nowait()
                output_lines.append(line)
        except queue.Empty:
            pass
        return output_lines

    def get_errors(self) -> List[str]:
        """Get all captured errors"""
        error_lines = []
        try:
            while True:
                line = self.error_queue.get_nowait()
                error_lines.append(line)
        except queue.Empty:
            pass
        return error_lines


class ReportManager:
    """Handles ScubaGoggles report files and results."""

    @staticmethod
    def find_reports(output_path: str) -> Dict[str, List[Path]]:
        """Find generated report files in output directory."""
        reports: Dict[str, List[Path]] = {
            "html": [],
            "json": [],
            "yaml": [],
        }

        if not output_path or not Path(output_path).exists():
            return reports

        output_dir = Path(output_path)

        # Find HTML reports
        reports["html"] = list(output_dir.glob("*.html"))

        # Find JSON reports
        reports["json"] = list(output_dir.glob("*.json"))

        # Find YAML configuration files
        reports["yaml"] = list(output_dir.glob("*.yaml")) + list(
            output_dir.glob("*.yml"),
        )

        return reports

    @staticmethod
    def get_report_summary(output_path: str) -> Optional[Dict[str, Any]]:
        """Extract summary information from generated reports."""
        reports = ReportManager.find_reports(output_path)

        if not reports["json"]:
            return None

        try:
            # Read the main JSON report
            main_report = reports["json"][0]  # Assume first JSON is the main report

            with open(main_report, "r", encoding="utf-8") as file_obj:
                report_data = yaml.safe_load(file_obj)  # JSON is valid YAML

            # Extract summary information
            summary: Dict[str, Any] = {
                "report_file": main_report.name,
                "timestamp": report_data.get("timestamp", "Unknown"),
                "baselines_assessed": [],
                "total_controls": 0,
                "passed_controls": 0,
                "failed_controls": 0,
                "warnings": 0,
            }

            # Parse baseline results if available
            if "results" in report_data:
                for baseline, results in report_data["results"].items():
                    summary["baselines_assessed"].append(baseline)

                    if isinstance(results, list):
                        for control in results:
                            summary["total_controls"] += 1

                            # Determine control status
                            status = control.get("status", "").lower()
                            if status == "pass":
                                summary["passed_controls"] += 1
                            elif status == "fail":
                                summary["failed_controls"] += 1
                            elif status == "warning":
                                summary["warnings"] += 1

            return summary

        except OSError as exc:
            st.error(f"Error reading report summary: {exc}")
            return None