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

try:
    from scubagoggles.version import Version as ScubaVersion
except ImportError:
    ScubaVersion = None


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
        # Try different ways to run ScubaGoggles
        commands_to_try = [
            # Method 1: Python module
            [sys.executable, "-m", "scubagoggles.main", "--config", config_path],
            # Method 2: Direct script (if scuba.py exists)
            [sys.executable, "scuba.py", "--config", config_path],
            # Method 3: Installed command
            ["scubagoggles", "--config", config_path],
        ]

        # Use the first available method
        return commands_to_try[0]  # For now, default to module method

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


def render_execution_section(config_dict: Dict[str, Any], validation_passed: bool) -> None:
    """Render the ScubaGoggles execution section."""
    st.header("🚀 Run Assessment")

    if not validation_passed:
        st.warning("⚠️ Please fix configuration validation errors before running assessment")
        st.button("🔍 Run Assessment", disabled=True)
        return

    col1, col2 = st.columns(2)

    with col1:
        if st.button("🔍 Run Assessment", type="primary"):
            run_scubagoggles_assessment(config_dict)

    with col2:
        if st.button("🧪 Test Configuration", type="secondary"):
            test_configuration(config_dict)


def run_scubagoggles_assessment(config_dict: Dict[str, Any]) -> None:
    """Run a full ScubaGoggles assessment with progress tracking."""

    # Create progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()

    def update_progress(message: str) -> None:
        status_text.text(f"🔄 {message}")

    try:
        runner = ScubaRunner()

        with st.spinner("Initializing ScubaGoggles..."):
            update_progress("Starting assessment...")
            success = runner.run_assessment(config_dict, update_progress)

        if success:
            progress_bar.progress(100)
            status_text.text("✅ Assessment completed successfully!")
            st.success("🎉 ScubaGoggles assessment completed!")

            # Show results
            show_assessment_results(config_dict.get('outputpath', './'))

            # Trigger balloon animation
            st.balloons()

        else:
            st.error("❌ ScubaGoggles assessment failed")

            # Show error details
            errors = runner.get_errors()
            if errors:
                with st.expander("Error Details"):
                    for error in errors:
                        st.error(error)
    except Exception as exc:  # pragma: no cover - defensive logging
        st.error(f"Failed to run assessment: {exc}")


def test_configuration(config_dict: Dict[str, Any]) -> None:
    """Test the configuration without running full assessment."""
    st.info("🧪 Testing configuration...")

    try:
        # Basic validation tests
        tests: list[Dict[str, Any]] = []

        # Test 1: Check credentials file exists
        if 'credentials' in config_dict:
            creds_path = Path(config_dict['credentials'])
            tests.append(
                {
                    'name': 'Credentials File',
                    'passed': creds_path.exists(),
                    'message': (
                        f"File exists: {creds_path}"
                        if creds_path.exists()
                        else f"File not found: {creds_path}"
                    ),
                },
            )

        # Test 2: Check output directory
        if 'outputpath' in config_dict:
            output_path = Path(config_dict['outputpath'])
            try:
                output_path.mkdir(parents=True, exist_ok=True)
                tests.append(
                    {
                        'name': 'Output Directory',
                        'passed': True,
                        'message': f"Directory accessible: {output_path}",
                    },
                )
            except OSError as exc:
                tests.append(
                    {
                        'name': 'Output Directory',
                        'passed': False,
                        'message': f"Cannot access: {exc}",
                    },
                )

        # Test 3: Check baselines
        baselines = config_dict.get('baselines', [])
        baseline_count = len(baselines)
        baselines_message = (
            f"{baseline_count} baseline(s) selected: {', '.join(baselines)}"
            if baselines
            else "No baselines selected"
        )
        tests.append(
            {
                'name': 'Baselines Selection',
                'passed': baseline_count > 0,
                'message': baselines_message,
            },
        )

        # Display test results
        st.subheader("🔍 Configuration Test Results")

        all_passed = True
        for test in tests:
            if test['passed']:
                st.success(f"✅ {test['name']}: {test['message']}")
            else:
                st.error(f"❌ {test['name']}: {test['message']}")
                all_passed = False

        if all_passed:
            st.success("🎉 All configuration tests passed!")
        else:
            st.warning("⚠️ Some configuration tests failed. Please review and fix issues.")

    except Exception as exc:  # pragma: no cover - defensive logging
        st.error(f"Configuration test failed: {exc}")


def show_assessment_results(output_path: str) -> None:
    """Display assessment results and generated reports."""
    st.subheader("📊 Assessment Results")

    # Find generated reports
    reports = ReportManager.find_reports(output_path)

    if not any(reports.values()):
        st.warning("No reports found in output directory")
        return

    # Show report summary
    summary = ReportManager.get_report_summary(output_path)
    if summary:
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Controls", summary['total_controls'])
        with col2:
            st.metric("Passed", summary['passed_controls'], delta=None)
        with col3:
            st.metric("Failed", summary['failed_controls'], delta=None)
        with col4:
            st.metric("Warnings", summary['warnings'], delta=None)

        st.info(f"📅 Assessment completed: {summary['timestamp']}")
        st.info(f"🎯 Baselines assessed: {', '.join(summary['baselines_assessed'])}")

    # Show available reports
    st.subheader("📁 Generated Reports")

    if reports['html']:
        st.success(f"📄 {len(reports['html'])} HTML report(s) generated")
        for html_report in reports['html']:
            col1, col2 = st.columns([3, 1])
            with col1:
                st.text(f"📄 {html_report.name}")
            with col2:
                # Note: Streamlit can't directly open files, but we can show the path
                if st.button("📂 Open", key=f"open_{html_report.name}"):
                    st.info(f"Report location: {html_report.absolute()}")

    if reports['json']:
        st.success(f"📊 {len(reports['json'])} JSON report(s) generated")

    st.info(f"📂 All reports saved to: {Path(output_path).absolute()}")


def render_runner_status() -> None:
    """Render status information about ScubaGoggles runner."""
    with st.sidebar:
        st.subheader("🔧 System Status")

        # Check Python version
        python_version = (
            f"{sys.version_info.major}."
            f"{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        )
        st.text(f"🐍 Python: {python_version}")

        # Check if ScubaGoggles modules are available
        if ScubaVersion is not None:
            try:
                version_obj = ScubaVersion()
                version_str = getattr(version_obj, "version", str(version_obj))
                st.text(f"🤿 ScubaGoggles: {version_str}")
                st.success("✅ Ready to run assessments")
            except Exception:  # pragma: no cover - defensive logging
                st.error("❌ ScubaGoggles not found")
                st.text("Please install ScubaGoggles first")
        else:
            st.error("❌ ScubaGoggles not found")
            st.text("Please install ScubaGoggles first")

        # Show current working directory
        st.text(f"📁 Working directory: {os.getcwd()}")