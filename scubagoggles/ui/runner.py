"""
ScubaGoggles execution and integration utilities for the UI
"""

import subprocess
import sys
import tempfile
import os
import threading
import queue
import time
from pathlib import Path
from typing import Dict, Any, Optional, Callable, List
import streamlit as st
import yaml


class ScubaRunner:
    """Handles execution of ScubaGoggles assessments"""
    
    def __init__(self):
        self.process = None
        self.output_queue = queue.Queue()
        self.error_queue = queue.Queue()
    
    def run_assessment(self, config_dict: Dict[str, Any], progress_callback: Optional[Callable] = None) -> bool:
        """Run ScubaGoggles assessment with given configuration"""
        try:
            # Create temporary config file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp_config:
                yaml.dump(config_dict, tmp_config, default_flow_style=False)
                config_path = tmp_config.name
            
            # Determine the correct way to run ScubaGoggles
            cmd = self._build_command(config_path)
            
            if progress_callback:
                progress_callback("Starting ScubaGoggles assessment...")
            
            # Run ScubaGoggles
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Start threads to capture output
            stdout_thread = threading.Thread(target=self._read_output, args=(self.process.stdout, self.output_queue))
            stderr_thread = threading.Thread(target=self._read_output, args=(self.process.stderr, self.error_queue))
            
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()
            
            # Monitor progress
            if progress_callback:
                self._monitor_progress(progress_callback)
            
            # Wait for completion
            return_code = self.process.wait()
            
            return return_code == 0
            
        except Exception as e:
            st.error(f"Failed to run ScubaGoggles: {e}")
            return False
        finally:
            # Cleanup temp config file
            try:
                if 'config_path' in locals():
                    os.unlink(config_path)
            except:
                pass
    
    def _build_command(self, config_path: str) -> List[str]:
        """Build the command to execute ScubaGoggles"""
        # Try different ways to run ScubaGoggles
        commands_to_try = [
            # Method 1: Python module
            [sys.executable, "-m", "scubagoggles.main", "--config", config_path],
            # Method 2: Direct script (if scuba.py exists)
            [sys.executable, "scuba.py", "--config", config_path],
            # Method 3: Installed command
            ["scubagoggles", "--config", config_path]
        ]
        
        # Use the first available method
        return commands_to_try[0]  # For now, default to module method
    
    def _read_output(self, stream, output_queue):
        """Read output from subprocess stream"""
        try:
            for line in iter(stream.readline, ''):
                if line:
                    output_queue.put(line.strip())
        except:
            pass
        finally:
            stream.close()
    
    def _monitor_progress(self, progress_callback: Callable):
        """Monitor progress and update callback"""
        progress_indicators = [
            "Initializing",
            "Loading baselines",
            "Connecting to APIs",
            "Gathering data",
            "Running policy checks",
            "Generating reports"
        ]
        
        current_step = 0
        
        while self.process.poll() is None:
            # Get output messages
            try:
                while True:
                    output = self.output_queue.get_nowait()
                    
                    # Update progress based on output patterns
                    if "baseline" in output.lower():
                        if current_step < 1:
                            current_step = 1
                    elif "connect" in output.lower() or "auth" in output.lower():
                        if current_step < 2:
                            current_step = 2
                    elif "gather" in output.lower() or "fetch" in output.lower():
                        if current_step < 3:
                            current_step = 3
                    elif "policy" in output.lower() or "check" in output.lower():
                        if current_step < 4:
                            current_step = 4
                    elif "report" in output.lower() or "generate" in output.lower():
                        if current_step < 5:
                            current_step = 5
                    
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
    """Handles ScubaGoggles report files and results"""
    
    @staticmethod
    def find_reports(output_path: str) -> Dict[str, List[Path]]:
        """Find generated report files in output directory"""
        reports = {
            'html': [],
            'json': [],
            'yaml': []
        }
        
        if not output_path or not Path(output_path).exists():
            return reports
        
        output_dir = Path(output_path)
        
        # Find HTML reports
        reports['html'] = list(output_dir.glob("*.html"))
        
        # Find JSON reports
        reports['json'] = list(output_dir.glob("*.json"))
        
        # Find YAML configuration files
        reports['yaml'] = list(output_dir.glob("*.yaml")) + list(output_dir.glob("*.yml"))
        
        return reports
    
    @staticmethod
    def get_report_summary(output_path: str) -> Optional[Dict[str, Any]]:
        """Extract summary information from generated reports"""
        reports = ReportManager.find_reports(output_path)
        
        if not reports['json']:
            return None
        
        try:
            # Read the main JSON report
            main_report = reports['json'][0]  # Assume first JSON is the main report
            
            with open(main_report, 'r', encoding='utf-8') as f:
                report_data = yaml.safe_load(f)  # JSON is valid YAML
            
            # Extract summary information
            summary = {
                'report_file': main_report.name,
                'timestamp': report_data.get('timestamp', 'Unknown'),
                'baselines_assessed': [],
                'total_controls': 0,
                'passed_controls': 0,
                'failed_controls': 0,
                'warnings': 0
            }
            
            # Parse baseline results if available
            if 'results' in report_data:
                for baseline, results in report_data['results'].items():
                    summary['baselines_assessed'].append(baseline)
                    
                    if isinstance(results, list):
                        for control in results:
                            summary['total_controls'] += 1
                            
                            # Determine control status
                            status = control.get('status', '').lower()
                            if status == 'pass':
                                summary['passed_controls'] += 1
                            elif status == 'fail':
                                summary['failed_controls'] += 1
                            elif status == 'warning':
                                summary['warnings'] += 1
            
            return summary
            
        except Exception as e:
            st.error(f"Error reading report summary: {e}")
            return None


def render_execution_section(config_dict: Dict[str, Any], validation_passed: bool):
    """Render the ScubaGoggles execution section"""
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


def run_scubagoggles_assessment(config_dict: Dict[str, Any]):
    """Run a full ScubaGoggles assessment with progress tracking"""
    
    # Create progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    def update_progress(message: str):
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
    
    except Exception as e:
        st.error(f"Failed to run assessment: {e}")


def test_configuration(config_dict: Dict[str, Any]):
    """Test the configuration without running full assessment"""
    st.info("🧪 Testing configuration...")
    
    try:
        # Basic validation tests
        tests = []
        
        # Test 1: Check credentials file exists
        if 'credentials' in config_dict:
            creds_path = Path(config_dict['credentials'])
            tests.append({
                'name': 'Credentials File',
                'passed': creds_path.exists(),
                'message': f"File exists: {creds_path}" if creds_path.exists() else f"File not found: {creds_path}"
            })
        
        # Test 2: Check output directory
        if 'outputpath' in config_dict:
            output_path = Path(config_dict['outputpath'])
            try:
                output_path.mkdir(parents=True, exist_ok=True)
                tests.append({
                    'name': 'Output Directory',
                    'passed': True,
                    'message': f"Directory accessible: {output_path}"
                })
            except Exception as e:
                tests.append({
                    'name': 'Output Directory',
                    'passed': False,
                    'message': f"Cannot access: {e}"
                })
        
        # Test 3: Check baselines
        baselines = config_dict.get('baselines', [])
        tests.append({
            'name': 'Baselines Selection',
            'passed': len(baselines) > 0,
            'message': f"{len(baselines)} baseline(s) selected: {', '.join(baselines)}" if baselines else "No baselines selected"
        })
        
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
    
    except Exception as e:
        st.error(f"Configuration test failed: {e}")


def show_assessment_results(output_path: str):
    """Display assessment results and generated reports"""
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
                if st.button(f"📂 Open", key=f"open_{html_report.name}"):
                    st.info(f"Report location: {html_report.absolute()}")
    
    if reports['json']:
        st.success(f"📊 {len(reports['json'])} JSON report(s) generated")
    
    st.info(f"📂 All reports saved to: {Path(output_path).absolute()}")


def render_runner_status():
    """Render status information about ScubaGoggles runner"""
    with st.sidebar:
        st.subheader("🔧 System Status")
        
        # Check Python version
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        st.text(f"🐍 Python: {python_version}")
        
        # Check if ScubaGoggles modules are available
        try:
            from scubagoggles.version import Version
            version = Version()
            st.text(f"🤿 ScubaGoggles: {version.version}")
            st.success("✅ Ready to run assessments")
        except ImportError:
            st.error("❌ ScubaGoggles not found")
            st.text("Please install ScubaGoggles first")
        
        # Show current working directory
        st.text(f"📁 Working directory: {os.getcwd()}")