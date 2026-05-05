"""
test_launch.py tests the launch.py methods.
"""

import sys
import pytest
from pathlib import Path
from scubagoggles.ui import launch
import signal
import subprocess

class TestLaunch:
    """Unit tests for the ScubaGoggles UI Launcher Program"""
    
    # Self-notes:
    #test_find_free_port - Mock only
    #test_prevent_streamlit_promotion - Mock only
    #test_resolve_app_file - Mock only
    #test_is_streamlit_installed - Mock only
    #test_kill_process_tree - Mock only

    #_get_app_to_run - Test
    #_build_streamlit_command - Test
    #_run_server - Test
    # main

    @pytest.mark.parametrize('resolve_app, streamlit_installed', [
            (False, False),
            (True, False),
            (True, True)
        ]
    )
    def test_get_app_to_run_success(self, mocker, resolve_app, streamlit_installed):
        """
        Verifies the _get_app_to_run method returns the expected result,
        either a path to the streamlit UI application, or raises a System Exit
        error if either the path or the app is unavailible
        """
        resolve_mock = None
        # name variable reduces character count on lines of code
        name = "_resolve_app_file"
        if resolve_app:
            # the Path directory can be arbitrary, doesn't matter for testing
            resolve_app_mock = mocker.patch.object(launch, name, return_value=Path("/home"))
        else:
            resolve_app_mock = mocker.patch.object(launch, name, return_value=None)
        
        streamlit_installed_mock = None
        name = "_is_streamlit_installed"
        if streamlit_installed:
            streamlit_installed_mock = mocker.patch.object(launch, name, return_value=True)
        else:
            streamlit_installed_mock = mocker.patch.object(launch, name, return_value=False)
        
        # cases where path is returned successfully
        if resolve_app and streamlit_installed:
            assert launch._get_app_to_run() == Path("/home")
        # either app path was not resolved or streamlit wasn't installed (same behavior)
        else:
            with pytest.raises(SystemExit) as ex:
                launch._get_app_to_run()
            assert ex.value.code == 1
    
    @pytest.mark.parametrize('dark_mode', [
            (True),
            (False)
        ]
    )
    def test_build_streamlit_command(self, mocker, dark_mode):
        """
        Tests the streamlit command building method
        Tests whether the command method builds the appropriate
        command given the app_path name (fixed) and the dark_mode toggle
        """
        name = "_find_free_port"
        #1000 is an arbitrary value
        resolve_app_mock = mocker.patch.object(launch, name, return_value=1000)
        # home is an arbitrary directory
        # avoid backslashes to bypass OS ambiguity Path to str conversion
        app_path = Path("home")
        command = launch._build_streamlit_command(app_path, force_dark=dark_mode)
        if command:
            command[0] = str(sys.executable)
        expected_cmd = [
            str(sys.executable), "-m", "streamlit", "run",
            "home",
            "--server.address", "localhost",
            "--server.port", "1000",
            "--server.headless", "false",
            "--browser.gatherUsageStats", "false",
        ]
        if dark_mode:
            expected_cmd.extend(["--theme.base", "dark"])
        for index, c in enumerate(command):
            assert c == expected_cmd[index]

    @pytest.mark.parametrize('exception, windows', [
            (False, False),
            (True, False),
            (False, True),
            (True, True)
        ]
    )    
    def test_run_server(self, mocker, exception, windows):
        """
        Tests the run server (the function that launches the UI)
        command
        """
        # Empty list, we just need something here as an argument
        cmd = list[str]
        # same thing with an empty dictionary
        popen_kwargs = dict()

        mock_server_proc = mocker.MagicMock()
        # other attributes
        # 1234 is arbitrary
        mock_server_proc.pid = 1234

        # patch the Popen command and mock the return value (process)
        mock_popen = mocker.patch("subprocess.Popen")
        mock_popen.return_value.__enter__.return_value = mock_server_proc

        # patch other things inside the context manager
        mock_atexit = mocker.patch("atexit.register")
        mock_kill_ptree = mocker.patch.object(launch, "_kill_process_tree")

        mock_print = None
        if exception:
            mock_print = mocker.patch("builtins.print")
            # side effect causes Exception to be raised/caught
            mock_server_proc.wait.side_effect = KeyboardInterrupt        
        
        mock_sys_platform = None
        mock_signal = None
        if not windows:
            mock_sys_platform = mocker.patch("sys.platform", "linux")
            mock_signal = mocker.patch("signal.signal")
        
        launch._run_server(cmd, popen_kwargs)
        mock_atexit.assert_called_once_with(mock_kill_ptree, mock_server_proc.pid)
        if not windows:
            mock_signal.assert_called_once()
            args, _ = mock_signal.call_args
            assert args[0] == signal.SIGINT
            # second lambda argument
            registered_lambda = args[1]
            assert callable(registered_lambda)
            # no Sys exit was executed
            # we need to see if it will raise if it was hypothetically
            # (in real-world scenarios)
            with pytest.raises(SystemExit) as exit_info:
                registered_lambda(None, None)
            
            # Note:
            # we already invoke mock_kill_ptree.assert_called_once_with(mock_server_proc.pid)
            # at the end of the script
            # Instead, we can assert _kill_process_tree is called twice later

            # See we exited with exit code zero
            assert exit_info.value.code == 0
        
        # try block
        mock_server_proc.wait.assert_called_once()
        if exception:
            # assert print statement in Exception block
            mock_print.assert_called_once_with("\nScubaGoggles UI stopped by user")
        
        # finally
        if windows:
            mock_kill_ptree.assert_called_once_with(mock_server_proc.pid)
        else:
            # assert the additional call to _kill_process_tree
            assert mock_kill_ptree.call_count == 2
