"""
test_launch.py tests the launch.py methods.
"""

import os
import sys
import pytest
from pathlib import Path
from scubagoggles.ui import launch
import signal

class TestLaunch:
    """Unit tests for the ScubaGoggles UI Launcher Program"""

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
        
        # name variable reduces character count on lines of code
        name = "_resolve_app_file"
        if resolve_app:
            # the Path directory can be arbitrary, doesn't matter for testing
            mocker.patch.object(launch, name, return_value=Path("/home"))
        else:
            mocker.patch.object(launch, name, return_value=None)

        
        name = "_is_streamlit_installed"
        if streamlit_installed:
            mocker.patch.object(launch, name, return_value=True)
        else:
            mocker.patch.object(launch, name, return_value=False)

        # cases where path is returned successfully
        if resolve_app and streamlit_installed:
            assert launch._get_app_to_run() == Path("/home") # pylint: disable=protected-access
        # either app path was not resolved or streamlit wasn't installed (same behavior)
        else:
            with pytest.raises(SystemExit) as ex:
                launch._get_app_to_run() # pylint: disable=protected-access
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
        mocker.patch.object(launch, name, return_value=1000)
        # home is an arbitrary directory
        # avoid backslashes to bypass OS ambiguity Path to str conversion
        app_path = Path("home")
        command, port = launch._build_streamlit_command(app_path, force_dark=dark_mode) # pylint: disable=protected-access
        expected_cmd = [
            str(sys.executable), "-m", "streamlit", "run",
            "home",
            "--server.address", "localhost",
            "--server.port", "1000",
            "--server.headless", "false",
            "--browser.gatherUsageStats", "false",
        ]
        # mock return
        assert port == 1000
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
        popen_kwargs = {}

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

    @pytest.mark.parametrize('dark_mode, windows',
        [
            (False, False),
            (True, False),
            (False, True),
            (True, True)
        ]
    )
    def test_main_method(self, mocker, monkeypatch, dark_mode, windows):
        """
        Test the main() method in launch.py
        """
        # to mock command line arguments
        str_args = ["launch.py"]
        # expected build command
        expected_cmd = [
            str(sys.executable), "-m", "streamlit", "run",
            "home",
            "--server.address", "localhost",
            "--server.port", "1234",
            "--server.headless", "false",
            "--browser.gatherUsageStats", "false",
        ]
        if dark_mode:
            str_args.append("--dark")
            monkeypatch.setenv("SCUBAGOGGLES_UI_DARK", "80")
            expected_cmd.extend(["--theme.base", "dark"])
        mocker.patch("sys.argv", str_args)
        # arbitrary return values for mocked functions
        mocker.patch.object(launch, "_find_free_port", return_value=1234)
        mocker.patch.object(launch, "_get_app_to_run", return_value=Path("home"))
        mocker.patch.object(launch, "_prevent_streamlit_promotion")
        mock_print = mocker.patch("builtins.print")
        mock_run_server = mocker.patch.object(launch, "_run_server")
        popen_kwargs = dict()
        if not windows:
            mocker.patch("sys.platform", "linux")
            popen_kwargs["start_new_session"] = True

        launch.main()
        # assertions
        if dark_mode:
            assert os.environ.get("SCUBAGOGGLES_UI_DARK") == "1"
            mock_print.assert_any_call(
                "Starting ScubaGoggles Configuration UI (dark (forced) theme) ...",
            )
        else:
            assert os.environ.get("SCUBAGOGGLES_UI_DARK") == None
            mock_print.assert_any_call(
                "Starting ScubaGoggles Configuration UI (auto theme) ...",
            )
        mock_print.assert_any_call("Opening http://localhost:1234 in your browser.")
        mock_print.assert_any_call("Press Ctrl+C to stop the server.\n")
        mock_run_server.assert_called_once_with(expected_cmd, popen_kwargs)
