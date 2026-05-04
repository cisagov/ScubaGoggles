"""
test_launch.py tests the launch.py methods.
"""

import pytest
from pathlib import Path
from scubagoggles.ui import launch

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

    @pytest.mark.parametrize('resolve_app, streamlit_installed',[
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