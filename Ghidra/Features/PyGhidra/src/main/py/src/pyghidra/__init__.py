## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
__version__ = "2.1.0"

# stub for documentation and typing
# this is mostly to hide the function parameter
def debug_callback(suspend=False, **kwargs):
    """
    Decorator for enabling debugging of functions called from a thread started in Java.
    All parameters are forwarded to `pydevd.settrace`.
    It is recommended to remove this decorator from a function when it is no longer needed.

    :param suspend: The suspend parameter for `pydevd.settrace` (Defaults to False)
    :return: The decorated function
    """


# this is the actual implementation
def _debug_callback(fun=None, *, suspend=False, **pydevd_kwargs):
    import functools
    import sys
    
    if not fun:
        return functools.partial(_debug_callback, suspend=suspend, **pydevd_kwargs)
    
    @functools.wraps(fun)
    def wrapper(*args, **kwargs):
        # NOTE: sys.modules is used directly to prevent errors in settrace
        # the debugger is responsible for connecting so it will have already
        # been imported
        pydevd = sys.modules.get("pydevd")
        if pydevd:
            pydevd_kwargs["suspend"] = suspend
            pydevd.settrace(**pydevd_kwargs)
        return fun(*args, **kwargs)
    
    return wrapper


debug_callback = _debug_callback


# Expose API
from pyghidra.core import run_script, start, started, open_program
from pyghidra.launcher import DeferredPyGhidraLauncher, GuiPyGhidraLauncher, HeadlessPyGhidraLauncher
from pyghidra.script import get_current_interpreter
from pyghidra.version import ApplicationInfo, ExtensionDetails


__all__ = [
    "debug_callback", "get_current_interpreter", "open_program", "run_script", "start",
    "started", "ApplicationInfo", "DeferredPyGhidraLauncher", "ExtensionDetails",
    "GuiPyGhidraLauncher", "HeadlessPyGhidraLauncher"
]
