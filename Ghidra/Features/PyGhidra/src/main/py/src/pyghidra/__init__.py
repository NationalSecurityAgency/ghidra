
__version__ = "2.0.0"

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
from .core import run_script, start, started, open_program
from .launcher import DeferredPyGhidraLauncher, GuiPyGhidraLauncher, HeadlessPyGhidraLauncher
from .script import get_current_interpreter
from .version import ApplicationInfo, ExtensionDetails


__all__ = [
    "debug_callback", "get_current_interpreter", "open_program", "run_script", "start",
    "started", "ApplicationInfo", "DeferredPyGhidraLauncher", "ExtensionDetails",
    "GuiPyGhidraLauncher", "HeadlessPyGhidraLauncher"
]
