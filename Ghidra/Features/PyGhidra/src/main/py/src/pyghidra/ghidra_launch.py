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
import argparse
import ctypes
from pathlib import Path
import sys
import threading

from pyghidra.launcher import PyGhidraLauncher, _run_mac_app


class GhidraLauncher(PyGhidraLauncher):
    
    def __init__(self, verbose=False, class_name=str, gui=False, *, install_dir: Path = None):
        super().__init__(verbose=verbose, install_dir=install_dir)
        self._class_name = class_name
        self._gui = gui
    
    def _launch(self):
        from ghidra import Ghidra
        from java.lang import Runtime, Thread # type:ignore @UnresolvedImport

        if self._gui:
            if sys.platform == "win32":
                appid = ctypes.c_wchar_p(self.app_info.name)
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(appid)  # @UndefinedVariable
            Thread(lambda: Ghidra.main([self._class_name, *self.args])).start()
            is_exiting = threading.Event()
            Runtime.getRuntime().addShutdownHook(Thread(is_exiting.set))
            if sys.platform == "darwin":
                _run_mac_app()
            is_exiting.wait()
        else:
            Ghidra.main([self._class_name, *self.args])


class ParsedArgs(argparse.Namespace):
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.gui = False
        self._dargs = []
        self._xargs = []
        self.install_dir: Path = None
        self.class_name: str = None
    
    @property
    def jvm_args(self):
        vmargs = []
        for arg in self._dargs:
            vmargs.append("-D" + arg)
        for arg in self._xargs:
            vmargs.append("-X" + arg)
        return vmargs


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-g",
        "--gui",
        action="store_true",
        dest="gui",
        help="Start Ghidra GUI"
    )
    parser.add_argument(
        "-D",
        dest="_dargs",
        action="append",
        metavar="",
        help="Argument to be forwarded to the JVM"
    )
    parser.add_argument(
        "-X",
        dest="_xargs",
        action="append",
        metavar="",
        help="Argument to be forwarded to the JVM"
    )
    parser.add_argument(
        "--install-dir",
        type=Path,
        default=None,
        dest="install_dir",
        metavar="",
        help="Path to Ghidra installation. " \
             "(defaults to the GHIDRA_INSTALL_DIR environment variable)"
    )
    parser.add_argument(
        "class_name",
        metavar="class"
    )
    return parser


if __name__ == "__main__":
    parser = get_parser()

    args = ParsedArgs()
    _, remaining = parser.parse_known_args(namespace=args)
    
    launcher = GhidraLauncher(False, args.class_name, args.gui, install_dir=args.install_dir)
    launcher.vm_args = args.jvm_args + launcher.vm_args
    launcher.args = remaining
    launcher.start()
