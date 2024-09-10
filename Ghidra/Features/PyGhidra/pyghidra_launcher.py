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
import os
import sys
import subprocess
from pathlib import Path
from typing import List
from sys import stderr

def upgrade(pip_args: List[str], dist_dir: Path, current_pyghidra_version: str) -> bool:
    from packaging.version import Version # if pyghidra imported, we know we have packaging
    included_pyghidra: Path = next(dist_dir.glob('pyghidra-*.whl'), None)
    if included_pyghidra is None:
         print('Warning: included pyghidra wheel was not found', file=sys.stderr)
         return
    included_version: Version = Version(included_pyghidra.name.split('-')[1])
    current_version: Version = Version(current_pyghidra_version)
    if included_version > current_version:
        choice: str = input(f'Do you wish to upgrade PyGhidra {current_version} to {included_version} (y/n)? ')
        if choice.lower() in ('y', 'yes'):
            pip_args.append('-U')
            subprocess.check_call(pip_args)
            return True
        else:
            print('Skipping upgrade')
            return False

def install(pip_args: List[str], dist_dir: Path) -> bool:
    choice: str = input('Do you wish to install PyGhidra (y/n)? ')
    if choice.lower() in ('y', 'yes'):
        subprocess.check_call(pip_args)
        return True
    elif choice.lower() in ('n', 'no'):
        return False
    else:
        print('Please answer yes or no.')
        return False 
            
def main() -> None:
    # Parse command line arguments
    parser = argparse.ArgumentParser(prog=Path(__file__).name)
    parser.add_argument('install_dir', metavar='<install dir>', help='Ghidra installation directory')
    parser.add_argument('-c', '--console', action='store_true', help='Force console launch')
    parser.add_argument('-d', '--dev', action='store_true', help='Ghidra development mode')
    parser.add_argument('-H', '--headless', action='store_true', help='Ghidra headless mode')
    args, remaining = parser.parse_known_args()
    
    # Setup variables
    python_cmd: str = sys.executable
    install_dir: Path = Path(args.install_dir)
    venv_dir: Path = install_dir / 'build' / 'venv'
    pyghidra_dir: Path = install_dir / 'Ghidra' / 'Features' / 'PyGhidra'
    src_dir: Path = pyghidra_dir / 'src' / 'main' / 'py'
    dist_dir: Path = pyghidra_dir / 'pypkg' / 'dist'
    
    # If headless, force console mode
    if args.headless:
        args.console = True
    
    if args.dev:
        # If in dev mode, launch PyGhidra from the source tree using the development virtual environment
        if not venv_dir.is_dir():
            print('Virtual environment not found!')
            print('Run "gradle prepdev" and try again.')
            return
        win_python_cmd = str(venv_dir / 'Scripts' / 'python.exe')
        linux_python_cmd = str(venv_dir / 'bin' / 'python3')
        python_cmd = win_python_cmd if os.name == 'nt' else linux_python_cmd
    else:
        # If in release mode, offer to install or upgrade PyGhidra before launching from user-controlled environment
        pip_args: List[str] = [python_cmd, '-m', 'pip', 'install', '--no-index', '-f', str(dist_dir), 'pyghidra']
        try:
            import pyghidra
            upgrade(pip_args, dist_dir, pyghidra.__version__)
        except ImportError:
            if not install(pip_args, dist_dir):
                return
    
    # Launch PyGhidra
    py_args: List[str] = [python_cmd, '-m', 'pyghidra.ghidra_launch', '--install-dir', str(install_dir)]
    if args.headless:
        py_args += ['ghidra.app.util.headless.AnalyzeHeadless']
    else:
        py_args += ['-g', 'ghidra.GhidraRun']
    if args.console:
        subprocess.call(py_args + remaining)
    else:
        creation_flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        subprocess.Popen(py_args + remaining, creationflags=creation_flags, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
 
if __name__ == "__main__":
    main()
