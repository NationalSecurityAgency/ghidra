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
import platform
import os
import sys
import subprocess
import sysconfig
import venv
from pathlib import Path
from typing import List, Dict
from sys import stderr, version

def get_application_properties(install_dir: Path) -> Dict[str, str]:
    app_properties_path: Path = install_dir / 'Ghidra' / 'application.properties'
    props: Dict[str, str] = {}
    with open(app_properties_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('#') or line.startswith('!'):
                continue
            key, value = line.split('=', 1)
            if key:
                props[key] = value
    return props

def get_user_settings_dir(install_dir: Path) -> Path:
    props: Dict[str, str] = get_application_properties(install_dir)
    app_name: str = props['application.name'].replace(' ', '').lower()
    app_version: str = props['application.version']
    app_release_name: str = props['application.release.name']
    versioned_name: str = f'{app_name}_{app_version}_{app_release_name}'
    xdg_config_home: str = os.environ.get('XDG_CONFIG_HOME')
    if xdg_config_home:
        return Path(xdg_config_home) / app_name / versioned_name
    if platform.system() == 'Windows':
        return Path(os.environ['APPDATA']) / app_name / versioned_name
    if platform.system() == 'Darwin':
        return Path.home() / 'Library' / app_name / versioned_name
    return Path.home() / '.config' / app_name / versioned_name
    
def in_venv() -> bool:
    return sys.prefix != sys.base_prefix

def is_externally_managed() -> bool:
    marker: Path = Path(sysconfig.get_path("stdlib", sysconfig.get_default_scheme())) / 'EXTERNALLY-MANAGED'
    return marker.is_file()

def get_venv_exe(venv_dir: Path) -> str:
    win_python_cmd: str = str(venv_dir / 'Scripts' / 'python.exe')
    linux_python_cmd: str = str(venv_dir / 'bin' / 'python3')
    return win_python_cmd if platform.system() == 'Windows' else linux_python_cmd

def get_ghidra_venv(install_dir: Path) -> Path:
    user_settings_dir: Path = get_user_settings_dir(install_dir)
    venv_dir: Path = user_settings_dir / 'venv'
    return venv_dir
    
def create_ghidra_venv(venv_dir: Path) -> None:
    print(f'Creating Ghidra virtual environemnt at {venv_dir}...')
    venv.create(venv_dir, with_pip=True)

def version_tuple(v):
   filled = []
   for point in v.split("."):
      filled.append(point.zfill(8))
   return tuple(filled)

def get_package_version(python_cmd: str, package: str) -> str:
    version = None
    result = subprocess.Popen([python_cmd, '-m', 'pip', 'show', package], stdout=subprocess.PIPE, text=True)
    for line in result.stdout.readlines():
        line = line.strip()
        print(line)
        key, value = line.split(':', 1)
        if key == 'Version':
            version = value.strip()
    return version
    
def install(install_dir: Path, python_cmd: str, pip_args: List[str], offer_venv: bool) -> bool:
    install_choice: str = input('Do you wish to install PyGhidra (y/n)? ')
    if install_choice.lower() in ('y', 'yes'):
        if offer_venv:
            ghidra_venv_choice: str = input('Install into new Ghidra virtual environment (y/n)? ')
            if ghidra_venv_choice.lower() in ('y', 'yes'):
                venv_dir = get_ghidra_venv(install_dir)
                create_ghidra_venv(venv_dir)
                python_cmd = get_venv_exe(venv_dir)
            elif ghidra_venv_choice.lower() in ('n', 'no'):
                system_venv_choice: str = input('Install into system environment (y/n)? ')
                if not system_venv_choice.lower() in ('y', 'yes'):
                    print('Must answer "y" to the prior choices, or launch in an already active virtual environment.')
                    return None
            else:
                print('Please answer yes or no.')
                return None 
        subprocess.check_call([python_cmd] + pip_args)
        return python_cmd
    elif not install_choice.lower() in ('n', 'no'):
        print('Please answer yes or no.')
    return None     

def upgrade(python_cmd: str, pip_args: List[str], dist_dir: Path, current_pyghidra_version: str) -> bool:
    included_pyghidra: Path = next(dist_dir.glob('pyghidra-*.whl'), None)
    if included_pyghidra is None:
         print('Warning: included pyghidra wheel was not found', file=sys.stderr)
         return
    included_version = included_pyghidra.name.split('-')[1]
    current_version = current_pyghidra_version
    if version_tuple(included_version) > version_tuple(current_version):
        choice: str = input(f'Do you wish to upgrade PyGhidra {current_version} to {included_version} (y/n)? ')
        if choice.lower() in ('y', 'yes'):
            pip_args.append('-U')
            subprocess.check_call([python_cmd] + pip_args)
            return True
        else:
            print('Skipping upgrade')
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
    pyghidra_dir: Path = install_dir / 'Ghidra' / 'Features' / 'PyGhidra'
    dist_dir: Path = pyghidra_dir / 'pypkg' / 'dist'
    dev_venv_dir = install_dir / 'build' / 'venv'
    release_venv_dir = get_ghidra_venv(install_dir)

    # If headless, force console mode
    if args.headless:
        args.console = True
    
    if args.dev:
        # If in dev mode, launch PyGhidra from the source tree using the development virtual environment
        if not dev_venv_dir.is_dir():
            print('Virtual environment not found!')
            print('Run "gradle prepdev" and try again.')
            sys.exit(1)
        python_cmd = get_venv_exe(dev_venv_dir)
    else:
        # If in release mode, offer to install or upgrade PyGhidra before launching from user-controlled environment
        pip_args: List[str] = ['-m', 'pip', 'install', '--no-index', '-f', str(dist_dir), 'pyghidra']

        # Setup the proper execution environment:
        # 1) If we are already in a virtual environment, use that
        # 2) If the Ghidra user settings virtual environment exists, use that
        # 3) If we are "externally managed", automatically create/use the Ghidra user settings virtual environment
        offer_venv: bool = False
        if in_venv():
            # If we are already in a virtual environment, assume that's where the user wants to be
            print(f'Using active virtual environment: {sys.prefix}')
        elif os.path.isdir(release_venv_dir):
            # If the Ghidra user settings venv exists, use that
            python_cmd = get_venv_exe(release_venv_dir)
            print(f'Using Ghidra virtual environment: {release_venv_dir}')
        elif is_externally_managed():
            print('Externally managed environment detected!')
            create_ghidra_venv(release_venv_dir)
            python_cmd = get_venv_exe(release_venv_dir)
        else:
            offer_venv = True

        # If PyGhidra is not installed in the execution environment, offer to install it
        # If it's already installed, offer to upgrade (if applicable)
        current_pyghidra_version = get_package_version(python_cmd, 'pyghidra')
        if current_pyghidra_version is None:
            python_cmd = install(install_dir, python_cmd, pip_args, offer_venv)
            if not python_cmd:
                sys.exit(1)
        else:
            upgrade(python_cmd, pip_args, dist_dir, current_pyghidra_version)

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
