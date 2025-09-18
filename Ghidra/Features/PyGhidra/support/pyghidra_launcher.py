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
from pathlib import Path
from itertools import chain
from typing import List, Dict, Tuple

def get_application_properties(install_dir: Path) -> Dict[str, str]:
    app_properties_path: Path = install_dir / 'Ghidra' / 'application.properties'
    props: Dict[str, str] = {}
    with open(app_properties_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            key, value = line.split('=', 1)
            if key:
                props[key] = value
    return props

def get_launch_properties(install_dir: Path, dev: bool) -> List[str]:
    if dev:
        launch_properties_path: Path = install_dir / 'Ghidra' / 'RuntimeScripts' / 'Common' / 'support' / 'launch.properties'
    else:
        launch_properties_path: Path = install_dir / 'support' / 'launch.properties'
    props: List[str] = []
    with open(launch_properties_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            props.append(line)
    return props

def get_user_settings_dir(install_dir: Path, dev: bool) -> Path:
    app_props: Dict[str, str] = get_application_properties(install_dir)
    app_name: str = app_props['application.name'].replace(' ', '').lower()
    app_version: str = app_props['application.version']
    app_release_name: str = app_props['application.release.name']
    versioned_name: str = f'{app_name}_{app_version}_{app_release_name}'
    if dev:
        versioned_name += f'_location_{install_dir.parent.name}'

    # Check for application.settingsdir in launch.properties
    for launch_prop in get_launch_properties(install_dir, dev):
        if launch_prop.startswith('VMARGS=-Dapplication.settingsdir='):
            application_settingsdir = launch_prop[launch_prop.rindex('=')+1:]
            if application_settingsdir:
                return Path(application_settingsdir) / app_name / versioned_name
    
    # Check for XDG_CONFIG_HOME environment variable
    xdg_config_home: str = os.environ.get('XDG_CONFIG_HOME')
    if xdg_config_home:
        return Path(xdg_config_home) / app_name / versioned_name
    
    # Default to platform-specific locations
    if platform.system() == 'Windows':
        return Path(os.environ['APPDATA']) / app_name / versioned_name
    if platform.system() == 'Darwin':
        return Path.home() / 'Library' / app_name / versioned_name
    return Path.home() / '.config' / app_name / versioned_name

def find_supported_python_exe(install_dir: Path, dev: bool) -> List[str]:
    python_cmds = []
    saved_python_cmd = get_saved_python_cmd(install_dir, dev)
    if saved_python_cmd is not None:
        python_cmds.append(saved_python_cmd)
        print("Last used Python executable: " + str(saved_python_cmd))
    
    props: Dict[str, str] = get_application_properties(install_dir)
    prop: str = 'application.python.supported'
    supported: List[str] = [s.strip() for s in props.get(prop, '').split(',')]
    if '' in supported:
        raise ValueError(f'Invalid "{prop}" value in application.properties file')

    python_cmds += list(chain.from_iterable([[f'python{s}'], ['py', f'-{s}']] for s in supported))
    python_cmds += [['python3'], ['python'], ['py']]

    for cmd in python_cmds:
        try:
            result = subprocess.run(cmd + ['-c', 'import sys; print("{0}.{1}".format(*sys.version_info))'], capture_output=True, text=True)
            version = result.stdout.strip()
            if result.returncode == 0 and version in supported:
                return cmd
        except FileNotFoundError:
            pass
        
    return None
    
def in_venv() -> bool:
    return sys.prefix != sys.base_prefix

def is_externally_managed() -> bool:
    get_default_scheme = 'get_default_scheme'
    if hasattr(sysconfig, get_default_scheme):
        # Python 3.10 and later
        default_scheme = getattr(sysconfig, get_default_scheme)
    else:
        # Python 3.9
        default_scheme = getattr(sysconfig, f'_{get_default_scheme}')
    marker: Path = Path(sysconfig.get_path("stdlib", default_scheme())) / 'EXTERNALLY-MANAGED'
    return marker.is_file()

def get_venv_exe(venv_dir: Path) -> List[str]:
    win_python_cmd: str = str(venv_dir / 'Scripts' / 'python.exe')
    linux_python_cmd: str = str(venv_dir / 'bin' / 'python3')
    return [win_python_cmd] if platform.system() == 'Windows' else [linux_python_cmd]

def get_ghidra_venv(install_dir: Path, dev: bool) -> Path:
    return (install_dir / 'build' if dev else get_user_settings_dir(install_dir, dev)) / 'venv'
    
def create_ghidra_venv(python_cmd: List[str], venv_dir: Path) -> None:
    print(f'Creating Ghidra virtual environment at {venv_dir}...')
    subprocess.run(python_cmd + ['-m', 'venv', venv_dir.absolute()])

def version_tuple(v: str) -> Tuple[str, ...]:
    filled = []
    for point in v.split("."):
        filled.append(point.zfill(8))
    return tuple(filled)

def get_package_version(python_cmd: List[str], package: str) -> str:
    version = None
    result = subprocess.run(python_cmd + ['-m', 'pip', 'show', package], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        line = line.strip()
        print(line)
        key, value = line.split(':', 1)
        if key == 'Version':
            version = value.strip()
    return version

def get_saved_python_cmd(install_dir: Path, dev: bool) -> List[str]:
    user_settings_dir: Path = get_user_settings_dir(install_dir, dev)
    save_file: Path = user_settings_dir / 'python_command.save'
    if not save_file.is_file():
        return None
    ret = []
    with open(save_file, 'r') as f:
        for line in f:
            ret.append(line.strip())
    return ret

def save_python_cmd(install_dir: Path, python_cmd: List[str], dev: bool) -> None:
    user_settings_dir: Path = get_user_settings_dir(install_dir, dev)
    if not user_settings_dir.is_dir():
        user_settings_dir.mkdir(parents=True, exist_ok=True)
    save_file: Path = user_settings_dir / 'python_command.save'
    with open(save_file, 'w') as f:
        f.write('\n'.join(python_cmd) + '\n')
    
def install(install_dir: Path, python_cmd: List[str], pip_args: List[str], offer_venv: bool) -> List[str]:
    install_choice: str = input('Do you wish to install PyGhidra (y/n)? ')
    if install_choice.lower() in ('y', 'yes'):
        if offer_venv:
            ghidra_venv_choice: str = input('Install into new Ghidra virtual environment (y/n)? ')
            if ghidra_venv_choice.lower() in ('y', 'yes'):
                venv_dir = get_ghidra_venv(install_dir, False)
                create_ghidra_venv(python_cmd, venv_dir)
                python_cmd = get_venv_exe(venv_dir)
                print(f'Switching to Ghidra virtual environment: {venv_dir}')
            elif ghidra_venv_choice.lower() in ('n', 'no'):
                system_venv_choice: str = input('Install into system environment (y/n)? ')
                if not system_venv_choice.lower() in ('y', 'yes'):
                    print('Must answer "y" to the prior choices, or launch in an already active virtual environment.')
                    return None
            else:
                print('Please answer yes or no.')
                return None 
        subprocess.check_call(python_cmd + pip_args)
        return python_cmd
    elif not install_choice.lower() in ('n', 'no'):
        print('Please answer yes or no.')
    return None     

def upgrade(python_cmd: List[str], pip_args: List[str], dist_dir: Path, current_pyghidra_version: str) -> bool:
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
            subprocess.check_call(python_cmd + pip_args)
            return True
        else:
            print('Skipping upgrade')
            return False
            
def main() -> None:
    # Parse command line arguments
    parser = argparse.ArgumentParser(prog=Path(__file__).name)
    parser.add_argument('install_dir', metavar='<install dir>', help='Ghidra installation directory')
    parser.add_argument('--console', action='store_true', help='Force console launch')
    parser.add_argument('--dev', action='store_true', help='Ghidra development mode')
    parser.add_argument('-H', '--headless', action='store_true', help='Ghidra headless mode')
    args, remaining = parser.parse_known_args()
    
    # Setup variables
    install_dir: Path = Path(os.path.normpath(args.install_dir))
    pyghidra_dir: Path = install_dir / 'Ghidra' / 'Features' / 'PyGhidra'
    dist_dir: Path = pyghidra_dir / 'pypkg' / 'dist'
    venv_dir = get_ghidra_venv(install_dir, args.dev)
    python_cmd: List[str] = find_supported_python_exe(install_dir, args.dev)
    
    if python_cmd is not None:
        print(f'Using Python command: "{" ".join(python_cmd)}"')
    else:
        print('Supported version of Python not found. Check application.properties file.')
        sys.exit(1)
    
    # If headless, force console mode
    if args.headless:
        args.console = True
    
    if args.dev:
        # If in dev mode, launch PyGhidra from the source tree using the development virtual environment
        if not venv_dir.is_dir():
            print('Virtual environment not found!')
            print('Run "gradle prepdev" and try again.')
            sys.exit(1)
        python_cmd = get_venv_exe(venv_dir)
        print(f'Switching to Ghidra virtual environment: {venv_dir}')
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
            python_cmd = get_venv_exe(Path(sys.prefix))
            print(f'Using active virtual environment: {sys.prefix}')
        elif os.path.isdir(venv_dir):
            # If the Ghidra user settings venv exists, use that
            python_cmd = get_venv_exe(venv_dir)
            print(f'Switching to Ghidra virtual environment: {venv_dir}')
        elif is_externally_managed():
            print('Externally managed environment detected!')
            create_ghidra_venv(python_cmd, venv_dir)
            python_cmd = get_venv_exe(venv_dir)
            print(f'Switching to Ghidra virtual environment: {venv_dir}')
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
    save_python_cmd(install_dir, python_cmd, args.dev)
    py_args: List[str] = python_cmd + ['-m', 'pyghidra.ghidra_launch', '--install-dir', str(install_dir)]
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
