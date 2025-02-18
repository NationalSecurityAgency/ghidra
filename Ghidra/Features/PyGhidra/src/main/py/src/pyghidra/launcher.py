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
import contextlib
import ctypes.util
import html
import importlib.metadata
import inspect
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from importlib.machinery import ModuleSpec
from pathlib import Path
from typing import List, NoReturn, Tuple, Union

import jpype
from jpype import imports, _jpype
from packaging.version import Version

from pyghidra.javac import java_compile
from pyghidra.script import PyGhidraScript
from pyghidra.version import ApplicationInfo, ExtensionDetails, MINIMUM_GHIDRA_VERSION

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def _silence_java_output(stdout=True, stderr=True):
    from java.io import OutputStream, PrintStream # type:ignore @UnresolvedImport
    from java.lang import System # type:ignore @UnresolvedImport
    out = System.out
    err = System.err
    null = PrintStream(OutputStream.nullOutputStream())

    # The user's Java SecurityManager might not allow this
    with contextlib.suppress(jpype.JException):
        if stdout:
            System.setOut(null)
        if stderr:
            System.setErr(null)

    try:
        yield
    finally:
        with contextlib.suppress(jpype.JException):
            System.setOut(out)
            System.setErr(err)


def _load_entry_points(group: str, *args):
    """
    Loads any entry point callbacks registered by external python packages.
    """
    try:
        entries = importlib.metadata.entry_points(group=group)
    except TypeError:
        # this is deprecated but the above doesn't work for 3.9
        entry_points = importlib.metadata.entry_points()
        if hasattr(entry_points, 'select'):
            entries = entry_points.select(group=group)
        else:
            entries = entry_points.get(group, None)
            if entries is None:
                return
    for entry in entries:
        name = entry.name
        try:
            # Give launcher to callback so they can edit vmargs, install plugins, etc.
            callback = entry.load()
            logger.debug(f"Calling {group} entry point: {name}")
            callback(*args)
        except Exception as e:
            logger.error(f"Failed to run {group} entry point {name} with error: {e}")


class _PyGhidraImportLoader:
    """ (internal) Finder hook for importlib to handle Python mod conflicts. """

    def find_spec(self, name, path, target=None):

        # If jvm is not started then there is nothing to find.
        if not _jpype.isStarted():
            return None

        if name.endswith('_') and _jpype.isPackage(name[:-1]):
            return ModuleSpec(name, self)

    def create_module(self, spec):
        return _jpype._JPackage(spec.name[:-1])

    def exec_module(self, fullname):
        pass

class _GhidraBundleFinder(importlib.machinery.PathFinder):
    """ (internal) Used to find modules in Ghidra bundle locations """
    
    def find_spec(self, fullname, path=None, target=None):
        from ghidra.framework import Application
        from ghidra.app.script import GhidraScriptUtil
        if Application.isInitialized():
            GhidraScriptUtil.acquireBundleHostReference()
            try:
                for directory in GhidraScriptUtil.getEnabledScriptSourceDirectories():
                    spec = super().find_spec(fullname, [directory.absolutePath], target)
                    if spec is not None:
                        return spec
            finally:
                GhidraScriptUtil.releaseBundleHostReference()
        return None

@contextlib.contextmanager
def _plugin_lock():
    """
    File lock for processing plugins
    """
    from java.io import RandomAccessFile # type:ignore @UnresolvedImport
    path = Path(tempfile.gettempdir()) / "pyghidra_plugin_lock"
    try:
        # Python doesn't have a file lock except for unix systems
        # so use the one available in Java instead of adding on
        # a third party library
        with RandomAccessFile(str(path), "rw") as fp:
            lock = fp.getChannel().lock()
            try:
                yield
            finally:
                lock.release()
    finally:
        try:
            path.unlink()
        except:
            # if it fails it's ok
            # another pyghidra process has the lock
            # it will be removed by said process when done
            pass


class PyGhidraLauncher:
    """
    Base pyghidra launcher
    """

    def __init__(self, verbose=False, *, install_dir: Path = None):
        """
        Initializes a new `PyGhidraLauncher`.

        :param verbose: True to enable verbose output when starting Ghidra.
        :param install_dir: Ghidra installation directory.
            (Defaults to the GHIDRA_INSTALL_DIR environment variable)
        :raises ValueError: If the Ghidra installation directory is invalid.
        """
        self._layout = None
        self._launch_support = None
        self._java_home = None
        self._dev_mode = False
        self._extension_path = None

        install_dir = install_dir or os.getenv("GHIDRA_INSTALL_DIR")
        self._install_dir = self._validate_install_dir(install_dir)

        java_home_override = os.getenv("JAVA_HOME_OVERRIDE")
        if java_home_override:
            self._java_home = java_home_override

        # check if we are in the ghidra source tree
        support = Path(install_dir) / "support"
        if not support.exists():
            self._dev_mode = True

        self._plugins: List[Tuple[Path, ExtensionDetails]] = []
        self.verbose = verbose

        ghidra_dir = self._install_dir / "Ghidra"
        utility_dir = ghidra_dir / "Framework" / "Utility"
        if self._dev_mode:
            self._setup_dev_classpath(utility_dir)
        else:
            self.class_path = [str(utility_dir / "lib" / "Utility.jar")]
        self.class_files = []
        self.vm_args = self._jvm_args()
        self.args = []
        self.app_info = ApplicationInfo.from_file(ghidra_dir / "application.properties")

    def _setup_dev_classpath(self, utility_dir: Path):
        """
        Sets up the classpath for dev mode as seen in
        Ghidra/RuntimeScripts/Linux/support/launch.sh
        """
        bin_dir = Path("bin") / "main"
        build_dir = Path("build") / "libs"
        ls_root = self._install_dir / "GhidraBuild" / "LaunchSupport"
        classpath = utility_dir / bin_dir
        launch_support = ls_root / bin_dir

        if not launch_support.exists():
            classpath = utility_dir / build_dir / "Utility.jar"
            launch_support = ls_root / build_dir / "LaunchSupport.jar"

        if not launch_support.exists():
            msg = "Cannot launch from repo because Ghidra has not been compiled " \
                  "with Eclipse or Gradle."
            self._report_fatal_error("Ghidra not built", msg, ValueError(msg))

        self.class_path = [str(classpath)]
        if not self._java_home:
            self._launch_support = launch_support

    def _parse_dev_args(self) -> List[str]:
        path = self._install_dir / "Ghidra" / "Features" / "Base" / ".launch" / "Ghidra.launch"
        for line in path.read_text("utf-8").splitlines():
            if "org.eclipse.jdt.launching.VM_ARGUMENTS" in line:
                _, _, value = line.partition("value=")
                value = value.removesuffix("/>")
                return html.unescape(value).split()

        raise Exception("org.eclipse.jdt.launching.VM_ARGUMENTS not found")

    def _jvm_args(self) -> List[str]:
        
        properties = [
            f"-Dpyghidra.sys.prefix={sys.prefix}",
            f"-Dpyghidra.sys.executable={sys.executable}"
        ]
        
        if self._dev_mode and self._java_home:
            return properties + self._parse_dev_args()

        suffix = "_" + platform.system().upper()
        if suffix == "_DARWIN":
            suffix = "_MACOS"
        option_pattern: re.Pattern = re.compile(fr"VMARGS(?:{suffix})?=(.+)")

        root = self._install_dir

        if self._dev_mode:
            root = root / "Ghidra" / "RuntimeScripts" / "Common"

        launch_properties = root / "support" / "launch.properties"

        for line in Path(launch_properties).read_text().splitlines():
            _, _, override = line.partition("JAVA_HOME_OVERRIDE=")
            if override:
                if override.startswith('"') and override.endswith('"'):
                    override = override.removeprefix('"').removesuffix('"')
                self._java_home = Path(override)
                continue
            match = option_pattern.match(line)
            if match:
                arg = match.group(1)
                name, sep, value = arg.partition('=')
                # unquote any values because quotes are automatically added during JVM startup
                if value.startswith('"') and value.endswith('"'):
                    value = value.removeprefix('"').removesuffix('"')
                properties.append(name + sep + value)
        return properties

    @property
    def extension_path(self) -> Path:
        if self._extension_path:
            return self._extension_path
        if not self._layout:
            raise RuntimeError("extension_path cannot be obtained until launcher starts.")
        # cache the extension path so we can use it after the JVM shuts down during testing
        self._extension_path = Path(self._layout.getUserSettingsDir().getPath()) / "Extensions"
        return self._extension_path

    @property
    def java_home(self) -> Path:
        if not self._java_home:
            if self._launch_support:
                launch_support = self._launch_support
            else:
                launch_support = self.install_dir / "support" / "LaunchSupport.jar"
            if not launch_support.exists():
                raise ValueError(f"{launch_support} does not exist")
            cmd = f'java -cp "{launch_support}" LaunchSupport "{self.install_dir}" -jdk_home -save'
            home = subprocess.check_output(cmd, encoding="utf-8", shell=True)
            self._java_home = Path(home.rstrip())
        return self._java_home

    @java_home.setter
    def java_home(self, path: Path):
        self._java_home = Path(path)

    @property
    def install_dir(self) -> Path:
        return self._install_dir

    @classmethod
    def _validate_install_dir(cls, install_dir: Union[Path, str]) -> Path:
        """
        Validates and sets the Ghidra installation directory.
        """
        if not install_dir:
            msg = (
                "Please set the GHIDRA_INSTALL_DIR environment variable "
                "or `install_dir` during the Launcher construction to the "
                "directory where Ghidra is installed."
            )
            cls._report_fatal_error("GHIDRA_INSTALL_DIR is not set", msg, ValueError(msg))

        # both the directory and the application.properties file must exist
        install_dir = Path(install_dir)
        if not install_dir.exists():
            msg = f"{install_dir} does not exist"
            cls._report_fatal_error("Invalid Ghidra Installation Directory", msg, ValueError(msg))

        path = install_dir / "Ghidra" / "application.properties"
        if not path.exists():
            msg = "The Ghidra installation does not contain the required " + \
                  "application.properties file"
            cls._report_fatal_error("Corrupt Ghidra Installation", msg, ValueError(msg))

        support = install_dir / "support"

        if not support.exists():
            # dev mode
            return install_dir

        path = install_dir / "Ghidra" / "Features" / "PyGhidra" / "lib" / "PyGhidra.jar"

        if not path.exists():
            msg = "The Ghidra installation does not contain the PyGhidra module\n" + \
                 f"{path} does not exist"
            cls._report_fatal_error("Incorrect Ghidra installation directory", msg, ValueError(msg))

        return install_dir

    def add_classpaths(self, *args):
        """
        Add additional entries to the classpath when starting the JVM
        """
        self.class_path += args

    def add_vmargs(self, *args):
        """
        Add additional vmargs for launching the JVM
        """
        self.vm_args += args

    def add_class_files(self, *args):
        """
        Add additional entries to be added the classpath after Ghidra has been fully loaded.
        This ensures that all of Ghidra is available so classes depending on it can be properly loaded.
        """
        self.class_files += args

    @classmethod
    def _report_fatal_error(cls, title: str, msg: str, cause: Exception) -> NoReturn:
        logger.error("%s: %s", title, msg)
        raise cause

    def check_ghidra_version(self):
        """
        Checks if the currently installed Ghidra version is supported.
        The launcher will report the problem and terminate if it is not supported.
        """
        if Version(self.app_info.version) < Version(MINIMUM_GHIDRA_VERSION):
            msg = f"Ghidra version {self.app_info.version} is not supported" + os.linesep + \
                  f"The minimum required version is {MINIMUM_GHIDRA_VERSION}"
            self._report_fatal_error("Unsupported Version", msg, ValueError(msg))

    def _setup_java(self, **jpype_kwargs):
        """
        Run setup entry points, start the JVM and prepare ghidra imports
        """
        # Before starting up, give launcher to installed entry points so they can do their thing.
        _load_entry_points("pyghidra.setup", self)

        # Merge classpath
        jpype_kwargs['classpath'] = self.class_path + jpype_kwargs.get('classpath', [])

        # force convert strings (required by pyghidra)
        jpype_kwargs['convertStrings'] = True

        # set the JAVA_HOME environment variable to the correct one so jpype uses it
        os.environ['JAVA_HOME'] = str(self.java_home)

        jpype_kwargs['ignoreUnrecognized'] = True

        if os.getenv("PYGHIDRA_DEBUG"):
            debug = "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=127.0.0.1:18001"
            self.vm_args.insert(0, debug)

        jpype.startJVM(
            None, # indicates to use JAVA_HOME as the jvm path
            *self.vm_args,
            **jpype_kwargs
        )

        # Install hooks into python importlib
        sys.meta_path.append(_PyGhidraImportLoader())
        sys.meta_path.append(_GhidraBundleFinder())

        imports.registerDomain("ghidra")

    def _pre_launch_init(self):
        """
        Prepare registered plugins and initialize the Ghidra environment
        """

        # import and create a temporary GhidraApplicationLayout this can be
        # used without initializing Ghidra to obtain the correct Extension path
        from ghidra import GhidraApplicationLayout
        self._layout = GhidraApplicationLayout()



        # remove any old installed pyhidra extension
        # if left in place Ghidra will fail to start with a confusing
        # and unrelated error about the InterpreterConsole class not being found
        # this is only needed for those using a DEV build of Ghidra
        # who also have and old version of pyhidra installed.
        # however, this took an unnecessary amount of time to debug
        self.uninstall_plugin("pyhidra")

        # uninstall any outdated plugins before initializing
        # Ghidra to ensure they are loaded correctly
        for _, details in self._plugins:
            try:
                self._uninstall_old_plugin(details)
            except:
                logger.warning("failed to uninstall plugin %s", details.name)

        from ghidra import GhidraLauncher
        self._layout = GhidraLauncher.initializeGhidraEnvironment()

        # import it at the end so interfaces in our java code may be implemented
        from pyghidra.internal.plugin.plugin import setup_plugin
        setup_plugin()

        # Add extra class paths
        # Do this before installing plugins incase dependencies are needed
        if self.class_files:
            from java.lang import ClassLoader # type:ignore @UnresolvedImport
            gcl = ClassLoader.getSystemClassLoader()
            for path in self.class_files:
                gcl.addPath(path)

        needs_reload = False

        # Install extra plugins.
        for source_path, details in self._plugins:
            try:
                needs_reload = self._install_plugin(source_path, details) or needs_reload
            except Exception as e:
                # we should always warn if a plugin failed to compile
                logger.warning(e, exc_info=e)

        if needs_reload:
            # "restart" Ghidra
            self._layout = GhidraLauncher.initializeGhidraEnvironment()

        # import properties to register the property customizer
        from pyghidra import properties as _  # @UnusedImport

        _load_entry_points("pyghidra.pre_launch")

    def start(self, **jpype_kwargs):
        """
        Starts Jpype connection to Ghidra (if not already started).
        """
        if jpype.isJVMStarted():
            return

        self.check_ghidra_version()

        try:
            self._setup_java(**jpype_kwargs)
            with _plugin_lock():
                self._pre_launch_init()
            self._launch()
        except Exception as e:
            self._report_fatal_error("An error occurred launching Ghidra", str(e), e)

    def get_install_path(self, plugin_name: str) -> Path:
        """
        Obtains the path for installation of a given plugin.
        """
        return self.extension_path / plugin_name

    def _get_plugin_jar_path(self, plugin_name: str) -> Path:
        return self.get_install_path(plugin_name) / "lib" / (plugin_name + ".jar")

    def uninstall_plugin(self, plugin_name: str):
        """
        Uninstalls given plugin.
        """
        path = self.get_install_path(plugin_name)
        if path.exists():
            # delete the existing extension so it will be up-to-date
            shutil.rmtree(path)

    def _uninstall_old_plugin(self, details: ExtensionDetails):
        """
        Automatically uninstalls an outdated plugin if it exists.
        """
        plugin_name = details.name
        path = self.get_install_path(plugin_name)
        ext = path / "extension.properties"

        # Uninstall old version.
        if path.exists() and ext.exists():
            orig_details = ExtensionDetails.from_file(ext)
            if not orig_details.plugin_version or orig_details.plugin_version != details.plugin_version:
                try:
                    self.uninstall_plugin(plugin_name)
                except Exception as e:
                    logger.warning("Could not delete existing plugin at %s", path, exc_info=e)
                else:
                    logger.info(f"Uninstalled older plugin: {plugin_name} {orig_details.plugin_version}")

    def _install_plugin(self, source_path: Path, details: ExtensionDetails):
        """
        Compiles and installs a Ghidra extension if not already installed.
        """
        # No clunky plugin building required
        # `pip install *` and done
        if details.version is None:
            details.version = self.app_info.version
        plugin_name = details.name
        path = self.get_install_path(plugin_name)
        ext = path / "extension.properties"
        manifest = path / "Module.manifest"
        root = source_path
        jar_path = path / "lib" / (plugin_name + ".jar")

        if not jar_path.exists():
            path.mkdir(parents=True, exist_ok=True)

            try:
                java_compile(root, jar_path)
            except:
                shutil.rmtree(path, ignore_errors=True)
                raise

            ext.write_text(str(details))

            # required empty file
            manifest.touch()

            # Copy over ghidra_scripts if included.
            ghidra_scripts = root / "ghidra_scripts"
            if ghidra_scripts.exists():
                shutil.copytree(ghidra_scripts, path / "ghidra_scripts")

            logger.info(f"Installed plugin: {plugin_name} {details.plugin_version}")
            return True

        return False

    def install_plugin(self, source_path: Path, details: ExtensionDetails):
        """
        Compiles and installs a Ghidra extension when launcher is started.
        """
        self._plugins.append((source_path, details))

    def _launch(self):
        pass

    @staticmethod
    def has_launched() -> bool:
        """
        Checks if jpype has started and if Ghidra has been fully initialized.
        """
        if not jpype.isJVMStarted():
            return False

        from ghidra.framework import Application
        return Application.isInitialized()


class DeferredPyGhidraLauncher(PyGhidraLauncher):
    """
    PyGhidraLauncher which allows full Ghidra initialization to be deferred.
    initialize_ghidra must be called before all Ghidra classes are fully available.
    """

    def initialize_ghidra(self, headless=True):
        """
        Finished Ghidra initialization

        :param headless: whether or not to initialize Ghidra in headless mode.
            (Defaults to True)
        """
        from ghidra import GhidraRun
        from ghidra.framework import Application, HeadlessGhidraApplicationConfiguration
        with _silence_java_output(not self.verbose, not self.verbose):
            if headless:
                config = HeadlessGhidraApplicationConfiguration()
                Application.initializeApplication(self._layout, config)
            else:
                GhidraRun().launch(self._layout, self.args)


class HeadlessPyGhidraLauncher(PyGhidraLauncher):
    """
    Headless pyghidra launcher
    """

    def _launch(self):
        from ghidra.framework import Application, HeadlessGhidraApplicationConfiguration
        with _silence_java_output(not self.verbose, not self.verbose):
            config = HeadlessGhidraApplicationConfiguration()
            Application.initializeApplication(self._layout, config)


class _PyGhidraStdOut:

    def __init__(self, stream):
        self._stream = stream

    def _get_current_script(self) -> "PyGhidraScript":
        for entry in inspect.stack():
            f_globals = entry.frame.f_globals
            if isinstance(f_globals, PyGhidraScript):
                return f_globals

    def flush(self):
        script = self._get_current_script()
        if script is not None:
            writer = script._script.writer
            if writer is not None:
                writer.flush()
                return

        self._stream.flush()

    def write(self, s: str) -> int:
        script = self._get_current_script()
        if script is not None:
            writer = script._script.writer
            if writer is not None:
                writer.write(s)
                return len(s)

        return self._stream.write(s)


class GuiPyGhidraLauncher(PyGhidraLauncher):
    """
    GUI pyghidra launcher
    """

    @classmethod
    def popup_error(cls, header: str, msg: str) -> NoReturn:
        import tkinter.messagebox
        tkinter.messagebox.showerror(header, msg)
        sys.exit()

    @classmethod
    def _report_fatal_error(cls, title: str, msg: str, cause: Exception) -> NoReturn:
        logger.exception(cause, exc_info=cause)
        cls.popup_error(title, msg)

    @staticmethod
    def _get_thread(name: str):
        from java.lang import Thread # type:ignore @UnresolvedImport
        for t in Thread.getAllStackTraces().keySet():
            if t.getName() == name:
                return t
        return None

    def _launch(self):
        from ghidra import Ghidra
        from java.lang import Runtime, Thread # type:ignore @UnresolvedImport

        if sys.platform == "win32":
            appid = ctypes.c_wchar_p(self.app_info.name)
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(appid) # @UndefinedVariable

        stdout = _PyGhidraStdOut(sys.stdout)
        stderr = _PyGhidraStdOut(sys.stderr)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            Thread(lambda: Ghidra.main(["ghidra.GhidraRun", *self.args])).start()
            is_exiting = threading.Event()
            Runtime.getRuntime().addShutdownHook(Thread(is_exiting.set))
            if sys.platform == "darwin":
                _run_mac_app()
            is_exiting.wait()


def _run_mac_app():
    # this runs the event loop
    # it is required for the GUI to show up
    from ctypes import c_void_p, c_double, c_uint64, c_int64, c_int32, c_bool, CFUNCTYPE

    CoreFoundation = ctypes.cdll.LoadLibrary(ctypes.util.find_library("CoreFoundation"))

    def get_function(name, restype, *argtypes):
        res = getattr(CoreFoundation, name)
        res.argtypes = [arg for arg in argtypes]
        res.restype = restype
        return res

    CFRunLoopTimerCallback = CFUNCTYPE(None, c_void_p, c_void_p)
    kCFRunLoopDefaultMode = c_void_p.in_dll(CoreFoundation, "kCFRunLoopDefaultMode")
    kCFRunLoopRunFinished = c_int32(1)
    NULL = c_void_p(0)
    INF_TIME = c_double(1.0e20)
    FIRE_ONCE = c_double(0)
    kCFAllocatorDefault = NULL

    CFRunLoopGetCurrent = get_function("CFRunLoopGetCurrent", c_void_p)
    CFRelease = get_function("CFRelease", None, c_void_p)

    CFRunLoopTimerCreate = get_function(
        "CFRunLoopTimerCreate",
        c_void_p,
        c_void_p,
        c_double,
        c_double,
        c_uint64,
        c_int64,
        CFRunLoopTimerCallback,
        c_void_p
    )

    CFRunLoopAddTimer = get_function("CFRunLoopAddTimer", None, c_void_p, c_void_p, c_void_p)
    CFRunLoopRunInMode = get_function("CFRunLoopRunInMode", c_int32, c_void_p, c_double, c_bool)

    @CFRunLoopTimerCallback
    def dummy_timer(timer, info):
        # this doesn't need to do anything
        # CFRunLoopTimerCreate just needs a valid callback
        return

    timer = CFRunLoopTimerCreate(kCFAllocatorDefault, INF_TIME, FIRE_ONCE, 0, 0, dummy_timer, NULL)
    CFRunLoopAddTimer(CFRunLoopGetCurrent(), timer, kCFRunLoopDefaultMode)
    CFRelease(timer)

    while CFRunLoopRunInMode(kCFRunLoopDefaultMode, INF_TIME, False) != kCFRunLoopRunFinished:
        pass
