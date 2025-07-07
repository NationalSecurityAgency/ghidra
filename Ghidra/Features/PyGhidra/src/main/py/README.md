# PyGhidra

The PyGhidra Python library, originally developed by the 
[Department of Defense Cyber Crime Center (DC3)](https://www.dc3.mil) under the name "Pyhidra", is a
Python library that provides direct access to the Ghidra API within a native CPython 3 interpreter 
using [JPype](https://jpype.readthedocs.io/en/latest). PyGhidra contains some conveniences for
setting up analysis on a given sample and running a Ghidra script locally. It also contains a Ghidra
plugin to allow the use of CPython 3 from the Ghidra GUI.

## Installation and Setup
Ghidra provides an out-of-the box integration with the PyGhidra Python library which makes 
installation and usage fairly straightforward. This enables the Ghidra GUI and headless Ghidra to
run GhidraScript's written in native CPython 3, as well as interact with the Ghidra GUI through a 
built-in REPL. To launch Ghidra in PyGhidra-mode, see Ghidra's latest
[Getting Started](https://github.com/NationalSecurityAgency/ghidra/blob/stable/GhidraDocs/GettingStarted.md#pyghidra-mode)
document.

It is also possible (and encouraged!) to use PyGhidra as a standalone Python library for usage 
in reverse engineering workflows where Ghidra may be one of many components involved. The following 
instructions in this document focus on this type of usage.

To install the PyGhidra Python library:
1. Download and install
   [Ghidra 11.3 or later](https://github.com/NationalSecurityAgency/ghidra/releases) to a desired 
   location.
2. Set the `GHIDRA_INSTALL_DIR` environment variable to point to the directory where Ghidra is 
   installed.
3. Install PyGhidra:
   * Online: `pip install pyghidra`
   * Offline: `python3 -m pip install --no-index -f 
     <GhidraInstallDir>/Ghidra/Features/PyGhidra/pypkg/dist pyghidra`
     
Optionally, you can also install the Ghidra type stubs to improve your development experience 
(assuming your Python editor supports it). The type stubs module is specific to each version of
Ghidra:
* Online: `pip install ghidra-stubs==<version>`
* Offline: `python3 -m pip install --no-index -f <GhidraInstallDir>/docs/ghidra_stubs ghidra-stubs`

## API
The current version of PyGhidra inherits an API from the original "Pyhidra" project that provides an
excellent starting point for interacting with a Ghidra installation. __NOTE:__ These functions are 
subject to change in the future as more thought and feedback is collected on PyGhidra's role in the
greater Ghidra ecosystem:

### pyghidra.start()
To get a raw connection to Ghidra use the `start()` function. This will setup a JPype connection and
initialize Ghidra in headless mode, which will allow you to directly import `ghidra` and `java`.

__NOTE:__ No projects or programs get setup in this mode.

```python
def start(verbose=False, *, install_dir: Path = None) -> "PyGhidraLauncher":
    """
    Starts the JVM and fully initializes Ghidra in Headless mode.

    :param verbose: Enable verbose output during JVM startup (Defaults to False)
    :param install_dir: The path to the Ghidra installation directory.
        (Defaults to the GHIDRA_INSTALL_DIR environment variable or "lastrun" file)
    :return: The PyGhidraLauncher used to start the JVM
    """
```

#### Example:
```python
import pyghidra
pyghidra.start()

import ghidra
from ghidra.app.util.headless import HeadlessAnalyzer
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.base.project import GhidraProject
from java.lang import String

# do things
```

### pyghidra.started()
To check to see if PyGhidra has been started, use the `started()` function.

```python
def started() -> bool:
    """
    Whether the PyGhidraLauncher has already started.
    """
```

#### Example: 
```python
import pyghidra

if pyghidra.started():
    ...
```

### pyghidra.open_program()
To have PyGhidra setup a binary file for you, use the `open_program()` function. This will setup a 
Ghidra project and import the given binary file as a program for you.

Again, this will also allow you to import `ghidra` and `java` to perform more advanced processing.

```python
def open_program(
        binary_path: Union[str, Path],
        project_location: Union[str, Path] = None,
        project_name: str = None,
        analyze=True,
        language: str = None,
        compiler: str = None,
        loader: Union[str, JClass] = None,
        program_name: str = None,
        nested_project_location = True
) -> ContextManager["FlatProgramAPI"]: # type: ignore
    """
    Opens given binary path (or optional program name) in Ghidra and returns FlatProgramAPI object.

    :param binary_path: Path to binary file, may be None.
    :param project_location: Location of Ghidra project to open/create.
        (Defaults to same directory as binary file)
    :param project_name: Name of Ghidra project to open/create.
        (Defaults to name of binary file suffixed with "_ghidra")
    :param analyze: Whether to run analysis before returning.
    :param language: The LanguageID to use for the program.
        (Defaults to Ghidra's detected LanguageID)
    :param compiler: The CompilerSpecID to use for the program. Requires a provided language.
        (Defaults to the Language's default compiler)
    :param loader: The `ghidra.app.util.opinion.Loader` class to use when importing the program.
        This may be either a Java class or its path. (Defaults to None)
    :param program_name: The name of the program to open in Ghidra.
        (Defaults to None, which results in the name being derived from "binary_path")
    :param nested_project_location: If True, assumes "project_location" contains an extra nested 
        directory named "project_name", which contains the actual Ghidra project files/directories.
        By default, PyGhidra creates Ghidra projects with this nested layout, but the standalone
        Ghidra program does not.  Nested project locations are True by default to maintain backwards
        compatibility with older versions of PyGhidra.
    :return: A Ghidra FlatProgramAPI object.
    :raises ValueError: If the provided language, compiler or loader is invalid.
    :raises TypeError: If the provided loader does not implement `ghidra.app.util.opinion.Loader`.
    """
```

#### Example:

```python
import pyghidra

with pyghidra.open_program("binary_file.exe") as flat_api:
    program = flat_api.getCurrentProgram()
    listing = program.getListing()
    print(listing.getCodeUnitAt(flat_api.toAddr(0x1234)))

    # We are also free to import ghidra while in this context to do more advanced things.
    from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
    decomp_api = FlatDecompilerAPI(flat_api)
    ...
    decomp_api.dispose()
```

By default, PyGhidra will run analysis for you. If you would like to do this yourself, set `analyze`
to `False`.

```python
import pyghidra

with pyghidra.open_program("binary_file.exe", analyze=False) as flat_api:
    from ghidra.program.util import GhidraProgramUtilities

    program = flat_api.getCurrentProgram()
    if GhidraProgramUtilities.shouldAskToAnalyze(program):
        flat_api.analyzeAll(program)
```

The `open_program()` function can also accept optional arguments to control the project name and
location that gets created (helpful for opening up a sample in an already existing project).

```python
import pyghidra

with pyghidra.open_program("binary_file.exe", project_name="MyProject", project_location=r"C:\projects") as flat_api:
    ...
```

### pyghidra.run_script()
PyGhidra can also be used to run an existing Ghidra Python script directly in your native CPython 
interpreter using the `run_script()` function. However, while you can technically run an existing 
Ghidra script unmodified, you may run into issues due to differences between Jython 2 and 
CPython 3/JPype. Therefore, some modification to the script may be needed.

```python
def run_script(
    binary_path: Optional[Union[str, Path]],
    script_path: Union[str, Path],
    project_location: Union[str, Path] = None,
    project_name: str = None,
    script_args: List[str] = None,
    verbose=False,
    analyze=True,
    lang: str = None,
    compiler: str = None,
    loader: Union[str, JClass] = None,
    program_name = None,
    nested_project_location = True,
    *,
    install_dir: Path = None
):
    """
    Runs a given script on a given binary path.

    :param binary_path: Path to binary file, may be None.
    :param script_path: Path to script to run.
    :param project_location: Location of Ghidra project to open/create.
        (Defaults to same directory as binary file if None)
    :param project_name: Name of Ghidra project to open/create.
        (Defaults to name of binary file suffixed with "_ghidra" if None)
    :param script_args: Command line arguments to pass to script.
    :param verbose: Enable verbose output during Ghidra initialization.
    :param analyze: Whether to run analysis, if a binary_path is provided, before running the script.
    :param lang: The LanguageID to use for the program.
        (Defaults to Ghidra's detected LanguageID)
    :param compiler: The CompilerSpecID to use for the program. Requires a provided language.
        (Defaults to the Language's default compiler)
    :param loader: The `ghidra.app.util.opinion.Loader` class to use when importing the program.
        This may be either a Java class or its path. (Defaults to None)
    :param install_dir: The path to the Ghidra installation directory. This parameter is only
        used if Ghidra has not been started yet.
        (Defaults to the GHIDRA_INSTALL_DIR environment variable or "lastrun" file)
    :param program_name: The name of the program to open in Ghidra.
        (Defaults to None, which results in the name being derived from "binary_path")
    :param nested_project_location: If True, assumes "project_location" contains an extra nested 
        directory named "project_name", which contains the actual Ghidra project files/directories.
        By default, PyGhidra creates Ghidra projects with this nested layout, but the standalone
        Ghidra program does not.  Nested project locations are True by default to maintain backwards
        compatibility with older versions of PyGhidra.
    :raises ValueError: If the provided language, compiler or loader is invalid.
    :raises TypeError: If the provided loader does not implement `ghidra.app.util.opinion.Loader`.
    """
```

#### Example:
```python
import pyghidra

pyghidra.run_script(r"C:\input.exe", r"C:\some_ghidra_script.py")
```

This can also be done on the command line using `pyghidra`.

```console
> pyghidra C:\input.exe C:\some_ghidra_script.py <CLI ARGS PASSED TO SCRIPT>
```

### pyghidra.launcher.PyGhidraLauncher()
JVM configuration for the classpath and vmargs may be done through a `PyGhidraLauncher`.  

```python
class PyGhidraLauncher:
    """
    Base pyghidra launcher
    """

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

    def start(self, **jpype_kwargs):
        """
        Starts Jpype connection to Ghidra (if not already started).
        """
```

The following `PyGhidraLauncher`s are available:

```python
class HeadlessPyGhidraLauncher(PyGhidraLauncher):
    """
    Headless pyghidra launcher
    """
```
```python
class DeferredPyGhidraLauncher(PyGhidraLauncher):
    """
    PyGhidraLauncher which allows full Ghidra initialization to be deferred.
    initialize_ghidra must be called before all Ghidra classes are fully available.
    """
```
```python
class GuiPyGhidraLauncher(PyGhidraLauncher):
    """
    GUI pyghidra launcher
    """
```

#### Example:
```python
from pyghidra.launcher import HeadlessPyGhidraLauncher

launcher = HeadlessPyGhidraLauncher()
launcher.add_classpaths("log4j-core-2.17.1.jar", "log4j-api-2.17.1.jar")
launcher.add_vmargs("-Dlog4j2.formatMsgNoLookups=true")
launcher.start()
```

## Handling Package Name Conflicts
There may be some Python modules and Java packages with the same import path. When this occurs the
Python module takes precedence. While JPype has its own mechanism for handling this situation, 
PyGhidra automatically makes the Java package accessible by allowing it to be imported with an 
underscore appended to the package name:

```python
import pdb   # imports Python's pdb
import pdb_  # imports Ghidra's pdb
```
## Change History
__2.2.1:__
* PyGhidra now launches with the current working directory removed from `sys.path` to prevent
  the potential for importing invalid modules from random `ghidra/` or `java/` directories that may 
  exist in the user's current working directory.

__2.2.0:__
* [`pyghidra.open_program()`](#pyghidraopen_program) and 
  [`pyghidra.run_script()`](#pyghidrarun_script) now accept a `nested_project_location` parameter
  which can be set to `False` to open existing Ghidra projects that were created with the
  Ghidra GUI.
* If a Ghidra installation directory is not specified by the `install_dir` parameter or
  `GHIDRA_INSTALL_DIR` environment variable, PyGhidra will look for a `lastrun` file in the
  Ghidra user settings parent directory, and use the installation directory it specifies.  The
  `lastrun` file is created by Ghidra 11.4 and later.

__2.1.0:__
* [`pyghidra.open_program()`](#pyghidraopen_program) now accepts a `program_name` parameter, which
  can be used to override the program name derived from the `binary_path` parameter.
* [`pyghidra.open_program()`](#pyghidraopen_program) now properly throws an exception if the project
  exists and is locked.
  
__2.0.1:__
* PyGhidra now respects the `application.settingsdir` property set in Ghidra's `launch.properties`
  file.
* Fixed an issue that prevented accessing Java getters/setters as properties on non-public classes.
* PyGhidra can now find modules that live in directories specified by Ghidra's _"Bundle Manager"_.

__2.0.0:__
* Initial Release.