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
   [Ghidra 12.0 or later](https://github.com/NationalSecurityAgency/ghidra/releases) to a desired 
   location.
2. Install PyGhidra:
   * Online: `pip install pyghidra`
   * Offline: `python3 -m pip install --no-index -f 
     <GhidraInstallDir>/Ghidra/Features/PyGhidra/pypkg/dist pyghidra`
3. Optionally install the Ghidra type stubs to improve your development experience (assuming your 
   Python editor supports it). The type stubs module is specific to each version of Ghidra:
   * Online: `pip install ghidra-stubs==<version>`
   * Offline: `python3 -m pip install --no-index -f <GhidraInstallDir>/docs/ghidra_stubs ghidra-stubs`
4. Optionally point PyGhidra at your Ghidra installation by setting the `GHIDRA_INSTALL_DIR` 
   environment variable. If not set, PyGhidra will point itself at the last used installation of
   Ghidra. Alternatively, you can point PyGhidra at a Ghidra installation with
   `pyghidra.start(install_dir=<GhidraInstallDir>)` (see below).

## API
The current version of PyGhidra introduces many new API methods with the goal of making the most
common Ghidra tasks quick and easy, such as opening a project, getting a program, running a
GhidraScript, etc. The inherited API from the original "Pyhidra" project is still available, but at 
this point it will only receive bug fixes.

### pyghidra.start()
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

### pyghidra.started()
```python
def started() -> bool:
    """
    Whether the PyGhidraLauncher has already started.
    """
```

### pyghidra.open_project()
```python
def open_project(
        path: Union[str, Path],
        name: str,
        create: bool = False
) -> "Project": # type: ignore
    """
    Opens the Ghidra project at the given location, optionally creating it if it doesn't exist.

    :param path: Path of Ghidra project parent directory.
    :param name: Name of Ghidra project to open/create.
    :param create: Whether to create the project if it doesn't exist
    :return: A Ghidra "Project" object.
    :raises FileNotFoundError: If the project to open was not found and it shouldn't be created.
    """
```

### pyghidra.open_filesystem()
```python
def open_filesystem(
        path: Union[str, Path]
    ) -> "GFileSystem":
    """
    Opens a filesystem in Ghidra.

    :param path: Path of filesystem to open in Ghidra.
    :return: A Ghidra "GFileSystem" object.
    :raises ValueError: If the filesystem to open is not supported by Ghidra.
    """
```

### pyghidra.consume_program()
```python
def consume_program(
        project: "Project", 
        path: Union[str, Path],
        consumer: Any = None
    ) -> Tuple["Program", "Object"]:
    """
    Gets the Ghidra program from the given project with the given project path. The returned program
    must be manually released when it is no longer needed.

    :param project: The Ghidra project that has the program.
    :param path: The project path of the program (should start with "/")
    :param consumer: An optional reference to the Java object "consuming" the returned program, used
        to ensure the underlying DomainObject is only closed when every consumer is done with it. If
        a consumer is not provided, one will be generated by this function.
    :return: A 2-element tuple containing the program and a consumer object that must be used to
        release the program when finished with it (i.e., program.release(consumer). If a consumer
        object was provided, the same consumer object is returned. Otherwise, a new consumer object
        is created and returned.
    :raises FileNotFoundError: If the path does not exist in the project.
    :raises TypeError: If the path in the project exists but is not a Program.
    """
```

### pyghidra.program_context()
```python
@contextlib.contextmanager
def program_context(
        project: "Project", 
        path: Union[str, Path],
    ) -> "Program":
    """
    Gets the Ghidra program from the given project with the given project path. The returned
    program's resource cleanup is performed by a context manager.

    :param project: The Ghidra project that has the program.
    :param path: The project path of the program (should start with "/").
    :return: The Ghidra program.
    :raises FileNotFoundError: If the path does not exist in the project.
    :raises TypeError: If the path in the project exists but is not a Program.
    """
```

### pyghidra.analyze()
```python
def analyze(program: "Program"):
    """
    Analyzes the given program.

    :param program: The Ghidra program to analyze.
    """
```

### pyghidra.ghidra_script()
```python
def ghidra_script(
        path: Union[str, Path],
        project: "Project",
        program: "Program" = None,
        echo_stdout = True,
        echo_stderr = True
    ) -> Tuple[str, str]:
    """
    Runs any type of GhidraScript (Java, PyGhidra, Jython, etc).

    :param path: The GhidraScript's path.
    :param project: The Ghidra project to run the GhidraScript in.
    :param program: An optional Ghidra program that the GhidraScript will see as its "currentProgram".
    :param echo_stdout: Whether or not to echo the GhidraScript's standard output.
    :param echo_stderr: Whether or not to echo the GhidraScript's standard error.
    :return: A 2 element tuple consisting of the GhidraScript's standard output and standard error.
    """
```

### pyghidra.transaction()
```python
@contextlib.contextmanager
def transaction(
        program: "Program",
        description: str = "Unnamed Transaction"
    ):
    """
    Creates a context for running a Ghidra transaction.

    :param program: The Ghidra program that will be affected.
    :param description: The transaction description
    :return: The transaction ID.
    """
```

### pyghidra.analysis_properties()
```python
def analysis_properties(program: "Program") -> "Options":
    """
    Convenience function to get the Ghidra "Program.ANALYSIS_PROPERTIES" options.

    :return: the Ghidra "Program.ANALYSIS_PROPERTIES" options.
    """
```

### pyghidra.program_info()
```python
def program_info(program: "Program") -> "Options":
    """
    Convenience function to get the Ghidra "Program.PROGRAM_INFO" options.

    :return: the Ghidra "Program.PROGRAM_INFO" options.
    """
```

### pyghidra.program_loader()
```python
def program_loader() -> "ProgramLoader.Builder":
    """
    Convenience function to get a Ghidra "ProgramLoader.Builder" object.

    :return: A Ghidra "ProgramLoader.Builder" object.
    """
```

### pyghidra.dummy_monitor()
```python
def dummy_monitor() -> "TaskMonitor":
    """
    Convenience function to get the Ghidra "TaskMonitor.DUMMY" object.

    :return: The Ghidra "TaskMonitor.DUMMY" object.
    """
```

### pyghidra.walk_project()
```python
def walk_project(
        project: "Project",
        callback: Callable[["DomainFile"], None],
        start: Union[str, Path] = "/",
        file_filter: Callable[["DomainFile"], bool] = lambda _f: True
    ):
    """
    Walks the the given Ghidra project, calling the provided function when each domain file is 
    encountered.

    :param project: The Ghidra project to walk.
    :param callback: The callback to process each domain file.
    :param start: An optional starting project folder path.
    :param file_filter: A filter used to limit what domain files get processed.
    :raises FileNotFoundError: If the starting folder is not found in the project.
    """
```

### pyghidra.walk_programs()
```python
def walk_programs(
        project: "Project",
        callback: Callable[["DomainFile", "Program"], None],
        start: Union[str, Path] = "/",
        program_filter: Callable[["DomainFile", "Program"], bool] = lambda _f, _p: True
    ):
    """
    Walks the the given Ghidra project, calling the provided function when each program is 
    encountered. Non-programs in the project are skipped.

    :param project: The Ghidra project to walk.
    :param callback: The callback to process each program.
    :param start: An optional starting project folder path.
    :param program_filter: A filter used to limit what programs get processed.
    :raises FileNotFoundError: If the starting folder is not found in the project.
    """
```

## Example
The following example, while not very useful, showcases much of the API:
```python
import os, jpype, pyghidra
pyghidra.start()

# Open/create a project
with pyghidra.open_project(os.environ["GHIDRA_PROJECT_DIR"], "ExampleProject", create=True) as project:

    # Walk a Ghidra release zip file, load every decompiler binary, and save them to the project
    with pyghidra.open_filesystem(f"{os.environ['DOWNLOADS_DIR']}/ghidra_11.4_PUBLIC_20250620.zip") as fs:
        loader = pyghidra.program_loader().project(project)
        for f in fs.files(lambda f: "os/" in f.path and f.name.startswith("decompile")):
            loader.source(f.getFSRL()).projectFolderPath("/" + f.parentFile.name)
            with loader.load() as load_results:
                load_results.save(pyghidra.dummy_monitor())

    # Analyze the windows decompiler program
    with pyghidra.program_context(project, "/win_x86_64/decompile.exe") as program:
        analysis_props = pyghidra.analysis_properties(program)
        with pyghidra.transaction(program):
            analysis_props.setBoolean("Non-Returning Functions - Discovered", False)
        pyghidra.analyze(program)
        program.save("Analyzed", pyghidra.dummy_monitor())
    
    # Walk the project and set a propery in each decompiler program
    def set_property(domain_file, program):
        with pyghidra.transaction(program):
            program_info = pyghidra.program_info(program)
            program_info.setString("PyGhidra Property", "Set by PyGhidra!")
        program.save("Setting property", pyghidra.dummy_monitor())
    pyghidra.walk_programs(project, set_property, program_filter=lambda f, p: p.name.startswith("decompile"))

    # Load some bytes as a new program
    ByteArrayCls = jpype.JArray(jpype.JByte)
    my_bytes = ByteArrayCls(b"\xaa\xbb\xcc\xdd\xee\xff")
    loader = pyghidra.program_loader().project(project).source(my_bytes).name("my_bytes")
    loader.loaders("BinaryLoader").language("DATA:LE:64:default")
    with loader.load() as load_results:
        load_results.save(pyghidra.dummy_monitor())

    # Run a GhidraScript
    pyghidra.ghidra_script(f"{os.environ['GHIDRA_SCRIPTS_DIR']}/HelloWorldScript.java", project)
```

## Legacy API

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
__3.0.0:__
* Introduced many new functions to the PyGhidra API. PyGhidra 3.0.0 requires Ghidra 12.0 or later
  to run.

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