# PyGhidra

PyGhidra is a Python library that provides direct access to the Ghidra API within a native CPython interpreter using [jpype](https://jpype.readthedocs.io/en/latest). As well, PyGhidra contains some conveniences for setting up analysis on a given sample and running a Ghidra script locally. It also contains a Ghidra plugin to allow the use of CPython from the Ghidra user interface.

PyGhidra was initially developed for use with Dragodis and is designed to be installable without requiring Java or Ghidra. This allows other Python projects 
have PyGhidra as a dependency and provide optional Ghidra functionality without requiring all users to install Java and Ghidra. It is recommended to recommend that users set the `GHIDRA_INSTALL_DIR` environment variable to simplify locating Ghidra.


## Usage


### Raw Connection

To get a raw connection to Ghidra use the `start()` function.
This will setup a Jpype connection and initialize Ghidra in headless mode,
which will allow you to directly import `ghidra` and `java`.

*NOTE: No projects or programs get setup in this mode.*

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

### Customizing Java and Ghidra initialization

JVM configuration for the classpath and vmargs may be done through a `PyGhidraLauncher`.

```python
from pyghidra.launcher import HeadlessPyGhidraLauncher

launcher = HeadlessPyGhidraLauncher()
launcher.add_classpaths("log4j-core-2.17.1.jar", "log4j-api-2.17.1.jar")
launcher.add_vmargs("-Dlog4j2.formatMsgNoLookups=true")
launcher.start()
```

### Registering an Entry Point

The `PyGhidraLauncher` can also be configured through the use of a registered entry point on your own python project.
This is useful for installing your own Ghidra plugin which uses PyGhidra and self-compiles.

First create an [entry_point](https://setuptools.pypa.io/en/latest/userguide/entry_point.html) for `pyghidra.setup`
pointing to a single argument function which accepts the launcher instance.

```python
# setup.py
from setuptools import setup

setup(
    # ...,
    entry_points={
        'pyghidra.setup': [
            'acme_plugin = acme.ghidra_plugin.install:setup',
        ]
    }
)
```


Then we create the target function.
This function will be called every time a user starts a PyGhidra launcher.
In the same fashion, another entry point `pyghidra.pre_launch` may be registered and will be called after Ghidra and all
plugins have been loaded.

```python
# acme/ghidra_plugin/install.py
from pathlib import Path
import pyghidra

def setup(launcher):
    """
    Run by PyGhidra launcher to install our plugin.
    """
    launcher.add_classpaths("log4j-core-2.17.1.jar", "log4j-api-2.17.1.jar")
    launcher.add_vmargs("-Dlog4j2.formatMsgNoLookups=true")

    # Install our plugin.
    source_path = Path(__file__).parent / "java" / "plugin"  # path to uncompiled .java code
    details = pyghidra.ExtensionDetails(
        name="acme_plugin",
        description="My Cool Plugin",
        author="acme",
        plugin_version="1.2",
    )
    launcher.install_plugin(source_path, details)  # install plugin (if not already)
```


### Analyze a File

To have PyGhidra setup a binary file for you, use the `open_program()` function.
This will setup a Ghidra project and import the given binary file as a program for you.

Again, this will also allow you to import `ghidra` and `java` to perform more advanced processing.

```python
import pyghidra

with pyghidra.open_program("binary_file.exe") as flat_api:
    program = flat_api.getCurrentProgram()
    listing = program.getListing()
    print(listing.getCodeUnitAt(flat_api.toAddr(0x1234)))

    # We are also free to import ghidra while in this context to do more advanced things.
    from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
    decomp_api = FlatDecompilerAPI(flat_api)
    # ...
    decomp_api.dispose()
```

By default, PyGhidra will run analysis for you. If you would like to do this yourself, set `analyze` to `False`.

```python
import pyghidra

with pyghidra.open_program("binary_file.exe", analyze=False) as flat_api:
    from ghidra.program.util import GhidraProgramUtilities

    program = flat_api.getCurrentProgram()
    if GhidraProgramUtilities.shouldAskToAnalyze(program):
        flat_api.analyzeAll(program)
```


The `open_program()` function can also accept optional arguments to control the project name and location that gets created.
(Helpful for opening up a sample in an already existing project.)

```python
import pyghidra

with pyghidra.open_program("binary_file.exe", project_name="EXAM_231", project_location=r"C:\exams\231") as flat_api:
    ...
```


### Run a Script

PyGhidra can also be used to run an existing Ghidra Python script directly in your native python interpreter
using the `run_script()` command.
However, while you can technically run an existing Ghidra script unmodified, you may
run into issues due to differences between Jython 2 and CPython 3.
Therefore, some modification to the script may be needed.

```python

import pyghidra

pyghidra.run_script(r"C:\input.exe", r"C:\some_ghidra_script.py")
```

This can also be done on the command line using `pyghidra`.

```console
> pyghidra C:\input.exe C:\some_ghidra_script.py <CLI ARGS PASSED TO SCRIPT>
```

### Handling Package Name Conflicts

There may be some Python modules and Java packages with the same import path. When this occurs the Python module takes precedence.
While jpype has its own mechanism for handling this situation, PyGhidra automatically makes the Java package accessible by allowing
it to be imported with an underscore appended to the package name.

```python
import pdb   # imports Python's pdb
import pdb_  # imports Ghidra's pdb
```
