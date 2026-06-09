# PyGhidra

This module provides the following capabilities:
* The [PyGhidra Python library](src/main/py/README.md) and its dependencies.
* A [Plugin](src/main/java/ghidra/pyghidra/PyGhidraPlugin.java) that provides a CPython interpreter.
* A [ScriptProvider](src/main/java/ghidra/pyghidra/PyGhidraScriptProvider.java) capable of running
  GhidraScripts written in native CPython 3.
* An [interactive python script](support/pyghidra_launcher.py) that Ghidra uses to install
  and launch PyGhidra. This script handles
  [virtual environments](https://docs.python.org/3/tutorial/venv.html) and
  [externally managed environments](https://packaging.python.org/en/latest/specifications/externally-managed-environments/).