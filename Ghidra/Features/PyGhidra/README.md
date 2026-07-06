# PyGhidra

PyGhidra provides native Python 3 scripting support for Ghidra, allowing you to write Ghidra scripts
using standard Python instead of Jython. This enables access to the full Python ecosystem including
popular libraries like `numpy`, `pandas`, and `requests`.

## Capabilities

This module provides the following capabilities:
* The [PyGhidra Python library](src/main/py/README.md) and its dependencies.
* A [Plugin](src/main/java/ghidra/pyghidra/PyGhidraPlugin.java) that provides a CPython interpreter.
* A [ScriptProvider](src/main/java/ghidra/pyghidra/PyGhidraScriptProvider.java) capable of running
  GhidraScripts written in native CPython 3.
* An [interactive python script](support/pyghidra_launcher.py) that Ghidra uses to install
  and launch PyGhidra. This script handles
  [virtual environments](https://docs.python.org/3/tutorial/venv.html) and
  [externally managed environments](https://packaging.python.org/en/latest/specifications/externally-managed-environments/).

## Requirements

* Python 3.9 or later (must be in your system PATH)
* Ghidra 11.2 or later

## Quick Start

### Launch PyGhidra

**Linux/macOS:**
```bash
./support/pyghidraRun
```

**Windows:**
```batch
support\pyghidraRun.bat
```

On first launch, PyGhidra will automatically create a virtual environment and install required dependencies.

### Write Your First PyGhidra Script

Create a file named `hello.py` with the following content:

```python
# hello.py - A simple PyGhidra script
#@category Examples
#@author Your Name

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Program

class HelloScript(GhidraScript):
    def run(self):
        currentProgram = self.getCurrentProgram()
        if currentProgram is None:
            self.println("No program is currently open.")
            return
        
        self.println(f"Program: {currentProgram.getName()}")
        self.println(f"Language: {currentProgram.getLanguageID()}")
        self.println(f"Compiler: {currentProgram.getCompilerSpec().getCompilerSpecID()}")
        
        # List all functions
        functionManager = currentProgram.getFunctionManager()
        functions = functionManager.getFunctions(True)
        self.println(f"\nTotal functions: {functionManager.getFunctionCount()}")
        
        for func in functions:
            self.println(f"  {func.getEntryPoint()} - {func.getName()}")

# Execute the script
script = HelloScript()
script.set(self)
script.run()
```

### Install Additional Python Packages

PyGhidra uses a virtual environment. To install additional packages:

**Option 1: Using the PyGhidra launcher**
```bash
./support/pyghidraRun --install-package numpy pandas
```

**Option 2: Manual installation**
```bash
# Find the virtual environment location
ls ~/.ghidra/.pyghidra_venv  # Linux/macOS
dir %USERPROFILE%\.ghidra\.pyghidra_venv  # Windows

# Activate and install
source ~/.ghidra/.pyghidra_venv/bin/activate  # Linux/macOS
.ghidra\.pyghidra_venv\Scripts\activate  # Windows
pip install numpy pandas
```

## PyGhidra vs Jython

| Feature | PyGhidra (Python 3) | Jython (Python 2) |
|---------|---------------------|-------------------|
| Python Version | 3.9+ | 2.7 |
| Access to Python ecosystem | ✅ Full access | ❌ Limited |
| Third-party libraries | ✅ Most libraries work | ❌ Pure Java libraries only |
| Performance | ✅ Native CPython | ⚠️ JVM-based |
| Ghidra API access | ✅ Full access via JPype | ✅ Full access |

## Troubleshooting

**Issue: "Python not found"**
- Ensure Python 3.9+ is installed and in your system PATH
- Verify with: `python --version` or `python3 --version`

**Issue: "Virtual environment creation failed"**
- Check that you have write permissions to `~/.ghidra/`
- Try manually creating the venv: `python -m venv ~/.ghidra/.pyghidra_venv`

**Issue: "Package installation failed"**
- Some packages may require compilation tools (gcc, python-dev)
- Check the PyGhidra log in `~/.ghidra/.pyghidra.log` for details

## Additional Resources

* [PyGhidra Python Library Documentation](src/main/py/README.md)
* [Ghidra Scripting Guide](https://ghidra-sre.org/CheatSheet.html)
* [JPype Documentation](https://jpype.readthedocs.io/) - Java-Python bridge used by PyGhidra