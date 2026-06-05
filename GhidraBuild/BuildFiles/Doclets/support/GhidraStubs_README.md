# Ghidra Type Stubs

The Ghidra Type Stubs library is a [PEP 561 stubs package][pep-0561] for the 
[Ghidra API](https://github.com/NationalSecurityAgency/ghidra). The stub files can be used to 
improve your development experience in supported editors like PyCharm and Visual Studio Code.

## Installation 

The stubs can be installed with `pip install ghidra-stubs*.whl` into the environment in which the 
real Ghidra module (i.e., `pyghidra`) is available. Any conformant tool will then use the stubs 
package for type analysis purposes.  

## Usage

Once installed, all you need to do is import the Ghidra modules as usual, and your supported editor
will do the rest.

```python
import pyghidra
```

To get support for the Ghidra builtins, you need to import them as well. The type hints for those 
exist in the generated `ghidra_builtins` stub. Since it is not a real Python module, importing it at
runtime will fail.

```python
try:
    from ghidra.ghidra_builtins import *
except:
    pass
```

If you are using [PyGhidra](https://pypi.org/project/pyghidra/) from a Python 3 environment where no
real `ghidra` module exists you can use a snippet like the following:

```python
import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

# actual code follows here
```

`typing.TYPE_CHECKING` is a special value that is always `False` at runtime but `True` during any 
kind of type checking or completion.

Once done, just code & enjoy.

[pep-0484]: https://www.python.org/dev/peps/pep-0484/
[pep-0561]: https://www.python.org/dev/peps/pep-0561/#stub-only-packages
