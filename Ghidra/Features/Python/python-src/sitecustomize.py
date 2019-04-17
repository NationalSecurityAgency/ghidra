"""
User-supplied customizations go here.
"""

# nice-to-have:  place 'java' and 'ghidra' into the local namespace, so you
#  can do fun things like "dir(java.lang)"
import java
import ghidra
import __main__
__main__.java = java
__main__.ghidra = ghidra

# fix Jython "bug": unknown type 'javainstance' or 'javapackage' even though
#  that is the type Jython gives us if we ask type(<someObject>) or
#  type(ghidra) (respectively)
import __builtin__
import org.python.core
# changed by Jim 20090528 for Jython 2.5
# not sure why I even put these here... the first one might be troublesome
#__builtin__.javainstance = org.python.core.PyJavaInstance
#__builtin__.javapackage = org.python.core.PyJavaPackage
#__builtin__.javaclass = org.python.core.PyJavaClass
__builtin__.javainstance = org.python.core.PyObjectDerived
__builtin__.javapackage = org.python.core.PyJavaPackage
__builtin__.javaclass = org.python.core.PyJavaType

# changed by Jim 20090528 for Jython 2.5
# REMOVED collections stuff
# OOPS still need this
import sys

# Ghidra documentation
import ghidradoc
