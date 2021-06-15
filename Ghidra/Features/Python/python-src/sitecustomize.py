## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##
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
