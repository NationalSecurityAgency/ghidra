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
# Example of being imported by a Ghidra Python script/module
# @category: Examples.Python

# The following line will fail if this module is imported from external_module_caller.py,
# because only the script that gets directly launched by Ghidra inherits fields and methods
# from the GhidraScript/FlatProgramAPI.
try:
    print currentProgram.getName()
except NameError:
    print "Failed to get the program name"

# The Python module that Ghidra directly launches is always called __main__.  If we import
# everything from that module, this module will behave as if Ghidra directly launched it.
from __main__ import *

# The below method call should now work
print currentProgram.getName()

