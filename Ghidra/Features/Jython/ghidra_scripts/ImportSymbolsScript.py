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
# Imports a text file containing symbol definitions, with a maximum of one symbol defined per line. Each symbol definition is in the form of "symbol_name address function_or_label", where "symbol_name" is the name of the symbol, "address" is the address of the symbol in one of the forms listed below, and "function_or_label" is either "f" or "l", with "f" indicating that a function is to be created and "l" indicating that a label is to be created.
# Address formats are the same as those that can be used with the "Go to address" function. For example:
# - 1234abcd
# - 0x1234abcd
# - ADDRESS_SPACE:1234abcd
# - ADDRESS_SPACE:0x1234abcd
# - MEMORY_REGION:1234abcd
# - MEMORY_REGION:0x1234abcd
# Omitting the address space or memory region specifier from the address will result in the function or label being created in the default address space.
# @author unkown; edited by matedealer <git@matedealer.de>
# @category Data
#

from ghidra.program.model.symbol.SourceType import *
import string

functionManager = currentProgram.getFunctionManager()

f = askFile("Give me a file to open", "Go baby go!")

for line in file(f.absolutePath):  # note, cannot use open(), since that is in GhidraScript
    pieces = line.split()

    name = pieces[0]
    address = toAddr(pieces[1])

    try:
        function_or_label = pieces[2]
    except IndexError:
        function_or_label = "l"

    
    if function_or_label == "f":
        func = functionManager.getFunctionAt(address)

        if func is not None:
            old_name = func.getName()
            func.setName(name, USER_DEFINED)
            print("Renamed function {} to {} at address {}".format(old_name, name, address))
        else:
            func = createFunction(address, name)
            print("Created function {} at address {}".format(name, address))

    else:
        print("Created label {} at address {}".format(name, address))
        createLabel(address, name, False)
