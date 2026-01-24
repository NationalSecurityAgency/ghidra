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
# Imports a text file containing symbol definitions, with a maximum of one symbol defined per line. Each symbol definition is in the form of "symbol_name address function_or_label [data_type]", where "symbol_name" is the name of the symbol, "address" is the address of the symbol in one of the forms listed below, "function_or_label" is either "f" or "l", with "f" indicating that a function is to be created and "l" indicating that a label is to be created, and "data_type" is an optional data type name to apply to labels.
# Address formats are the same as those that can be used with the "Go to address" function. For example:
# - 1234abcd
# - 0x1234abcd
# - ADDRESS_SPACE:1234abcd
# - ADDRESS_SPACE:0x1234abcd
# - MEMORY_REGION:1234abcd
# - MEMORY_REGION:0x1234abcd
# Omitting the address space or memory region specifier from the address will result in the function or label being created in the default address space.
# Data type formats (optional 4th field for labels only):
# - Simple types: "byte", "word", "dword", "pointer", etc.
# - Array types: "byte[256]", "dword[10]", etc.
# @author <donour@cs.unm.edu>; edited by matedealer <git@matedealer.de>
# @category Data
# @runtime Jython
#

from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.data import ArrayDataType
import string

functionManager = currentProgram.getFunctionManager()
dataTypeManager = currentProgram.getDataTypeManager()
listing = currentProgram.getListing()

def parseDataType(type_spec):
    # Check for array syntax: type[count]
    if '[' in type_spec and type_spec.endswith(']'):
        base_type = type_spec[:type_spec.index('[')]
        array_count = int(type_spec[type_spec.index('[')+1:-1])
        dt_list = []
        dataTypeManager.findDataTypes(base_type, dt_list)
        if len(dt_list) > 0:
            return ArrayDataType(dt_list[0], array_count, dt_list[0].getLength())
        else:
            print("Warning: base data type '{}' not found".format(base_type))
            return None
    else:
        dt_list = []
        dataTypeManager.findDataTypes(type_spec, dt_list)
        if len(dt_list) > 0:
            return dt_list[0]
        else:
            print("Warning: data type '{}' not found".format(type_spec))
            return None

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
        createLabel(address, name, False)
        if len(pieces) > 3:
            dt = parseDataType(pieces[3])
            if dt is not None:
                listing.createData(address, dt)
        print("Created label {} at address {}".format(name, address))
