# Imports a file with lines in the form "symbolName 0xADDRESS function_or_label" where "f" indicates a function and "l" a label
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
    address = toAddr(long(pieces[1], 16))

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
