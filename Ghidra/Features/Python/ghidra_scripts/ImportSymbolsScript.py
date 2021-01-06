# Imports a file with lines in the form "symbolName 0xADDRESS function_or_label" where "f" indicates a function and "l" a label
# Additionally, if a comment type and a comment is included, those will be added to the line
# @author unkown; edited by matedealer <git@matedealer.de>, and then joeFischetti <git@joeFischetti>
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
        
    try:
        comment_type = pieces[3]
        comment = pieces[4]

        commentTypes = {
            '0': ghidra.program.model.listing.CodeUnit.EOL_COMMENT,
            '1': ghidra.program.model.listing.CodeUnit.PRE_COMMENT,
            '2': ghidra.program.model.listing.CodeUnit.POST_COMMENT,
            '3': ghidra.program.model.listing.CodeUnit.PLATE_COMMENT,
            '4': ghidra.program.model.listing.CodeUnit.REPEATABLE_COMMENT,
        }

        currentProgram.getListing().setComment(address, commentTypes[comment_type], comment)

    except IndexError:
        print("No comments specified for: " + name)
