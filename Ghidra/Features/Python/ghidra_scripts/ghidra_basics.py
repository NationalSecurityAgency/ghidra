# Examples of basic Ghidra scripting in Python
# @category: Examples.Python

# Get info about the current program
print
print "Program Info:"
program_name = currentProgram.getName()
creation_date = currentProgram.getCreationDate()
language_id = currentProgram.getLanguageID()
compiler_spec_id = currentProgram.getCompilerSpec().getCompilerSpecID()
print "%s: %s_%s (%s)\n" % (program_name, language_id, compiler_spec_id, creation_date)

# Get info about the current program's memory layout
print "Memory layout:"
print "Imagebase: " + hex(currentProgram.getImageBase().getOffset())
for block in getMemoryBlocks():
    start = block.getStart().getOffset()
    end = block.getEnd().getOffset()
    print "%s [start: 0x%x, end: 0x%x]" % (block.getName(), start, end)
print

# Get the current program's function names
function = getFirstFunction()
while function is not None:
    print function.getName()
    function = getFunctionAfter(function)
print

# Get the address of the current program's current location
print "Current location: " + hex(currentLocation.getAddress().getOffset())

# Get some user input
val = askString("Hello", "Please enter a value")
print val

# Output to a popup window
popup(val)

# Add a comment to the current program
minAddress = currentProgram.getMinAddress()
listing = currentProgram.getListing()
codeUnit = listing.getCodeUnitAt(minAddress)
codeUnit.setComment(codeUnit.PLATE_COMMENT, "This is an added comment!")

# Get a data type from the user
from ghidra.app.util.datatype import DataTypeSelectionDialog
from ghidra.util.data.DataTypeParser import AllowedDataTypes
tool = state.getTool()
dtm = currentProgram.getDataTypeManager()
selectionDialog = DataTypeSelectionDialog(tool, dtm, -1, AllowedDataTypes.FIXED_LENGTH)
tool.showDialog(selectionDialog)
dataType = selectionDialog.getUserChosenDataType()
if dataType != None: print "Chosen data type: " + str(dataType)

# Report progress to the GUI.  Do this in all script loops!
import time
monitor.initialize(10)
for i in range(10):
    monitor.checkCanceled() # check to see if the user clicked cancel
    time.sleep(1) # pause a bit so we can see progress
    monitor.incrementProgress(1) # update the progress
    monitor.setMessage("Working on " + str(i)) # update the status message
