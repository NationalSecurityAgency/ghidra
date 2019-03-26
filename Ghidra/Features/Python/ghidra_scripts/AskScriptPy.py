# An example of asking for user input.

# Note the ability to pre-populate values for some of these variables when AskScript.properties file exists.
# Also notice how the previous input is saved.

# DISCLAIMER: This is a recreation of a Java Ghidra script for example
# use only. Please run the Java version in a production environment.

#@category Examples.Python

from ghidra.framework.model import DomainFile
from ghidra.framework.model import DomainFolder
from ghidra.program.model.address import Address
from ghidra.program.model.lang import LanguageCompilerSpecPair
from ghidra.program.model.listing import Program
from ghidra.util import Msg

from java.lang import IllegalArgumentException

# The presence of the AskScript.properties file in the same location (as AskScript.java) 
# allows for the following behavior:
#		- GUI: if applicable, auto-populates the input field with the value in the 
#			.properties file (the first	time that input	field appears)
#   	- Headless: uses the value in the .properties file for the variable assigned to the
#			corresponding askXxx() method in the GhidraScript.
try:
    file1 = askFile("FILE", "Choose file:")
    print "file was: " + str(file1)

    directory1 = askDirectory("Directory", "Choose directory:")
    print "directory was: " + str(directory1)

    lang = askLanguage("Language Picker", "I want this one!")
    print "language was: " + lang.toString()

    domFolder = askProjectFolder("Please pick a domain folder!")
    print "domFolder was: " + domFolder.getName()

    int1 = askInt("integer 1", "enter integer 1")
    int2 = askInt("integer 2", "enter integer 2")
    print "int1 + int2 = " + str(int1 + int2)

    long1 = askLong("long 1", "enter long 1")
    long2 = askLong("long 2", "enter long 2")
    print "long1 + long2 = " + str(long1 + long2)

    address1 = askAddress("address 1", "enter address 1")
    address2 = askAddress("address 2", "enter address 2")
    print "address1 + address2 = " + address1.add(address2.getOffset()).toString()

    #bytes = askBytes("bytes", "enter byte pattern")
    #for b in bytes: 
    #   print "b = " + str(b & 0xff)
			
    prog = askProgram("Please choose a program to open.")
    print "Program picked: " + prog.getName()

    domFile = askDomainFile("Which domain file would you like?")
    print "Domain file: " + domFile.getName()

    d1 = askDouble("double 1", "enter double 1")
    d2 = askDouble("double 2", "enter double 2")
    print "d1 + d2 = " + str(d1 + d2)

    myStr = askString("String Specification", "Please type a string: ")
    myOtherStr = askString("Another String Specification", "Please type another string: ", "replace me!")
    print "You typed: " + myStr + " and " + myOtherStr

    choice = askChoice("Choice", "Please choose one", [ "grumpy", "dopey", "sleepy", "doc", "bashful" ], "bashful")
    print "Choice? " + choice

    choices1 = askChoices("Choices 1", "Please choose one or more numbers.", [ 1, 2, 3, 4, 5, 6 ])
    print "Choices 1: "
    for intChoice in choices1: 
        print str(intChoice) + " "
    print ""

    choices2 = askChoices("Choices 2", "Please choose one or more of the following.", 
        [ 1.1, 2.2, 3.3, 4.4, 5.5, 6.6 ], ["Part 1", "Part 2", "Part 3", "Part 4", "Part 5", "Part 6" ])
    print "Choices 2: "
    for intChoice in choices2:
        print str(intChoice) + " "	
    print ""

    yesOrNo = askYesNo("yes or no", "is this a yes/no question?")
    print "Yes or No? " + str(yesOrNo)

except IllegalArgumentException as error:
    Msg.warn(self, "Error during headless processing: " + error.toString())
	
