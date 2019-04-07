#Imports a file with lines in the form "symbolName 0xADDRESS"
#@category Data
#@author 
 
f = askFile("Give me a file to open", "Go baby go!")

for line in file(f.absolutePath):  # note, cannot use open(), since that is in GhidraScript
    pieces = line.split()
    address = toAddr(long(pieces[1], 16))
    print "creating symbol", pieces[0], "at address", address
    createLabel(address, pieces[0], False)
