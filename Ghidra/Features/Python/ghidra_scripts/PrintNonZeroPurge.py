# Prints out all the functions in the program that have a non-zero stack purge size

for func in currentProgram.getFunctionManager().getFunctions(currentProgram.evaluateAddress("0"), 1):
  if func.getStackPurgeSize() != 0:
    print "Function", func, "at", func.getEntryPoint(), "has nonzero purge size", func.getStackPurgeSize()
