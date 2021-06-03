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
# Prints out all the functions in the program that have a non-zero stack purge size

for func in currentProgram.getFunctionManager().getFunctions(currentProgram.evaluateAddress("0"), 1):
  if func.getStackPurgeSize() != 0:
    print "Function", func, "at", func.getEntryPoint(), "has nonzero purge size", func.getStackPurgeSize()
