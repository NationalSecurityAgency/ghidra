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
# This example script locates a memory address for a file offset.  
#Prompt user for a file offset.
#Print the associated memory address to the Ghidra console
#Print the file offset as a Ghidra comment at the memory address in the Ghidra Listing
#If multiple addresses are located, then print the addresses to the console (do not set a Ghidra comment)
# @category Examples   

import sys
from ghidra.program.model.address import Address
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.listing import Listing
from ghidra.program.model.mem import Memory
from java.util import Set

def getFileOffset():
  userFileOffset = askString('File offset', 'Please provide a hexadecimal file offset')
  try:
    int(userFileOffset,16)
  except ValueError:
     raise ValueError('Please provide a hexadecimal file offset.')
  myFileOffset = long(userFileOffset,16) #specify base 16 since we expect address in hex
  if myFileOffset < 0:
    raise ValueError('Offset cannot be a negative value.')
  return myFileOffset

def processAddress(addr, memBlockName, fileOffset):
  println('File offset ' + hex(fileOffset) + ' is associated with memory block:address ' + memBlockName + ':' + addr.toString());
  myCodeUnit = currentProgram.getListing().getCodeUnitContaining(addr)
  comment = myCodeUnit.getComment(0)
  if not comment:
    myCodeUnit.setComment(0, getScriptName() + ': File offset: ' + hex(fileOffset) + 
      ', Memory block:address ' + memBlockName + ':'+ addr.toString())
  else:
    myCodeUnit.setComment(0, comment + ' ' + getScriptName() + ': File offset: ' + hex(fileOffset) + 
      ', Memory block:address ' + memBlockName + ':' + addr.toString())

myFileOffset = getFileOffset()
mem = currentProgram.getMemory()
addressList = mem.locateAddressesForFileOffset(myFileOffset)
if addressList.isEmpty():
  println('No memory address found for: ' + hex(myFileOffset))
elif addressList.size() == 1:
  address = addressList.get(0)
  processAddress(address, mem.getBlock(address).getName(), myFileOffset)
#file offset matches to multiple addresses.  Let the user decide which address they want.
else:
  println('Possible memory block:address are:')
  for addr in addressList:
    println(mem.getBlock(addr).getName() + ":" + addr.toString())
