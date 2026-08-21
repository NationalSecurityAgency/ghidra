## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
# Examples of PyGhidra-specific functionality
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

# we can import java libraries just as if they were python libraries
from java.util import LinkedList

# and then use them like they are natural classes
java_list = LinkedList([1,2,3])
print(f"linked list object class: {java_list.__class__}")

# importing and using Ghidra modules is the same
from ghidra.program.flatapi import FlatProgramAPI
print(f"max references to a flat program api: {FlatProgramAPI.MAX_REFERENCES_TO}")

# we can also do normal python-ish things on our Java objects, like:
# indexing
print(f"first element of the list: {java_list[0]}")

# slicing
print(f"first two elements of the list: {java_list[0:2]}")

# list comprehension
java_list_double = [i * 2 for i in java_list]
print(f"list comprehension result: {java_list_double}")

# automatic calls to getters
print(f"current program name: {currentProgram.name}") # calls currentProgram.getName()

# here's an example of how this stuff might come in handy with Ghidra:
print('current program memory blocks:\n')
for block in currentProgram.memory.blocks:
    print(block.name)


# many Ghidra functions need a Java-native array to pass or receive values
# JPype provides objects of JByte, JChar, etc. to meet this need
# this example demonstrates how you would create an array of bytes to get
# the first 10 bytes of memory from the .text section

# we need this import to get at the helper classes
import jpype

# get the block we need
block = currentProgram.memory.getBlock('.text')
if block:
    # the verbose way of getting the array
    byte_array_maker = jpype.JArray(jpype.JByte)
    byte_array = byte_array_maker(10)

    # we also could have taken a shortcut with just:
    # byte_array = jpype.JByte[10]

    # let's have a look at our new object
    print(f"array class: {byte_array.__class__}")
    # will be <java class 'byte[]'>
    print(f"array length: {len(byte_array)}")

    # we can now use this array wherever a Java method requires a byte[] type
    # the signature of getBytes is getBytes(Address addr, byte[] b)
    block.getBytes(block.start, byte_array)

    # after the call, we can get the bytes out as desired
    # we just put them in a list comprehension here
    print(f"first 10 bytes of .text: {['%#x' % ((b+256)%256) for b in byte_array]}")
    
    # if the data isn't being changed, a bytes-like objct may be used
    data = b"Hello"
    clearListing(block.start, block.start.add(len(data) - 1))
    block.putBytes(block.start, data)

else:
    print('no block named .text in this program.')

# see the user manual of JPype for more details on interoperability:
# https://jpype.readthedocs.io/en/latest/userguide.html
