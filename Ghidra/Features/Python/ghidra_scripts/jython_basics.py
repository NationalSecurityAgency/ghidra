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
# Examples of Jython-specific functionality
# @category: Examples.Python

# Using Java data structures from Jython
python_list = [1, 2, 3]
java_list = java.util.LinkedList(java.util.Arrays.asList(1, 2, 3))
print str(type(python_list))
print str(type(java_list))

# Importing Java packages for simpler Java calls
from java.util import LinkedList, Arrays
python_list = [1, 2, 3]
java_list = LinkedList(Arrays.asList(1, 2, 3))
print str(type(python_list))
print str(type(java_list))

# Python adds helpful syntax to Java data structures
print python_list[0]
print java_list[0]   # can't normally do this in java
print java_list[0:2] # can't normally do this in java

# Iterate over Java collection the Python way
for entry in java_list:
    print entry

# "in" keyword compatibility
print str(3 in java_list)

# Create GUI with Java Swing
from javax.swing import JFrame
frame = JFrame() # don't call constructor with "new"
frame.setSize(400,400)
frame.setLocation(200, 200)
frame.setTitle("Jython JFrame")
frame.setVisible(True)

# Use JavaBean properties in constructor with keyword arguments!
JFrame(title="Super Jython JFrame", size=(400,400), visible=True)
