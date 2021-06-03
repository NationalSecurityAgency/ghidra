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
# An example using the Python string formatting.
# See FormatExampleScript.java for examples of using the printf() method.

# DISCLAIMER: This is a recreation of a Java Ghidra script for example
# use only. Please run the Java version in a production environment.

#@category Examples.Python

from time import *
import java.util.Calendar

print "The %s jumped over the %s" % ("cow", "moon")

print "The %s jumped over the %s " % ("cow", "moon") + strftime("%X")

print "The %s jumped over the %s - timestamp: %s" % ("cow", "moon", strftime("%c %Z"))

print "The %s jumped over the %s at %s on %s" % ("cow", "moon", strftime("%I:%M%p"), strftime("%A, %b %d"))

print "Padding: %03d" % (1)

print "Hex: 0x%x" % (10)

print "Left-justified: %-10d" % (1)
print "Right-justified: %10d" % (1)

print "String fill: '%10s'" % ("Fill")
print "String fill, left justified: '%-10s'" % ("Fill")
