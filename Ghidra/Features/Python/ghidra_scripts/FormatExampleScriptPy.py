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
