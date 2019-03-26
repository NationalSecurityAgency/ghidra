# An example of how to color the listing background 

# DISCLAIMER: This is a recreation of a Java Ghidra script for example
# use only. Please run the Java version in a production environment.

#@category Examples.Python

from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet

from java.awt import Color

service = state.getTool().getService(ColorizingService)
if service is None:
     print "Can't find ColorizingService service"
if currentSelection is not None:
     service.setBackgroundColor(currentSelection, Color(255, 200, 200))
elif currentAddress is not None:
     service.setBackgroundColor(currentAddress, currentAddress, Color(255, 200, 200))
else:
     print "No selection or current address to color"
     
anotherAddress = currentAddress.add(10)
setBackgroundColor(anotherAddress, Color.YELLOW)

# create an address set with values you want to change
addresses = AddressSet()
addresses.add(currentAddress.add(10))
addresses.add(currentAddress.add(11))
addresses.add(currentAddress.add(12))
setBackgroundColor(addresses, Color(100, 100, 200))
