# Writes properties to the tool.

# DISCLAIMER: This is a recreation of a Java Ghidra script for example
# use only. Please run the Java version in a production environment.

#@category    Examples.Python

from ghidra.framework.options import Options
from ghidra.framework.plugintool import PluginTool

tool = state.getTool()
options = tool.getOptions("name of my script")

fooString = options.getString("foo", None)

if fooString is not None : #does not exist in tool options
    fooString = askString("enter foo", "what value for foo:")
    if fooString is not None :
        options.setString("foo", fooString)

popup(fooString)
