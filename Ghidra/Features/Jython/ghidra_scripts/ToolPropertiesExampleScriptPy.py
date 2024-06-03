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
