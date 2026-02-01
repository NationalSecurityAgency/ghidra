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
"""
Ties the Ghidra documentation into the builtin Python help.
"""

import __builtin__
import java
import re
import json
import os
import zipfile

from ghidra.framework import Application
from ghidra.util import SystemUtilities

class _Helper:
    def __init__(self):
        self.orig_help = __builtin__.help
        if SystemUtilities.isInHeadlessMode():
            # ./pythonRun scenario
            self.msg = "\nExample workflow:\n"
            self.msg += "  # Import headless analyzer\n"
            self.msg += "  from ghidra.app.util.headless import HeadlessAnalyzer\n\n"
            self.msg += "  # View HeadlessAnalyzer API\n"
            self.msg += "  help(HeadlessAnalyzer)\n\n"
            self.msg += "  # Get a HeadlessAnalyzer instance\n"
            self.msg += "  headless = HeadlessAnalyzer.getInstance()\n\n"
            self.msg += "  # Get headless options\n"
            self.msg += "  options = headless.getOptions()\n\n"
            self.msg += "  # View HeadlessOptions API and set options accordingly\n"
            self.msg += "  help(options)\n\n"
            self.msg += "  # View processLocal method API\n"
            self.msg += "  help(headless.processLocal)\n\n"
            self.msg += "  # Perform headless processing\n"
            self.msg += "  headless.processLocal(...)\n\n"
        else:
            # PythonPlugin scenario
            self.msg = "Press 'F1' for usage instructions"

    def __call__(self, param=None):

        def get_class_and_method(param):
            if param is None and not SystemUtilities.isInHeadlessMode():
                # Enable help() in PythonPlugin scenario to show help for GhidraScript
                return "ghidra.app.script.GhidraScript", None
            class_name = None
            method_name = None
            if type(param) in [type(1), type(1j), type(1L), type(1.0), type(None), type(True), type([]), type({}), type(()), type({1})]:
                # These are instances of builtin types, so skip
                pass
            elif type(param) == type(str):
                # These are builtin Python types, so skip
                pass
            elif type(param) == type(str.split):
                # These are python functions, so skip
                pass
            elif type(param) == type(java):
                # These are java packages, which we don't don't document, so skip
                pass
            elif type(param) == type(java.lang.Object):
                # This is a java class, so extract its class name
                match = re.search("'(.*)'", str(param))
                if match is not None:
                    class_name = match.group(1)
            elif type(param) == type(java.lang.Object().toString):
                # This is a java method, so extract its class name and method name
                tokens = str(param).split(" ")[2].split(".")
                class_name = ".".join(tokens[:-1])
                method_name = tokens[-1]
            else:
                # Assuming this is a java object, so extract its class name
                match = re.search("'(.*)'", str(type(param)))
                if match is not None:
                    class_name = match.group(1)
            return class_name, method_name

        def get_jsondoc(class_name):
            jsondoc = None
            try:
                root = Application.getApplicationRootDirectory().getFile(False).getParentFile().getAbsolutePath()
                javadoc_zip_name = "GhidraAPI_javadoc.zip"
                if SystemUtilities.isInDevelopmentMode():
                    javadoc_zip = root + "/build/tmp/" + javadoc_zip_name
                else:
                    javadoc_zip = root + "/docs/" + javadoc_zip_name
                if os.path.exists(javadoc_zip):
                    json_path = "api/" + class_name.replace('.', '/') + '.json'
                    with zipfile.ZipFile(javadoc_zip, "r").open(json_path) as f:
                        jsondoc = json.load(f)
            except (IOError, KeyError) as e:
                pass
            return jsondoc

        def format_class(cls):
            sig = "class " + cls["name"] + "\n"
            if "extends" in cls:
                sig += "  extends " + cls["extends"] + "\n"
            implements = ""
            for interface in cls["implements"]:
                if len(implements) > 0:
                    implements += ", "
                implements += interface
            if len(implements) > 0:
                sig += "  implements " + implements + " \n"
            sig += "\n" + cls["comment"]
            return sig

        def format_field(field):
            sig = "%s %s" % (field["type_long"], field["name"])
            if field["static"]:
                sig = "static " + sig
            if field["constant_value"]:
                sig += " = " + field["constant_value"]
            sig += "\n"
            desc = "  %s\n" % (field["comment"]) if len(field["comment"]) > 0 else ""
            return sig + desc

        def format_method(method):
            paramsig = ""
            args = ""
            for param in method["params"]:
                if len(paramsig) > 0:
                    paramsig += ", "
                paramsig += "%s %s" % (param["type_short"], param["name"])
                args += "  @param %s (%s): %s\n" % (param["name"], param["type_long"], param["comment"])
            throws = ""
            for exception in method["throws"]:
                throws += "  @throws %s: %s\n" % (exception["type_short"], exception["comment"])
            sig = "%s %s(%s)\n" % (method["return"]["type_short"], method["name"], paramsig)
            if method["static"]:
                sig = "static " + sig
            desc = "  %s\n\n" % (method["comment"]) if len(method["comment"]) > 0 else ""
            ret = ""
            if method["return"]["type_short"] != "void":
                ret = "  @return %s: %s\n" % (method["return"]["type_long"], method["return"]["comment"])
            return sig + desc + args + ret + throws

        class_name, method_name = get_class_and_method(param)
        if class_name is None:
            self.orig_help(param)
        else:
            try_again = True
            while try_again:
                try_again = False
                print "Searching API for " + class_name + ("" if method_name is None else "." + method_name + "()") + "..."
                jsondoc = get_jsondoc(class_name)
                if jsondoc is None:
                    print "No API found for " + class_name
                elif method_name is None:
                    print "#####################################################"
                    print format_class(jsondoc)
                    print "#####################################################\n"
                    for field in jsondoc["fields"]:
                        print format_field(field)
                        print "-----------------------------------------------------"
                    for method in jsondoc["methods"]:
                        print format_method(method)
                        print "-----------------------------------------------------"
                else:
                    found_method = False
                    for method in jsondoc["methods"]:
                        if method["name"] == method_name:
                            print "-----------------------------------------------------"
                            print format_method(method)
                            print "-----------------------------------------------------"
                            found_method = True
                    if not found_method:
                        # The method may be inherited, so check for a super class and try again
                        if "extends" in jsondoc:
                            class_name = jsondoc["extends"]
                            try_again = True

    def __repr__(self):
        return self.msg

__builtin__.help = _Helper()
