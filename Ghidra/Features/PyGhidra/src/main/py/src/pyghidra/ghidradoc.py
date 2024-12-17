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
"""
Ties the Ghidra documentation into the builtin Python help.
"""

import json
from pathlib import Path
import zipfile

from java.lang import Class # type:ignore @UnresolvedImport
from java.io import PrintWriter # type:ignore @UnresolvedImport
from jpype import JMethod, JObject, JClass

from ghidra.framework import Application
from ghidra.util import SystemUtilities

class _Helper:
    def __init__(self, stdout: PrintWriter):
        self.stdout = stdout
        self.orig_help = help
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
            # PyGhidraPlugin scenario
            self.msg = "Press 'F1' for usage instructions"

    def __call__(self, param=None):

        def get_class_and_method(param):
            if param is None and not SystemUtilities.isInHeadlessMode():
                # Enable help() in PyGhidraPlugin scenario to show help for GhidraScript
                return "ghidra.app.script.GhidraScript", None
            class_name = None
            method_name = None
            if isinstance(param, JClass):
                class_name = param.class_.getName()
            elif isinstance(param, Class):
                class_name = param.getName()
            elif isinstance(param, JMethod):
                class_name, _, method_name = param.__qualname__.rpartition('.')
            elif isinstance(param, JObject):
                class_name = param.getClass().getName()
            return class_name, method_name

        def get_jsondoc(class_name: str):
            jsondoc = None
            try:
                root = Path(Application.getApplicationRootDirectory().getAbsolutePath()).parent
                javadoc_zip_name = "GhidraAPI_javadoc.zip"
                if SystemUtilities.isInDevelopmentMode():
                    javadoc_zip = root / "build" / "tmp" / javadoc_zip_name
                else:
                    javadoc_zip = root / "docs" / javadoc_zip_name
                if javadoc_zip.exists():
                    json_path = "api/" + class_name.replace('.', '/') + ".json"
                    with zipfile.ZipFile(javadoc_zip, "r") as docs:
                        with docs.open(json_path) as f:
                            jsondoc = json.load(f)
            except (IOError, KeyError):
                pass
            return jsondoc

        def format_class(cls):
            sig = "class " + cls['name'] + "\n"
            if "extends" in cls:
                sig += "  extends " + cls['extends'] + "\n"
            implements = ", ".join(cls['implements'])
            if implements:
                sig += "  implements " + implements + " \n"
            sig += "\n" + cls['comment']
            return sig

        def format_field(field):
            sig = f"{field['type_long']} {field['name']}"
            if field['static']:
                sig = "static " + sig
            if constant_value := field['constant_value']:
                sig += " = " + constant_value
            sig += "\n"
            if comment := field['comment']:
                sig += f"  {comment}\n"
            return sig

        def format_method(method):
            paramsig = ""
            args = ""
            for param in method['params']:
                if paramsig:
                    paramsig += ", "
                paramsig += f"{param['type_short']} {param['name']}"
                args += f"  @param {param['name']} ({param['type_long']}): {param['comment']}\n"
            throws = ""
            for exception in method['throws']:
                throws += f"  @throws {exception['type_short']}: {exception['comment']}\n"
            sig = f"{method['return']['type_short']} {method['name']}({paramsig})\n"
            if method['static']:
                sig = "static " + sig
            if comment := method['comment']:
                desc = f"  {comment}\n\n"
            else:
                desc = ""
            ret = ""
            if method['return']['type_short'] != "void":
                ret = f"  @return {method['return']['type_long']}: {method['return']['comment']}\n"
            return sig + desc + args + ret + throws

        class_name, method_name = get_class_and_method(param)
        if class_name is None:
            self.orig_help(param)
        else:
            try_again = True
            while try_again:
                try_again = False
                target = ""
                if method_name:
                    target = "." + method_name + "()"
                self.stdout.println("Searching API for " + class_name + target + "...")
                jsondoc = get_jsondoc(class_name)
                if jsondoc is None:
                    self.stdout.println("No API found for " + class_name)
                elif method_name is None:
                    self.stdout.println("#####################################################")
                    self.stdout.println(format_class(jsondoc))
                    self.stdout.println("#####################################################\n")
                    for field in jsondoc['fields']:
                        self.stdout.println(format_field(field))
                        self.stdout.println("-----------------------------------------------------")
                    for method in jsondoc['methods']:
                        self.stdout.println(format_method(method))
                        self.stdout.println("-----------------------------------------------------")
                else:
                    found_method = False
                    for method in jsondoc['methods']:
                        if method['name'] == method_name:
                            self.stdout.println("-----------------------------------------------------")
                            self.stdout.println(format_method(method))
                            self.stdout.println("-----------------------------------------------------")
                            found_method = True
                    if not found_method:
                        # The method may be inherited, so check for a super class and try again
                        if "extends" in jsondoc:
                            class_name = jsondoc['extends']
                            try_again = True

    def __repr__(self):
        return self.msg
