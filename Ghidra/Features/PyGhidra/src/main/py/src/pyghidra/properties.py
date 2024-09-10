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
import inspect
import keyword
import logging

import jpype


# pylint: disable=no-member, too-few-public-methods
@jpype.JImplementationFor("java.lang.Object")
class _JavaObject:

    def __jclass_init__(self: jpype.JClass):
        try:
            if isinstance(self, jpype.JException):
                # don't process any exceptions
                return
            exposer = jpype.JClass("ghidra.pyghidra.PythonFieldExposer")
            if exposer.class_.isAssignableFrom(self.class_):
                return
            utils = jpype.JClass("ghidra.pyghidra.property.PropertyUtils")
            for prop in utils.getProperties(self.class_):
                field = prop.field
                if keyword.iskeyword(field):
                    field += '_'
                if field == "class_":
                    continue
                # check for existing inherited properties
                existing = inspect.getattr_static(self, field, None)
                fget = None
                fset = None
                if prop.hasGetter():
                    fget = prop.fget
                elif existing and hasattr(existing, "fget"):
                    fget = existing.fget
                if prop.hasSetter():
                    fset = prop.fset
                elif existing and hasattr(existing, "fset"):
                    fset = existing.fset
                self._customize(field, property(fget, fset))

        # allowing any exception to escape here causes the traceback to be lost
        # log it here so we can figure out what happened
        # pylint: disable=bare-except
        except:
            logger = logging.getLogger(__name__)
            logger.error("Failed to add property customizations for %s", self, exc_info=1)

    def __repr__(self):
        return str(self)
