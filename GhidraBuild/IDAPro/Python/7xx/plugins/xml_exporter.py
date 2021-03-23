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
#---------------------------------------------------------------------
# xmlexp.py - IDA XML Exporter plugin
#---------------------------------------------------------------------
"""
Plugin for IDA which exports a XML PROGRAM document file from a database.
This file must be placed in the IDA plugins directory.
The file idaxml.py must be placed in the IDA python directory.
"""

import ida_auto
import ida_idaapi
import ida_kernwin
import idaxml
import idc
import sys


class XmlExporterPlugin(ida_idaapi.plugin_t):
    """
    XML Exporter plugin class
    """
    flags = 0
    comment = "Export database as XML file"
    help = "Export database as XML <PROGRAM> document"
    wanted_name = "XML Exporter"
    wanted_hotkey = "Ctrl-Shift-x"


    def init(self):
        """
        init function for XML Exporter plugin.
        
        Returns:
            Constant PLUGIN_OK if this IDA version supports the plugin,
            else returns PLUGIN_SKIP if this IDA is older than the supported
            baseline version.
        """
        if idaxml.is_ida_version_supported():
            return ida_idaapi.PLUGIN_OK 
        else:
            return ida_idaapi.PLUGIN_SKIP


    def run(self, arg):
        """
        run function for XML Exporter plugin.
        
        Args:
            arg: Integer, non-zero value enables auto-run feature for
                IDA batch (no gui) processing mode. Default is 0.
        """
        st = idc.set_ida_state(idc.IDA_STATUS_WORK)
        xml = idaxml.XmlExporter(arg)
        try:
            try:
                xml.export_xml()
            except idaxml.Cancelled:
                ida_kernwin.hide_wait_box()
                msg = "XML Export cancelled!"
                print "\n" + msg
                idc.warning(msg)
            except:
                ida_kernwin.hide_wait_box()
                msg = "***** Exception occurred: XML Exporter failed! *****"
                print "\n" + msg + "\n", sys.exc_type, sys.exc_value
                idc.warning(msg)
        finally:
            xml.cleanup()
            ida_auto.set_ida_state(st)


    def term(self):
        pass


def PLUGIN_ENTRY():
    return XmlExporterPlugin()
