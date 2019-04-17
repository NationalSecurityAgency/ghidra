#---------------------------------------------------------------------
# xmlimp.py - IDA XML Importer plugin
#---------------------------------------------------------------------
"""
Plugin for IDA to import a XML PROGRAM file into an existing open database.
This file must be placed in the IDA plugins directory.
The file idaxml.py must be placed in the IDA python directory.
"""

import ida_idaapi
import ida_pro
import idaxml
import idc
import sys

class XmlImporterPlugin(ida_idaapi.plugin_t):
    """
    XML Importer plugin class
    """
    flags = 0
    comment = "Import XML PROGRAM file"
    help = "Import XML <PROGRAM> document to database"
    wanted_name = "XML Importer"
    wanted_hotkey = "Ctrl-Alt-l"

    def init(self):
        """
        init function for XML Importer plugin.
        
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
        run function for XML Importer plugin.
        
        Args:
            arg: Integer, a non-zero value enables auto-run feature for
                 IDA batch (no gui) processing mode. Default is 0.
        """
        st = idc.set_ida_state(idc.IDA_STATUS_WORK)
        xml = idaxml.XmlImporter(idaxml.PLUGIN, arg)
        try:
            try:
                xml.import_xml()
            except idaxml.Cancelled:
                msg = "XML Import cancelled!"
                print "\n" + msg
                idc.warning(msg)
            except idaxml.MultipleAddressSpacesNotSupported:
                msg  = "XML Import cancelled!"
                msg += "\n\nXML Import does not currently support"
                msg += "\nimporting multiple address spaces."
                print "\n" + msg
                idc.warning(msg)
            except:
                msg = "***** Exception occurred: XML Importer failed! *****"
                print "\n" + msg + "\n", sys.exc_type, sys.exc_value
                idc.warning(msg)
        finally:
            xml.cleanup()
            idc.set_ida_state(st)


    def term(self):
        pass


def PLUGIN_ENTRY():
    return XmlImporterPlugin()
