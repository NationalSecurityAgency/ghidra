#---------------------------------------------------------------------
# xmlldr.py - IDA XML loader
#---------------------------------------------------------------------
"""
Loader for IDA to import a XML PROGRAM file and create a new database (.idb).
This file must be placed in the IDA loaders directory.
The file idaxml.py must be placed in the IDA python directory.
"""

import ida_idaapi
import ida_idp
import ida_kernwin
import ida_pro
import idaxml
import idc
import sys


"""
Loader functions
"""
def accept_file(li, filename):
    """
    Check if the file is of supported format

    @param li: a file-like object which can be used to access the input data
    @param n : format number. The function will be called with incrementing
                number until it returns zero
    @return: 0 - no more supported formats
                string "name" - format name to display in the chooser dialog
                dictionary { 'format': "name", 'options': integer }
                options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
                to indicate preferred format
    """
    if not idaxml.is_ida_version_supported():
        return 0
    # read 16K bytes to allow for the DTD
    data = li.read(0x4000)
    # look for start of <PROGRAM> element
    start = data.find("<PROGRAM")
    if start >= 0:
        s = data.find("<PROCESSOR ")
        p = data[s+11:]
        e = p.find("/>")
        proc = p[:e]
        ida_kernwin.info("Processor specified in the XML file is:\n" + proc +
                         "\n\nYou must select and set the compatible " +
                         "IDA processor type.")
        return { 'format': "XML PROGRAM file", 'options': 0x8001 }
    return 0


def load_file(li, neflags, format):
    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """
    global event, element
    if ida_idp.get_idp_name() == None:
        ida_idp.set_processor_type("metapc", ida_idp.SETPROC_LOADER)
    status = 0
    st = idc.set_ida_state(idc.IDA_STATUS_WORK)
    xml = idaxml.XmlImporter(idaxml.LOADER, 0)
    try:
        status = xml.import_xml()
    except idaxml.Cancelled:
        msg = "XML PROGRAM import cancelled!"
        print "\n" + msg
        idc.warning(msg)
    except idaxml.MultipleAddressSpacesNotSupported:
        msg  = "XML Import cancelled!"
        msg += "\n\nXML Import does not currently support"
        msg += "\nimporting multiple address spaces."
        print "\n" + msg
        idc.warning(msg)
    except:
        print "\nHouston, we have a problem!"
        msg = "***** Exception occurred: XML loader failed! *****"
        print "\n" + msg + "\n", sys.exc_type, sys.exc_value
        print event, element.tag, element.attrib
        idc.warning(msg)
    finally:
        idc.set_ida_state(st)
        xml.cleanup()
        return status
