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
# xmlldr.py - IDA XML Import loader and plugin
#---------------------------------------------------------------------
"""
Loader and plugin for IDA to import a XML PROGRAM file to a database.
"""

import idaapi
import sys
import time
from xml.etree import cElementTree


XML_IMPORTER_VERSION = "2.1.1"
BASELINE_IDA_VERSION = 620
IDA_SDK_VERSION = idaapi.IDA_SDK_VERSION
BADADDR = idaapi.BADADDR


"""
Loader functions
"""
def accept_file(li, n):
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
    if IDA_SDK_VERSION < BASELINE_IDA_VERSION:
        return 0
    # we support only one format per file
    if n > 0: return 0
    # read 16K bytes to allow for the DTD
    data = li.read(0x4000)
    # look for start of <PROGRAM> element
    start = data.find("<PROGRAM")
    if start >= 0: return "XML PROGRAM file"
    return 0


def load_file(li, neflags, format):
    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """
    global event, element
    plugin = False
    status = 0
    st = idaapi.setStat(idaapi.st_Work)
    xml = XmlImporter(False, 0)
    try:
        status = xml.import_xml()
    except Cancelled:
        msg = "XML PROGRAM import cancelled!"
        print "\n" + msg
        idaapi.warning(msg)
    except MultipleAddressSpacesNotSupported:
        msg  = "XML Import cancelled!"
        msg += "\n\nXML Import does not currently support"
        msg += "\nimporting multiple address spaces."
        print "\n" + msg
        idaapi.warning(msg)
    except:
        print "\nHouston, we have a problem!"
        msg = "***** Exception occurred: XML loader failed! *****"
        print "\n" + msg + "\n", sys.exc_type, sys.exc_value
        print event, element.tag, element.attrib
        idaapi.warning(msg)
    finally:
        idaapi.setStat(st)
        xml.cleanup()
        return status


class XmlImporterPlugin(idaapi.plugin_t):
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
        if IDA_SDK_VERSION < BASELINE_IDA_VERSION:
            idaapi.msg('\nXML Importer plugin (xmlldr.py) not supported ' +
                        'by this version of IDA\n')
            return idaapi.PLUGIN_SKIP
        return idaapi.PLUGIN_OK

    def run(self, arg):
        """
        run function for XML Importer plugin.
        
        Args:
            arg: Integer, a non-zero value enables auto-run feature for
                 IDA batch (no gui) processing mode. Default is 0.
        """
        st = idaapi.setStat(idaapi.st_Work)
        xml = XmlImporter(True, arg)
        try:
            try:
                xml.import_xml()
            except Cancelled:
                msg = "XML Import cancelled!"
                print "\n" + msg
                idaapi.warning(msg)
            except MultipleAddressSpacesNotSupported:
                msg  = "XML Import cancelled!"
                msg += "\n\nXML Import does not currently support"
                msg += "\nimporting multiple address spaces."
                print "\n" + msg
                idaapi.warning(msg)
            except:
                msg = "***** Exception occurred: XML Importer failed! *****"
                print "\n" + msg + "\n", sys.exc_type, sys.exc_value
                idaapi.warning(msg)
        finally:
            xml.cleanup()
            idaapi.setStat(st)


    def term(self):
        pass


def PLUGIN_ENTRY():
    return XmlImporterPlugin()


class Cancelled(Exception):
    pass


class FileError(Exception):
    pass


class MultipleAddressSpacesNotSupported(Exception):
    pass


class XmlImporter:
    """
    XmlImporter class contains methods to import an XML PROGRAM
        document into IDA.
    """
    def __init__(self, plugin, arg):
        """
        Initializes the XmlImporter attributes

        Args:
            arg: Integer, non-zero value enables auto-run feature for
                IDA batch (no gui) processing mode. Default is 0.
        """
        self.plugin = plugin
        self.autorun = False
        self.debug = False # set this to True for debug prints
        self.Elements = {}
        self.Counters = []
        self.Tags = []
        self.Timers = dict()
        self.xmlfile = 0
        self.addr_mode = 1
        self.create = True
        self.dataseg = None
        self.deferred = []
        self.callbacks = {
            'start' : {
                BOOKMARKS           : self.update_import,
                CODE                : self.update_import,
                COMMENTS            : self.update_import,
                COMPILER            : self.import_compiler,
                DATA                : self.update_import,
                DATATYPES           : self.update_import,
                EQUATES             : self.update_import,
                FUNCTIONS           : self.update_import,
                INFO_SOURCE         : self.import_info_source,
                MARKUP              : self.update_import,
                MEMORY_MAP          : self.import_memory_map,
                PROCESSOR           : self.import_processor,
                PROGRAM             : self.import_program,
                PROGRAM_ENTRY_POINTS: self.update_import,
                REGISTER_VALUES     : self.update_import,
                SYMBOL_TABLE        : self.update_import },
            'end' : {
                BOOKMARK            : self.import_bookmark,
                CODE_BLOCK          : self.import_codeblock,
                COMMENT             : self.import_comment,
                DEFINED_DATA        : self.import_defined_data,
                ENUM                : self.import_enum,
                EQUATE_GROUP        : self.import_equate_group,
                EQUATE_REFERENCE    : self.import_equate_reference,
                FUNCTION            : self.import_function,
                FUNCTION_DEF        : self.import_function_def,
                MANUAL_INSTRUCTION  : self.import_manual_instruction,
                MANUAL_OPERAND      : self.import_manual_operand,
                MEMORY_REFERENCE    : self.import_memory_reference,
                MEMORY_SECTION      : self.import_memory_section,
                PROGRAM_ENTRY_POINT : self.import_program_entry_point,
                REGISTER_VALUE_RANGE: self.import_register_value_range,
                STACK_REFERENCE     : self.import_stack_reference,
                STRUCTURE           : self.import_structure,
                SYMBOL              : self.import_symbol,
                TYPE_DEF            : self.import_typedef,
                UNION               : self.import_union,
                # end element for elapse time
                BOOKMARKS           : self.display_timer,
                CODE                : self.display_timer,
                COMMENTS            : self.display_timer,
                DATA                : self.display_timer,
                DATATYPES           : self.process_deferred,
                EQUATES             : self.display_timer,
                FUNCTIONS           : self.display_timer,
                MARKUP              : self.display_timer,
                MEMORY_MAP          : self.display_timer,
                PROGRAM             : self.display_total_time,
                PROGRAM_ENTRY_POINTS: self.display_timer,
                REGISTER_VALUES     : self.display_timer,
                SYMBOL_TABLE        : self.display_timer }
            }


    def import_xml(self):
        """
        Imports the XML PROGRAM file into the database.
        """
        self.display_xml_importer_version()
        displayMenu = self.plugin == True and self.autorun == False 
        #displayMenu = self.autorun == False 
        self.get_options(displayMenu)
        if self.plugin:
            self.filename=idaapi.askfile_c(0, "*.xml",
                                        "Enter name of xml file:")
        else:
            self.filename = idaapi.get_input_file_path()
        if (len(self.filename) == 0):
            return
        idaapi.msg('\nImporting from: ' + self.filename + '\n') 
        idc.Wait()
        if self.plugin == False: idaapi.hide_wait_box()
        idaapi.show_wait_box("Importing XML PROGRAM document....")
        n = 0
        for event,element in cElementTree.iterparse(self.filename,
                                                events=("start","end")):
            if idaapi.wasBreak() == True:
                raise Cancelled
            
            if self.debug == True and event == 'start':
                print element.tag, element.attrib, element.text
            
            if event in self.callbacks:
                if element.tag in self.callbacks[event]:
                    if event == 'start':
                        self.Timers[element.tag] = time.clock()
                    self.callbacks[event][element.tag](element)
                    if event == 'end':
                        element.clear()
            if event == 'end':
                n += 1
        end = time.clock()
        idaapi.hide_wait_box()
        self.display_summary()
        idaapi.msg('\nXML Elements parsed: ' + str(n) + '\n\n')
        return 1
    

    def get_options(self, display):
        """
        Displays the options menu and retrieves the option settings. 
        """
        fmt =  "HELP\n"
        fmt += "XML PROGRAM loader/importer plugin (Python)\n"
        fmt += "IDA SDK: "+ str(IDA_SDK_VERSION) + "\n\n"
        fmt +=  "The XML PROGRAM loader loads elements from a "
        fmt +=  "XML <PROGRAM> document to create an idb database.\n\n"
        fmt +=  "ENDHELP\n"
        fmt +=  "Import from XML PROGRAM document...."
        fmt += "\n <##Options##Code Blocks:{CodeBlocks}>"
        fmt += "\n <Entry Points:{EntryPoints}>"
        fmt += "\n <Segment Register Value Ranges:{RegisterValues}>"
        fmt += "\n <Data Types:{DataTypes}>"
        fmt += "\n <Data Definitions:{DataDefinitions}>"
        fmt += "\n <Symbols:{Symbols}>"
        fmt += "\n <Comments:{Comments}>"
        fmt += "\n <Bookmarks:{Bookmarks}>"
        fmt += "\n <Functions:{Functions}>"
        fmt += "\n <Memory References:{MemoryReferences}>"
        fmt += "\n <Equate/Enum References:{EquateReferences}>"
        fmt += "\n <Manual Instructions/Operands:{Manual}>{cGroup1}>"
        fmt += "\n\n"
    
        Opts = { 'cGroup1': idaapi.Form.ChkGroupControl(
                ( 
                "CodeBlocks", "EntryPoints", "RegisterValues",
                "DataTypes", "DataDefinitions",
                "Symbols", "Comments", "Bookmarks",
                "Functions", "MemoryReferences", "EquateReferences",
                "Manual")) }
        
        self.Options = idaapi.Form(fmt, Opts)
        self.Options.Compile()
    
        self.Options.CodeBlocks.checked       = True
        self.Options.EntryPoints.checked      = True
        self.Options.RegisterValues.checked   = True
        self.Options.DataTypes.checked        = True
        self.Options.DataDefinitions.checked  = True
        self.Options.Symbols.checked          = True
        self.Options.Functions.checked        = True
        self.Options.Comments.checked         = True
        self.Options.Bookmarks.checked        = True
        self.Options.MemoryReferences.checked = True
        self.Options.EquateReferences.checked = True
        self.Options.Manual.checked           = True
        
        if display == True:
            ok = self.Options.Execute()
            if (ok == 0):
                raise Cancelled
            
    def cleanup(self):
        """
        Frees memory and closes message box at termination.
        """
        if self.plugin:
            self.Options.Free()
        idaapi.hide_wait_box()
    

    def display_timer(self, element):
        """
        Displays the elapsed processing time for XML elements.
        
        Args:
            element: XML element object value containing the element tag.
        """
        if element.tag == MEMORY_MAP and self.plugin:
            return
        if element.tag in self.Timers:
            idaapi.msg('elapsed time: %.4f' %
                    (time.clock()-self.Timers[element.tag]))
    

    def display_total_time(self, element):
        """
        Displays the total processing time.
        
        Args:
            element: XML element object value (not used).
        """
        TOTAL = 'Total '
        idaapi.msg('\n%35selapsed time: %.4f' %
                (TOTAL,time.clock()-self.Timers[PROGRAM]))
    

    def display_summary(self):
        """
        Displays summary of the XML PROGRAM import in IDA output window.
        """
        summary = ''
        total = 0
        for tag in self.Tags:
            count = self.Counters[self.Elements[tag]]
            summary += "\n%s: %d" % (tag, count)
            total += count
        summary += '\n--------------------------------------'
        header = '\n--------------------------------------'
        header += ('\nTotal XML Elements Processed: %d') % total
        summary = header + summary
        idaapi.msg(summary)
        if self.plugin and self.autorun == False:
            frmt  = "TITLE XML Import Successful!\n"
            frmt += "ICON INFO\n"
            frmt += "AUTOHIDE NONE\n"
            frmt += "HIDECANCEL\n"
            firstline = "\n XML IMPORT SUCCESSFUL!"
            fileline = '\n\nFile: %s' % self.filename
            details = '\n\nSee output window for details...'
            idaapi.info("%s" % (frmt + firstline + fileline + details))
    

    def display_xml_importer_version(self):
        """
        Displays XML Importer plugin version info in IDA output window.
        """
        if self.plugin:
            f = idaapi.idadir(idaapi.PLG_SUBDIR) + '/xmlldr.py'
        else:
            f = idaapi.idadir(idaapi.LDR_SUBDIR) + '/xmlldr.py'
        plugintime = time.localtime(os.path.getmtime(f))
        ts = time.strftime('%b %d %Y %H:%M:%S', plugintime)
        version = "\nXML Importer Version " + XML_IMPORTER_VERSION
        version += " : SDK " + str(IDA_SDK_VERSION)
        version += " : Python : "+ ts + '\n'
        idaapi.msg(version)
    

    def get_address(self, element, attr):
        """
        Returns the address value for an element.
        
        Args:
            element: XML element object.
            attr: String containing the address attribute name.
            
        Returns:
            Numeric value representing the address.
        """
        addrstr = element.get(attr)
        if '::' in addrstr:
            # overlayed addresses not currently handled
            return BADADDR
        elif ':' in addrstr:
            [segstr, offset_str] = string.split(addrstr,':')
            offset = int(offset_str,16)
            if self.is_int(segstr) == True:
                sgmt = int(segstr,16)
                addr = (sgmt << 4) + offset
            else:
                # multiple address spaces not currently implemented
                addr = BADADDR
            return addr
        else:
            return int(element.get(attr), 16)
    

    def get_attribute(self, element, attr):
        """
        Returns the attribute value string.
        
        Args:
            element: XML element object.
            attr: String containing the attribute name.
            
        Returns:
            String representing the attribute value.
        """
        return element.get(attr)
    

    def get_attribute_value(self, element, attr):
        """
        Returns the numeric attribute value.
        
        Args:
            element: XML element object.
            attr: String containing the attribute name.
            
        Returns:
            Numeric value representing the attribute value.
        """
        val = element.get(attr)
        try:
            if val.upper().startswith('0X') or val.upper().startswith('-0X'):
                return int(val, 16)
            return int(val)
        except:
            idaapi.msg('\nUnable to decode string as value: ' + val)
            return 0
        

    def get_cbsize(self):
        """
        Returns the size of the addressable codebyte for the processor.
        
        Returns:
            Integer representing the number of 8-bit bytes in an
            addressable codebyte.
        """
        return (idaapi.ph_get_cnbits()+7)/8
    

    def get_datatype_flags(self, datatype, size):
        """
        Returns the flags bitmask for the datatype.
        
        Args:
            datatype: String representing the datatype.
            size: Integer representing the datatype size.

        Returns:
            Integer representing the bitmask.
        """
        if datatype.lower().startswith("byte"):     return idaapi.byteflag()
        if datatype.lower().startswith("word"):     return idaapi.wordflag()
        if datatype.lower().startswith("dword"):    return idaapi.dwrdflag()
        if datatype.lower().startswith("qword"):    return idaapi.qwrdflag()
        if datatype.lower().startswith("oword"):    return idaapi.owrdflag()
        if datatype.lower().startswith("tbyte"):    return idaapi.tbytflag()
        if datatype.lower().startswith("float"):    return idaapi.floatflag()
        if datatype.lower().startswith("double"):   return idaapi.doubleflag()
        if datatype.lower().startswith("packed"):   return idaapi.packrealflag()
        if self.is_string_type(datatype):           return idaapi.asciflag()
        if self.is_enumeration(datatype):           return idaapi.enumflag()
        if self.is_structure(datatype):             return idaapi.struflag()
        #if size == 4:                               return idaapi.dwrdflag()
        return 0
    

    def get_string_type(self, datatype):
        if datatype.lower() == 'mbcstring':
            return idaapi.ASCSTR_UNICODE
        if datatype.lower().find('unicode') != -1:
            if datatype.lower().find('pascal') != -1:
                return idaapi.ASCSTR_ULEN2
            return idaapi.ASCSTR_UNICODE
        if datatype.lower().find('pascal') != -1:
            return idaapi.ASCSTR_LEN2
        return idaapi.ASCSTR_TERMCHR
            
    
    def has_attribute(self, element, attr):
        """
        Returns true if the XML element contains the named attribute.
        
        Args:
            element: XML element object
            attr: String containing name of the attribute
        
        Returns:
            True if the element contains the named attribute, otherwise False.
        """
        return attr in element.attrib
    

    def is_enumeration(self, datatype):
        """
        Returns true if datatype is an existing enumeration in the database.
        
        Args:
            datatype: String representing the datatype.
            
        Returns:
            True if the datatype is an enumeration in the database,
            otherwise False.
        """
        if idaapi.get_enum(datatype) == idaapi.BADNODE:  return False
        return True
    
    
    def is_int(self, s):
        try:
            int(s, 16)
            return True
        except:
            return False
        

    def is_pointer_type(self, dtype):
        """
        Returns true if the datatype represents a pointer.
        
        Args:
            dtype: String representing the datatype.
            
        Returns:
            True if the datatype represents a pointer, otherwise False.
        """
        if dtype.lower().startswith("pointer") or dtype.endswith('*'):
            return True
        return False
    

    def is_string_type(self, datatype):
        """
        Returns true if the datatype represents a string type.
        
        Args:
            datatype: String representing the datatype.
            
        Returns:
            True if the datatype represents a string, otherwise False.
        """
        if datatype.lower().startswith("unicode"):  return True
        if datatype.lower().startswith("string"):   return True
        return False
    

    def is_structure(self, datatype):
        """
        Returns true if the datatype represents a structure in the database.
        
        Args:
            dtype: String representing the datatype.
            
        Returns:
            True if the datatype represents an existing structure,
            otherwise False.
        """
        if idaapi.get_struc_id(datatype) == idaapi.BADNODE:  return False
        return True
    

    def import_address_range(self, address_range):
        """
        Processes ADDRESS_RANGE element.
        
        Args:
            address_range: XML element object containing start and end address
                attributes for the address range.
                
        Returns:
            Tuple containing two integers, the start and end address values.
        """
        start = self.get_address(address_range,START)
        end = self.get_address(address_range, END)
        self.update_counter(ADDRESS_RANGE)
        return (start, end)
    

    def import_bit_mask(self, bitmask, eid):
        """
        Processes a BIT_MASK element as an enum bitmask member.
        
        Args:
            bitmask: XML element object representing the IDA enum bitmask.
            eid: Integer representing the IDA enum id
        """
        if IDA_SDK_VERSION < 640:
            return
        name = self.get_attribute(bitmask,NAME)
        value = self.get_attribute_value(bitmask,VALUE)
        idaapi.set_bmask_name(eid, value, name)
        cid = idaapi.get_const_by_name(name)
        self.update_counter(BIT_MASK)
        regcmt = bitmask.find(REGULAR_CMT)
        if regcmt != None:
            idaapi.set_const_cmt(cid, regcmt.text, False);
            self.update_counter(BIT_MASK + ':' + REGULAR_CMT)
        rptcmt = bitmask.find(REPEATABLE_CMT)
        if rptcmt != None:
            idaapi.set_const_cmt(cid, rptcmt.txt, True);
            self.update_counter(BIT_MASK + ':' + REPEATABLE_CMT)
    

    def import_bookmark(self, bookmark):
        """
        Processes a BOOKMARK element.
        
        Args:
            bookmark: XML element object containing bookmark data.
        """
        if self.Options.Bookmarks.checked == False:
            return
        try:
            addr = self.get_address(bookmark, ADDRESS)
            if self.has_attribute(bookmark, TYPE):
                typ = self.get_attribute(bookmark, TYPE)
            category = ''
            if self.has_attribute(bookmark, CATEGORY):
                category = self.get_attribute(bookmark, CATEGORY)
            description = ''
            if self.has_attribute(bookmark, DESCRIPTION):
                description = self.get_attribute(bookmark, DESCRIPTION)
            if idaapi.isEnabled(addr) == False:
                msg = ("import_bookmark: address %X not enabled in database"
                       % addr)
                print msg
                return
            self.update_counter(BOOKMARK)
            for slot in range(1,1025):
                if IDA_SDK_VERSION != 695:
                    ea = idc.GetMarkedPos(slot)
                else:
                    import ida_moves
                    import ida_pro
                    curloc = ida_moves.curloc()
                    intp = ida_pro.int_pointer()
                    intp.assign(slot)
                    ea = curloc.markedpos(intp)
                if ea == BADADDR:
                    curloc = idaapi.curloc()
                    curloc.ea = addr
                    curloc.mark(slot, category, description)
                    break
        except:
            msg = "** Exception occurred in import_bookmark **"
            print "\n" + msg + "\n", sys.exc_type, sys.exc_value
    

    def import_cmts(self, element, sid, typ):
        """
        Processes REGULAR_CMT and REPEATABLE_CMT elements for structures.
        
        Args:
            element: XML element object containing a REGULAR_CMT or
                REPEATABLE_CMT element
            sid: Integer representing the structure id
            typ: String indicating structure type (STRUCTURE or UNION)
        """
        regcmt = element.find(REGULAR_CMT)
        if regcmt != None:
            idaapi.set_struc_cmt(sid, regcmt.text, False)
            self.update_counter(typ + ':' + REGULAR_CMT)
        rptcmt = element.find(REPEATABLE_CMT)
        if rptcmt != None:
            idaapi.set_struc_cmt(sid, rptcmt.text, True)
            self.update_counter(typ + ':' + REPEATABLE_CMT)
            
        
    def import_codeblock(self, code_block):
        """
        Processes a CODE_BLOCK element by disassembling the address range.
        
        Args:
            code_block: XML element containing codeblock start and end
                addresses.
        """
        if self.Options.CodeBlocks.checked == False:
            return
        start = self.get_address(code_block, START)
        end = self.get_address(code_block, END)
        idaapi.do_unknown_range(start, end-start+1, 3)
        addr = start
        while (addr <= end):
            length = idaapi.create_insn(addr)
            addr += idaapi.get_item_size(addr) * self.get_cbsize()
        self.update_counter(CODE_BLOCK)
    

    def import_comment(self, comment):
        """
        Processes a COMMENT element by creating the comment at the address.
        
        Args:
            comment: XML element containing the comment address, type,
                and text.
        """
        if self.Options.Comments.checked == False:
            return
        addr = self.get_address(comment, ADDRESS)
        ctype = self.get_attribute(comment,TYPE)
        text = comment.text
        if ctype == 'pre':
            idaapi.add_long_cmt(addr, True, text)
        elif ctype == 'end-of-line':
            idaapi.set_cmt(addr, text, False)
        elif ctype == 'repeatable':
            idaapi.set_cmt(addr, text, True)
        elif ctype == 'post':
            idaapi.add_long_cmt(addr, False, text)
        self.update_counter(COMMENT+':' + ctype)
    

    def import_compiler(self, compiler):
        """
        Processes the COMPILER element containing the compiler name.
        
        Args:
            compiler: XML element containing the compiler name.
        """
        name = self.get_attribute(compiler, NAME)
        comp = idaapi.COMP_UNK
        if   name == "Visual C++":      comp = idaapi.COMP_MS
        elif name == "Borland C++":     comp = idaapi.COMP_BC
        elif name == "Watcom C++":      comp = idaapi.COMP_WATCOM
        elif name == "GNU C++":         comp = idaapi.COMP_GNU
        elif name == "Visual Age C++":  comp = idaapi.COMP_VISAGE
        elif name == "Delphi":          comp = idaapi.COMP_BP
        idaapi.cvar.inf.cc.id = comp
        self.update_counter(COMPILER)
    

    def import_defined_data(self, defined_data):
        """
        Processes a DEFINED_DATA element by creating a data item at the
            specified address.
        
        Args:
            defined_data: XML element containing the address and
                datatype information for the data item
        """
        if self.Options.DataDefinitions.checked == False:
            return
        addr = self.get_address(defined_data, ADDRESS)
        datatype = self.get_attribute(defined_data, DATATYPE)
        size = self.get_attribute_value(defined_data, SIZE)
        self.update_counter(DEFINED_DATA)        
        ti = idaapi.opinfo_t()
        if self.is_pointer_type(datatype):
            #idaapi.set_refinfo(ti, 0, 0, 0, REF_OFF32)
            flag = idaapi.dwrdflag() | idaapi.FF_0OFF
            #idaapi.set_typeinfo(addr, 0, flag, ti)
        else:
            flag = self.get_datatype_flags(datatype, size)
        if flag == idaapi.asciflag():
            idaapi.make_ascii_string(addr, size,
                                     self.get_string_type(datatype))
        elif flag == idaapi.struflag():
            idaapi.doStruct(addr, size, idaapi.get_struc_id(datatype))
        else:
            idaapi.do_data_ex(addr, flag, size, idaapi.BADNODE)        
        typecmt = defined_data.find(TYPEINFO_CMT)
        if typecmt != None:
            self.update_counter(DEFINED_DATA + ':' + TYPEINFO_CMT)


    def import_enum(self, enum):
        """
        Processes an ENUM element by creating the enumeration.
        
        Args:
            enum: XML element containing the enumeration name and
                member data.
        """
        if self.Options.DataTypes.checked == False:
            return
        name = self.get_attribute(enum, NAME)
        if self.has_attribute(enum,NAMESPACE):
            namespace = self.get_attribute(enum, NAMESPACE)
        if self.has_attribute(enum,SIZE):
            size = self.get_attribute_value(enum, SIZE)
        eid = idaapi.add_enum(BADADDR, name,
                              idaapi.hexflag() | idaapi.dwrdflag())
        self.update_counter(ENUM)
        regcmt = enum.find(REGULAR_CMT)
        if regcmt != None:
            idaapi.set_enum_cmt(eid, regcmt.text, False)
            self.update_counter(ENUM + ':' + REGULAR_CMT)
        rptcmt = enum.find(REPEATABLE_CMT)
        if rptcmt != None:
            idaapi.set_enum_cmt(eid, rptcmt.text, True)
            self.update_counter(ENUM + ':' + REPEATABLE_CMT)
        display_settings = enum.find(DISPLAY_SETTINGS)
        if display_settings != None:
            self.update_counter(ENUM + ':' + DISPLAY_SETTINGS)
        enum_entries = enum.findall(ENUM_ENTRY)
        for enum_entry in enum_entries:
            self.import_enum_entry(enum_entry, eid)
    

    def import_enum_entry(self, enum_entry, eid):
        """
        Processes an ENUM_ENTRY by creating a member in the enumeration.
        
        Args:
            enum_entry: XML element containing the member name and value.
            eid: Integer representing the id of the enumeration.
        """
        name = self.get_attribute(enum_entry, NAME)
        value = self.get_attribute_value(enum_entry, VALUE)
        if IDA_SDK_VERSION > 630:
            idaapi.add_const(eid, name, value)
        else:
            idaapi.add_enum_member(eid, name, value)
        if IDA_SDK_VERSION > 630:
            cid = idaapi.get_const_by_name(name)
        else:
            cid = idaapi.get_enum_member_by_name(name)
        self.update_counter(ENUM_ENTRY)
        regcmt = enum_entry.find(REGULAR_CMT)
        if regcmt != None:
            if IDA_SDK_VERSION > 630:
                idaapi.set_const_cmt(cid, regcmt.text, False);
            else:
                idaapi.set_enum_member_cmt(cid, regcmt.text, False);
            self.update_counter(ENUM_ENTRY + ':' + REGULAR_CMT)
        rptcmt = enum_entry.find(REPEATABLE_CMT)
        if rptcmt != None:
            if IDA_SDK_VERSION > 630:
                idaapi.set_const_cmt(cid, rptcmt.text, True);
            else:
                idaapi.set_enum_member_cmt(cid, rptcmt.text, True);
            self.update_counter(ENUM_ENTRY + ':' + REPEATABLE_CMT)
    

    def import_equate(self, equate, eid):
        """
        Processes EQUATE element as member of an enumeration.
        
        Args:
            enum_entry: XML element containing the equate name and value.
            eid: Integer representing the id for the enumeration.
        """
        name = self.get_attribute(equate,NAME)
        value = self.get_attribute_value(equate,VALUE)
        bm = -1
        if self.has_attribute(equate, BIT_MASK):
            bm = self.get_attribute_value(equate, BIT_MASK)
        if IDA_SDK_VERSION > 630:
            #idaapi.add_const(eid, name, value, bm)
            idaapi.add_const(eid, name, value)
            cid = idaapi.get_const_by_name(name)
        else:
            #idaapi.add_enum_member(eid, name, value, bm)
            idaapi.add_enum_member(eid, name, value)
            cid = idaapi.get_enum_member_by_name(name)
        self.update_counter(EQUATE)
        regcmt = equate.find(REGULAR_CMT) 
        if regcmt != None:
            if IDA_SDK_VERSION > 630:
                idaapi.set_const_cmt(cid, regcmt.text, False);
            else:
                idaapi.set_enum_member_cmt(cid, regcmt.text, False);
            self.update_counter(EQUATE + ':' + REGULAR_CMT)
        rptcmt = equate.find(REPEATABLE_CMT)
        if rptcmt != None:
            if IDA_SDK_VERSION > 630:
                idaapi.set_const_cmt(cid, rptcmt.text, True);
            else:
                idaapi.set_enum_member_cmt(cid, rptcmt.text, True);
            self.update_counter(EQUATE + ':' + REPEATABLE_CMT)
    

    def import_equate_group(self, equate_group):
        """
        Processes EQUATE_GROUP as IDA enumeration type.
        
        Args:
            equate_group: XML element containing the group name and
                equate definitions.
        """
        if self.Options.DataTypes.checked == False:
            return
        msg = EQUATE_GROUP
        name = ''
        if self.has_attribute(equate_group, NAME):
            name = self.get_attribute(equate_group, NAME)
        bf = ''
        if self.has_attribute(equate_group, BIT_FIELD):
            bf = self.get_attribute(equate_group, BIT_FIELD)
        eid = idaapi.add_enum(BADADDR, name, idaapi.hexflag())
        idaapi.set_enum_bf(eid, (bf == 'yes'))
        self.update_counter(EQUATE_GROUP)
        regcmt = equate_group.find(REGULAR_CMT)
        if regcmt != None:
            idaapi.set_enum_cmt(eid, regcmt.text, False)
            self.update_counter(EQUATE_GROUP + ':' + REGULAR_CMT)
        rptcmt = equate_group.find(REPEATABLE_CMT)
        if rptcmt != None:
            idaapi.set_enum_cmt(eid, rptcmt.text, True)
            self.update_counter(EQUATE_GROUP + ':' + REPEATABLE_CMT)
        equates = equate_group.findall(EQUATE)
        for equate in equates:
            self.import_equate(equate,eid)
        bit_masks = equate_group.findall(BIT_MASK)
        for bit_mask in bit_masks:
            self.import_bit_mask(bit_mask, eid)
    

    def import_equate_reference(self, equate_reference):
        if (self.Options.DataTypes.checked == False or
            self.Options.EquateReferences.checked == False):
            return
        self.update_counter(EQUATE_REFERENCE)
        addr = self.get_address(equate_reference, ADDRESS)
        name = ''
        if self.has_attribute(equate_reference, NAME):
            name = self.get_attribute(equate_reference, NAME)
        if name == '':
            return
        opnd = 0
        if self.has_attribute(equate_reference, OPERAND_INDEX):
            opnd = self.get_attribute_value(equate_reference, OPERAND_INDEX)
        value = None
        if self.has_attribute(equate_reference, VALUE):
            value = self.get_attribute_value(equate_reference, VALUE)
        if IDA_SDK_VERSION < 650:
            cid = idaapi.get_enum_member_by_name(name)
        else:
            cid = idaapi.get_const_by_name(name)
        if cid == idaapi.BADNODE:
            return
        if IDA_SDK_VERSION < 650:
            eid = idaapi.get_enum_member_enum(cid)
        else:
            eid = idaapi.get_const_enum(cid)
        if eid == idaapi.BADNODE:
            return
        idaapi.op_enum(addr, opnd, eid, 0)
        

    def import_function(self, function):
        """
        Creates a function using the FUNCTION attributes.
        
        Args:
            function: XML element containing the function address and
                attributes.
        """
        if self.Options.Functions.checked == False:
            return
        try:
            entry_point = self.get_address(function, ENTRY_POINT)
            name = ''
            if self.has_attribute(function, NAME):
                name = self.get_attribute(function, NAME)
            libfunc = 'n'
            if self.has_attribute(function, LIBRARY_FUNCTION):
                libfunc = self.get_attribute(function, LIBRARY_FUNCTION)
            if idaapi.isEnabled(entry_point) == False:
                msg = ("import_function: address %X not enabled in database"
                       % entry_point)
                print msg
                return
            idaapi.add_func(entry_point, BADADDR)
            self.update_counter(FUNCTION)
            func = idaapi.get_func(entry_point)
            if libfunc == 'y':
                func.flags |= idaapi.FUNC_LIB
            ranges = function.findall(ADDRESS_RANGE)
            for addr_range in ranges:
                (start, end) = self.import_address_range(addr_range)
                idaapi.append_func_tail(func, start, end)
                #idaapi.analyze_area(start, end+1)
            idc.Wait()
            regcmt = function.find(REGULAR_CMT)
            if regcmt != None:
                self.update_counter(FUNCTION + ':' + REGULAR_CMT)
                idaapi.set_func_cmt(func, regcmt.text, False)
            rptcmt = function.find(REPEATABLE_CMT)
            if rptcmt != None:
                self.update_counter(FUNCTION + ':' + REPEATABLE_CMT)
                idaapi.set_func_cmt(func, rptcmt.text, True)
            typecmt = function.find(TYPEINFO_CMT)
            if typecmt != None:
                self.update_counter(FUNCTION + ':' + TYPEINFO_CMT)
                idc.SetType(entry_point, typecmt.text + ';')
            sf = function.find(STACK_FRAME)
            if sf != None:
                self.import_stack_frame(sf, func)
            register_vars = function.findall(REGISTER_VAR)
            for register_var in register_vars:
                self.import_register_var(register_var, func)
        except:
            msg = "** Exception occurred in import_function **"
            print "\n" + msg + "\n", sys.exc_type, sys.exc_value


    def import_function_def(self, function_def):
        # import_function_def: NOT IMPLEMENTED
        if self.Options.DataTypes.checked == False:
            return
        self.update_counter(FUNCTION_DEF)
        

    def import_info_source(self, info_source):
        """
        Processes INFO_SOURCE containing information about the
            source of the XML PROGRAM file.
        
        Args:
            info_source: XML element containing attributes that identify
                the source of the PROGRAM data.
        """
        if self.has_attribute(info_source, TOOL):
            tool = self.get_attribute(info_source, TOOL)
        if self.has_attribute(info_source, USER):
            user = self.get_attribute(info_source, USER)
        if self.has_attribute(info_source, FILE):
            f = self.get_attribute(info_source, FILE)
        if self.has_attribute(info_source, TIMESTAMP):
            ts = self.get_attribute(info_source, TIMESTAMP)
        self.update_counter(INFO_SOURCE)
    

    def import_manual_instruction(self, manual_instruction):
        """
        Creates a manual instruction.
        
        Args:
            manual_instruction: XML element containing MANUAL_INSTRUCTION.
        """
        if self.Options.Manual.checked == False:
            return
        addr = self.get_address(manual_instruction, ADDRESS)
        idaapi.set_manual_insn(addr, manual_instruction.text)
        self.update_counter(MANUAL_INSTRUCTION)
    

    def import_manual_operand(self, manual_operand):
        """
        Creates a manual operand at an address.
        
        Args:
            manual_operand: MANUAL_OPERAND XML element.
        """
        if self.Options.Manual.checked == False:
            return
        addr = self.get_address(manual_operand, ADDRESS)
        op = self.get_attribute_value(manual_operand, OPERAND_INDEX)
        if idaapi.isEnabled(addr):
            idaapi.set_forced_operand(addr, op, manual_operand.text)
            self.update_counter(MANUAL_OPERAND)


    def process_deferred(self, element):
        """
        Processes the list of deferred structure members when the
        DATATYPES end element is encountered.
        
        Args:
            element: XML end element for DATATYPES 
        """
        for (member, sptr) in self.deferred:
            self.import_member(member, sptr, False)
        self.display_timer(element)


    def import_member(self, member, sptr, defer=True):
        """
        Creates a member for a structure.
        
        Args:
            member: MEMBER XML element.
            sptr:
            defer:  boolean indicating if processing a member should be
                    deferred when the type is unknown. A member should
                    only be deferred on the first pass, not when processing
                    the deferred list.
        """
        offset = self.get_attribute_value(member, OFFSET)
        datatype = self.get_attribute(member, DATATYPE)
        if self.has_attribute(member, DATATYPE_NAMESPACE):
            dt_namespace = self.get_attribute(member, DATATYPE_NAMESPACE)
        name = ''
        if self.has_attribute(member, NAME):
            name = self.get_attribute(member, NAME)
        size = 0
        if self.has_attribute(member, SIZE):
            size = self.get_attribute_value(member, SIZE)
        ti = idaapi.opinfo_t()
        if self.is_pointer_type(datatype):
            #idaapi.set_refinfo(ti, 0, BADADDR, 0, REF_OFF32)
            flag = idaapi.dwrdflag() | idaapi.FF_0OFF
        else:
            flag = self.get_datatype_flags(datatype, size)
        if flag == 0:
            if defer:
                self.deferred.append([member, sptr])
                return                
        if flag == idaapi.enumflag():
            t = idaapi.get_enum(datatype)
            ti.ec.tid = t
            ti.ec.serial = idaapi.get_enum_idx(t)
        if flag == idaapi.struflag():
            t = idaapi.get_struc_id(datatype)
            ti.tid = t
        error = idaapi.add_struc_member(sptr, name, offset, flag, ti, size)
        mbr = idaapi.get_member(sptr, offset)
        self.import_member_cmts(member, mbr)
        self.update_counter(MEMBER)
        
        
    def import_member_cmts(self, member, mbr):
        """
        Processes REGULAR_CMT and REPEATABLE_CMT elements for members.
        
        Args:
            element: XML element object containing a REGULAR_CMT or
                REPEATABLE_CMT element
            mbr: Integer representing the member id
        """
        regcmt = member.find(REGULAR_CMT)
        if regcmt != None:
            idaapi.set_member_cmt(mbr, regcmt.text, False)
            self.update_counter(MEMBER + ':' + REGULAR_CMT)
        rptcmt = member.find(REPEATABLE_CMT)
        if rptcmt != None:
            idaapi.set_member_cmt(mbr, rptcmt.text, True)
            self.update_counter(MEMBER + ':' + REPEATABLE_CMT)
        

    def import_members(self, element, sptr):
        """
        Add data members to a structure.
        
        Args:
            element: STRUCTURE XML element containing MEMBER sub-elements.
            sptr:
        """
        members = element.findall(MEMBER)
        for member in members:
            self.import_member(member, sptr)
                

    def import_memory_contents(self, memory_contents, start, size):
        """
        Processes MEMORY_CONTENTS to load data for a memory block.
        
        Args:
            memory_contents: MEMORY_CONTENTS XML element.
        """
        if memory_contents.get(START_ADDR) == None:
            saddr = start
        else:
            saddr = self.get_address(memory_contents, START_ADDR)
        fname = self.get_attribute(memory_contents, FILE_NAME)
        offset = self.get_attribute_value(memory_contents, FILE_OFFSET)
        if memory_contents.get(LENGTH) == None:
            length = size
        else:
            length = self.get_attribute_value(memory_contents, LENGTH)
        #(binfilename, ext) = os.path.splitext(self.filename)
        #binfilename += ".bytes"
        (binfilename, fileext) = os.path.split(self.filename)
        binfilename += '/' + fname
        binfile = idaapi.loader_input_t()
        binfile.open(binfilename)
        binfile.file2base(offset,saddr,saddr+length,False)
        binfile.close()
        self.update_counter(MEMORY_CONTENTS)
    

    def import_memory_map(self, memory_map):
        """
        Processes the MEMORY_MAP element.
        
        Args:
            memory_map: MEMORY_MAP XML element.
            
        MEMORY_MAP is only processed by the IDA loader. It is ignored when
            run as an IDA plugin.
        """
        # import memory sections only when run as loader
        if self.plugin:
            return
        self.update_import(memory_map)
    

    def import_memory_reference(self, memory_reference):
        """
        Processes the MEMORY_REFERENCE element.
        
        Args:
            memory_reference: MEMORY_REFERENCE XML element.
        """
        if self.Options.MemoryReferences.checked == False:
            return        
        addr = self.get_address(memory_reference, ADDRESS)
        if self.has_attribute(memory_reference, OPERAND_INDEX):
            op = self.get_attribute_value(memory_reference, OPERAND_INDEX)
        if self.has_attribute(memory_reference, USER_DEFINED):
            user = self.get_attribute(memory_reference, USER_DEFINED)
        to_addr = self.get_address(memory_reference, TO_ADDRESS)
        if self.has_attribute(memory_reference, BASE_ADDRESS):
            base_addr = self.get_address(memory_reference, BASE_ADDRESS)
        if self.has_attribute(memory_reference, PRIMARY):
            primary = self.get_attribute(memory_reference, PRIMARY)
        self.update_counter(MEMORY_REFERENCE)
        # TODO: import_memory_reference - add code to store reference
 
 
    def import_memory_section(self, memory_section):
        """
        Creates a memory segment in the database.
        
        Args:
            memory_section: MEMORY_SECTION XML element.
            
        MEMORY_SECTION is only processed by the IDA loader. It is ignored
            when run as an IDA plugin.
        """
        # TODO: import_memory_section - handle overlays?
        # import memory sections only when run as loader
        if self.plugin:
            return
        name = self.get_attribute(memory_section, NAME)
        length = self.get_attribute_value(memory_section, LENGTH)

        s = idaapi.segment_t()
        addrstr = self.get_attribute(memory_section, START_ADDR)
        seg_str = ''
        if '::' in addrstr:
            # overlay - skip for now
            print '  ** Overlayed memory block %s skipped **  ' % name
            msg  = 'Overlayed memory block %s skipped!' % name
            msg += "\n\nXML Import does not currently support"
            msg += "\noverlayed memory blocks."
            idaapi.warning(msg)
            return
        elif ':' in addrstr:
            [seg_str, offset_str] = string.split(addrstr,':')
            offset = int(offset_str, 16)
            if self.is_int(seg_str):
                base = int(seg_str, 16)
                sel = idaapi.setup_selector(base)
                start = self.get_address(memory_section, START_ADDR)
            else:
                raise MultipleAddressSpacesNotSupported
                return
        else:
            sel = idaapi.allocate_selector(0)
            start = int(addrstr, 16)

        s.sel = sel
        s.startEA = start
        s.endEA = start+length
        s.bitness = self.addr_mode

        perms = ''
        if self.has_attribute(memory_section, PERMISSIONS):
            perms = self.get_attribute(memory_section, PERMISSIONS)
        s.perm = 0
        if 'r' in perms: s.perm |= idaapi.SEGPERM_READ
        if 'w' in perms: s.perm |= idaapi.SEGPERM_WRITE
        if 'x' in perms: s.perm |= idaapi.SEGPERM_EXEC
        idaapi.add_segm_ex(s, name, "", idaapi.ADDSEG_OR_DIE |
                                            idaapi.ADDSEG_QUIET)
        self.update_counter(MEMORY_SECTION)
        for memory_contents in memory_section.findall(MEMORY_CONTENTS):
            self.import_memory_contents(memory_contents, start, length)
    

    def import_processor(self, processor):
        """
        Processes the PROCESSOR element.
        
        Args:
            processor: PROCESSOR XML element.
        """
        name = self.get_attribute(processor, NAME)
        self.update_counter(PROCESSOR)
        if self.plugin:
            return
        address_model = self.get_attribute(processor, ADDRESS_MODEL)
        if address_model != None:
            flag = idaapi.ph_get_flag()
            if str.lower(address_model) == '16-bit':
                self.addr_mode = 0
            elif str.lower(address_model) == '32-bit':
                self.addr_mode = 1
            elif str.lower(address_model) == '64-bit':
                self.addr_mode = 2
        

    def import_program(self, program):
        """
        Processes the PROGRAM element.
        
        Args:
            program: PROGRAM XML element.
        """
        self.update_status(PROGRAM)
        name = self.get_attribute(program, NAME)
        if self.has_attribute(program, EXE_PATH):
            epath = self.get_attribute(program, EXE_PATH)
            idaapi.set_root_filename(epath)
        else:
            idaapi.set_root_filename(name)
        if self.has_attribute(program, EXE_FORMAT):
            eformat = self.get_attribute(program, EXE_FORMAT)
            RootNode = idaapi.netnode('Root Node')
            if IDA_SDK_VERSION < 650:
                RootNode.supset(1, eformat)
            else:
                RootNode.supset(idaapi.RIDX_FILE_FORMAT_NAME, eformat)
        if self.has_attribute(program, IMAGE_BASE):
            base = self.get_attribute_value(program, IMAGE_BASE)
            idaapi.set_imagebase(base)
        if self.has_attribute(program, INPUT_MD5):
            input_md5 = self.get_attribute(program, INPUT_MD5)
            # store original md5 in a special netnode
            md5 = idaapi.netnode(INPUT_MD5, len(INPUT_MD5), True)
            if (IDA_SDK_VERSION < 650):
                md5.supset(1302, input_md5)
            else:
                md5.supset(idaapi.RIDX_MD5, input_md5)
        self.update_counter(PROGRAM)
        """
        # TODO: this needs to be on "end" event for PROGRAM
        description = program.find(DESCRIPTION)
        if description != None:
            pass  # figure out what to do with it
        """

        
    def import_program_entry_point(self, program_entry_point):
        """
        Defines a program entry point.
        
        Args:
            program_entry_point: PROGRAM_ENTRY_POINT XML element.
                Contains the entry point address.
        """
        if self.Options.EntryPoints.checked == False:
            return
        addr = self.get_address(program_entry_point, ADDRESS)
        idaapi.add_entry(addr, addr, "", True)
        self.update_counter(PROGRAM_ENTRY_POINT)
    

    def import_register_value_range(self, register_value_range):
        """
        Defines the address range for a register value.
        
        Args:
            register_value_range: REGISTER_VALUE_RANGE XML element.
                Contains the register, value, start address and range length.
        """
        if self.Options.RegisterValues.checked == False:
            return
        self.update_counter(REGISTER_VALUE_RANGE)
        reg = self.get_attribute(register_value_range, REGISTER)
        if reg == 'cs': return
        value = self.get_attribute_value(register_value_range, VALUE)
        addr = self.get_address(register_value_range, START_ADDRESS)
        length = self.get_attribute_value(register_value_range, LENGTH)
        r = idaapi.str2reg(reg)
        if r >= idaapi.ph.regFirstSreg and r <= idaapi.ph.regLastSreg:
            if IDA_SDK_VERSION < 670:
                idaapi.splitSRarea1(addr, r, value, 2)
            else:
                idaapi.splitSRarea1(addr, r, value, idaapi.SR_user)
    

    def import_register_var(self, register_var, func):
        """
        Defines a register variable for a function.
        
        Args:
            register_var: REGISTER_VAR XML element.
                Contains register, variable name, and datatype.
            func: IDA function object
        """
        name = self.get_attribute(register_var, NAME)
        reg = self.get_attribute(register_var, REGISTER)
        if self.has_attribute(register_var, DATATYPE):
            datatype = self.get_attribute(register_var, DATATYPE)
        if self.has_attribute(register_var, DATATYPE_NAMESPACE):
            namespace = self.get_attribute(register_var, DATATYPE_NAMESPACE)
        idc.MakeLocal(func.startEA, func.endEA, reg, name)
        self.update_counter(REGISTER_VAR)
    

    def import_stack_frame(self, stack_frame, func):
        """
        Defines a stack frame for a function.
        
        Args:
            stack_frame: STACK_FRAME element with STACK_VAR child elements.
        """
        if self.has_attribute(stack_frame, LOCAL_VAR_SIZE):
            lvsize = self.get_attribute_value(stack_frame, LOCAL_VAR_SIZE)
        if self.has_attribute(stack_frame, PARAM_OFFSET):
            param_offset = self.get_attribute_value(stack_frame, PARAM_OFFSET)
        if self.has_attribute(stack_frame, REGISTER_SAVE_SIZE):
            reg_save_size = self.get_attribute_value(stack_frame,
                                                     REGISTER_SAVE_SIZE)
        if self.has_attribute(stack_frame, RETURN_ADDR_SIZE):
            retaddr_size = self.get_attribute_value(stack_frame,
                                                    RETURN_ADDR_SIZE)
        if self.has_attribute(stack_frame, BYTES_PURGED):
            bytes_purged = self.get_attribute_value(stack_frame, BYTES_PURGED)
        self.update_counter(STACK_FRAME)
        for stack_var in stack_frame.findall(STACK_VAR):
            self.import_stack_var(stack_var, func)
    

    def import_stack_reference(self, stack_reference):
        # import_stack_reference: NOT IMPLEMENTED
        #self.update_counter(STACK_REFERENCE)
        pass
                    

    def import_stack_var(self, stack_var, func):
        """
        Processes STACK_VAR element.
        
        Args:
            stack_var: STACK_VAR XML element.
            
        Stack variables are created by IDA's function analysis. 
        Only the STACK_VAR NAME attribute is used to set the name for
        a stack variable at the specified stack/frame offset. 
        """
        spoffset = self.get_attribute_value(stack_var, STACK_PTR_OFFSET)
        datatype = self.get_attribute(stack_var, DATATYPE)
        offset = spoffset + func.frsize + func.frregs
        if self.has_attribute(stack_var, FRAME_PTR_OFFSET):
            fpoffset = self.get_attribute_value(stack_var, FRAME_PTR_OFFSET)
            offset = fpoffset + func.frsize
        name = ''
        if self.has_attribute(stack_var, NAME):
            name = self.get_attribute(stack_var, NAME)
        if self.has_attribute(stack_var, DATATYPE_NAMESPACE):
            namespace = self.get_attribute(stack_var, DATATYPE_NAMESPACE)
        if self.has_attribute(stack_var, SIZE):
            size = self.get_attribute_value(stack_var, SIZE)
        self.update_counter(STACK_VAR)
        sf = idaapi.get_frame(func)
        if name != '':
            idaapi.set_member_name(sf, offset, name)
    

    def import_structure(self, structure):
        """
        Adds a structure.
        
        Args:
            structure: STRUCTURE XML element.
                Contains the STRUCTURE attributes and child elements.
        """
        if self.Options.DataTypes.checked == False:
            return
        name = self.get_attribute(structure, NAME)
        dtyp = idaapi.get_struc_id(name)
        if dtyp != idaapi.BADNODE:
            # duplicate name, try adding name space
            if self.has_attribute(structure, NAMESPACE) == False:
                return
            namespace = self.get_attribute(structure, NAMESPACE)
            name = namespace + '__' + name
            name.replace('/','_')
            name.replace('.','_')
            dtyp = idaapi.get_struc_id(name)
            # skip if still duplicate (could add sequence #)
            if dtyp != idaapi.BADNODE:
                return
        size = 0
        if self.has_attribute(structure, SIZE):
            size = self.get_attribute_value(structure, SIZE)
        if self.has_attribute(structure, VARIABLE_LENGTH):
            vl = self.get_attribute_value(structure, VARIABLE_LENGTH)
            isVariableLength = vl == 'y'
        sid = idaapi.add_struc(BADADDR, name, False)
        sptr = idaapi.get_struc(sid)
        self.update_counter(STRUCTURE)
        self.import_cmts(structure, sid, STRUCTURE)
        self.import_members(structure, sptr)
        t = idaapi.opinfo_t()
        if idaapi.get_struc_size(sptr) < size:
            idaapi.add_struc_member(sptr,"",size-1,idaapi.byteflag(),t,1)
        

    def import_symbol(self, symbol):
        """
        Adds a symbol name at the specified address.
        
        Args:
            symbol: SYMBOL XML element.
                Contains symbol name and address. Optionally includes
                type and mangled symbol.
        """
        if self.Options.Symbols.checked == False:
            return
        addr = self.get_address(symbol, ADDRESS)
        name = self.get_attribute(symbol, NAME)
        if self.has_attribute(symbol, MANGLED):
            name = self.get_attribute(symbol, MANGLED)
        flag = idaapi.SN_NOWARN
        if self.has_attribute(symbol, TYPE):
            typ = self.get_attribute(symbol, TYPE)
            if  typ == 'local': flag |= idaapi.SN_LOCAL
        idaapi.set_name(addr, name, flag)
        self.update_counter(SYMBOL)
    

    def import_typedef(self, type_def):
        # import_typedef: NOT IMPLEMENTED
        if self.Options.DataTypes.checked == False:
            return
        self.update_counter(TYPE_DEF)
        

    def import_union(self, union):
        """
        Adds a union datatype.
        
        Args:
            union: UNION XML element.
                Contains UNION attributes and child elements.
        """
        if self.Options.DataTypes.checked == False:
            return
        name = self.get_attribute(union, NAME)
        dtyp = idaapi.get_struc_id(name)
        if dtyp != idaapi.BADNODE:
            # duplicate name, try adding name space
            if self.has_attribute(union, NAMESPACE) == False:
                return
            namespace = self.get_attribute(union, NAMESPACE)
            name = namespace + '__' + name
            name.replace('/','_')
            name.replace('.','_')
            dtyp = idaapi.get_struc_id(name)
            # skip if still duplicate (could add sequence #)
            if dtyp != idaapi.BADNODE:
                return
        size = 0
        if self.has_attribute(union, SIZE):
            size = self.get_attribute_value(union, SIZE)
        sid = idaapi.add_struc(BADADDR, name, True)
        sptr = idaapi.get_struc(sid)
        self.update_counter(UNION)
        self.import_cmts(union, sid, UNION)
        self.import_members(union, sptr)
        t = idaapi.opinfo_t()
        if idaapi.get_struc_size(sptr) < size:
            idaapi.add_struc_member(sptr,"", size-1, idaapi.byteflag(), None, 1)
            

    def open_file(self, filename, mode):
        """
        Opens filename to specified mode.
        
        Args:
            filename: String representing absolute filepath.
            mode: String representing mode for open.
            
        Returns
            File handle.
        
        Exceptions:
            Displays a warning and raises FileError exception
            if open fails.
        """
        try:
            f = open(filename, mode)
            return f
        except:
            fmt = "TITLE ERROR!\n"
            fmt += "ICON ERROR\n"
            fmt += "AUTOHIDE NONE\n"
            fmt += "HIDECANCEL\n"
            fmt += "Error opening file" + filename + "!\n"
            idaapi.warning(fmt)
            raise FileError
    

    def update_counter(self, tag):
        """
        Updates the counter for the element tag.
        
        Args:
            tag: String representing element tag.
        """
        if tag in self.Elements:
            self.Counters[self.Elements[tag]] += 1
        else:
            self.Elements[tag] = len(self.Elements)
            self.Counters.append(1)
            self.Tags.append(tag)
    

    def update_import(self, element):
        """
        Update the element counter and processing status.
        
        Args:
            element: XML element
            
        This function is used to process certain high-level elements
        (such as COMMENTS, CODE_BLOCKS, SYMBOL_TABLE, FUNCTIONS, etc.)
        that are used to group sub-elements.
        """
        self.update_counter(element.tag)
        self.update_status(element.tag)
    

    def update_status(self, tag):
        """
        Displays the processing status in the IDA window.
        
        Args:
            tag: String representing XML element tag
        """
        status = 'Importing ' + tag
        idaapi.msg('\n%-35s' % status)
        idaapi.hide_wait_box()
        idaapi.show_wait_box(status)
    
        
# Global XML string constants for elements and attributes
ADDRESS = 'ADDRESS'
ADDRESS_MODEL = 'ADDRESS_MODEL'
ADDRESS_RANGE = 'ADDRESS_RANGE'
BASE_ADDRESS = 'BASE_ADDRESS'
BIT_FIELD = 'BIT_FIELD'
BIT_MAPPED = 'BIT_MAPPED'
BIT_MASK = 'BIT_MASK'
BOOKMARK = 'BOOKMARK'
BOOKMARKS = 'BOOKMARKS'
BYTES = 'BYTES'
BYTES_PURGED = 'BYTES_PURGED'
CATEGORY = 'CATEGORY'
CODE = 'CODE'
CODE_BLOCK = 'CODE_BLOCK'
COMMENT = 'COMMENT'
COMMENTS = 'COMMENTS'
COMPILER = 'COMPILER'
DATA = 'DATA'
DATATYPE = 'DATATYPE'
DATATYPES = 'DATATYPES'
DATATYPE_NAMESPACE = 'DATATYPE_NAMESPACE'
DEFINED_DATA = 'DEFINED_DATA'
DESCRIPTION = 'DESCRIPTION'
DISPLAY_SETTINGS = 'DISPLAY_SETTINGS'
END = 'END'
ENDIAN = 'ENDIAN'
ENTRY_POINT = 'ENTRY_POINT'
ENUM = 'ENUM'
ENUM_ENTRY = 'ENUM_ENTRY'
EQUATE = 'EQUATE'
EQUATES = 'EQUATES'
EQUATE_GROUP = 'EQUATE_GROUP'
EQUATE_REFERENCE = 'EQUATE_REFERENCE'
EXE_FORMAT = 'EXE_FORMAT'
EXE_PATH = 'EXE_PATH'
EXT_LIBRARY = 'EXT_LIBRARY'
EXT_LIBRARY_REFERENCE = 'EXT_LIBRARY_REFERENCE'
EXT_LIBRARY_TABLE = 'EXT_LIBRARY_TABLE'
FAMILY = 'FAMILY'
FILE = 'FILE'
FILE_NAME = 'FILE_NAME'
FILE_OFFSET = 'FILE_OFFSET'
FOLDER = 'FOLDER'
FORMAT = 'FORMAT'
FRAGMENT = 'FRAGMENT'
FRAME_PTR_OFFSET = 'FRAME_PTR_OFFSET'
FUNCTION = 'FUNCTION'
FUNCTIONS = 'FUNCTIONS'
FUNCTION_DEF = 'FUNCTION_DEF'
IMAGE_BASE = 'IMAGE_BASE'
INPUT_MD5 = 'INPUT_MD5'
INFO_SOURCE = 'INFO_SOURCE'
LANGUAGE_PROVIDER = 'LANGUAGE_PROVIDER'
LENGTH = 'LENGTH'
LIB_ADDR = 'LIB_ADDR'
LIB_LABEL = 'LIB_LABEL'
LIB_ORDINAL = 'LIB_ORDINAL'
LIB_PROG_NAME = 'LIB_PROG_NAME'
LIBRARY_FUNCTION = 'LIBRARY_FUNCTION'
LOCAL_VAR_SIZE = 'LOCAL_VAR_SIZE'
MANGLED = 'MANGLED'
MANUAL_INSTRUCTION = 'MANUAL_INSTRUCTION'
MANUAL_OPERAND = 'MANUAL_OPERAND'
MARKUP = 'MARKUP'
MEMBER = 'MEMBER'
MEMORY_CONTENTS = 'MEMORY_CONTENTS'
MEMORY_MAP = 'MEMORY_MAP'
MEMORY_REFERENCE = 'MEMORY_REFERENCE'
MEMORY_SECTION = 'MEMORY_SECTION'
NAME = 'NAME'
NAMESPACE = 'NAMESPACE'
OFFSET = 'OFFSET'
OPERAND_INDEX = 'OPERAND_INDEX'
PARAM_OFFSET = 'PARAM_OFFSET'
PATH = 'PATH'
PERMISSIONS = 'PERMISSIONS'
PRIMARY = 'PRIMARY'
PROCESSOR = 'PROCESSOR'
PROGRAM = 'PROGRAM'
PROGRAM_ENTRY_POINT = 'PROGRAM_ENTRY_POINT'
PROGRAM_ENTRY_POINTS = 'PROGRAM_ENTRY_POINTS'
PROGRAM_TREES = 'PROGRAM_TREES'
PROPERTIES = 'PROPERTIES'
PROPERTY = 'PROPERTY'
REGISTER = 'REGISTER'
REGISTER_SAVE_SIZE = 'REGISTER_SAVE_SIZE'
REGISTER_VALUES = 'REGISTER_VALUES'
REGISTER_VALUE_RANGE = 'REGISTER_VALUE_RANGE'
REGISTER_VAR = 'REGISTER_VAR'
REGULAR_CMT = 'REGULAR_CMT'
RELOCATION = 'RELOCATION'
RELOCATION_TABLE = 'RELOCATION_TABLE'
REPEATABLE_CMT = 'REPEATABLE_CMT'
RETURN_ADDR_SIZE = 'RETURN_ADDR_SIZE'
RETURN_TYPE = 'RETURN_TYPE'
SHOW_TERMINATOR = 'SHOW_TERMINATOR'
SIGNED = 'SIGNED'
SIZE = 'SIZE'
SOURCE_ADDRESS = 'SOURCE_ADDRESS'
SOURCE_TYPE = 'SOURCE_TYPE'
STACK_FRAME = 'STACK_FRAME'
STACK_PTR_OFFSET = 'STACK_PTR_OFFSET'
STACK_REFERENCE = 'STACK_REFERENCE'
STACK_VAR = 'STACK_VAR'
START = 'START'
START_ADDR = 'START_ADDR'
START_ADDRESS = 'START_ADDRESS'
STRUCTURE = 'STRUCTURE'
SYMBOL = 'SYMBOL'
SYMBOL_TABLE = 'SYMBOL_TABLE'
TIMESTAMP = 'TIMESTAMP'
TOOL = 'TOOL'
TO_ADDRESS = 'TO_ADDRESS'
TREE = 'TREE'
TYPE = 'TYPE'
TYPEINFO_CMT = 'TYPEINFO_CMT'
TYPE_DEF = 'TYPE_DEF'
UNION = 'UNION'
USER = 'USER'
USER_DEFINED = 'USER_DEFINED'
VALUE = 'VALUE'
VARIABLE_LENGTH = 'VARIABLE_LENGTH'
ZERO_PAD = 'ZERO_PAD'

