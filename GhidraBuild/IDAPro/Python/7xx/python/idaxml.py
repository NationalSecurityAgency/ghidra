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
# idaxml.py - IDA XML classes
#---------------------------------------------------------------------
"""
"""

import ida_auto
import ida_bytes
import ida_diskio
import ida_enum
import ida_fpro
import ida_frame
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_loader
import ida_moves
import ida_nalt
import ida_name
import ida_netnode
import ida_pro
import ida_segment
import ida_segregs
import ida_struct
import ida_typeinf
import ida_ua
import ida_xref
import idautils
import idc
import datetime
import os
import sys
import time
from xml.etree import cElementTree


DEBUG = False  # print debug statements

IDAXML_VERSION = "5.0.1"
BASELINE_IDA_VERSION = 700
BASELINE_STR = '7.00'
IDA_SDK_VERSION = ida_pro.IDA_SDK_VERSION
BADADDR = idc.BADADDR
BADNODE = ida_netnode.BADNODE
PLUGIN = True
LOADER = not PLUGIN
AUTO_WAIT = True


def is_ida_version_supported():
    '''
    Determines if IDA version is supported by this idaxml module.
    
    Returns:
        True if IDA version is supported, else False.
    '''
    supported = IDA_SDK_VERSION >= BASELINE_IDA_VERSION
    if not supported:
        idc.msg('\nThe IDA XML plugins and loader are not supported ' +
                'by this version of IDA.\n')
        idc.msg('Please use IDA ' + BASELINE_STR + ' or greater ' +
                'with this version of XML.\n')
    return supported


class Cancelled(Exception):
    pass


class FileError(Exception):
    pass


class MultipleAddressSpacesNotSupported(Exception):
    pass


class IdaXml:
    def __init__(self, arg):
        self.autorun = False if arg == 0 else True
        self.debug = DEBUG
        self.elements = {}
        self.counters = []
        self.tags = []
        self.xmlfile = 0
        self.options = None
    

    def cleanup(self):
        """
        Frees memory and closes message box and XML file at termination.
        """
        if self.options != None:
            self.options.Free()
        ida_kernwin.hide_wait_box()
        self.close_xmlfile()


    def close_xmlfile(self):
        """
        Closes the XML data file for the XML Exporter.
        """
        if self.xmlfile != 0:
            self.xmlfile.close()
            self.xmlfile = 0


    def dbg(self, message):
        """
        Outputs debug message if debug flag is enabled.
        
        Args:
            message: String containing the debug message.
        """
        if (self.debug == True):
            idc.msg(message)
        

    def display_summary(self, what):
        """
        Displays summary in IDA output window.
        """
        summary = ''
        total = 0
        for tag in self.tags:
            count = self.counters[self.elements[tag]]
            summary += "\n%-26s %8d" % (tag, count)
            total += count
        summary  = "\n--------------------------------------" + summary
        summary += "\n--------------------------------------"
        summary += ("\n%-26s %8d" % ("Total XML Elements:",total))
        idc.msg(summary)
        if self.autorun == False: # and self.plugin:
            frmt  = "TITLE XML " + what + " Successful!\n"
            frmt += "ICON INFO\n"
            frmt += "AUTOHIDE NONE\n"
            frmt += "HIDECANCEL\n"
            fileline = '\n\nFile: %s' % self.filename
            details = '\nSee output window for details...'
            ida_kernwin.info("%s" % (frmt + fileline + details))


    def display_version(self, what):
        """
        Displays XML version info in IDA output window.
        
        Args:
            what: String indicating Exporter, Importer, or Loader 
        """
        f = ida_diskio.idadir('python') + '/idaxml.py'
        ftime = time.localtime(os.path.getmtime(f))
        ts = time.strftime('%b %d %Y %H:%M:%S', ftime)
        version = "\nXML " + what + " v" + IDAXML_VERSION
        version += " : SDK " + str(IDA_SDK_VERSION)
        version += " : Python : "+ ts + '\n'
        idc.msg(version)
        
    
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
            idc.warning(fmt)
            raise FileError

    
    def update_counter(self, tag):
        """
        Updates the counter for the element tag.
        
        Args:
            tag: String representing element tag.
        """
        if tag in self.elements:
            self.counters[self.elements[tag]] += 1
        else:
            self.elements[tag] = len(self.elements)
            self.counters.append(1)
            self.tags.append(tag)
    

    def update_status(self, tag):
        """
        Displays the processing status in the IDA window.
        
        Args:
            tag: String representing XML element tag
        """
        status = 'Processing ' + tag
        idc.msg('\n%-35s' % status)
        ida_kernwin.hide_wait_box()
        ida_kernwin.show_wait_box(status)
    

class XmlExporter(IdaXml):
    """
    XML Exporter contains methods to export an IDA database as a
        XML PROGRAM document.
    """
    def __init__(self, arg):
        """
        Initializes the XmlExporter attributes

        Args:
            arg: Integer, non-zero value enables auto-run feature for
                IDA batch (no gui) processing mode. Default is 0.
        """
        IdaXml.__init__(self, arg)
        self.indent_level = 0
        self.seg_addr = False
        self.has_overlays = False
        self.hexrays = False
        
        # initialize class variables from database
        self.inf = ida_idaapi.get_inf_structure()
        self.min_ea = self.inf.min_ea
        self.max_ea = self.inf.max_ea
        self.cbsize = (ida_idp.ph_get_cnbits()+7)/8
        self.processor = str.upper(ida_idp.get_idp_name())
        self.batch = ida_kernwin.cvar.batch


    def export_xml(self):
        """
        Exports the IDA database to a XML PROGRAM document file.
        """
        self.display_version('Exporter')
        self.check_and_load_decompiler()
        
        self.get_options()
    
        if (self.autorun == True):
            (self.filename, ext) = os.path.splitext(idc.get_idb_path())
            self.filename += ".xml"
        else:
            self.filename=ida_kernwin.ask_file(1, "*.xml",
                                         "Enter name of export xml file:")
            
        if self.filename == None or len(self.filename) == 0:
            raise Cancelled
        self.xmlfile = self.open_file(self.filename, "w")
        
        ida_kernwin.show_wait_box("Exporting XML <PROGRAM> document ....")
        idc.msg("\n------------------------------------------------" +
                   "-----------")
        idc.msg("\nExporting XML <PROGRAM> document ....")
        begin = time.clock()
        
        self.write_xml_declaration()
        self.export_program()
        
        # export database items based on options
        if (self.options.DataTypes.checked         == True or
            self.options.DataDefinitions.checked   == True or 
            self.options.Functions.checked         == True):
            self.export_datatypes()
        if (self.options.MemorySections.checked    == True or
            self.options.MemoryContent.checked     == True):
            self.export_memory_map()
        if (self.options.RegisterValues.checked    == True):
            self.export_register_values()   
        if (self.options.CodeBlocks.checked        == True):
            self.export_code()  
        if (self.options.DataDefinitions.checked   == True):
            self.export_data()  
        if (self.options.Comments.checked          == True):
            self.export_comments()
            self.export_bookmarks()     
        if (self.options.EntryPoints.checked       == True):
            self.export_program_entry_points()  
        if (self.options.Symbols.checked           == True):
            self.export_symbol_table()  
        if (self.options.Functions.checked         == True):
            self.export_functions() 
        if (self.options.MemoryReferences.checked  == True or 
            self.options.StackReferences.checked   == True or
            self.options.Manual.checked            == True or
            self.options.DataTypes.checked         == True):
            self.export_markup()    
        self.end_element(PROGRAM)
        
        idc.msg('\n%35s' % 'Total ')
        self.display_cpu_time(begin)
        ida_kernwin.hide_wait_box()  
        self.display_summary('Export')
        idc.msg('\nDatabase exported to: ' + self.filename + '\n')
        

    # TODO: Test decompiler comments in batch and gui modes
    def check_and_load_decompiler(self):
        """
        Checks for the presence of a decompiler plugin for the database.
        
        Note: The decompiler must be loaded by the XML Exporter plugin
            if it is running in batch mode. IDA will load the decompiler
            plugin automatically if not in batch mode.
        
        Note: There was no support for decompiler plugins in IDAPython until
            IDA 6.6, so skip if this is an older version.
        
        Note: Currently the 4 decompiler plugins for the  x86, x64,
            ARM32, and ARM64 are supported.
        """
        if self.batch == 0:
            self.hexrays = ida_hexrays.init_hexrays_plugin()
            return
        plugin = ''
        if self.processor == 'PC':
            if self.inf.is_64bit():
                plugin = "hexx64"
            elif self.inf.is_32bit():
                plugin = 'hexrays'
        elif self.processor == 'ARM':
            if self.inf.is_64bit():
                plugin = "hexarm64"
            elif self.inf.is_32bit():
                plugin = "hexarm"
        if len(plugin) > 0:
            try:
                ida_loader.load_plugin(plugin)
                self.hexrays = ida_hexrays.init_hexrays_plugin()
            except:
                return
    

    def check_char(self, ch):
        """
        Replaces a special XML character with an entity string.
        
        Args:
            ch: String containing the character to check.
            
        Returns:
            String containing either the character or the entity
            substition string.
        """
        if ((ord(ch) < 0x20) and (ord(ch) != 0x09 and
             ord(ch) != 0x0A and ord(ch) != 0x0D)): return ''
        elif ch == '&' :  return '&amp;'
        elif ch == '<' :  return "&lt;"
        elif ch == '>' :  return "&gt;"
        elif ch == '\'' : return "&apos;"
        elif ch == '"' :  return "&quot;"
        elif ch == '\x7F': return ''
        elif ord(ch) > 0x7F: return '&#x' + format(ord(ch),"x") + ";"
        return ch
    

    def check_for_entities(self, text):
        """
        Checks all characters in a string for special XML characters.
        
        Args:
            text: String to check for special XML characters.
            
        Returns:
            String containing original string with substitutions for
                any special XML characters.
        """
        new = ''
        for c in text:
            new += self.check_char(c)
        return new
    

    def check_if_seg_contents(self, seg):
        """
        Determines if any address in a segment contains a value.
        
        Args:
            seg: IDA segment object
            
        Returns:
            True if any address in a segment contains a value.
            False if no address in a segment contains a value.
        """
        for addr in idautils.Heads(seg.start_ea, seg.end_ea):
            if idc.has_value(idc.get_full_flags(addr)) == True:
                return True
        return False


    def check_stack_frame(self, sframe):
        """
        Determines if stack frame contains any parameters or local variables.
        
        Args:
            sframe: IDA stack frame for a function.
            
        Returns:
            True if stack frame has parameters or local variables.
            False if stack frame has no parameters or local variables.
        """
        n = sframe.memqty
        for i in range(n):
            member = sframe.get_member(i)
            if member == None:
                continue
            mname = ida_struct.get_member_name(member.id)
            if mname != None and len(mname) > 0: 
                if mname != " s" and mname != " r":
                    return True
        return False


    def close_binfile(self):
        """
        Closes the binary data file for the XML Exporter.
        """
        if self.binfile != 0:
            self.binfile.close()
            self.binfile = 0


    def close_tag(self, has_contents=False):
        """
        Closes the start tag for an XML element.
        
        Args:
            has_contents: Boolean indicating if the element has
            sub-elements or text.
        """
        if has_contents:
            self.write_to_xmlfile(">")
            self.indent_level += 1
        else:
            self.write_to_xmlfile(" />")

    
    def display_cpu_time(self, start):
        """
        Displays the elapsed CPU time since the start time.
        
        Args:
            start: Floating-point value representing start time in seconds.
        """
        idc.msg('CPU time: %6.4f' % (time.clock() - start))
            

    def end_element(self, tag, newline=True):
        """
        Writes the element end tag to the XML file.
        
        Args:
            tag: String containing the element name.
            newline: Boolean indicating if end tag should go on new line.
        """
        self.indent_level -= 1
        if newline:
            start = '\n' + ("    " * self.indent_level)
        else:
            start = ''
        self.write_to_xmlfile(start  + "</" + tag + ">")


    '''
    # BIT_MASK not currently supported for ENUM
    def export_bitmask(self, eid, mask):
        """
        Exports an enum bitmask member as BIT_MASK element.
        
        Args:
            eid: Integer representing the IDA enum id
            mask: Integer representing the IDA enum mask value
        """
        name = idc.get_bmask_name(eid, mask)
        if name == None:
            return
        self.start_element(BIT_MASK)
        self.write_attribute(NAME, name)
        self.write_numeric_attribute(VALUE, mask)
        regcmt = idc.get_bmask_cmt(eid, mask, False)
        rptcmt = idc.get_bmask_cmt(eid, mask, True)
        has_comment =  regcmt != None or rptcmt != None
        self.close_tag(has_comment)
        if regcmt != None and len(regcmt) > 0:
            self.export_regular_cmt(regcmt)
        if rptcmt != None and len(rptcmt) > 0:
            self.export_repeatable_cmt(rptcmt)
        if (has_comment):
            self.end_element(BIT_MASK)
    '''


    def export_bookmarks(self):
        """
        Exports marked location descriptions as BOOKMARK elements.
        """
        found = False
        timer = time.clock()
        for slot in range(0,1025):
            address = idc.get_bookmark(slot)
            description = idc.get_bookmark_desc(slot)
            if address == BADADDR:
                continue
            if description == None:
                continue
            if found == False:
                found = True
                self.update_status(BOOKMARKS)
                self.start_element(BOOKMARKS, True)
            self.start_element(BOOKMARK)
            self.write_address_attribute(ADDRESS, address)
            self.write_attribute(DESCRIPTION, description)
            self.close_tag()
        if found:
            self.end_element(BOOKMARKS)
            self.display_cpu_time(timer)


    def export_c_comments(self):
        """
        Exports block and end-of-line comments entered in the decompiler
        interface.
        """
        if self.hexrays == False:
            return
        functions = idautils.Functions()
        if functions == None:
            return
        for addr in functions:
            try:
                if ida_segment.is_spec_ea(addr):
                    continue
                ccmts = ida_hexrays.restore_user_cmts(addr)
                if ccmts == None:
                    continue
                p = ida_hexrays.user_cmts_begin(ccmts)
                while p != ida_hexrays.user_cmts_end(ccmts):
                    cmk = ida_hexrays.user_cmts_first(p)
                    cmv = ida_hexrays.user_cmts_second(p)
                    if cmk.itp < (ida_hexrays.ITP_COLON+1):
                        self.export_comment(cmk.ea, "end-of-line", cmv.c_str())
                    else:
                        self.export_comment(cmk.ea, "pre", cmv.c_str())
                    p=ida_hexrays.user_cmts_next(p)
                ida_hexrays.user_cmts_free(ccmts)
            except:
                continue


    def export_code(self):
        """
        Exports the address ranges of code sequences as CODE_BLOCK(s)
        with START and END address attributes.
        """
        addr = self.min_ea
        if idc.is_code(idc.get_full_flags(addr)) == False:
            addr = ida_bytes.next_that(addr, self.max_ea, idc.is_code)
        if (addr == BADADDR):
            return
        self.update_status(CODE)
        timer = time.clock()
        data = ida_bytes.next_that(addr, self.max_ea, idc.is_data)
        unknown = ida_bytes.next_unknown(addr, self.max_ea)
        self.start_element(CODE, True)
        while (addr != BADADDR):
            start = addr
            end = min(data, unknown)
            if (end == BADADDR):
                if (ida_segment.getseg(start).end_ea < self.max_ea):
                    codeend = ida_segment.getseg(start).end_ea - 1
                    addr = ida_segment.getseg(idc.next_addr(codeend)).start_ea
                    if idc.is_code(idc.get_full_flags(addr)) == False:
                        addr = ida_bytes.next_that(addr, self.max_ea,
                                               idc.is_code)
                else:
                    codeend = self.max_ea - 1
                    addr = BADADDR
            else:
                if (ida_segment.getseg(start).end_ea < end):
                    codeend = ida_segment.getseg(start).end_ea - 1
                    addr = ida_segment.getseg(idc.next_addr(codeend)).start_ea
                    if idc.is_code(ida_bytes.get_full_flags(addr)) == False:
                        addr = ida_bytes.next_that(addr, self.max_ea,
                                               idc.is_code)
                else:
                    codeend = idc.get_item_end(ida_bytes.prev_that(end,
                                                start, idc.is_code)) - 1
                    addr = ida_bytes.next_that(end, self.max_ea, idc.is_code)
                if (data < addr):
                    data = ida_bytes.next_that(addr, self.max_ea,
                                           idc.is_data)
                if (unknown < addr):
                    unknown = ida_bytes.next_unknown(addr, self.max_ea)
            self.start_element(CODE_BLOCK)
            self.write_address_attribute(START, start)
            self.write_address_attribute(END, codeend)
            self.close_tag()
        self.end_element(CODE)
        self.display_cpu_time(timer)


    def export_comment(self, addr, cmt_type, cmt):
        """
        Exports a <COMMENT> element with ADDRESS and TYPE attributes.
        The comment is exported as the element text (parsed character data).
        
        Args:
            addr: Integers representing address of comment.
            cmt_type: String indicating the comment type.
            cmt: String containing the comment.
        """
        self.start_element(COMMENT)
        self.write_address_attribute(ADDRESS, addr)
        self.write_attribute(TYPE, cmt_type)
        self.close_tag(True)
        # tag_remove seems to be losing last character
        # work around is to add a space
        cmt_text = ida_lines.tag_remove(cmt + ' ')
        self.write_text(cmt_text.decode('utf-8'))
        self.end_element(COMMENT, False)


    def export_comments(self):
        """
        Exports all comments in the IDA database as <COMMENT> elements.
        """
        addr = self.min_ea
        if ida_bytes.has_cmt(idc.get_full_flags(addr)) == False:
            addr = ida_bytes.next_that(addr, self.max_ea, ida_bytes.has_cmt)
        if (addr == BADADDR):
            return
        self.update_status(COMMENTS)
        timer = time.clock()
        self.start_element(COMMENTS, True)
        while (addr != BADADDR):
            cmt = idc.get_cmt(addr, False)
            if (cmt != None):
                self.export_comment(addr, "end-of-line", cmt)
            cmt = idc.get_cmt(addr, True)
            if (cmt != None):
                self.export_comment(addr, "repeatable", cmt)
            addr = ida_bytes.next_that(addr, self.max_ea, ida_bytes.has_cmt)
        addr = self.min_ea
        if ida_bytes.has_extra_cmts(idc.get_full_flags(addr)) == False:
            addr = ida_bytes.next_that(addr, self.max_ea, ida_bytes.has_extra_cmts)
        while (addr != BADADDR):
            extra = idc.get_extra_cmt(addr, idc.E_PREV)
            if (extra != None):
                self.export_extra_comment(addr, "pre", idc.E_PREV)
            extra = idc.get_extra_cmt(addr, idc.E_NEXT)
            if (extra != None):
                self.export_extra_comment(addr, "post", idc.E_NEXT)
            addr = ida_bytes.next_that(addr, self.max_ea, ida_bytes.has_extra_cmts)
        self.export_c_comments()
        self.end_element(COMMENTS)
        self.display_cpu_time(timer)


    def export_data(self):
        """
        Exports the data items in the database as <DEFINED_DATA> elements.
        """
        addr = self.min_ea
        if idc.is_data(idc.get_full_flags(addr)) == False:
            addr = ida_bytes.next_that(addr, self.max_ea, idc.is_data)
        if (addr == BADADDR):
            return
        timer = time.clock()
        self.update_status(DATA)
        self.start_element(DATA, True)
        while (addr != BADADDR):
            f = idc.get_full_flags(addr)
            if ida_bytes.is_align(f) == True:
                addr = ida_bytes.next_that(addr, self.max_ea, idc.is_data)
                continue
            dtype = self.get_datatype(addr)
            size = idc.get_item_size(addr)
            ti = ida_nalt.opinfo_t()
            msize = ida_bytes.get_data_elsize(addr, f, ti)
            if ida_bytes.is_struct(f) == True:
                s = idc.get_struc_id(dtype)
                msize = idc.get_struc_size(s)
                if msize == 0:
                    msize = 1
            if idc.is_strlit(f) == False and size != msize:
                dtype = "%s[%d]" % (dtype, size/msize)
            self.start_element(DEFINED_DATA)
            self.write_address_attribute(ADDRESS, addr)
            self.write_attribute(DATATYPE, dtype)
            self.write_numeric_attribute(SIZE, size*self.cbsize)
            #TODO consider using GetTrueNameEx and Demangle
            demangled = ida_name.get_demangled_name(addr,
                            DEMANGLED_TYPEINFO, self.inf.demnames, idc.GN_STRICT)
            outbuf = ''
            # TODO: How to handle print_type for data mangled names?
            #outbuf = idaapi.print_type(addr, False)
            if demangled == "'string'":
                demangled == None
            has_typeinfo = ((demangled != None and len(demangled) > 0) or
                            (outbuf != None and len(outbuf) > 0))
            #TODO export_data: add DISPLAY_SETTINGS
            self.close_tag(has_typeinfo)
            if has_typeinfo == True:
                if demangled != None and len(demangled) > 0:
                    self.export_typeinfo_cmt(demangled)
                elif len(outbuf) > 0:
                    self.export_typeinfo_cmt(outbuf)
                self.end_element(DEFINED_DATA)
            addr = ida_bytes.next_that(addr, self.max_ea, idc.is_data)
        self.end_element(DATA)
        self.display_cpu_time(timer)
        

    def export_datatypes(self):
        """
        Exports the structures and enums in IDA database.
        """
        # skip if no structures/unions to export
        if idc.get_struc_qty() == 0: return
        self.update_status(DATATYPES)
        timer = time.clock()
        self.start_element(DATATYPES, True)
        self.export_structures()
        self.export_enums()
        self.end_element(DATATYPES)
        self.display_cpu_time(timer)


    def export_enum_member(self, cid, bf, mask, radix, signness):
        """
        Exports a member of an enum.

        Args:
            cid: Integer representing id of enum member
            bf: Boolean indicates if a bitfield
            mask: Integer representing bitmask if bitfield
            radix: Integer representing numeric display format
            signness: Boolean indicating if signed value 
        """
        cname = ida_enum.get_enum_member_name(cid)
        if cname == None or len(cname) == 0:
            return
        regcmt = ida_enum.get_enum_member_cmt(cid, False)
        rptcmt = ida_enum.get_enum_member_cmt(cid, True)
        has_comment =  regcmt != None or rptcmt != None
        self.start_element(ENUM_ENTRY)
        self.write_attribute(NAME, cname)
        value = ida_enum.get_enum_member_value(cid)
        self.write_numeric_attribute(VALUE, value, radix, signness)
        # BIT_MASK attribute not currently supported for ENUM_ENTRY
        #if bf == True:
        #    self.write_numeric_attribute(BIT_MASK, mask)
        self.close_tag(has_comment)
        if regcmt != None and len(regcmt) > 0:
            self.export_regular_cmt(regcmt)
        if rptcmt != None and len(rptcmt) > 0:
            self.export_repeatable_cmt(rptcmt)
        if (has_comment):
            self.end_element(ENUM_ENTRY)


    def export_enum_members(self, eid, bf, eflags):
        """
        Exports the members of an enum.

        This function can only be called by IDA versions newer than 6.3 
        
        Args:
            eid: Integer representing id of enum
            bf: Boolean indicates if a bitfield
            eflags: Integer representing the enum flags
        """
        mask=0xFFFFFFFF
        if bf == True:
            mask = idc.get_first_bmask(eid)
        first = True
        for n in range(idc.get_enum_size(eid)):
            if (first == True):
                value = ida_enum.get_first_enum_member(eid, mask)
                first = False
            else:
                value = ida_enum.get_next_enum_member(eid, value, mask)
            (cid, serial) = ida_enum.get_first_serial_enum_member(eid, value, mask)
            main_cid = cid
            while cid != BADNODE:
                self.export_enum_member(cid, bf, mask,
                                   ida_bytes.get_radix(eflags, 0),
                                   self.is_signed_data(eflags))
                last_value = ida_enum.get_last_enum_member(eid, mask)
                if value == last_value:
                    # ENUM BIT_MASK exporting not currently supported
                    #self.export_bitmask(eid, mask)
                    mask = idc.get_next_bmask(eid, mask)
                    first = True
                (cid, serial) = ida_enum.get_next_serial_enum_member(serial, main_cid)


    def export_enum_reference(self, addr, op):
        """
        Exports the enum reference for an operand at an address.
        
        Args:
            addr: Integer representing the instruction address.
            op: Integer representing the operand index (0-based)
        """
        (eid, serial) = ida_bytes.get_enum_id(addr, op)
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, addr)
        value = insn.ops[op].value
        cid = BADNODE
        last = idc.get_last_bmask(eid)
        if idc.is_bf(eid) == True:
            last = idc.get_last_bmask(eid)
            mask = idc.get_first_bmask(eid)
            while  cid == BADNODE:
                cid = ida_enum.get_enum_member(eid, (value & mask), 0, mask)
                if cid != BADNODE or mask == last:
                    break
                mask = idc.get_next_bmask(eid, mask)
        else:
            cid = ida_enum.get_enum_member(eid, value, 0, last)
        if cid == BADNODE:
            return
        self.start_element(EQUATE_REFERENCE)
        self.write_address_attribute(ADDRESS, addr)
        self.write_numeric_attribute(OPERAND_INDEX, op, 10)
        self.write_numeric_attribute(VALUE, ida_enum.get_enum_member_value(cid))
        cname = ida_enum.get_enum_member_name(cid)
        if cname != None and len(cname) > 0:
            self.write_attribute(NAME, cname)
        if idc.is_bf(eid) == True:
            self.write_numeric_attribute("BIT_MASK", mask);
        self.close_tag()
        

    def export_enum_references(self, addr):
        """
        Finds and exports enum references at an address.
        
        Args:
            addr: Integer representing the instruction address.
        """
        f = idc.get_full_flags(addr)
        for op in range(2):
            if ida_bytes.is_enum(f, op) == True:
                self.export_enum_reference(addr, op)
                

    def export_enums(self):
        """
        Exports enumerations.
        """
        num_enums = idc.get_enum_qty()
        if (num_enums == 0):
            return
        for i in range(num_enums):
            self.start_element(ENUM)
            eid = idc.getn_enum(i)
            ename = idc.get_enum_name(eid)
            if (ename == None or len(ename) == 0):
                continue
            self.write_attribute(NAME, ename)
            ewidth = idc.get_enum_width(eid)
            if ewidth != 0 and ewidth <= 7:
                self.write_numeric_attribute(SIZE, 1 << (ewidth-1), 10)
            eflags = idc.get_enum_flag(eid)
            bf = idc.is_bf(eid)
            # BIT_FIELD attribute not supported for ENUM export
            #if bf == True:
            #    self.write_attribute(BIT_FIELD, "yes")
            regcmt = idc.get_enum_cmt(eid, False)
            rptcmt = idc.get_enum_cmt(eid, True)
            has_children = ((idc.get_enum_size(eid) > 0) or
                            (regcmt != None) or (rptcmt != None) or
                            (ida_bytes.get_radix(eflags, 0) != 16) or
                            (self.is_signed_data(eflags) == True))
            self.close_tag(has_children)
            if (ida_bytes.get_radix(eflags, 0) != 16 or
                self.is_signed_data(eflags) == True):
                self.start_element(DISPLAY_SETTINGS)
                if ida_bytes.get_radix(eflags, 0) != 16:
                    self.write_attribute(FORMAT, self.get_format(eflags))
                if self.is_signed_data(eflags) == True:
                    self.write_attribute(SIGNED, "yes")
                self.close_tag()
            if regcmt != None:
                self.export_regular_cmt(regcmt)
            if rptcmt != None:
                self.export_repeatable_cmt(rptcmt)
            self.export_enum_members(eid, bf, eflags)
            if (has_children):
                self.end_element(ENUM)


    def export_extra_comment(self, addr, cmt_type, extra):
        """
        Exports pre- and post- comments for an address.
        
        Args:
            addr: Integer representing the instruction address.
            cmt_type: String indicating comment type
            extra: Integer representing extra comment index
        """
        cmt = ''
        nextline = idc.get_extra_cmt(addr, extra)
        while (nextline != None):
            # workaround for tag_remove bug is to add space
            cmt += ida_lines.tag_remove(nextline + ' ')
            extra += 1
            nextline = idc.get_extra_cmt(addr, extra)
            if (nextline != None):
                cmt += '\n' 
        self.export_comment(addr, cmt_type, cmt)


    def export_functions(self):
        """
        Exports information about all functions. 
        """
        functions = idautils.Functions()
        if functions == None:
            return
        self.update_status(FUNCTIONS)
        timer = time.clock()
        self.start_element(FUNCTIONS, True)
        for addr in functions:
            function = ida_funcs.get_func(addr)
            if ida_segment.is_spec_ea(function.start_ea) == True:
                continue
            self.start_element(FUNCTION)
            self.write_address_attribute(ENTRY_POINT, function.start_ea)
            if ida_bytes.has_user_name(idc.get_full_flags(addr)) == True:
                name = self.get_symbol_name(addr)
                if name != None and len(name) > 0:
                    self.write_attribute(NAME, name)
            if function.flags & idc.FUNC_LIB != 0:
                self.write_attribute(LIBRARY_FUNCTION, "y")
            self.close_tag(True)
            fchunks = idautils.Chunks(addr)
            for (startEA, endEA) in fchunks:
                self.start_element(ADDRESS_RANGE)
                self.write_address_attribute(START, startEA)
                self.write_address_attribute(END, endEA-1)
                self.close_tag()
            regcmt = ida_funcs.get_func_cmt(function, False)
            if regcmt != None:
                self.export_regular_cmt(regcmt)
            rptcmt = ida_funcs.get_func_cmt(function, True)
            if rptcmt != None:
                self.export_repeatable_cmt(rptcmt)
            demangled = ida_name.get_demangled_name(addr,
                                            DEMANGLED_TYPEINFO,
                                            self.inf.demnames, True)
            if demangled != None and demangled == "'string'":
                demangled = None
            outbuf = ''
            # TODO: How to handle print_type for function typeinfo cmts
            #outbuf = idaapi.print_type(addr, False)
            has_typeinfo = (demangled != None or (outbuf != None and
                            len(outbuf) > 0))
            if demangled != None:
                self.export_typeinfo_cmt(demangled)
            elif has_typeinfo == True:
                self.export_typeinfo_cmt(outbuf[:-1])
            self.export_stack_frame(function)
            self.end_element(FUNCTION)
        self.end_element(FUNCTIONS)
        self.display_cpu_time(timer)


    def export_manual_instruction(self, addr):
        """
        Exports user-entered "manual instruction" at an address.
        
        Args:
            addr: Integer representing instruction address.
        """
        text = idc.get_manual_insn(addr)
        if text == None or len(text) == 0:
            return
        self.start_element(MANUAL_INSTRUCTION)
        self.write_address_attribute(ADDRESS, addr)
        self.close_tag(True)
        self.write_text(text)
        self.end_element(MANUAL_INSTRUCTION, False)
        

    def export_manual_operand(self, addr):
        """
        Exports user-entered "manual operands" at an address.
        
        Args:
            addr: Integer representing instruction address.
        """
        for op in range(ida_ida.UA_MAXOP):
            if ida_bytes.is_forced_operand(addr, op) == True:
                text = idc.get_forced_operand(addr, op)
                if text != None and len(text) > 0:
                    self.start_element(MANUAL_OPERAND)
                    self.write_address_attribute(ADDRESS, addr)
                    self.write_numeric_attribute(OPERAND_INDEX, op, 10)
                    self.close_tag(True)
                    self.write_text(text)
                    self.end_element(MANUAL_OPERAND, False)


    def export_markup(self):
        """
        Exports markup for instructions and data items including references
        and manual instructions and operands.
        """
        self.update_status(MARKUP)
        timer = time.clock()
        self.start_element(MARKUP, True)
        addr = self.min_ea
        while addr != BADADDR:
            f = idc.get_full_flags(addr)
            if self.options.MemoryReferences.checked == True:
                if ida_bytes.has_xref(f) == True:
                    self.export_user_memory_reference(addr)
                if ida_bytes.is_off(f, ida_bytes.OPND_ALL) == True:
                    self.export_memory_references(addr)
            if (self.options.Functions.checked == True and
                    self.options.StackReferences.checked == True and
                    ida_bytes.is_stkvar(f, ida_bytes.OPND_ALL) == True):
                self.export_stack_reference(addr)
            if (self.options.DataTypes.checked == True and
                    ida_bytes.is_enum(f, ida_bytes.OPND_ALL) == True):
                self.export_enum_references(addr)
            if self.options.Manual.checked == True:
                # TODO: Ask about OPND_ALL and retrieving additional manual operands
                #if ida_bytes.is_forced_operand(addr, ida_bytes.OPND_ALL) == True:
                if (ida_bytes.is_forced_operand(addr, 0) == True or
                        ida_bytes.is_forced_operand(addr, 1) == True):
                    self.export_manual_operand(addr)
                if ida_bytes.is_manual_insn(addr) == True:
                    self.export_manual_instruction(addr)
            addr = idc.next_head(addr, self.max_ea)
        self.end_element(MARKUP)
        self.display_cpu_time(timer)


    def export_members(self, s):
        """
        Exports the members of a structure or union.
        
        Args:
            s: IDA structure/union instance
        """
        nmembers = s.memqty
        for n in range(nmembers):
            m = s.get_member(n)
            offset = m.soff
            if s.is_union() == True:
                offset = 0
            self.start_element(MEMBER)
            self.write_numeric_attribute(OFFSET, offset)
            mname = ida_struct.get_member_name(m.id)
            if len(mname) > 0:
                self.write_attribute(NAME, mname)
            dtype = self.get_member_type(m)
            if ida_struct.is_varmember(m) == True:
                msize = 0
                size  = 0
            else:
                mtibuf = ida_nalt.opinfo_t()
                mti = ida_struct.retrieve_member_info(mtibuf, m)
                #if IDA_SDK_VERSION < 640:
                #    msize = idaapi.get_type_size0(None, dtype)
                #    if msize == None or msize == 0:
                #        msize = ida_struct.get_member_size(m)
                #else:
                size = ida_struct.get_member_size(m)
                #msize = idaapi.get_data_type_size(m.flag, mtibuf)
                # TODO: How to handle get_date_type_size for structure members
                msize = size
                if size < msize: size = msize
            if (size != msize):
                arraytype = self.get_member_type(m)
                dtype = "%s[%d]" % (arraytype, size/msize)
            self.write_attribute(DATATYPE, dtype)
            self.write_numeric_attribute(SIZE, size*self.cbsize)
            regcmt = ida_struct.get_member_cmt(m.id, False)
            rptcmt = ida_struct.get_member_cmt(m.id, True)
            hascmt = regcmt != None or rptcmt != None
            self.close_tag(hascmt)
            if (hascmt):
                if regcmt != None:
                    self.export_regular_cmt(regcmt)
                if rptcmt != None:
                    self.export_repeatable_cmt(rptcmt)
                self.end_element(MEMBER)


    def export_memory_contents(self, binfilename, binfile, start, end):
        """
        Exports the binary memory contents in the database.
        
        A MEMORY_CONTENTS element is generated for each contiguous address
        range where each address in the range contains a value.
        The binary values are store in a separate file (not the XML file),
        and the MEMORY_CONTENTS element identifies the file and the
        offset in the file where the address range is located.

        Args:
            binfilename: String containing the absolute filepath
            binfile: IDA file instance for binary file
            start: Integer representing the starting address
            end: Integer representing the ending address
        """
        length = 0
        startaddr = start
        for addr in range(start, end):
            # reset start address when length == 0
            if (length == 0):
                startaddr = addr
            has_val = ida_bytes.has_value(idc.get_full_flags(addr))
            if has_val == True:
                length += self.cbsize
            next_address = idc.next_addr(addr)
            if ((has_val == False) or (next_address != addr+1) or
                    (next_address == end)):
                if length > 0:
                    offset = binfile.tell()
                    ida_loader.base2file(binfile.get_fp(), offset, startaddr,
                                     startaddr+length)
                    self.start_element(MEMORY_CONTENTS)
                    self.write_address_attribute(START_ADDR, startaddr)
                    self.write_attribute(FILE_NAME, binfilename)
                    self.write_numeric_attribute(FILE_OFFSET, offset)
                    self.write_numeric_attribute(LENGTH, length)
                    self.close_tag(False)
                    length=0


    def export_memory_map(self):
        """
        Exports information about all memory blocks in the database.
        
        A MEMORY_SECTION is generated for each block (segment). If the
        memory block is initialized (has values), the contents are exported
        using the MEMORY_CONTENTS element.
        """
        nsegs = ida_segment.get_segm_qty()
        if (nsegs == 0):
            return
        self.update_status(MEMORY_MAP)
        timer = time.clock();
        binfilename = ''
        if (self.options.MemoryContent.checked == True):
            (binfilename, ext) = os.path.splitext(self.filename)
            binfilename += ".bytes"
            self.binfile = ida_fpro.qfile_t()
            self.binfile.open(binfilename,'wb');
        self.start_element(MEMORY_MAP, True)
        for i in range(nsegs):
            self.export_memory_section(ida_segment.getnseg(i), binfilename)
        self.end_element(MEMORY_MAP)
        if (self.options.MemoryContent.checked == True):
            self.close_binfile()
        self.display_cpu_time(timer)


    def export_memory_reference(self, addr, op):
        """
        Exports the memory reference for operand at the address.
        
        Args:
            addr: Integer representing the instruction address.
            op: Integer representing the operand index (0-based)
        """
        f = idc.get_full_flags(addr)
        ri = ida_nalt.refinfo_t()
        if ida_nalt.get_refinfo(ri, addr, op) == 1: 
            if ri.target != BADADDR:
                target = ri.target
            elif idc.is_code(f) == True:
                insn = ida_ua.insn_t()
                ida_ua.decode_insn(insn, addr)
                target = (insn.ops[op].value - ri.tdelta + ri.base) & ((1 << 64) - 1)
            elif idc.is_data(f) == True:
                target = (self.get_data_value(addr) - ri.tdelta + ri.base) & ((1 << 64) - 1)
            else:
                return
        else:
            return
        if ida_bytes.is_mapped(target) == False:
            return
        self.start_element(MEMORY_REFERENCE)
        self.write_address_attribute(ADDRESS, addr)
        self.write_numeric_attribute(OPERAND_INDEX, op, 10)
        self.write_address_attribute(TO_ADDRESS, target)
        self.write_attribute(PRIMARY, "y")
        self.close_tag()
        

    def export_memory_references(self, addr):
        """
        Exports the memory references for any operands at the address.
        
        Args:
            addr: Integer representing the instruction address.
        """
        f = idc.get_full_flags(addr)
        for op in range(ida_ida.UA_MAXOP):
            if ida_bytes.is_off(f, op) == True and (idc.is_data(f) == True or
                    (idc.is_code(f) == True and
                    self.is_imm_op(addr, op) == True)):
                self.export_memory_reference(addr, op)
    

    def export_memory_section(self, seg, binfilename):
        """
        Exports segment information as a MEMORY_SECTIONS element.
        
        Args:
            seg: IDA segment instance
            binfilename: String containing absolute filepath for binary file.
        """
        segname = ida_segment.get_segm_name(seg)
        self.start_element(MEMORY_SECTION)
        self.write_attribute(NAME, segname)
        self.write_address_attribute(START_ADDR, seg.start_ea)
        length = (seg.end_ea - seg.start_ea)*self.cbsize
        self.write_numeric_attribute(LENGTH, length)
        perms = ""
        if (seg.perm != 0):
            if (seg.perm & ida_segment.SEGPERM_READ  != 0):
                perms += 'r'
            if (seg.perm & ida_segment.SEGPERM_WRITE != 0):
                perms += 'w' 
            if (seg.perm & ida_segment.SEGPERM_EXEC  != 0):
                perms += 'x'
            if (len(perms) > 0):
                self.write_attribute(PERMISSIONS, perms)
        has_contents = (self.options.MemoryContent.checked == True and
                       self.check_if_seg_contents(seg) == True)
        self.close_tag(has_contents)
        if (has_contents == True):
            self.export_memory_contents(os.path.basename(binfilename),
                                      self.binfile, seg.start_ea, seg.end_ea)
            self.end_element(MEMORY_SECTION)


    def export_program(self):
        """
        Exports basic information about the program as the PROGRAM,
        INFO_SOURCE, PROCESSOR, and COMPILER elements.
        """
        # output the PROGRAM element
        self.update_status(PROGRAM);
        timer = time.clock()
        self.start_element(PROGRAM)
        self.write_attribute(NAME, idc.get_root_filename())
        self.write_attribute(EXE_PATH, idc.get_input_file_path())
        etype = ida_loader.get_file_type_name()
        if (len(etype) > 0):
            self.write_attribute(EXE_FORMAT, etype)
        # check for presence of INPUT_MD5 netnode
        md5 = ida_netnode.netnode(INPUT_MD5)
        if md5 == BADNODE:
            input_md5 = idc.retrieve_input_file_md5()
        else:
            input_md5 = md5.supval(ida_nalt.RIDX_MD5)
        if input_md5 != None:
            self.write_attribute(INPUT_MD5,input_md5)
        self.close_tag(True)
    
        # output the INFO_SOURCE element
        self.start_element(INFO_SOURCE)
        tool  = 'IDA-Pro ' + ida_kernwin.get_kernel_version()
        tool += ' XML plugin v' + IDAXML_VERSION + ' (Python) SDK ' + str(IDA_SDK_VERSION)
        self.write_attribute(TOOL, tool)
        user = os.getenv("USERNAME", "UNKNOWN")
        if (user == "UNKNOWN"):
            user = os.getenv("USER", "UNKNOWN")
        self.write_attribute(USER, user)
        self.write_attribute(FILE, idc.get_idb_path())
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        self.write_attribute(TIMESTAMP, ts)
        self.close_tag()
    
        # output the PROCESSOR element
        self.start_element(PROCESSOR)
        self.write_attribute(NAME, self.inf.procname)
        if self.inf.is_be() == True:
            byte_order ="big"
        else:
            byte_order ="little"
        self.write_attribute(ENDIAN, byte_order)
        self.seg_addr = False
        bitness = 1
        model_warning = False
        nsegs = ida_segment.get_segm_qty()
        if (nsegs > 0):
            bitness = ida_segment.getnseg(0).bitness
            for i in range(1,nsegs):
                seg = ida_segment.getnseg(i)
                if (seg.bitness != bitness):
                    model_warning = True
                if (seg.bitness > bitness):
                    bitness = seg.bitness
        addr_model = "32-bit"
        if (bitness == 0):
            addr_model = "16-bit"
        elif (bitness == 2):
            addr_model = "64-bit"
        self.write_attribute(ADDRESS_MODEL, addr_model)
        self.close_tag()
        if (model_warning):
            idc.msg("WARNING: Segments do not have same " +
                       "addressing model!\n")
        if (ida_idp.ph.id == ida_idp.PLFM_386 and bitness == 0):
            self.seg_addr = True
        # find any overlayed memory before processing addressable items
        self.find_overlay_memory()
    
        # output compiler info
        self.start_element(COMPILER)
        self.write_attribute(NAME, ida_typeinf.get_compiler_name(self.inf.cc.id))
        self.close_tag()
        self.display_cpu_time(timer)


    def export_program_entry_points(self):
        """
        Exports entry points for the program.
        """
        nepts = idc.get_entry_qty()
        if (nepts  == 0):
            return
        self.update_status(PROGRAM_ENTRY_POINTS)
        timer = time.clock()
        self.start_element(PROGRAM_ENTRY_POINTS, True)
        for i in range(nepts):
            self.start_element(PROGRAM_ENTRY_POINT)
            addr = idc.get_entry(idc.get_entry_ordinal(i))
            self.write_address_attribute(ADDRESS, addr)
            self.close_tag()
        self.end_element(PROGRAM_ENTRY_POINTS)
        self.display_cpu_time(timer)


    def export_register_values(self):
        """
        Exports segment register value ranges.
        """
        first = ida_idp.ph_get_reg_first_sreg()
        last  = ida_idp.ph_get_reg_last_sreg() + 1
        has_segregareas = False
        for j in range(first, last):
            nsegregareas = ida_segregs.get_sreg_ranges_qty(j)
            if nsegregareas != 0:
                has_segregareas = True
                break;
        if has_segregareas == False:
            return
        self.update_status(REGISTER_VALUES)
        timer = time.clock();
        self.start_element(REGISTER_VALUES, True)
        sr = ida_segregs.sreg_range_t()
        for j in range(first, last):
            nsegregareas = ida_segregs.get_sreg_ranges_qty(j)
            if nsegregareas == 0:
                continue
            for i in range(nsegregareas):
                success = ida_segregs.getn_sreg_range(sr, j, i)
                if success == False:
                    continue
                value = sr.val
                if value == idc.BADSEL:
                    continue
                regname = ida_idp.ph.regnames[j]
                if regname == None:
                    continue
                if regname.lower() == "cs":
                    continue
                if (ida_idp.ph.id == ida_idp.PLFM_TMS and
                    regname.lower() == "ds"):
                    continue
                self.start_element(REGISTER_VALUE_RANGE)
                self.write_attribute(REGISTER, ida_idp.ph.regnames[j])
                self.write_numeric_attribute(VALUE, value)
                self.write_address_attribute(START_ADDRESS, sr.start_ea)
                length = (sr.end_ea - sr.start_ea) * self.cbsize
                self.write_numeric_attribute(LENGTH, length)
                self.close_tag()
        self.end_element(REGISTER_VALUES)
        self.display_cpu_time(timer)


    def export_regular_cmt(self, cmt):
        """
        Exports the regular comment for an item.
        
        Args:
            cmt: String containing the regular comment.
        """
        self.write_comment_element(REGULAR_CMT, cmt)
    

    def export_repeatable_cmt(self, cmt):
        """
        Exports the repeatable comment for an item.
        
        Args:
            cmt: String containing the repeatable comment.
        """
        self.write_comment_element(REPEATABLE_CMT, cmt)
    

    def export_stack_frame(self, function):
        """
        Export information about a function stack frame including
        variables allocated on the stack.
        
        Args:
            function: IDA function instance
        """
        sframe = ida_struct.get_struc(function.frame)
        if sframe == None or sframe.memqty <= 0:
            return
        self.start_element(STACK_FRAME)
        self.write_numeric_attribute(LOCAL_VAR_SIZE, function.frsize)
        self.write_numeric_attribute(REGISTER_SAVE_SIZE, function.frregs)
        retsize = ida_frame.get_frame_retsize(function)
        self.write_numeric_attribute(RETURN_ADDR_SIZE, retsize)
        self.write_numeric_attribute(BYTES_PURGED, function.argsize)
        has_stack_vars = self.check_stack_frame(sframe)
        self.close_tag(has_stack_vars)
        if has_stack_vars == True:
            self.export_stack_vars(function, sframe)
            self.end_element(STACK_FRAME)


    def export_stack_reference(self, addr):
        """
        Exports references to stack variables at the address.
        
        Args:
            addr: Integer containing instruction address.
        """
        f = idc.get_full_flags(addr)
        for op in range(ida_ida.UA_MAXOP):
            if idc.is_code(f) == True and ida_bytes.is_stkvar(f, op) == True:
                insn = ida_ua.insn_t()
                ida_ua.decode_insn(insn, addr)
                opnd = insn.ops[op]
                # TODO:How to handle opnd.type for stack references
                optype = opnd.type
                if optype == idc.o_void:
                    continue
                # TODO:How to handle op_t_get_addr for stack references
                SV = ida_frame.get_stkvar(insn, opnd, opnd.value)
                if SV == None:
                    continue
                (sv, actval) = SV
                function = ida_funcs.get_func(addr)
                self.start_element(STACK_REFERENCE)
                self.write_address_attribute(ADDRESS, addr)
                self.write_numeric_attribute(OPERAND_INDEX, op, 10)
                offset = opnd.addr
                spoff = offset - function.frregs
                if offset > 0x7FFFFFFF:
                    offset -= 0x100000000
                if spoff > 0x7FFFFFFF:
                    spoff  -= 0x100000000
                self.write_numeric_attribute(STACK_PTR_OFFSET, spoff,
                                             16, True)
                if (function.flags & idc.FUNC_FRAME) != 0:
                    self.write_numeric_attribute(FRAME_PTR_OFFSET,
                                                offset, 16, True)
                self.close_tag()


    def export_stack_vars(self, function, sframe):
        """
        Exports the stack variables (parameters and locals) in a stack frame.
        
        Args:
            function: IDA function instance.
            sframe: IDA stack frame instance.
        """
        for i in range(sframe.memqty):
            member = sframe.get_member(i)
            if member == None:
                continue
            mname = ida_struct.get_member_name(member.id)
            if mname == None or len(mname) < 0:
                continue
            if mname == " s" or mname == " r":
                continue
            spoff = member.soff - function.frsize - function.frregs
            froff = member.soff - function.frsize
            self.start_element(STACK_VAR)
            self.write_numeric_attribute(STACK_PTR_OFFSET, spoff, 16, True)
            if function.flags & idc.FUNC_FRAME != 0:
                self.write_numeric_attribute(FRAME_PTR_OFFSET, froff, 16, True)
            pre = mname[0:4]
            if pre != "var_" and pre != "arg_":
                self.write_attribute(NAME, mname)
            f = member.flag
            size = ida_struct.get_member_size(member)
            mtype = self.get_member_type(member)
            msize = size
            if idc.is_struct(f) == True:
                msize = idc.get_struc_size(ida_struct.get_struc_id(mtype))
            elif idc.is_strlit(f) == False:
                mtibuf = ida_nalt.opinfo_t()
                mti = ida_struct.retrieve_member_info(mtibuf, member)
                # TODO: How to handle get_data_type_size (for stack vars)
                #msize = idaapi.get_data_type_size(f, mtibuf)
            if size < msize: size = msize
            if (idc.is_strlit(f) == False and ida_bytes.is_align(f) == False
                and size != msize):
                mtype = "%s[%d]" % (mtype, size/msize)
            self.write_attribute(DATATYPE, mtype)
            self.write_numeric_attribute(SIZE, size*self.cbsize)
            regcmt = ida_struct.get_member_cmt(member.id, False)
            rptcmt = ida_struct.get_member_cmt(member.id, True)
            if regcmt != None:
                regcmt  = ida_lines.tag_remove(regcmt + " ", 0)
            if rptcmt != None:
                rptrcmt = ida_lines.tag_remove(rptcmt + " ", 0)
            has_regcmt = regcmt != None and len(regcmt) > 0
            has_rptcmt = rptcmt != None and len(rptcmt) > 0
            has_content = has_regcmt or has_rptcmt
            self.close_tag(has_content)
            if has_content == True:
                if has_regcmt == True:
                    self.export_regular_cmt(regcmt)
                if has_rptcmt == True:
                    self.export_repeatable_cmt(rptcmt)
                self.end_element(STACK_VAR)


    def export_structures(self):
        """
        Exports information about all structures and unions.
        """
        structs = idautils.Structs()
        for struct in structs:
            (idx, sid, sname) = struct
            s = ida_struct.get_struc(sid)
            stype = STRUCTURE
            if s.is_union() == True:
                stype = UNION
            self.start_element(stype)
            self.write_attribute(NAME, sname)
            size = idc.get_struc_size(sid)*self.cbsize
            self.write_numeric_attribute(SIZE, size)
            if s.is_varstr() == True:
                self.write_attribute(VARIABLE_LENGTH, "y")
            regcmt = idc.get_struc_cmt(sid, False)
            rptcmt = idc.get_struc_cmt(sid, True)
            has_contents = regcmt != None or rptcmt != None or s.memqty > 0
            self.close_tag(has_contents)
            if (has_contents):
                if regcmt != None:
                    self.export_regular_cmt(regcmt)
                if rptcmt != None:
                    self.export_repeatable_cmt(rptcmt)
                if s.memqty > 0:
                    self.export_members(s)
                self.end_element(stype)
    

    def export_symbol(self, addr, name, stype=""):
        """
        Exports name for an address as a SYMBOL element. If the name is a
        demangled name, add the mangled name as the MANGLED attribute.
        
        Args:
            addr: Integer representing the symbol address.
            name: String containing the symbol name.
            stype: String indicating symbol type (global or local)
        """
        self.start_element(SYMBOL)
        self.write_address_attribute(ADDRESS, addr)
        self.write_attribute(NAME, name)
        self.write_attribute(TYPE, stype)
        mangled = idc.get_name(addr, idc.GN_STRICT)
        if name != None and mangled != name:
            self.write_attribute("MANGLED", mangled)
        self.close_tag()
        

    def export_symbol_table(self):
        """
        Exports user-defined and non-default names as SYMBOL elements.
        """
        addr = self.min_ea
        if ida_bytes.has_any_name(idc.get_full_flags(addr)) == False:
            addr = ida_bytes.next_that(addr, self.max_ea, ida_bytes.has_any_name)
        if addr == BADADDR:
            return
        self.update_status(SYMBOL_TABLE)
        self.start_element(SYMBOL_TABLE, True)
        timer = time.clock()
        while addr != BADADDR:
            # only export meaningful names (user and auto)
            f = idc.get_full_flags(addr)
            if (ida_bytes.has_user_name(f) == True or
                ida_bytes.has_auto_name(f) == True):
                # check for global name
                name = self.get_symbol_name(addr)
                if name != None and len(name) > 0:
                    self.export_symbol(addr, name)
                # check for local name
                if ida_nalt.has_lname(addr):
                    name = idc.get_name(addr, idc.GN_LOCAL)
                    if name != None and len(name) > 0:
                        self.export_symbol(addr, name, 'local')
            # get next address with any name
            addr = ida_bytes.next_that(addr, self.max_ea,
                                   ida_bytes.has_any_name)
        self.end_element(SYMBOL_TABLE)
        self.display_cpu_time(timer)
        

    def export_typeinfo_cmt(self, cmt):
        """
        Exports comment containing type information for data and functions.
        
        Args:
            cmt: String containing type info.
        """
        # older versions of IDAPython returned a '\n' at end of cmt
        if(len(cmt) > 0):
            while cmt[-1] == '\n':
                cmt = cmt[:-1]
        
        self.write_comment_element(TYPEINFO_CMT, cmt)
        

    def export_user_memory_reference(self, addr):
        """
        Exports a user-specified memory reference at the address.
        
        Args:
            addr: Integer representing the instruction address.
        """
        for xref in idautils.XrefsTo(addr, ida_xref.XREF_FAR):
            if xref.user == 1:
                self.start_element(MEMORY_REFERENCE)
                self.write_address_attribute(ADDRESS, xref.frm)
                self.write_address_attribute(TO_ADDRESS, xref.to)
                self.write_attribute(USER_DEFINED, "y")
                self.close_tag()


    def find_overlay_memory(self):
        """
        Determines if any memory blocks (segments) are overlays.
        
        A segment is an overlay if it translates to the same logical
        address as another segment. This is rare, but may occur, for
        example when a processor has a small logical address space
        (i.e. a 16-bit address is limited to 64K) and multiple physical
        segments are mapped into the same logical segment.
        """
        self.overlay = dict()
        self.has_overlays = False;
        nsegs = ida_segment.get_segm_qty()
        if nsegs == 0:
            return
        s = ida_segment.getnseg(0)
        start = self.translate_address(s.start_ea)
        self.overlay[start] = False
        for i in range(1, nsegs):
            s = ida_segment.getnseg(i)
            space = self.get_space_name(s.start_ea)
            saddr = self.translate_address(s.start_ea)
            eaddr = self.translate_address(s.end_ea-1)
            is_overlay = False
            for j in range(i):
                s2 = ida_segment.getnseg(j)
                space2 = self.get_space_name(s2.start_ea)
                if space == space2:
                    start = self.translate_address(s2.start_ea)
                    end   = self.translate_address(s2.end_ea - 1)
                    if ((saddr >= start and saddr <= end) or 
                        (eaddr >= start and eaddr <= end)):
                        is_overlay = True
                        self.has_overlays = True
                        break
            self.overlay[saddr] = is_overlay


    def get_address_string(self, addr):
        """
        Returns a string representing the address.
        
        The representation is typically a hex string of the address,
        but may include a segment or space name prefixe based on the
        processor or architecture.
        
        Args:
            addr: Integer representing a program address.
        """
        temp = "0x%X" % (addr - ida_segment.get_segm_base(ida_segment.getseg(addr)))
        space = self.get_space_name(addr)
        if space != None:
            temp = "%s:%04X" % (space,
                            addr - ida_segment.get_segm_base(ida_segment.getseg(addr)))
        else:
            if (ida_idp.ph_get_id() == ida_idp.PLFM_386 and
                ida_segment.getseg(addr).bitness == 0):
                base = ida_segment.get_segm_para(ida_segment.getseg(addr))
                temp = "%04X:%04X" % (base, addr - (base << 4))
        if ida_idp.ph_get_id() == ida_idp.PLFM_C166:
            temp = "0x%X" % addr
        if self.has_overlays == True and self.is_overlay(addr) == True:
            oname = ida_segment.get_segm_name(ida_segment.getseg(addr))
            if len(oname) > 0:
                temp = oname + "::" + temp
        return temp


    def get_data_value(self, addr):
        """
        Returns the data item value at an address based on its size.
        
        Args:
            addr: Integer representing a program address.
        """
        size = idc.get_item_size(addr)*self.cbsize
        if size == 1:   return ida_bytes.get_byte(addr)
        if size == 2:   return ida_bytes.get_16bit(addr)
        if size == 4:   return ida_bytes.get_32bit(addr)
        if size == 8:   return ida_bytes.get_64bit(addr)
        return 0
    

    def get_datatype(self, addr):
        """
        Returns the datatype at an address.
        
        The type could be a basic type (byte, word, dword, etc.),
        a structure, an array, a pointer, or a string type.
        
        Args:
            addr: Integer representing a program address.
        """
        f = idc.get_full_flags(addr)
        t = self.get_type(f)
        if ida_bytes.is_struct(f) == True:
            opndbuf = ida_nalt.opinfo_t()
            opnd = ida_bytes.get_opinfo(opndbuf, addr, 0, f)
            return idc.get_struc_name(opnd.tid)
        if idc.is_strlit(f) == True:
            str_type = idc.get_str_type(addr)
            #print ida_bytes.print_strlit_type(str_type)
            if str_type == ida_nalt.STRTYPE_TERMCHR:   return "string"
            if str_type == ida_nalt.STRTYPE_PASCAL:    return "string1"
            if str_type == ida_nalt.STRTYPE_LEN2:      return "string2"
            if str_type == ida_nalt.STRTYPE_LEN4:      return "string4"
            if str_type == ida_nalt.STRTYPE_C_16:   return "unicode"
            if str_type == ida_nalt.STRTYPE_C_16:     return "unicode2"
            if str_type == ida_nalt.STRTYPE_C_32:     return "unicode4"
            return "string"
        if ida_bytes.is_off0(f) == True: return "pointer"
        return t


    def get_format(self, flags):
        """
        Returns the display format of a data item based on its flags.
        
        Args:
            flags: Integer representing IDA item flags
            
        Returns:
            String representing IDA display format.
        """
        if ida_bytes.is_char0(flags): return "char"
        radix = ida_bytes.get_radix(flags, 0)
        if radix == 2:  return "binary"
        if radix == 8:  return "octal"
        if radix == 10: return "decimal"
        return "hex" # default
    

    def get_member_type(self, m):
        """
        Returns the datatype of a structure member.
        
        Args:
            m: IDA member instance.
            
        Returns:
            String representing member datatype.
        """
        f = m.flag
        t = self.get_type(f)
        if ida_bytes.is_off0(f) == True:
            t = "pointer"
        if ida_bytes.is_struct(f) == False:
            return t
        s = ida_struct.get_sptr(m)
        if (s == None):
            return t
        sname = idc.get_struc_name(s.id)
        if (sname == None):
            return t
        return sname


    def get_options(self):
        """
        Displays the options menu and retrieves the option settings. 
        """
        fmt =  "HELP\n"
        fmt += "XML plugin (Python)\n"
        fmt += "IDA SDK: "+ str(IDA_SDK_VERSION) + "\n"
        fmt += "\n"
        fmt += "The XML interface provides a dump of the IDA-Pro database as "
        fmt += "a XML \"PROGRAM\" document. The XML PROGRAM document contains "
        fmt += "information from the idb file in a readable text format, and "
        fmt += "can be viewed with a text editor or web browser.\n\n"
        fmt += "ENDHELP\n"
        fmt += "Export as XML PROGRAM document...."
        fmt += "\n <##Options##Memory Sections:{MemorySections}>"
        fmt += "\n <Memory Content:{MemoryContent}>"
        fmt += "\n <Segment Register Value Ranges:{RegisterValues}>"
        fmt += "\n <Data Types:{DataTypes}>"
        fmt += "\n <Code Blocks:{CodeBlocks}>"
        fmt += "\n <Data Definitions:{DataDefinitions}>"
        fmt += "\n <Comments:{Comments}>"
        fmt += "\n <Entry Points:{EntryPoints}>"
        fmt += "\n <Symbols:{Symbols}>"
        fmt += "\n <Functions:{Functions}>"
        fmt += "\n <Memory References:{MemoryReferences}>"
        fmt += "\n <Stack References:{StackReferences}>"
        fmt += "\n <Manual Instructions/Operands:{Manual}>{cGroup1}>"
        fmt += "\n\n"

        Opts = { 'cGroup1': ida_kernwin.Form.ChkGroupControl ((
                    "MemorySections",
                    "MemoryContent",
                    "RegisterValues",
                    "DataTypes",
                    "CodeBlocks",
                    "DataDefinitions",
                    "Comments",
                    "EntryPoints",
                    "Symbols",
                    "Functions",
                    "MemoryReferences",
                    "StackReferences",
                    "Manual"
                ))}

        self.options = ida_kernwin.Form(fmt, Opts)
        self.options.Compile()
        
        self.options.MemorySections.checked   = True
        self.options.MemoryContent.checked    = True
        self.options.DataTypes.checked        = True
        self.options.RegisterValues.checked   = True
        self.options.CodeBlocks.checked       = True
        self.options.DataDefinitions.checked  = True
        self.options.Symbols.checked          = True
        self.options.EntryPoints.checked      = True
        self.options.Functions.checked        = True
        self.options.Comments.checked         = True
        self.options.MemoryReferences.checked = True
        self.options.StackReferences.checked  = False
        self.options.Manual.checked           = True

        if (self.autorun == False):
            ok = self.options.Execute()
            if (ok == 0):
                raise Cancelled


    def get_space_name(self, addr):
        """
        Returns the memory space name associated with an address.
        
        Args:
            addr: Integer representing a program address.
            
        Returns:
            String containg the memory space name.
            None if single address space architecture.

        Used for Harvard architectures (Intel 8051 and TMS, add others
        as needed). 
        """
        pid = ida_idp.ph_get_id()
        stype = ida_segment.segtype(addr)
        if pid == ida_idp.PLFM_8051:
            if stype == idc.SEG_CODE:
                return "CODE"
            else:
                if stype == idc.SEG_IMEM:
                    iaddr = addr - ida_segment.get_segm_base(ida_segment.getseg(addr))
                    if iaddr < 0x80:
                        return "INTMEM"
                    else:
                        return "SFR"
                else:
                    return "EXTMEM"
        if pid == ida_idp.PLFM_TMS:
            if stype == idc.SEG_CODE:
                return "CODE"
            else:
                return "DATA"
        return None


    def get_symbol_name(self, ea):
        """
        Returns the symbol name for the address.
        
        Args:
            ea: Integer representing the symbol address.
            
        Returns:
            String containing the symbol name.
        
        The demangled name will be returned if it exists, otherwise the
        displayed name is returned. Spaces (' ') will be replaced with '_'.
        """
        name = ida_name.get_demangled_name(ea, DEMANGLED_FORM,
                                         self.inf.demnames, idc.GN_STRICT)
        if name == None or len(name) == 0 or name == "`string'":
            name = idc.get_name(ea)
        if name != None:
            name = name.replace(" ","_")
        return name


    def get_type(self, flags):
        """
        Returns a datatype string based on the item flags.
        
        Args:
            flags: IDA item flags.
            
        Returns:
            String representing item datatype.
        """
        if (self.cbsize == 2):
            if ida_bytes.is_byte(flags)  == True: return "word"
            if ida_bytes.is_word(flags)  == True: return "dword"
        if ida_bytes.is_byte(flags)      == True: return "byte"
        if ida_bytes.is_word(flags)      == True: return "word"
        if ida_bytes.is_dword(flags)     == True: return "dword"
        if ida_bytes.is_qword(flags)     == True: return "qword"
        if ida_bytes.is_oword(flags)     == True: return "oword"
        if ida_bytes.is_tbyte(flags)     == True: return "tbyte"
        if ida_bytes.is_float(flags)     == True: return "float"
        if ida_bytes.is_double(flags)    == True: return "double"
        if ida_bytes.is_pack_real(flags) == True: return "packed"
        if idc.is_strlit(flags)          == True: return "ascii"
        if ida_bytes.is_struct(flags)    == True: return "structure"
        if ida_bytes.is_align(flags)     == True: return "align"
        return "unknown"


    def is_imm_op(self, addr, op):
        """
        Returns true if instruction operand at address is an immediate value.
        
        Args:
            addr: Integer representing instruction address.
            op: Integer representing operand index (0-based).
            
        Returns:
            True if instruction operand at address is an immediate value.
            False otherwise.
        """
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, addr)
        if (insn.ops[op].type == idc.o_imm):
            return True
        return False
        

    def is_overlay(self, addr):
        """
        Checks if memory block (segment) is an overlay.
        
        Args:
            addr: Integer representing a program address.
            
        Returns:
            True if memory block (segment) is an overlay.
        """
        if ida_idp.ph_get_id() == ida_idp.PLFM_C166:
            return False
        s = ida_segment.getseg(addr)
        if s.startEA in self.overlay:
            return self.overlay[s.startEA]
        return False

    
    def is_signed_data(self, flags):
        return (flags & ida_bytes.FF_SIGN) != 0


    def start_element(self, tag, close=False):
        """
        Outputs the start of a new element on a new indented line.
        
        Args:
            tag: String representing the element tag
            close: Boolean indicating if tag is should be closed.
        """
        if ida_kernwin.user_cancelled() == True:
            raise Cancelled
        self.write_to_xmlfile("\n" + ("    " * self.indent_level) + "<" + tag)
        if (close):
            self.close_tag(True)
        self.update_counter(tag)
        

    def translate_address(self, addr):
        """
        Returns the translated logical address.

        The logical address is adjusted for the segment base address.
        For 16-bit segmented memory, return the 20-bit address.
        
        Args:
            addr: Integer representing a program address.
            
        Returns:
            Integer representing the logical address.
        """
        if self.seg_addr == False:
            return addr - ida_segment.get_segm_base(ida_segment.getseg(addr))
        base = ida_segment.get_segm_para(ida_segment.getseg(addr))
        return (base << 16) + (addr - (base << 4))
    

    def write_address_attribute(self, name, addr):
        """
        Outputs an address attribute for an element.
        
        Args:
            name: String representing attribute name.
            addr: Integer representing a program address.
        """
        self.write_attribute(name, self.get_address_string(addr))
    

    def write_attribute(self, name, value):
        """
        Outputs an attribute (name and value) for an element.
        
        Args:
            name: String representing attribute name.
            value: String representing attribute value.
        """
        if name == None or value == None:
            return
        if (len(name) == 0) or (len(value) == 0):
            return
        attr = " " + name + '="' + self.check_for_entities(value) + '"'
        self.write_to_xmlfile(attr)
        

    def write_comment_element(self, name, cmt):
        """
        Outputs the tag and text for a comment element.
        Comment elements can be REGULAR_CMT, REPEATABLE_CMT, or TYPEINFO_CMT.
        
        Args:
            name: String representing the comment element name.
            cmt: String containing the comment.
        """
        self.start_element(name, True)
        self.write_text(cmt)
        self.end_element(name, False)
        

    def write_numeric_attribute(self, name, value, base=16, signedhex=False):
        """
        Outputs a numeric value attribute (name and value) for an element.
        
        Args:
            name: String representing the attribute name.
            value: Integer representing the attribute value.
            base: Integer representing numeric base to use for value.
            signedhex: Boolean indicating if hex representation of
                value is signed.
        """
        if base == 10:
            temp = "%d" % value
        else:
            if signedhex == True and value < 0:
                temp = "-0x%X" % abs(value)
            else:
                temp = "0x%X" % value
        self.write_attribute(name, temp)


    def write_text(self, text):
        """
        Outputs the parsed character text for an element.
        The text is checked for special characters.
        
        Args:
            text: String representing the element text.
        """
        self.write_to_xmlfile(self.check_for_entities(text))
    

    def write_to_xmlfile(self, buf):
        """
        Writes the buffer to the XML file.
        
        Args:
            buf: String containg data to write to XML file.
        """
        self.xmlfile.write(buf)
        self.dbg(buf)
    

    def write_xml_declaration(self):
        """
        Writes the XML Declarations at the start of the XML file.
        """
        self.dbg("\n")
        xml_declaration  = "<?xml version=\"1.0\" standalone=\"yes\"?>"
        xml_declaration += "\n<?program_dtd version=\"1\"?>\n"
        self.write_to_xmlfile(xml_declaration)


class XmlImporter(IdaXml):
    """
    XmlImporter class contains methods to import an XML PROGRAM
        document into IDA.
    """
    def __init__(self, as_plugin, arg=0):
        """
        Initializes the XmlImporter attributes

        Args:
            as_plugin:
            debug: 
        """
        IdaXml.__init__(self, arg)
        self.plugin = as_plugin
        self.timers = dict()
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
                DESCRIPTION         : self.import_description,
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
        global event, element
        self.display_version('Importer' if self.plugin else 'Loader')
        displayMenu = self.autorun == False
        self.get_options(displayMenu)
        if self.plugin:
            self.filename=ida_kernwin.ask_file(0, "*.xml",
                                               "Enter name of xml file:")
        else:
            self.filename = idc.get_input_file_path()
        if self.filename == None or len(self.filename) == 0:
            return
        idc.msg('\nImporting from: ' + self.filename + '\n')
        if self.plugin == False:
            ida_kernwin.hide_wait_box()
        ida_kernwin.show_wait_box("Importing XML PROGRAM document....")
        n = 0
        for event,element in cElementTree.iterparse(self.filename,
                                                events=("start","end")):
            if ida_kernwin.user_cancelled() == True:
                raise Cancelled
            
            if self.debug == True and event == 'start':
                msg = ''
                if element.tag != None:
                    msg += str(element.tag) + ' '
                if element.attrib != None:
                    msg += str(element.attrib) + ' '
                if element.text != None:
                    msg += str(element.text)
                if len(msg) > 0:
                    idc.msg('\n' + msg)
            
            if event in self.callbacks:
                if element.tag in self.callbacks[event]:
                    if event == 'start':
                        self.timers[element.tag] = time.clock()
                    self.callbacks[event][element.tag](element)
                    if event == 'end':
                        element.clear()
            if event == 'end':
                n += 1
        end = time.clock()
        ida_kernwin.hide_wait_box()
        self.display_summary('Import' if self.plugin else "Load")
        idc.msg('\nXML Elements parsed: ' + str(n) + '\n\n')
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
    
        Opts =  { 'cGroup1': ida_kernwin.Form.ChkGroupControl (( 
                    "CodeBlocks",
                    "EntryPoints",
                    "RegisterValues",
                    "DataTypes",
                    "DataDefinitions",
                    "Symbols",
                    "Comments",
                    "Bookmarks",
                    "Functions",
                    "MemoryReferences",
                    "EquateReferences",
                    "Manual"
                ))}
        
        self.options = ida_kernwin.Form(fmt, Opts)
        self.options.Compile()
    
        self.options.CodeBlocks.checked       = True
        self.options.EntryPoints.checked      = True
        self.options.RegisterValues.checked   = True
        self.options.DataTypes.checked        = True
        self.options.DataDefinitions.checked  = True
        self.options.Symbols.checked          = True
        self.options.Functions.checked        = True
        self.options.Comments.checked         = True
        self.options.Bookmarks.checked        = True
        self.options.MemoryReferences.checked = True
        self.options.EquateReferences.checked = True
        self.options.Manual.checked           = True

        if display == True:
            ok = self.options.Execute()
            if (ok == 0):
                raise Cancelled


    def display_timer(self, element):
        """
        Displays the elapsed processing time for XML elements.
        
        Args:
            element: XML element object value containing the element tag.
        """
        if element.tag == MEMORY_MAP and self.plugin:
            return
        if element.tag in self.timers:
            idc.msg('elapsed time: %.4f' %
                    (time.clock()-self.timers[element.tag]))
    
    
    def display_total_time(self, element):
        """
        Displays the total processing time.
        
        Args:
            element: XML element object value (not used).
        """
        TOTAL = 'Total '
        idc.msg('\n%35selapsed time: %.4f' %
                (TOTAL,time.clock()-self.timers[PROGRAM]))
    
    

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
            [segstr, offset_str] = str.split(addrstr,':')
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
            idc.msg('\nUnable to decode string as value: ' + val)
            return 0
        

    def get_cbsize(self):
        """
        Returns the size of the addressable codebyte for the processor.
        
        Returns:
            Integer representing the number of 8-bit bytes in an
            addressable codebyte.
        """
        return (ida_idp.ph_get_cnbits()+7)/8
    

    def get_datatype_flags(self, datatype, size):
        """
        Returns the flags bitmask for the datatype.
        
        Args:
            datatype: String representing the datatype.
            size: Integer representing the datatype size.

        Returns:
            Integer representing the bitmask.
        """
        if datatype.lower().startswith("byte"):     return ida_bytes.byte_flag()
        if datatype.lower().startswith("word"):     return ida_bytes.word_flag()
        if datatype.lower().startswith("dword"):    return ida_bytes.dword_flag()
        if datatype.lower().startswith("qword"):    return ida_bytes.qword_flag()
        if datatype.lower().startswith("oword"):    return ida_bytes.oword_flag()
        if datatype.lower().startswith("tbyte"):    return ida_bytes.tbyte_flag()
        if datatype.lower().startswith("float"):    return ida_bytes.float_flag()
        if datatype.lower().startswith("double"):   return ida_bytes.double_flag()
        if datatype.lower().startswith("packed"):   return ida_bytes.packreal_flag()
        if self.is_string_type(datatype):           return ida_bytes.strlit_flag()
        if self.is_enumeration(datatype):           return ida_bytes.enum_flag()
        if self.is_structure(datatype):             return ida_bytes.stru_flag()
        #if size == 4:                               return ida_bytes.dword_flag()
        return 0
    

    def get_string_type(self, datatype):
        if datatype.lower() == 'mbcstring':
            return ida_nalt.STRTYPE_C_16
        if datatype.lower().find('unicode') != -1:
            if datatype.lower().find('pascal') != -1:
                return ida_nalt.STRTYPE_LEN2_16
            return ida_nalt.STRTYPE_C_16
        if datatype.lower().find('pascal') != -1:
            return ida_nalt.STRTYPE_C_16
        return ida_nalt.STRTYPE_TERMCHR
            
    
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
        if ida_enum.get_enum(datatype) == BADNODE:  return False
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
        if ida_struct.get_struc_id(datatype) == BADNODE:  return False
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
        name = self.get_attribute(bitmask,NAME)
        value = self.get_attribute_value(bitmask,VALUE)
        ida_enum.set_bmask_name(eid, value, name)
        cid = ida_enum.get_enum_member_by_name(name)
        self.update_counter(BIT_MASK)
        regcmt = bitmask.find(REGULAR_CMT)
        if regcmt != None:
            ida_enum.set_enum_member_cmt(cid, regcmt.text, False);
            self.update_counter(BIT_MASK + ':' + REGULAR_CMT)
        rptcmt = bitmask.find(REPEATABLE_CMT)
        if rptcmt != None:
            ida_enum.set_enum_member_cmt(cid, rptcmt.txt, True);
            self.update_counter(BIT_MASK + ':' + REPEATABLE_CMT)
    

    def import_bookmark(self, bookmark):
        """
        Processes a BOOKMARK element.
        
        Args:
            bookmark: XML element object containing bookmark data.
        """
        if self.options.Bookmarks.checked == False:
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
            if idc.is_mapped(addr) == False:
                msg = ("import_bookmark: address %X not enabled in database"
                       % addr)
                print msg
                return
            self.update_counter(BOOKMARK)
            for slot in range(ida_moves.MAX_MARK_SLOT):
                ea = idc.get_bookmark(slot)
                if ea == BADADDR:
                    idc.put_bookmark(addr, 0, 0, 0, slot, description)
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
            ida_struct.set_struc_cmt(sid, regcmt.text, False)
            self.update_counter(typ + ':' + REGULAR_CMT)
        rptcmt = element.find(REPEATABLE_CMT)
        if rptcmt != None:
            ida_struct.set_struc_cmt(sid, rptcmt.text, True)
            self.update_counter(typ + ':' + REPEATABLE_CMT)
            
        
    def import_codeblock(self, code_block):
        """
        Processes a CODE_BLOCK element by disassembling the address range.
        
        Args:
            code_block: XML element containing codeblock start and end
                addresses.
        """
        if self.options.CodeBlocks.checked == False:
            return
        start = self.get_address(code_block, START)
        end = self.get_address(code_block, END)
        ida_bytes.del_items(start, 3, end-start+1)
        addr = start
        while (addr <= end):
            length = ida_ua.create_insn(addr)
            addr += ida_bytes.get_item_size(addr) * self.get_cbsize()
        self.update_counter(CODE_BLOCK)
    

    def import_comment(self, comment):
        """
        Processes a COMMENT element by creating the comment at the address.
        
        Args:
            comment: XML element containing the comment address, type,
                and text.
        """
        if self.options.Comments.checked == False:
            return
        addr = self.get_address(comment, ADDRESS)
        ctype = self.get_attribute(comment,TYPE)
        text = comment.text
        if ctype == 'pre':
            ida_lines.add_extra_cmt(addr, True, text)
        elif ctype == 'end-of-line':
            idc.set_cmt(addr, text, False)
        elif ctype == 'repeatable':
            idc.set_cmt(addr, text, True)
        elif ctype == 'post':
            ida_lines.add_extra_cmt(addr, False, text)
        self.update_counter(COMMENT+':' + ctype)
    

    def import_compiler(self, compiler):
        """
        Processes the COMPILER element containing the compiler name.
        
        Args:
            compiler: XML element containing the compiler name.
        """
        name = self.get_attribute(compiler, NAME)
        self.update_counter(COMPILER)
        if self.plugin:
            return        
        comp = idc.COMP_UNK
        if   name == "Visual C++":      comp = ida_typeinf.COMP_MS
        elif name == "Borland C++":     comp = ida_typeinf.COMP_BC
        elif name == "Watcom C++":      comp = ida_typeinf.COMP_WATCOM
        elif name == "GNU C++":         comp = ida_typeinf.COMP_GNU
        elif name == "Visual Age C++":  comp = ida_typeinf.COMP_VISAGE
        elif name == "Delphi":          comp = ida_typeinf.COMP_BP
        ida_typeinf.set_compiler_id(comp)
    

    def import_defined_data(self, defined_data):
        """
        Processes a DEFINED_DATA element by creating a data item at the
            specified address.
        
        Args:
            defined_data: XML element containing the address and
                datatype information for the data item
        """
        if self.options.DataDefinitions.checked == False:
            return
        addr = self.get_address(defined_data, ADDRESS)
        datatype = self.get_attribute(defined_data, DATATYPE)
        size = self.get_attribute_value(defined_data, SIZE)
        self.update_counter(DEFINED_DATA)        
        ti = ida_nalt.opinfo_t()
        if self.is_pointer_type(datatype):
            #idaapi.set_refinfo(ti, 0, 0, 0, REF_OFF32)
            flag = ida_bytes.dword_flag() | idc.FF_0OFF
            #idaapi.set_typeinfo(addr, 0, flag, ti)
        else:
            flag = self.get_datatype_flags(datatype, size)
        if flag == ida_bytes.strlit_flag():
            ida_bytes.create_strlit(addr, size, self.get_string_type(datatype))
        elif flag == ida_bytes.stru_flag():
            idc.create_struct(addr, size, datatype)
        else:
            idc.create_data(addr, flag, size, BADNODE)        
        typecmt = defined_data.find(TYPEINFO_CMT)
        if typecmt != None:
            self.update_counter(DEFINED_DATA + ':' + TYPEINFO_CMT)
            
            
    def import_description(self, description):
        """
        Processes the DESCRIPTION element.
        
        Args:
            description: DESCRIPTION XML element.
        """
        self.update_counter(DESCRIPTION)
        # TODO: import_description: decide what to do with DESCRIPTION
        # print description.text


    def import_enum(self, enum):
        """
        Processes an ENUM element by creating the enumeration.
        
        Args:
            enum: XML element containing the enumeration name and
                member data.
        """
        if self.options.DataTypes.checked == False:
            return
        name = self.get_attribute(enum, NAME)
        if self.has_attribute(enum,NAMESPACE):
            namespace = self.get_attribute(enum, NAMESPACE)
        if self.has_attribute(enum,SIZE):
            size = self.get_attribute_value(enum, SIZE)
        eid = idc.add_enum(BADNODE, name,
                           ida_bytes.hex_flag() | ida_bytes.dword_flag())
        self.update_counter(ENUM)
        regcmt = enum.find(REGULAR_CMT)
        if regcmt != None:
            idc.set_enum_cmt(eid, regcmt.text, False)
            self.update_counter(ENUM + ':' + REGULAR_CMT)
        rptcmt = enum.find(REPEATABLE_CMT)
        if rptcmt != None:
            idc.set_enum_cmt(eid, rptcmt.text, True)
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
        ida_enum.add_enum_member(eid, name, value)
        cid = idc.get_enum_member_by_name(name)
        self.update_counter(ENUM_ENTRY)
        regcmt = enum_entry.find(REGULAR_CMT)
        if regcmt != None:
            idc.set_enum_member_cmt(cid, regcmt.text, False);
            self.update_counter(ENUM_ENTRY + ':' + REGULAR_CMT)
        rptcmt = enum_entry.find(REPEATABLE_CMT)
        if rptcmt != None:
            idc.set_enum_member_cmt(cid, rptcmt.text, True);
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
        idc.add_enum_member(eid, name, value, bm)
        cid = idc.get_enum_member_by_name(name)
        self.update_counter(EQUATE)
        regcmt = equate.find(REGULAR_CMT) 
        if regcmt != None:
            idc.set_enum_member_cmt(cid, regcmt.text, False);
            self.update_counter(EQUATE + ':' + REGULAR_CMT)
        rptcmt = equate.find(REPEATABLE_CMT)
        if rptcmt != None:
            idc.set_enum_member_cmt(cid, rptcmt.text, True);
            self.update_counter(EQUATE + ':' + REPEATABLE_CMT)
    

    def import_equate_group(self, equate_group):
        """
        Processes EQUATE_GROUP as IDA enumeration type.
        
        Args:
            equate_group: XML element containing the group name and
                equate definitions.
        """
        if self.options.DataTypes.checked == False:
            return
        msg = EQUATE_GROUP
        name = ''
        if self.has_attribute(equate_group, NAME):
            name = self.get_attribute(equate_group, NAME)
        bf = ''
        if self.has_attribute(equate_group, BIT_FIELD):
            bf = self.get_attribute(equate_group, BIT_FIELD)
        eid = idc.add_enum(BADADDR, name, ida_bytes.hex_flag())
        idc.set_enum_bf(eid, (bf == 'yes'))
        self.update_counter(EQUATE_GROUP)
        regcmt = equate_group.find(REGULAR_CMT)
        if regcmt != None:
            idc.set_enum_cmt(eid, regcmt.text, False)
            self.update_counter(EQUATE_GROUP + ':' + REGULAR_CMT)
        rptcmt = equate_group.find(REPEATABLE_CMT)
        if rptcmt != None:
            idc.set_enum_cmt(eid, rptcmt.text, True)
            self.update_counter(EQUATE_GROUP + ':' + REPEATABLE_CMT)
        equates = equate_group.findall(EQUATE)
        for equate in equates:
            self.import_equate(equate,eid)
        bit_masks = equate_group.findall(BIT_MASK)
        for bit_mask in bit_masks:
            self.import_bit_mask(bit_mask, eid)
    

    def import_equate_reference(self, equate_reference):
        if (self.options.DataTypes.checked == False or
            self.options.EquateReferences.checked == False):
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
            cid = idc.get_enum_member_by_name(name)
        if cid == BADNODE:
            return
        eid = idc.get_enum_member_enum(cid)
        if eid == BADNODE:
            return
        idc.op_enum(addr, opnd, eid, 0)
        

    def import_function(self, function):
        """
        Creates a function using the FUNCTION attributes.
        
        Args:
            function: XML element containing the function address and
                attributes.
        """
        if self.options.Functions.checked == False:
            return
        try:
            entry_point = self.get_address(function, ENTRY_POINT)
            name = ''
            if self.has_attribute(function, NAME):
                name = self.get_attribute(function, NAME)
            libfunc = 'n'
            if self.has_attribute(function, LIBRARY_FUNCTION):
                libfunc = self.get_attribute(function, LIBRARY_FUNCTION)
            if idc.is_mapped(entry_point) == False:
                msg = ("import_function: address %X not enabled in database"
                       % entry_point)
                print msg
                return
            idc.add_func(entry_point, BADADDR)
            self.update_counter(FUNCTION)
            func = ida_funcs.get_func(entry_point)
            if libfunc == 'y':
                func.flags |= idc.FUNC_LIB
            ranges = function.findall(ADDRESS_RANGE)
            for addr_range in ranges:
                (start, end) = self.import_address_range(addr_range)
                ida_funcs.append_func_tail(func, start, end)
            # TODO: auto_wait is probably not needed...
            if AUTO_WAIT:
                ida_auto.auto_wait()
            regcmt = function.find(REGULAR_CMT)
            if regcmt != None:
                self.update_counter(FUNCTION + ':' + REGULAR_CMT)
                ida_funcs.set_func_cmt(func, regcmt.text, False)
            rptcmt = function.find(REPEATABLE_CMT)
            if rptcmt != None:
                self.update_counter(FUNCTION + ':' + REPEATABLE_CMT)
                ida_funcs.set_func_cmt(func, rptcmt.text, True)
            typecmt = function.find(TYPEINFO_CMT)
            if typecmt != None:
                self.update_counter(FUNCTION + ':' + TYPEINFO_CMT)
                # TODO: TYPECMTs
                #idc.SetType(entry_point, typecmt.text + ';')
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
        if self.options.DataTypes.checked == False:
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
        if self.options.Manual.checked == False:
            return
        addr = self.get_address(manual_instruction, ADDRESS)
        idc.set_manual_insn(addr, manual_instruction.text)
        self.update_counter(MANUAL_INSTRUCTION)
    

    def import_manual_operand(self, manual_operand):
        """
        Creates a manual operand at an address.
        
        Args:
            manual_operand: MANUAL_OPERAND XML element.
        """
        if self.options.Manual.checked == False:
            return
        addr = self.get_address(manual_operand, ADDRESS)
        op = self.get_attribute_value(manual_operand, OPERAND_INDEX)
        if idc.is_mapped(addr):
            ida_bytes.set_forced_operand(addr, op, manual_operand.text)
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
        ti = ida_nalt.opinfo_t()
        if self.is_pointer_type(datatype):
            flag = ida_bytes.dword_flag() | idc.FF_0OFF
            r = ida_nalt.refinfo_t()
            r.init(ida_nalt.get_reftype_by_size(4) | ida_nalt.REFINFO_NOBASE)
            ti.ri = r
        else:
            flag = self.get_datatype_flags(datatype, size)
        if flag == 0 and defer == True:
            self.deferred.append((member, sptr))
            return
        if flag == ida_bytes.enum_flag():
            t = idc.get_enum(datatype)
            ti.ec.tid = t
            ti.ec.serial = idc.get_enum_idx(t)
        if flag == ida_bytes.stru_flag():
            t = idc.get_struc_id(datatype)
            ti.tid = t
        error = ida_struct.add_struc_member(sptr, name, offset, flag, ti, size)
        mbr = ida_struct.get_member(sptr, offset)
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
            ida_struct.set_member_cmt(mbr, regcmt.text, False)
            self.update_counter(MEMBER + ':' + REGULAR_CMT)
        rptcmt = member.find(REPEATABLE_CMT)
        if rptcmt != None:
            ida_struct.set_member_cmt(mbr, rptcmt.text, True)
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
        binfilename += "/" + fname
        binfile = ida_idaapi.loader_input_t()
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
        Currently nothing is done with MEMORY_REFERENCEs.
        
        Args:
            memory_reference: MEMORY_REFERENCE XML element.
        """
        if self.options.MemoryReferences.checked == False:
            return
        # initialize implied attributes
        user = None
        op = None
        primary = None
        base_addr = None
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
        # TODO: import_memory_reference: store refs? maybe only user-defined?
        '''
        if user == 'y':
            #print "%08X %08X" % (addr, to_addr), op, primary
            pass
        '''
 
 
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

        s = ida_segment.segment_t()
        addrstr = self.get_attribute(memory_section, START_ADDR)
        seg_str = ''
        if '::' in addrstr:
            # overlay - skip for now
            print '  ** Overlayed memory block %s skipped **  ' % name
            msg  = 'Overlayed memory block %s skipped!' % name
            msg += "\n\nXML Import does not currently support"
            msg += "\noverlayed memory blocks."
            idc.warning(msg)
            return
        elif ':' in addrstr:
            [seg_str, offset_str] = str.split(addrstr,':')
            offset = int(offset_str, 16)
            if self.is_int(seg_str):
                base = int(seg_str, 16)
                sel = ida_segment.setup_selector(base)
                start = self.get_address(memory_section, START_ADDR)
            else:
                raise MultipleAddressSpacesNotSupported
                return
        else:
            sel = ida_segment.allocate_selector(0)
            start = self.get_address(memory_section, START_ADDR)
        
        s.sel = sel
        s.start_ea = start
        s.end_ea = start+length
        s.bitness = self.addr_mode
        
        perms = ''
        if self.has_attribute(memory_section, PERMISSIONS):
            perms = self.get_attribute(memory_section, PERMISSIONS)
        s.perm = 0
        if 'r' in perms: s.perm |= ida_segment.SEGPERM_READ
        if 'w' in perms: s.perm |= ida_segment.SEGPERM_WRITE
        if 'x' in perms: s.perm |= ida_segment.SEGPERM_EXEC
        ok = ida_segment.add_segm_ex(s, name, "",
                                idc.ADDSEG_OR_DIE | idc.ADDSEG_QUIET)
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
            if str.lower(address_model) == '16-bit':
                self.addr_mode = 0
                idc.set_flag(idc.INF_LFLAGS, idc.LFLG_PC_FLAT, 0)
                idc.set_flag(idc.INF_LFLAGS, idc.LFLG_64BIT, 0)
            elif str.lower(address_model) == '32-bit':
                self.addr_mode = 1
                idc.set_flag(idc.INF_LFLAGS, idc.LFLG_PC_FLAT, 1)
                idc.set_flag(idc.INF_LFLAGS, idc.LFLG_64BIT, 0)
            elif str.lower(address_model) == '64-bit':
                self.addr_mode = 2
                idc.set_flag(idc.INF_LFLAGS, idc.LFLG_PC_FLAT, 1)
                idc.set_flag(idc.INF_LFLAGS, idc.LFLG_64BIT, 1)
        

    def import_program(self, program):
        """
        Processes the PROGRAM element.
        
        Args:
            program: PROGRAM XML element.
        """
        self.update_status(PROGRAM)
        self.update_counter(PROGRAM)
        if self.plugin:
            return
        name = self.get_attribute(program, NAME)
        if self.has_attribute(program, EXE_PATH):
            epath = self.get_attribute(program, EXE_PATH)
            idc.set_root_filename(epath)
        else:
            idc.set_root_filename(name)
        if self.has_attribute(program, EXE_FORMAT):
            eformat = self.get_attribute(program, EXE_FORMAT)
            RootNode = ida_netnode.netnode('Root Node')
            RootNode.supset(ida_nalt.RIDX_FILE_FORMAT_NAME, eformat)
        if self.has_attribute(program, IMAGE_BASE):
            base = self.get_attribute_value(program, IMAGE_BASE)
            ida_nalt.set_imagebase(base)
        if self.has_attribute(program, INPUT_MD5):
            input_md5 = self.get_attribute(program, INPUT_MD5)
            # store original md5 in a special netnode
            md5 = ida_netnode.netnode(INPUT_MD5, len(INPUT_MD5), True)
            md5.supset(ida_nalt.RIDX_MD5, input_md5)

        
    def import_program_entry_point(self, program_entry_point):
        """
        Defines a program entry point.
        
        Args:
            program_entry_point: PROGRAM_ENTRY_POINT XML element.
                Contains the entry point address.
        """
        if self.options.EntryPoints.checked == False:
            return
        addr = self.get_address(program_entry_point, ADDRESS)
        idc.add_entry(addr, addr, "", True)
        self.update_counter(PROGRAM_ENTRY_POINT)
    

    def import_register_value_range(self, register_value_range):
        """
        Defines the address range for a register value.
        
        Args:
            register_value_range: REGISTER_VALUE_RANGE XML element.
                Contains the register, value, start address and range length.
        """
        if self.options.RegisterValues.checked == False:
            return
        self.update_counter(REGISTER_VALUE_RANGE)
        reg = self.get_attribute(register_value_range, REGISTER)
        if reg == 'cs': return
        value = self.get_attribute_value(register_value_range, VALUE)
        addr = self.get_address(register_value_range, START_ADDRESS)
        length = self.get_attribute_value(register_value_range, LENGTH)
        r = ida_idp.str2reg(reg)
        if r >= ida_idp.ph_get_reg_first_sreg() and r <= ida_idp.ph_get_reg_last_sreg():
            ida_segregs.split_sreg_range(addr, r, value, idc.SR_user, True)
    

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
        idc.define_local_var(func.startEA, func.endEA, reg, name)
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
        self.update_counter(STACK_REFERENCE)
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
        sf = ida_frame.get_frame(func)
        if name != '':
            ida_struct.set_member_name(sf, offset, name)
    

    def import_structure(self, structure):
        """
        Adds a structure.
        
        Args:
            structure: STRUCTURE XML element.
                Contains the STRUCTURE attributes and child elements.
        """
        if self.options.DataTypes.checked == False:
            return
        name = self.get_attribute(structure, NAME)
        dtyp = idc.get_struc_id(name)
        if dtyp != BADNODE:
            # duplicate name, try adding name space
            if self.has_attribute(structure, NAMESPACE) == False:
                return
            namespace = self.get_attribute(structure, NAMESPACE)
            name = namespace + '__' + name
            name.replace('/','_')
            name.replace('.','_')
            dtyp = idc.get_struc_id(name)
            # skip if still duplicate (could add sequence #)
            if dtyp != BADNODE:
                return
        size = 0
        if self.has_attribute(structure, SIZE):
            size = self.get_attribute_value(structure, SIZE)
        if self.has_attribute(structure, VARIABLE_LENGTH):
            vl = self.get_attribute_value(structure, VARIABLE_LENGTH)
            isVariableLength = vl == 'y'        
        sid = idc.add_struc(-1, name, 0)
        sptr = ida_struct.get_struc(sid)
        self.update_counter(STRUCTURE)
        self.import_cmts(structure, sid, STRUCTURE)
        self.import_members(structure, sptr)
        if idc.get_struc_size(sptr) < size:
            t = ida_nalt.opinfo_t()
            ida_struct.add_struc_member(sptr,"",size-1,ida_bytes.byte_flag(),t,1)
        

    def import_symbol(self, symbol):
        """
        Adds a symbol name at the specified address.
        
        Args:
            symbol: SYMBOL XML element.
                Contains symbol name and address. Optionally includes
                type and mangled symbol.
        """
        if self.options.Symbols.checked == False:
            return
        addr = self.get_address(symbol, ADDRESS)
        name = self.get_attribute(symbol, NAME)
        if self.has_attribute(symbol, MANGLED):
            name = self.get_attribute(symbol, MANGLED)
        flag = idc.SN_NOWARN
        if self.has_attribute(symbol, TYPE):
            typ = self.get_attribute(symbol, TYPE)
            if  typ == 'local': flag |= idc.SN_LOCAL
        idc.set_name(addr, name, flag)
        self.update_counter(SYMBOL)
    

    def import_typedef(self, type_def):
        # import_typedef: NOT IMPLEMENTED
        if self.options.DataTypes.checked == False:
            return
        self.update_counter(TYPE_DEF)
        

    def import_union(self, union):
        """
        Adds a union datatype.
        
        Args:
            union: UNION XML element.
                Contains UNION attributes and child elements.
        """
        if self.options.DataTypes.checked == False:
            return
        name = self.get_attribute(union, NAME)
        dtyp = idc.get_struc_id(name)
        if dtyp != BADNODE:
            # duplicate name, try adding name space
            if self.has_attribute(union, NAMESPACE) == False:
                return
            namespace = self.get_attribute(union, NAMESPACE)
            name = namespace + '__' + name
            name.replace('/','_')
            name.replace('.','_')
            dtyp = idc.get_struc_id(name)
            # skip if still duplicate (could add sequence #)
            if dtyp != BADNODE:
                return
        size = 0
        if self.has_attribute(union, SIZE):
            size = self.get_attribute_value(union, SIZE)
        sid = idc.add_struc(BADADDR, name, True)
        sptr = ida_struct.get_struc(sid)
        self.update_counter(UNION)
        self.import_cmts(union, sid, UNION)
        self.import_members(union, sptr)
        if idc.get_struc_size(sptr) < size:
            t = ida_nalt.opinfo_t()
            ida_struct.add_struc_member(sptr,"", size-1, ida_bytes.byte_flag(), t, 1)
            

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
    

# Global constants
# mangled name inhibit flags are not currently exposed in python api
# inhibit flags for symbol names
# DEMANGLE_FORM (MNG_SHORT_FORM | MNG_NOBASEDT | MNG_NOCALLC | MNG_NOCSVOL)
DEMANGLED_FORM = 0x0ea3ffe7
# inhibit flags for typeinfo cmts
# DEMANGLED_TYPEINFO (MNG_LONG_FORM)
DEMANGLED_TYPEINFO = 0x06400007

        
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
