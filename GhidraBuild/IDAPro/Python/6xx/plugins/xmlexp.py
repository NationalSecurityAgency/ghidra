#---------------------------------------------------------------------
# xmlexp.py - IDA XML Exporter plugin
#---------------------------------------------------------------------
"""
Plugin for IDA which exports a XML PROGRAM document file from a database.
"""

import idaapi
import idautils
import idc
import datetime
import sys
import time


XML_EXPORTER_VERSION = "4.1.2"
BASELINE_IDA_VERSION = 620
IDA_SDK_VERSION = idaapi.IDA_SDK_VERSION
BADADDR = idaapi.BADADDR


class XmlExporterPlugin(idaapi.plugin_t):
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
        if IDA_SDK_VERSION < BASELINE_IDA_VERSION:
            idaapi.msg('\nXML Exporter plugin (xmlexp.py) not supported ' +
                        'by this version of IDA\n')
            return idaapi.PLUGIN_SKIP
        return idaapi.PLUGIN_OK


    def run(self, arg):
        """
        run function for XML Exporter plugin.
        
        Args:
            arg: Integer, non-zero value enables auto-run feature for
                IDA batch (no gui) processing mode. Default is 0.
        """
        xml = XmlExporter(arg)
        try:
            try:
                xml.export_xml()
            except Cancelled:
                idaapi.hide_wait_box()
                msg = "XML Export cancelled!"
                print "\n" + msg
                idaapi.warning(msg)
            except:
                idaapi.hide_wait_box()
                msg = "***** Exception occurred: XML Exporter failed! *****"
                print "\n" + msg + "\n", sys.exc_type, sys.exc_value
                idaapi.warning(msg)
        finally:
            xml.cleanup()
            idaapi.setStat(xml.state)


    def term(self):
        pass


def PLUGIN_ENTRY():
    return XmlExporterPlugin()


class Cancelled(Exception):
    pass


class FileError(Exception):
    pass


class XmlExporter:
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
        self.debug = False
        self.autorun = False
        if arg != 0:
            self.autorun = True
        self.state = idaapi.setStat(idaapi.st_Work)
        self.indent_level = 0
        self.seg_addr = False
        self.has_overlays = False
        self.hexrays = False
        self.options = None
        self.xmlfile = 0
        self.elements = {}
        self.counters = []
        self.tags = []
        
        # initialize class variables from database
        self.inf = idaapi.get_inf_structure()
        self.min_ea = self.inf.minEA
        self.max_ea = self.inf.maxEA
        self.cbsize = (idaapi.ph_get_cnbits()+7)/8
        self.processor = str.upper(idaapi.get_idp_name())
        self.batch = idaapi.cvar.batch


    def export_xml(self):
        """
        Exports the IDA database to a XML PROGRAM document file.
        """
        self.check_and_load_decompiler()
        self.display_xml_exporter_version()
        self.display_database_info()
        
        self.get_options()
    
        if (self.autorun == True):
            (self.filename, ext) = os.path.splitext(idaapi.cvar.database_idb)
            self.filename += ".xml"
        else:
            self.filename=idaapi.askfile_c(1, "*.xml",
                                           "Enter name of export xml file:")
            
        if self.filename == None or len(self.filename) == 0:
            raise Cancelled
        self.xmlfile = self.open_file(self.filename, "w")
        
        idaapi.show_wait_box("Exporting XML <PROGRAM> document ....")
        idaapi.msg("\n------------------------------------------------" +
                   "-----------")
        idaapi.msg("\nExporting XML <PROGRAM> document ....")
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
        
        idaapi.msg('\n%35s' % 'Total ')
        self.display_cpu_time(begin)
        idaapi.hide_wait_box()  
        self.display_summary()


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
        if self.batch == 0 or IDA_SDK_VERSION < 660:
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
                idaapi.load_plugin(plugin)
                self.hexrays = idaapi.init_hexrays_plugin()
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
        elif ord(ch) > 0x7F: return '&#x' + format((ord(ch),"x")) + ";"
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
        for addr in idautils.Heads(seg.startEA, seg.endEA):
            if idaapi.hasValue(idaapi.getFlags(addr)) == True:
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
            mname = idaapi.get_member_name(member.id)
            if mname != None and len(mname) > 0: 
                if mname != " s" and mname != " r":
                    return True
        return False


    def cleanup(self):
        """
        Frees memory and closes message box and XML file at termination.
        """
        if self.options != None:
            self.options.Free()
        idaapi.hide_wait_box()
        self.close_xmlfile()


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
            idaapi.msg(message)


    def display_cpu_time(self, start):
        """
        Displays the elapsed CPU time since the start time.
        
        Args:
            start: Floating-point value representing start time in seconds.
        """
        idaapi.msg('CPU time: %6.4f' % (time.clock() - start))
        

    def display_database_info(self):
        """
        Displays information about the database in IDA output window.
        """
        idaapi.msg('\nProcessor Module: ' + self.processor)


    def display_message(self, message):
        """
        Displays an indented message to IDA output window.
        
        Args:
            message: String containing message to display.
        """
        line = "    " + message
        idaapi.msg('\n%-35s' % line)
        

    def display_summary(self):
        """
        Displays summary of exported PROGRAM document in IDA output window.
        """
        fileline = '\nFile: %s' % self.filename
        summary  = "\n--------------------------------------"
        total = 0
        tags = self.tags[:]
        for tag in tags:
            count = self.counters[self.elements[tag]]
            summary += "\n%-22s %8d" % (tag, count)
            total += count
        summary += ("\n%-22s %8d" % ("Total XML Elements:",total))
        idaapi.msg(summary)
        idaapi.msg("\n\nDatabase exported to: %s" % self.filename)
        idaapi.msg("\n--------------------------------------------" +
                   "---------------")
        if self.autorun == False:
            frmt  = "TITLE XML Export Successful!\n"
            frmt += "ICON INFO\n"
            frmt += "AUTOHIDE NONE\n"
            frmt += "HIDECANCEL\n"
            details = '\nSee output window for details...'
            idaapi.info("%s" % (frmt + fileline + details))


    def display_xml_exporter_version(self):
        """
        Displays XML Exporter plugin version info in IDA output window.
        """
        plugin = idaapi.idadir(idaapi.PLG_SUBDIR) + '/xmlexp.py'
        plugintime = time.localtime(os.path.getmtime(plugin))
        # ts = time.strftime('%Y-%m-%d %H:%M:%S', plugintime)
        ts = time.strftime('%b %d %Y %H:%M:%S', plugintime)
        version = "\nXML Exporter Version " + XML_EXPORTER_VERSION
        version += " : SDK " + str(IDA_SDK_VERSION)
        version += " : Python : "+ ts + '\n'
        idaapi.msg(version)
    

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
        name = idaapi.get_bmask_name(eid, mask)
        if name == None:
            return
        self.start_element(BIT_MASK)
        self.write_attribute(NAME, name)
        self.write_numeric_attribute(VALUE, mask)
        regcmt = idaapi.get_bmask_cmt(eid, mask, False)
        rptcmt = idaapi.get_bmask_cmt(eid, mask, True)
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
        if IDA_SDK_VERSION > 690:
            import ida_moves
            import ida_pro
        for slot in range(1,1025):
            if IDA_SDK_VERSION <= 690:
                address = idc.GetMarkedPos(slot)
                description = idc.GetMarkComment(slot)
            else:
                curloc = ida_moves.curloc()
                intp = ida_pro.int_pointer()
                intp.assign(slot)
                address = curloc.markedpos(intp)
                description = curloc.markdesc(slot)
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
        if IDA_SDK_VERSION < 660 or self.hexrays == False:
            return
        functions = idautils.Functions()
        if functions == None:
            return
        for addr in functions:
            try:
                if idaapi.is_spec_ea(addr):
                    continue
                ccmts = idaapi.restore_user_cmts(addr)
                if ccmts == None:
                    continue
                p = idaapi.user_cmts_begin(ccmts)
                while p != idaapi.user_cmts_end(ccmts):
                    cmk = idaapi.user_cmts_first(p)
                    cmv = idaapi.user_cmts_second(p)
                    if cmk.itp < (idaapi.ITP_COLON+1):
                        self.export_comment(cmk.ea, "end-of-line", cmv.c_str())
                    else:
                        self.export_comment(cmk.ea, "pre", cmv.c_str())
                    p=idaapi.user_cmts_next(p)
                idaapi.user_cmts_free(ccmts)
            except:
                continue


    def export_code(self):
        """
        Exports the address ranges of code sequences as CODE_BLOCK(s)
        with START and END address attributes.
        """
        addr = self.min_ea
        if idaapi.isCode(idaapi.getFlags(addr)) == False:
            addr = idaapi.nextthat(addr, self.max_ea, idaapi.isCode)
        if (addr == BADADDR):
            return
        self.update_status(CODE)
        timer = time.clock()
        data = idaapi.nextthat(addr, self.inf.maxEA, isData)
        unknown = idaapi.next_unknown(addr, self.inf.maxEA)
        self.start_element(CODE, True)
        while (addr != BADADDR):
            start = addr
            end = min(data, unknown)
            if (end == BADADDR):
                if (idaapi.getseg(start).endEA < self.inf.maxEA):
                    codeend = idaapi.getseg(start).endEA - 1
                    addr = idaapi.getseg(idaapi.nextaddr(codeend)).startEA
                    if idaapi.isCode(idaapi.getFlags(addr)) == False:
                        addr = idaapi.nextthat(addr, self.max_ea,
                                               idaapi.isCode)
                else:
                    codeend = self.max_ea - 1
                    addr = BADADDR
            else:
                if (idaapi.getseg(start).endEA < end):
                    codeend = idaapi.getseg(start).endEA - 1
                    addr = idaapi.getseg(idaapi.nextaddr(codeend)).startEA
                    if idaapi.isCode(idaapi.getFlags(addr)) == False:
                        addr = idaapi.nextthat(addr, self.max_ea,
                                               idaapi.isCode)
                else:
                    codeend = idaapi.get_item_end(idaapi.prevthat(end,
                                                start, idaapi.isCode)) - 1
                    addr = idaapi.nextthat(end, self.max_ea,
                                           idaapi.isCode)
                if (data < addr):
                    data = idaapi.nextthat(addr, self.max_ea,
                                           idaapi.isData)
                if (unknown < addr):
                    unknown = idaapi.next_unknown(addr, self.max_ea)
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
        cmt_text = idaapi.tag_remove(cmt + ' ')
        self.write_text(cmt_text)
        self.end_element(COMMENT, False)


    def export_comments(self):
        """
        Exports all comments in the IDA database as <COMMENT> elements.
        """
        addr = self.min_ea
        if idaapi.has_cmt(idaapi.getFlags(addr)) == False:
            addr = idaapi.nextthat(addr, self.max_ea, idaapi.has_cmt)
        if (addr == BADADDR):
            return
        self.update_status(COMMENTS)
        timer = time.clock()
        self.start_element(COMMENTS, True)
        while (addr != BADADDR):
            cmt = idaapi.get_cmt(addr, False)
            if (cmt != None):
                self.export_comment(addr, "end-of-line", cmt)
            cmt = idaapi.get_cmt(addr, True)
            if (cmt != None):
                self.export_comment(addr, "repeatable", cmt)
            addr = idaapi.nextthat(addr, self.max_ea, idaapi.has_cmt)
        addr = self.min_ea
        if idaapi.hasExtra(idaapi.getFlags(addr)) == False:
            addr = idaapi.nextthat(addr, self.max_ea, idaapi.hasExtra)
        while (addr != BADADDR):
            if IDA_SDK_VERSION < 640:
                extra = idaapi.ExtraGet(addr, idaapi.E_PREV)
            else:
                extra = idaapi.get_extra_cmt(addr, idaapi.E_PREV)
            if (extra != None):
                self.export_extra_comment(addr, "pre", idaapi.E_PREV)
            if IDA_SDK_VERSION < 640:
                extra = idaapi.ExtraGet(addr, idaapi.E_NEXT)
            else:
                extra = idaapi.get_extra_cmt(addr, idaapi.E_NEXT)
            if (extra != None):
                self.export_extra_comment(addr, "post", idaapi.E_NEXT)
            addr = idaapi.nextthat(addr, self.max_ea, idaapi.hasExtra)
        self.export_c_comments()
        self.end_element(COMMENTS)
        self.display_cpu_time(timer)


    def export_data(self):
        """
        Exports the data items in the database as <DEFINED_DATA> elements.
        """
        addr = self.min_ea
        if idaapi.isData(idaapi.getFlags(addr)) == False:
            addr = idaapi.nextthat(addr, self.max_ea, idaapi.isData)
        if (addr == BADADDR):
            return
        timer = time.clock()
        self.update_status(DATA)
        self.start_element(DATA, True)
        while (addr != BADADDR):
            f = idaapi.getFlags(addr)
            if idaapi.isAlign(f) == True:
                addr = idaapi.nextthat(addr, self.max_ea, idaapi.isData)
                continue
            dtype = self.get_datatype(addr)
            size = idaapi.get_item_size(addr)
            ti = idaapi.opinfo_t()
            if IDA_SDK_VERSION < 640:
                msize = idaapi.get_data_elsize(addr, f, ti)
            else:
                msize = idaapi.get_data_type_size(f, ti)
            if idaapi.isStruct(f) == True:
                s = idaapi.get_struc_id(dtype)
                msize = idaapi.get_struc_size(s)
                if msize == 0:
                    msize = 1
            if idaapi.isASCII(f) == False and size != msize:
                dtype = "%s[%d]" % (dtype, size/msize)
            self.start_element(DEFINED_DATA)
            self.write_address_attribute(ADDRESS, addr)
            self.write_attribute(DATATYPE, dtype)
            self.write_numeric_attribute(SIZE, size*self.cbsize)
            #TODO consider using GetTrueNameEx and Demangle
            demangled = idaapi.get_demangled_name(BADADDR, addr,
                            DEMANGLED_TYPEINFO, self.inf.demnames, True)
            outbuf = ''
            if IDA_SDK_VERSION < 660:
                outbuf = idaapi.print_type(addr, False)
            else:
                outbuf = idaapi.print_type(addr, outbuf)
            if demangled == "'string'":
                demangled == None
            has_typeinfo = demangled != None or (outbuf != None and
                                                len(outbuf) > 0)
            #TODO export_data: add DISPLAY_SETTINGS
            self.close_tag(has_typeinfo)
            if has_typeinfo == True:
                if demangled != None:
                    self.export_typeinfo_cmt(demangled)
                else:
                    #TODO export_data - check this
                    self.export_typeinfo_cmt(outbuf[:-1])
                self.end_element(DEFINED_DATA)
            addr = idaapi.nextthat(addr, self.max_ea, idaapi.isData)
        self.end_element(DATA)
        self.display_cpu_time(timer)
        

    def export_datatypes(self):
        """
        Exports the structures and enums in IDA database.
        """
        # skip if no structures/unions to export
        if idaapi.get_struc_qty() == 0: return
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

        This function can only be called by IDA versions newer than 6.3 
        
        Args:
            cid: Integer representing id of enum member
            bf: Boolean indicates if a bitfield
            mask: Integer representing bitmask if bitfield
            radix: Integer representing numeric display format
            signness: Boolean indicating if signed value 
        """
        if IDA_SDK_VERSION < 640:
            return
        cname = idaapi.get_const_name(cid)
        if cname == None or len(cname) == 0:
            return
        regcmt = idaapi.get_const_cmt(cid, False)
        rptcmt = idaapi.get_const_cmt(cid, True)
        has_comment =  regcmt != None or rptcmt != None
        self.start_element(ENUM_ENTRY)
        self.write_attribute(NAME, cname)
        value = idaapi.get_const_value(cid)
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


    def export_enum_member_legacy(self, cid, bf, mask, radix, signness):
        """
        Exports a member of an enum.
        
        This function can only be called by IDA versions older than 6.3 

        Args:
            cid: Integer representing id of enum member
            bf: Boolean indicates if a bitfield
            mask: Integer representing bitmask if bitfield
            radix: Integer representing numeric display format
            signness: Boolean indicating if signed value 
        """
        if IDA_SDK_VERSION > 630:
            return
        cname = idaapi.get_enum_member_name(cid)
        if cname == None or len(cname) == 0:
            return
        regcmt = idaapi.get_enum_member_cmt(cid, False)
        rptcmt = idaapi.get_enum_member_cmt(cid, True)
        has_comment =  regcmt != None or rptcmt != None
        self.start_element(ENUM_ENTRY)
        self.write_attribute(NAME, cname)
        value = idaapi.get_enum_member_value(cid)
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
        if IDA_SDK_VERSION < 640:
            return
        mask=0xFFFFFFFF
        if bf == True:
            mask = idaapi.get_first_bmask(eid)
        first = True
        for n in range(idaapi.get_enum_size(eid)):
            if (first == True):
                value = idaapi.get_first_const(eid, mask)
                first = False
            else:
                value = idaapi.get_next_const(eid, value, mask)
            (cid, serial) = idaapi.get_first_serial_const(eid, value, mask)
            main_cid = cid
            while cid != idaapi.BADNODE:
                self.export_enum_member(cid, bf, mask,
                                   idaapi.getRadix(eflags, 0),
                                   self.is_signed_data(eflags))
                last_value = idaapi.get_last_const(eid, mask)
                if value == last_value:
                    # BIT_MASK not currently supported for ENUM
                    #self.export_bitmask(eid, mask)
                    mask = idaapi.get_next_bmask(eid, mask)
                    first = True
                (cid, serial) = idaapi.get_next_serial_const(main_cid)


    def export_enum_members_legacy(self, eid, bf, eflags):
        """
        Exports the members of an enum.
        
        This function can only be called by IDA versions older than 6.3 
        
        Args:
            eid: Integer representing id of enum
            bf: Boolean indicates if a bitfield
            eflags: Integer representing the enum flags
        """
        if IDA_SDK_VERSION > 630:
            return
        mask=0xFFFFFFFF
        if bf == True:
            mask = idaapi.get_first_bmask(eid)
        first = True
        for n in range(idaapi.get_enum_size(eid)):
            if (first == True):
                value = idaapi.get_first_enum_member(eid, mask)
                first = False
            else:
                value = idaapi.get_next_enum_member(eid, value, mask)
            (cid, serial) = idaapi.get_first_serial_enum_member(eid, value, mask)
            main_cid = cid
            while cid != idaapi.BADNODE:
                self.export_enum_member_legacy(cid, bf, mask,
                                   idaapi.getRadix(eflags, 0),
                                   self.is_signed_data(eflags))
                last_value = idaapi.get_last_enum_member(eid, mask)
                if value == last_value:
                    # BIT_MASK not currently supported for ENUM
                    #self.export_bitmask(eid, mask)
                    mask = idaapi.get_next_bmask(eid, mask)
                    first = True
                (cid, serial) = idaapi.get_next_serial_enum_member(main_cid)


    def export_enum_reference(self, addr, op):
        """
        Exports the enum reference for an operand at an address.
        
        Args:
            addr: Integer representing the instruction address.
            op: Integer representing the operand index (0-based)
        """
        (eid, serial) = idaapi.get_enum_id(addr, op)
        idaapi.decode_insn(addr)
        value = idaapi.cmd.Operands[op].value
        cid = idaapi.BADNODE
        last = idaapi.get_last_bmask(eid)
        if idaapi.is_bf(eid) == True:
            last = idaapi.get_last_bmask(eid)
            mask = idaapi.get_first_bmask(eid)
            while  (cid == idaapi.BADNODE):
                if IDA_SDK_VERSION < 640:
                    cid = idaapi.get_enum_member(eid, (value & mask), 0, mask)
                else:
                    cid = idaapi.get_const(eid, (value & mask), 0, mask)
                if cid != idaapi.BADNODE or mask == last:
                    break
                mask = idaapi.get_next_bmask(eid, mask)
        else:
            if IDA_SDK_VERSION < 640:
                cid = idaapi.get_enum_member(eid, value, 0, last)
            else:
               cid = idaapi.get_const(eid, value, 0, last)
        if (cid == idaapi.BADNODE):
            return
        self.start_element(EQUATE_REFERENCE)
        self.write_address_attribute(ADDRESS, addr)
        self.write_numeric_attribute(OPERAND_INDEX, op, 10)
        if IDA_SDK_VERSION < 640:
            self.write_numeric_attribute(VALUE, idaapi.get_enum_member_value(cid))
            cname = idaapi.get_enum_member_name(cid)
        else:
            self.write_numeric_attribute(VALUE, idaapi.get_const_value(cid))
            cname = idaapi.get_const_name(cid)
        if cname != None and len(cname) > 0:
            self.write_attribute(NAME, cname)
        # BIT_MASK feature not currently supported
        #if idaapi.is_bf(eid) == True:
        #    self.write_numeric_attribute("BIT_MASK", mask);
        self.close_tag()
        

    def export_enum_references(self, addr):
        """
        Finds and exports enum references at an address.
        
        Args:
            addr: Integer representing the instruction address.
        """
        f = idaapi.getFlags(addr)
        for op in range(2):
            if idaapi.isEnum(f, op) == True:
                self.export_enum_reference(addr, op)
                

    def export_enums(self):
        """
        Exports enumerations.
        """
        num_enums = idaapi.get_enum_qty()
        if (num_enums == 0):
            return
        for i in range(num_enums):
            self.start_element(ENUM)
            eid = idaapi.getn_enum(i)
            ename = idaapi.get_enum_name(eid)
            if (ename == None or len(ename) == 0):
                continue
            self.write_attribute(NAME, ename)
            ewidth = idaapi.get_enum_width(eid)
            if ewidth != 0 and ewidth <= 7:
                self.write_numeric_attribute(SIZE, 1 << (ewidth-1), 10)
            eflags = idaapi.get_enum_flag(eid)
            bf = idaapi.is_bf(eid)
            # BIT_FIELD attribute not supported for ENUM
            #if bf == True:
            #    self.write_attribute(BIT_FIELD, "yes")
            regcmt = idaapi.get_enum_cmt(eid, False)
            rptcmt = idaapi.get_enum_cmt(eid, True)
            has_children = ((idaapi.get_enum_size(eid) > 0) or
                            (regcmt != None) or (rptcmt != None) or
                            (idaapi.getRadix(eflags, 0) != 16) or
                            (self.is_signed_data(eflags) == True))
            self.close_tag(has_children)
            if (idaapi.getRadix(eflags, 0) != 16 or
                self.is_signed_data(eflags) == True):
                self.start_element(DISPLAY_SETTINGS)
                if idaapi.getRadix(eflags, 0) != 16:
                    self.write_attribute(FORMAT, self.get_format(eflags))
                if self.is_signed_data(eflags) == True:
                    self.write_attribute(SIGNED, "yes")
                self.close_tag()
            if regcmt != None:
                self.export_regular_cmt(regcmt)
            if rptcmt != None:
                self.export_repeatable_cmt(rptcmt)
            if IDA_SDK_VERSION < 640:
                self.export_enum_members_legacy(eid, bf, eflags)
            else:
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
        if IDA_SDK_VERSION < 640:
            nextline = idaapi.ExtraGet(addr, extra)
        else:
            nextline = idaapi.get_extra_cmt(addr, extra)
        while (nextline != None):
            # workaround for tag_remove bug is to add space
            cmt += idaapi.tag_remove(nextline + ' ')
            extra += 1
            if IDA_SDK_VERSION < 640:
                nextline = idaapi.ExtraGet(addr, extra)
            else:
                nextline = idaapi.get_extra_cmt(addr, extra)
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
            function = idaapi.get_func(addr)
            if idaapi.is_spec_ea(function.startEA) == True:
                continue
            self.start_element(FUNCTION)
            self.write_address_attribute(ENTRY_POINT, function.startEA)
            if idaapi.has_user_name(idaapi.getFlags(addr)) == True:
                name = self.get_symbol_name(addr)
                if name != None and len(name) > 0:
                    self.write_attribute(NAME, name)
            if function.flags & idaapi.FUNC_LIB != 0:
                self.write_attribute(LIBRARY_FUNCTION, "y")
            self.close_tag(True)
            fchunks = idautils.Chunks(addr)
            for (startEA, endEA) in fchunks:
                self.start_element(ADDRESS_RANGE)
                self.write_address_attribute(START, startEA)
                self.write_address_attribute(END, endEA-1)
                self.close_tag()
            regcmt = idaapi.get_func_cmt(function, False)
            if regcmt != None:
                self.export_regular_cmt(regcmt)
            rptcmt = idaapi.get_func_cmt(function, True)
            if rptcmt != None:
                self.export_repeatable_cmt(rptcmt)
            demangled = idaapi.get_demangled_name(BADADDR, addr,
                                            DEMANGLED_TYPEINFO,
                                            self.inf.demnames, True)
            if demangled != None and demangled == "'string'":
                demangled = None
            outbuf = ''
            if IDA_SDK_VERSION < 660:
                outbuf = idaapi.print_type(addr, False)
            else:
                outbuf = idaapi.print_type(addr, outbuf)
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
        text = idaapi.get_manual_insn(addr)
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
        for op in range(idaapi.UA_MAXOP):
            if idaapi.is_forced_operand(addr, op) == True:
                text = idaapi.get_forced_operand(addr, op)
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
            f = idaapi.getFlags(addr)
            if self.options.MemoryReferences.checked == True:
                if idaapi.hasRef(f) == True:
                    self.export_user_memory_reference(addr)
                if idaapi.isOff(f, idaapi.OPND_ALL) == True:
                    self.export_memory_references(addr)
            if (self.options.Functions.checked == True and
               self.options.StackReferences.checked == True and
               idaapi.isStkvar(f, idaapi.OPND_ALL) == True):
               self.export_stack_reference(addr)
            if (self.options.DataTypes.checked == True and
                    idaapi.isEnum(f, idaapi.OPND_ALL) == True):
                self.export_enum_references(addr)
            if self.options.Manual.checked == True:
                if idaapi.isFop(f, idaapi.OPND_ALL)   == True:
                    self.export_manual_operand(addr)
                if idaapi.is_manual_insn(addr) == True:
                    self.export_manual_instruction(addr)
            addr = idaapi.next_head(addr, self.max_ea)
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
            mname = idaapi.get_member_name(m.id)
            if len(mname) > 0:
                self.write_attribute(NAME, mname)
            dtype = self.get_member_type(m)
            if idaapi.is_varmember(m) == True:
                msize = 0
                size  = 0
            else:
                mtibuf = idaapi.opinfo_t()
                mti = idaapi.retrieve_member_info(m, mtibuf)
                if IDA_SDK_VERSION < 640:
                    msize = idaapi.get_type_size0(None, dtype)
                    if msize == None or msize == 0:
                        msize = idaapi.get_member_size(m)
                else:
                    msize = idaapi.get_data_type_size(m.flag, mtibuf)
                size = idaapi.get_member_size(m)
                osize = size
                if size < msize: size = msize
            if (size != msize):
                arraytype = self.get_member_type(m)
                dtype = "%s[%d]" % (arraytype, size/msize)
            self.write_attribute(DATATYPE, dtype)
            self.write_numeric_attribute(SIZE, size*self.cbsize)
            regcmt = idaapi.get_member_cmt(m.id, False)
            rptcmt = idaapi.get_member_cmt(m.id, True)
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
            has_val = idaapi.hasValue(idaapi.getFlags(addr))
            if has_val == True:
                length += self.cbsize
            next_address = idaapi.nextaddr(addr)
            if ((has_val == False) or (next_address != addr+1) or
                    (next_address == end)):
                if length > 0:
                    offset = binfile.tell()
                    idaapi.base2file(binfile.get_fp(), offset, startaddr,
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
        nsegs = idaapi.get_segm_qty()
        if (nsegs == 0):
            return
        self.update_status(MEMORY_MAP)
        timer = time.clock();
        binfilename = ''
        if (self.options.MemoryContent.checked == True):
            (binfilename, ext) = os.path.splitext(self.filename)
            binfilename += ".bytes"
            self.binfile = idaapi.qfile_t()
            self.binfile.open(binfilename,'wb');
        self.start_element(MEMORY_MAP, True)
        for i in range(nsegs):
            self.export_memory_section(idaapi.getnseg(i), binfilename)
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
        f = idaapi.getFlags(addr)
        ri = idaapi.refinfo_t()
        if idaapi.get_refinfo(addr, op, ri) == 1: 
            if ri.target != BADADDR:
                target = ri.target
            elif idaapi.isCode(f) == True:
                idaapi.decode_insn(addr)
                target = idaapi.cmd.Operands[op].value - ri.tdelta + ri.base
            elif idaapi.isData(f) == True:
                target = self.get_data_value(addr) - ri.tdelta + ri.base;
            else:
                return
        else:
            return
        if idaapi.isEnabled(target) == False:
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
        f = idaapi.getFlags(addr)
        for op in range(idaapi.UA_MAXOP):
            if idaapi.isOff(f, op) == True and (idaapi.isData(f) == True or
                    (idaapi.isCode(f) == True and
                    self.is_imm_op(addr, op) == True)):
                self.export_memory_reference(addr, op)
    

    def export_memory_section(self, seg, binfilename):
        """
        Exports segment information as a MEMORY_SECTIONS element.
        
        Args:
            seg: IDA segment instance
            binfilename: String containing absolute filepath for binary file.
        """
        segname = idaapi.get_segm_name(seg)
        self.start_element(MEMORY_SECTION)
        self.write_attribute(NAME, segname)
        self.write_address_attribute(START_ADDR, seg.startEA)
        length = (seg.endEA - seg.startEA)*self.cbsize
        self.write_numeric_attribute(LENGTH, length)
        perms = ""
        if (seg.perm != 0):
            if (seg.perm & idaapi.SEGPERM_READ  != 0):
                perms += 'r'
            if (seg.perm & idaapi.SEGPERM_WRITE != 0):
                perms += 'w' 
            if (seg.perm & idaapi.SEGPERM_EXEC  != 0):
                perms += 'x'
            if (len(perms) > 0):
                self.write_attribute(PERMISSIONS, perms)
        has_contents = (self.options.MemoryContent.checked == True and
                       self.check_if_seg_contents(seg) == True)
        self.close_tag(has_contents)
        if (has_contents == True):
            self.export_memory_contents(os.path.basename(binfilename),
                                      self.binfile, seg.startEA, seg.endEA)
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
        self.write_attribute(NAME, idaapi.get_root_filename())
        self.write_attribute(EXE_PATH, idaapi.get_input_file_path())
        etype = idaapi.get_file_type_name()
        if (len(etype) > 0):
            self.write_attribute(EXE_FORMAT, etype)
        # check for presence of INPUT_MD5 netnode
        md5 = idaapi.netnode(INPUT_MD5)
        if md5 == idaapi.BADNODE:
            input_md5 = idc.GetInputMD5()
        else:
            input_md5 = md5.supval(idaapi.RIDX_MD5)
        if input_md5 != None:
            self.write_attribute(INPUT_MD5,input_md5)
        self.close_tag(True)
    
        # output the INFO_SOURCE element
        self.start_element(INFO_SOURCE)
        if IDA_SDK_VERSION < 670:
            tool  = 'IDA-Pro XML plugin (Python) SDK '
            tool +=  str(IDA_SDK_VERSION)
        else:
            tool  = 'IDA-Pro ' + idaapi.get_kernel_version()
            tool += ' XML plugin (Python) SDK ' + str(IDA_SDK_VERSION)
        self.write_attribute(TOOL, tool)
        user = os.getenv("USERNAME", "UNKNOWN")
        if (user == "UNKNOWN"):
            user = os.getenv("USER", "UNKNOWN")
        self.write_attribute(USER, user)
        self.write_attribute(FILE, idaapi.cvar.database_idb)
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        self.write_attribute(TIMESTAMP, ts)
        self.close_tag()
    
        # output the PROCESSOR element
        self.start_element(PROCESSOR)
        self.write_attribute(NAME, self.inf.procName)
        if (self.inf.mf):
            byte_order ="big"
        else:
            byte_order ="little"
        self.write_attribute(ENDIAN, byte_order)
        self.seg_addr = False
        bitness = 1
        model_warning = False
        nsegs = idaapi.get_segm_qty()
        if (nsegs > 0):
            bitness = idaapi.getnseg(0).bitness
            for i in range(1,nsegs):
                seg = idaapi.getnseg(i)
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
            idaapi.msg("WARNING: Segments do not have same " +
                       "addressing model!\n")
        if (idaapi.ph.id == idaapi.PLFM_386 and bitness == 0):
            self.seg_addr = True
        # find any overlayed memory before processing addressable items
        self.find_overlay_memory()
    
        # output compiler info
        self.start_element(COMPILER)
        self.write_attribute(NAME, idaapi.get_compiler_name(self.inf.cc.id))
        self.close_tag()
        self.display_cpu_time(timer)


    def export_program_entry_points(self):
        """
        Exports entry points for the program.
        """
        nepts = idaapi.get_entry_qty()
        if (nepts  == 0):
            return
        self.update_status(PROGRAM_ENTRY_POINTS)
        timer = time.clock()
        self.start_element(PROGRAM_ENTRY_POINTS, True)
        for i in range(nepts):
            self.start_element(PROGRAM_ENTRY_POINT)
            addr = idaapi.get_entry(idaapi.get_entry_ordinal(i))
            self.write_address_attribute(ADDRESS, addr)
            self.close_tag()
        self.end_element(PROGRAM_ENTRY_POINTS)
        self.display_cpu_time(timer)


    def export_register_values(self):
        """
        Exports segment register value ranges.
        """
        # should use legacy function if IDA > 660
        if IDA_SDK_VERSION < 670:
            self.export_register_values_legacy()
            return
        first = idaapi.ph_get_regFirstSreg()
        last  = idaapi.ph_get_regLastSreg()+1
        has_segregareas = False
        for j in range(first, last):
            nsegregareas = idaapi.get_srareas_qty2(j)
            if nsegregareas != 0:
                has_segregareas = True
                break;
        if has_segregareas == False:
            return
        self.update_status(REGISTER_VALUES)
        timer = time.clock();
        self.start_element(REGISTER_VALUES, True)
        sr = idaapi.segreg_area_t()
        for j in range(first, last):
            nsegregareas = idaapi.get_srareas_qty2(j)
            if nsegregareas == 0:
                continue
            for i in range(nsegregareas):
                success = idaapi.getn_srarea2(sr, j, i)
                if success == False:
                    continue
                value = sr.val
                if value == idaapi.BADSEL:
                    continue
                regname = idaapi.ph.regnames[j]
                if regname == None:
                    continue
                if regname.lower() == "cs":
                    continue
                if (idaapi.ph.id == idaapi.PLFM_TMS and
                    regname.lower() == "ds"):
                    continue
                self.start_element(REGISTER_VALUE_RANGE)
                self.write_attribute(REGISTER, idaapi.ph.regnames[j])
                self.write_numeric_attribute(VALUE, value)
                self.write_address_attribute(START_ADDRESS, sr.startEA)
                length = (sr.endEA - sr.startEA) * self.cbsize
                self.write_numeric_attribute(LENGTH, length)
                self.close_tag()
        self.end_element(REGISTER_VALUES)
        self.display_cpu_time(timer)


    def export_register_values_legacy(self):
        """
        Exports segment register value ranges.
        """
        # should use export_register_values() if IDA > 660
        if IDA_SDK_VERSION > 660:
            return
        if IDA_SDK_VERSION < 650:
            n = 0
            srarea = idaapi.getnSRarea(n)
            while type(srarea) == idaapi.segreg_t:
                n += 1
                srarea = idaapi.getnSRarea(n)
            nsegregareas = n
        else:
            nsegregareas = idaapi.get_srareas_qty()
        if (nsegregareas == 0):
            return
        self.update_status(REGISTER_VALUES)
        timer = time.clock();
        self.start_element(REGISTER_VALUES, True)
        for i in range(nsegregareas):
            if IDA_SDK_VERSION < 650:
                sr = idaapi.getnSRarea(i)
            else:
                sr = idaapi.getn_srarea(i)
            first = idaapi.ph_get_regFirstSreg()
            last  = idaapi.ph_get_regLastSreg()+1
            for j in range(first, last):
                value = idaapi.getSR(sr.startEA, j)
                if value == idaapi.BADSEL:
                    continue
                regname = idaapi.ph.regnames[j]
                if regname == None:
                    continue
                if regname.lower() == "cs":
                    continue
                if (idaapi.ph.id == idaapi.PLFM_TMS and
                    regname.lower() == "ds"):
                    continue
                self.start_element(REGISTER_VALUE_RANGE)
                self.write_attribute(REGISTER, idaapi.ph.regnames[j])
                self.write_numeric_attribute(VALUE, value)
                self.write_address_attribute(START_ADDRESS, sr.startEA)
                length = (sr.endEA - sr.startEA) * self.cbsize
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
        sframe = idaapi.get_struc(function.frame)
        if sframe == None or sframe.memqty <= 0:
            return
        self.start_element(STACK_FRAME)
        self.write_numeric_attribute(LOCAL_VAR_SIZE, function.frsize)
        self.write_numeric_attribute(REGISTER_SAVE_SIZE, function.frregs)
        retsize = idaapi.get_frame_retsize(function)
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
        f = idaapi.getFlags(addr)
        for op in range(idaapi.UA_MAXOP):
            if idaapi.isCode(f) == True and idaapi.isStkvar(f, op) == True:
                idaapi.decode_insn(addr)
                opnd = idaapi.cmd.Operands[op]
                optype = idaapi.op_t_get_type(opnd)
                if optype == idaapi.o_void:
                    continue
                SV = idaapi.get_stkvar(opnd, idaapi.op_t_get_addr(opnd))
                if SV == None:
                    continue
                (sv, actval) = SV
                function = idaapi.get_func(addr)
                self.start_element(STACK_REFERENCE)
                self.write_address_attribute(ADDRESS, addr)
                self.write_numeric_attribute(OPERAND_INDEX, op, 10)
                offset = opnd.addr
                spoff = offset - function.frregs
                if offset > 0x7FFFFFFF:
                    offset -= 0x100000000
                if spoff > 0x7FFFFFFF:
                    spoff  -= 0x100000000
                self.write_numeric_attribute(STACK_PTR_OFFSET,
                                             spoff,
                                             16, True)
                if (function.flags & FUNC_FRAME) != 0:
                    self.write_numeric_attribute(FRAME_PTR_OFFSET,
                                                offset,
                                                16, True)
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
            mname = idaapi.get_member_name(member.id)
            if mname == None or len(mname) < 0:
                continue
            if mname == " s" or mname == " r":
                continue
            spoff = member.soff - function.frsize - function.frregs
            froff = member.soff - function.frsize
            self.start_element(STACK_VAR)
            self.write_numeric_attribute(STACK_PTR_OFFSET, spoff, 16, True)
            if function.flags & idaapi.FUNC_FRAME != 0:
                self.write_numeric_attribute(FRAME_PTR_OFFSET, froff, 16, True)
            pre = mname[0:4]
            if pre != "var_" and pre != "arg_":
                self.write_attribute(NAME, mname)
            f = member.flag
            size = idaapi.get_member_size(member)
            mtype = self.get_member_type(member)
            msize = size
            if idaapi.isStruct(f) == True:
                msize = idaapi.get_struc_size(idaapi.get_struc_id(mtype))
            elif idaapi.isASCII(f) == False:
                mtibuf = idaapi.opinfo_t()
                mti = idaapi.retrieve_member_info(member, mtibuf)
                if IDA_SDK_VERSION < 640:
                    msize = idaapi.get_type_size0(None, mtype)
                    if msize == None or msize == 0:
                        msize = idaapi.get_member_size(member)
                else:
                    msize = idaapi.get_data_type_size(f, mtibuf)
            if size < msize: size = msize
            if (idaapi.isASCII(f) == False and idaapi.isAlign(f) == False
                and size != msize):
                mtype = "%s[%d]" % (mtype, size/msize)
            self.write_attribute(DATATYPE, mtype)
            self.write_numeric_attribute(SIZE, size*self.cbsize)
            regcmt = idaapi.get_member_cmt(member.id, False)
            rptcmt = idaapi.get_member_cmt(member.id, True)
            if regcmt != None:
                regcmt  = idaapi.tag_remove(regcmt + " ", 0)
            if rptcmt != None:
                rptrcmt = idaapi.tag_remove(rptcmt + " ", 0)
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
            (sid, idx, sname) = struct
            s = idaapi.get_struc(idx)
            stype = STRUCTURE
            if s.is_union() == True:
                stype = UNION
            self.start_element(stype)
            self.write_attribute(NAME, sname)
            size = idaapi.get_struc_size(idx)*self.cbsize
            self.write_numeric_attribute(SIZE, size)
            if s.is_varstr() == True:
                self.write_attribute(VARIABLE_LENGTH, "y")
            regcmt = idaapi.get_struc_cmt(idx, False)
            rptcmt = idaapi.get_struc_cmt(idx, True)
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
        mangled = idaapi.get_name(BADADDR, addr)
        if name != None and mangled != name:
            self.write_attribute("MANGLED", mangled)
        self.close_tag()
        

    def export_symbol_table(self):
        """
        Exports user-defined and non-default names as SYMBOL elements.
        """
        addr = self.min_ea
        if idaapi.has_any_name(idaapi.getFlags(addr)) == False:
            addr = idaapi.nextthat(addr, self.max_ea, idaapi.has_any_name)
        if addr == BADADDR:
            return
        self.update_status(SYMBOL_TABLE)
        self.start_element(SYMBOL_TABLE, True)
        timer = time.clock()
        while addr != BADADDR:
            # only export meaningful names (user and auto)
            f = idaapi.getFlags(addr)
            if (idaapi.has_user_name(f) == True or
                idaapi.has_auto_name(f) == True):
                # check for global name
                name = self.get_symbol_name(addr)
                if name != None and len(name) > 0:
                    self.export_symbol(addr, name)
                # check for local name
                if ((IDA_SDK_VERSION > 620 and
                    idaapi.has_lname(addr)) or
                    idaapi.get_aflags(addr) & idaapi.AFL_LNAME):
                    if IDA_SDK_VERSION < 680:
                        name = idaapi.get_name(addr, addr)
                    else:
                        name = idaapi.get_ea_name(addr, idaapi.GN_LOCAL)
                    if name != None and len(name) > 0:
                        self.export_symbol(addr, name, 'local')
            # get next address with any name
            addr = idaapi.nextthat(addr, self.max_ea,
                                   idaapi.has_any_name)
        self.end_element(SYMBOL_TABLE)
        self.display_cpu_time(timer)
        

    def export_typeinfo_cmt(self, cmt):
        """
        Exports comment containing type information for data and functions.
        
        Args:
            cmt: String containing type info.
        """
        # older versions of IDAPython returned a '\n' at end of cmt
        if cmt[-1] == '\n':
            cmt = cmt[0:-1]
        self.write_comment_element(TYPEINFO_CMT, cmt)
        

    def export_user_memory_reference(self, addr):
        """
        Exports a user-specified memory reference at the address.
        
        Args:
            addr: Integer representing the instruction address.
        """
        for xref in idautils.XrefsTo(addr, idaapi.XREF_FAR):
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
        nsegs = idaapi.get_segm_qty()
        if nsegs == 0:
            return
        s = idaapi.getnseg(0)
        start = self.translate_address(s.startEA)
        self.overlay[start] = False
        for i in range(1, nsegs):
            s = idaapi.getnseg(i)
            space = self.get_space_name(s.startEA)
            saddr = self.translate_address(s.startEA)
            eaddr = self.translate_address(s.endEA-1)
            is_overlay = False
            for j in range(i):
                s2 = idaapi.getnseg(j)
                space2 = self.get_space_name(s2.startEA)
                if space == space2:
                    start = self.translate_address(s2.startEA)
                    end   = self.translate_address(s2.endEA-1)
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
        temp = "0x%X" % (addr - idaapi.get_segm_base(idaapi.getseg(addr)))
        space = self.get_space_name(addr)
        if space != None:
            temp = "%s:%04X" % (space,
                            addr - idaapi.get_segm_base(idaapi.getseg(addr)))
        else:
            if (idaapi.ph_get_id() == idaapi.PLFM_386 and
                idaapi.getseg(addr).bitness == 0):
                base = idaapi.get_segm_para(idaapi.getseg(addr))
                temp = "%04X:%04X" % (base, addr - (base << 4))
        if idaapi.ph_get_id() == idaapi.PLFM_C166:
            temp = "0x%X" % addr
        if self.has_overlays == True and self.is_overlay(addr) == True:
            oname = idaapi.get_segm_name(idaapi.getseg(addr))
            if len(oname) > 0:
                temp = oname + "::" + temp
        return temp


    def get_data_value(self, addr):
        """
        Returns the data item value at an address based on its size.
        
        Args:
            addr: Integer representing a program address.
        """
        size = idaapi.get_item_size(addr)*self.cbsize
        if size == 1:   return idaapi.get_byte(addr)
        if size == 2:   return idaapi.get_16bit(addr)
        if size == 4:   return idaapi.get_32bit(addr)
        if size == 8:   return idaapi.get_64bit(addr)
        return 0
    

    def get_datatype(self, addr):
        """
        Returns the datatype at an address.
        
        The type could be a basic type (byte, word, dword, etc.),
        a structure, an array, a pointer, or a string type.
        
        Args:
            addr: Integer representing a program address.
        """
        f = idaapi.getFlags(addr)
        t = self.get_type(f)
        if idaapi.isStruct(f) == True:
            opndbuf = idaapi.opinfo_t()
            opnd = idaapi.get_opinfo(addr, 0, f, opndbuf)
            return idaapi.get_struc_name(opnd.tid)
        if idaapi.isASCII(f) == True:
            str_type = idc.GetStringType(addr)
            if str_type == idaapi.ASCSTR_TERMCHR:   return "string"
            if str_type == idaapi.ASCSTR_PASCAL:    return "string1"
            if str_type == idaapi.ASCSTR_LEN2:      return "string2"
            if str_type == idaapi.ASCSTR_LEN4:      return "string4"
            if str_type == idaapi.ASCSTR_UNICODE:   return "unicode"
            if str_type == idaapi.ASCSTR_ULEN2:     return "unicode2"
            if str_type == idaapi.ASCSTR_ULEN4:     return "unicode4"
            return "string"
        if idaapi.isOff0(f) == True: return "pointer"
        return t


    def get_format(self, flags):
        """
        Returns the display format of a data item based on its flags.
        
        Args:
            flags: Integer representing IDA item flags
            
        Returns:
            String representing IDA display format.
        """
        if idaapi.isChar0(flags): return "char"
        radix = idaapi.getRadix(flags, 0)
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
        if idaapi.isOff0(f) == True:
            t = "pointer"
        if idaapi.isStruct(f) == False:
            return t
        s = idaapi.get_sptr(m)
        if (s == None):
            return t
        sname = idaapi.get_struc_name(s.id)
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
        
        Opts = { 'cGroup1': idaapi.Form.ChkGroupControl
            (
                (
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
                )
            )
        }
        
        self.options = idaapi.Form(fmt, Opts)
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
        pid = idaapi.ph_get_id()
        stype = idaapi.segtype(addr)
        if pid == idaapi.PLFM_8051:
            if stype == idaapi.SEG_CODE:
                return "CODE"
            else:
                if stype == idaapi.SEG_IMEM:
                    iaddr = addr - idaapi.get_segm_base(idaapi.getseg(addr))
                    if iaddr < 0x80:
                        return "INTMEM"
                    else:
                        return "SFR"
                else:
                    return "EXTMEM"
        if pid == idaapi.PLFM_TMS:
            if stype == idaapi.SEG_CODE:
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
        flags = idaapi.getFlags(ea)
        name = idaapi.get_demangled_name(BADADDR, ea, DEMANGLED_FORM,
                                         self.inf.demnames, False)
        if name == None or len(name) == 0 or name == "`string'":
            name = idaapi.get_name(BADADDR, ea)
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
            if idaapi.isByte(flags) == True: return "word"
            if idaapi.isWord(flags) == True: return "dword"
        if idaapi.isByte(flags)     == True: return "byte"
        if idaapi.isWord(flags)     == True: return "word"
        if idaapi.isDwrd(flags)     == True: return "dword"
        if idaapi.isQwrd(flags)     == True: return "qword"
        if idaapi.isOwrd(flags)     == True: return "oword"
        if idaapi.isTbyt(flags)     == True: return "tbyte"
        if idaapi.isFloat(flags)    == True: return "float"
        if idaapi.isDouble(flags)   == True: return "double"
        if idaapi.isPackReal(flags) == True: return "packed"
        if idaapi.isASCII(flags)    == True: return "ascii"
        if idaapi.isStruct(flags)   == True: return "structure"
        if idaapi.isAlign(flags)    == True: return "align"
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
        idaapi.decode_insn(addr)
        if (idaapi.cmd.Operands[op].type == idaapi.o_imm):
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
        if idaapi.ph_get_id() == idaapi.PLFM_C166:
            return False
        s = idaapi.getseg(addr)
        if s.startEA in self.overlay:
            return self.overlay[s.startEA]
        return False
    
    def is_signed_data(self, flags):
        return (flags & idaapi.FF_SIGN) != 0


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


    def start_element(self, tag, close=False):
        """
        Outputs the start of a new element on a new indented line.
        
        Args:
            tag: String representing the element tag
            close: Boolean indicating if tag is should be closed.
        """
        if idaapi.wasBreak() == True:
            raise Cancelled
        self.write_to_xmlfile("\n" + ("    " * self.indent_level) + "<" + tag)
        if (close):
            self.close_tag(True)
        # Add a counter for this tag; increment counter if it already exists.
        if (tag in self.elements) == False:
            self.elements[tag] = len(self.elements)
            self.counters.append(1)
            self.tags.append(tag)
        else:
            self.counters[self.elements[tag]] += 1
        

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
            return addr - idaapi.get_segm_base(idaapi.getseg(addr))
        base = idaapi.get_segm_para(idaapi.getseg(addr))
        return (base << 16) + (addr - (base << 4))
    

    def update_status(self, tag):
        """
        Displays the processing status in the IDA window.
        
        Args:
            tag: String representing XML element tag
        """
        status = "Exporting <" + tag + ">"
        idaapi.msg('\n%-35s' % status)
        idaapi.hide_wait_box()
        idaapi.show_wait_box(status)


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

# Global constants
# mangled name inhibit flags are not exposed in idaapi
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
