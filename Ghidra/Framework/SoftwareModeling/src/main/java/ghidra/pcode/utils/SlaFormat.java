/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.pcode.utils;

import java.io.*;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

import generic.jar.ResourceFile;
import ghidra.program.model.pcode.*;

/**
 * Encoding values for the .sla file format
 */
public class SlaFormat {

	/**
	 * FORMAT_VERSION will be incremented whenever the format of the .sla
	 * files change.
	 * <p>
	 * Version 4: Compressed and packed file format
	 * Version 3: January 2021: added source file information for each constructor. <br>
	 * Version 2: April 2019: Changed numbering of Overlay spaces.<br>
	 * Version 1: Initial version.<br>
	 */
	public static final int FORMAT_VERSION = 4;

	/**
	 * Absolute limit on the number of bytes in a .sla file
	 */
	public static final int MAX_FILE_SIZE = 1 << 24;		// 16 Megabytes
	// Attributes

	// ATTRIB_CONTENT = 1 is reserved
	public static final AttributeId ATTRIB_VAL = new AttributeId("val", 2);
	public static final AttributeId ATTRIB_ID = new AttributeId("id", 3);
	public static final AttributeId ATTRIB_SPACE = new AttributeId("space", 4);
	public static final AttributeId ATTRIB_S = new AttributeId("s", 5);
	public static final AttributeId ATTRIB_OFF = new AttributeId("off", 6);
	public static final AttributeId ATTRIB_CODE = new AttributeId("code", 7);
	public static final AttributeId ATTRIB_MASK = new AttributeId("mask", 8);
	public static final AttributeId ATTRIB_INDEX = new AttributeId("index", 9);
	public static final AttributeId ATTRIB_NONZERO = new AttributeId("nonzero", 10);
	public static final AttributeId ATTRIB_PIECE = new AttributeId("piece", 11);
	public static final AttributeId ATTRIB_NAME = new AttributeId("name", 12);
	public static final AttributeId ATTRIB_SCOPE = new AttributeId("scope", 13);
	public static final AttributeId ATTRIB_STARTBIT = new AttributeId("startbit", 14);
	public static final AttributeId ATTRIB_SIZE = new AttributeId("size", 15);
	public static final AttributeId ATTRIB_TABLE = new AttributeId("table", 16);
	public static final AttributeId ATTRIB_CT = new AttributeId("ct", 17);
	public static final AttributeId ATTRIB_MINLEN = new AttributeId("minlen", 18);
	public static final AttributeId ATTRIB_BASE = new AttributeId("base", 19);
	public static final AttributeId ATTRIB_NUMBER = new AttributeId("number", 20);
	public static final AttributeId ATTRIB_CONTEXT = new AttributeId("context", 21);
	public static final AttributeId ATTRIB_PARENT = new AttributeId("parent", 22);
	public static final AttributeId ATTRIB_SUBSYM = new AttributeId("subsym", 23);
	public static final AttributeId ATTRIB_LINE = new AttributeId("line", 24);
	public static final AttributeId ATTRIB_SOURCE = new AttributeId("source", 25);
	public static final AttributeId ATTRIB_LENGTH = new AttributeId("length", 26);
	public static final AttributeId ATTRIB_FIRST = new AttributeId("first", 27);
	public static final AttributeId ATTRIB_PLUS = new AttributeId("plus", 28);
	public static final AttributeId ATTRIB_SHIFT = new AttributeId("shift", 29);
	public static final AttributeId ATTRIB_ENDBIT = new AttributeId("endbit", 30);
	public static final AttributeId ATTRIB_SIGNBIT = new AttributeId("signbit", 31);
	public static final AttributeId ATTRIB_ENDBYTE = new AttributeId("endbyte", 32);
	public static final AttributeId ATTRIB_STARTBYTE = new AttributeId("startbyte", 33);
	public static final AttributeId ATTRIB_VERSION = new AttributeId("version", 34);
	public static final AttributeId ATTRIB_BIGENDIAN = new AttributeId("bigendian", 35);
	public static final AttributeId ATTRIB_ALIGN = new AttributeId("align", 36);
	public static final AttributeId ATTRIB_UNIQBASE = new AttributeId("uniqbase", 37);
	public static final AttributeId ATTRIB_MAXDELAY = new AttributeId("maxdelay", 38);
	public static final AttributeId ATTRIB_UNIQMASK = new AttributeId("uniqmask", 39);
	public static final AttributeId ATTRIB_NUMSECTIONS = new AttributeId("numsections", 40);
	public static final AttributeId ATTRIB_DEFAULTSPACE = new AttributeId("defaultspace", 41);
	public static final AttributeId ATTRIB_DELAY = new AttributeId("delay", 42);
	public static final AttributeId ATTRIB_WORDSIZE = new AttributeId("wordsize", 43);
	public static final AttributeId ATTRIB_PHYSICAL = new AttributeId("physical", 44);
	public static final AttributeId ATTRIB_SCOPESIZE = new AttributeId("scopesize", 45);
	public static final AttributeId ATTRIB_SYMBOLSIZE = new AttributeId("symbolsize", 46);
	public static final AttributeId ATTRIB_VARNODE = new AttributeId("varnode", 47);
	public static final AttributeId ATTRIB_LOW = new AttributeId("low", 48);
	public static final AttributeId ATTRIB_HIGH = new AttributeId("high", 49);
	public static final AttributeId ATTRIB_FLOW = new AttributeId("flow", 50);
	public static final AttributeId ATTRIB_CONTAIN = new AttributeId("contain", 51);
	public static final AttributeId ATTRIB_I = new AttributeId("i", 52);
	public static final AttributeId ATTRIB_NUMCT = new AttributeId("numct", 53);
	public static final AttributeId ATTRIB_SECTION = new AttributeId("section", 54);
	public static final AttributeId ATTRIB_LABELS = new AttributeId("labels", 55);

	public static final ElementId ELEM_CONST_REAL = new ElementId("const_real", 1);
	public static final ElementId ELEM_VARNODE_TPL = new ElementId("varnode_tpl", 2);
	public static final ElementId ELEM_CONST_SPACEID = new ElementId("const_spaceid", 3);
	public static final ElementId ELEM_CONST_HANDLE = new ElementId("const_handle", 4);
	public static final ElementId ELEM_OP_TPL = new ElementId("op_tpl", 5);
	public static final ElementId ELEM_MASK_WORD = new ElementId("mask_word", 6);
	public static final ElementId ELEM_PAT_BLOCK = new ElementId("pat_block", 7);
	public static final ElementId ELEM_PRINT = new ElementId("print", 8);
	public static final ElementId ELEM_PAIR = new ElementId("pair", 9);
	public static final ElementId ELEM_CONTEXT_PAT = new ElementId("context_pat", 10);
	public static final ElementId ELEM_NULL = new ElementId("null", 11);
	public static final ElementId ELEM_OPERAND_EXP = new ElementId("operand_exp", 12);
	public static final ElementId ELEM_OPERAND_SYM = new ElementId("operand_sym", 13);
	public static final ElementId ELEM_OPERAND_SYM_HEAD = new ElementId("operand_sym_head", 14);
	public static final ElementId ELEM_OPER = new ElementId("oper", 15);
	public static final ElementId ELEM_DECISION = new ElementId("decision", 16);
	public static final ElementId ELEM_OPPRINT = new ElementId("opprint", 17);
	public static final ElementId ELEM_INSTRUCT_PAT = new ElementId("instruct_pat", 18);
	public static final ElementId ELEM_COMBINE_PAT = new ElementId("combine_pat", 19);
	public static final ElementId ELEM_CONSTRUCTOR = new ElementId("constructor", 20);
	public static final ElementId ELEM_CONSTRUCT_TPL = new ElementId("construct_tpl", 21);
	public static final ElementId ELEM_SCOPE = new ElementId("scope", 22);
	public static final ElementId ELEM_VARNODE_SYM = new ElementId("varnode_sym", 23);
	public static final ElementId ELEM_VARNODE_SYM_HEAD = new ElementId("varnode_sym_head", 24);
	public static final ElementId ELEM_USEROP = new ElementId("userop", 25);
	public static final ElementId ELEM_USEROP_HEAD = new ElementId("userop_head", 26);
	public static final ElementId ELEM_TOKENFIELD = new ElementId("tokenfield", 27);
	public static final ElementId ELEM_VAR = new ElementId("var", 28);
	public static final ElementId ELEM_CONTEXTFIELD = new ElementId("contextfield", 29);
	public static final ElementId ELEM_HANDLE_TPL = new ElementId("handle_tpl", 30);
	public static final ElementId ELEM_CONST_RELATIVE = new ElementId("const_relative", 31);
	public static final ElementId ELEM_CONTEXT_OP = new ElementId("context_op", 32);

	public static final ElementId ELEM_SLEIGH = new ElementId("sleigh", 33);
	public static final ElementId ELEM_SPACES = new ElementId("spaces", 34);
	public static final ElementId ELEM_SOURCEFILES = new ElementId("sourcefiles", 35);
	public static final ElementId ELEM_SOURCEFILE = new ElementId("sourcefile", 36);
	public static final ElementId ELEM_SPACE = new ElementId("space", 37);
	public static final ElementId ELEM_SYMBOL_TABLE = new ElementId("symbol_table", 38);
	public static final ElementId ELEM_VALUE_SYM = new ElementId("value_sym", 39);
	public static final ElementId ELEM_VALUE_SYM_HEAD = new ElementId("value_sym_head", 40);
	public static final ElementId ELEM_CONTEXT_SYM = new ElementId("context_sym", 41);
	public static final ElementId ELEM_CONTEXT_SYM_HEAD = new ElementId("context_sym_head", 42);
	public static final ElementId ELEM_END_SYM = new ElementId("end_sym", 43);
	public static final ElementId ELEM_END_SYM_HEAD = new ElementId("end_sym_head", 44);
	public static final ElementId ELEM_SPACE_OTHER = new ElementId("space_other", 45);
	public static final ElementId ELEM_SPACE_UNIQUE = new ElementId("space_unique", 46);
	public static final ElementId ELEM_AND_EXP = new ElementId("and_exp", 47);
	public static final ElementId ELEM_DIV_EXP = new ElementId("div_exp", 48);
	public static final ElementId ELEM_LSHIFT_EXP = new ElementId("lshift_exp", 49);
	public static final ElementId ELEM_MINUS_EXP = new ElementId("minus_exp", 50);
	public static final ElementId ELEM_MULT_EXP = new ElementId("mult_exp", 51);
	public static final ElementId ELEM_NOT_EXP = new ElementId("not_exp", 52);
	public static final ElementId ELEM_OR_EXP = new ElementId("or_exp", 53);
	public static final ElementId ELEM_PLUS_EXP = new ElementId("plus_exp", 54);
	public static final ElementId ELEM_RSHIFT_EXP = new ElementId("rshift_exp", 55);
	public static final ElementId ELEM_SUB_EXP = new ElementId("sub_exp", 56);
	public static final ElementId ELEM_XOR_EXP = new ElementId("xor_exp", 57);
	public static final ElementId ELEM_INTB = new ElementId("intb", 58);
	public static final ElementId ELEM_END_EXP = new ElementId("end_exp", 59);
	public static final ElementId ELEM_NEXT2_EXP = new ElementId("next2_exp", 60);
	public static final ElementId ELEM_START_EXP = new ElementId("start_exp", 61);
	public static final ElementId ELEM_EPSILON_SYM = new ElementId("epsilon_sym", 62);
	public static final ElementId ELEM_EPSILON_SYM_HEAD = new ElementId("epsilon_sym_head", 63);
	public static final ElementId ELEM_NAME_SYM = new ElementId("name_sym", 64);
	public static final ElementId ELEM_NAME_SYM_HEAD = new ElementId("name_sym_head", 65);
	public static final ElementId ELEM_NAMETAB = new ElementId("nametab", 66);
	public static final ElementId ELEM_NEXT2_SYM = new ElementId("next2_sym", 67);
	public static final ElementId ELEM_NEXT2_SYM_HEAD = new ElementId("next2_sym_head", 68);
	public static final ElementId ELEM_START_SYM = new ElementId("start_sym", 69);
	public static final ElementId ELEM_START_SYM_HEAD = new ElementId("start_sym_head", 70);
	public static final ElementId ELEM_SUBTABLE_SYM = new ElementId("subtable_sym", 71);
	public static final ElementId ELEM_SUBTABLE_SYM_HEAD = new ElementId("subtable_sym_head", 72);
	public static final ElementId ELEM_VALUEMAP_SYM = new ElementId("valuemap_sym", 73);
	public static final ElementId ELEM_VALUEMAP_SYM_HEAD = new ElementId("valuemap_sym_head", 74);
	public static final ElementId ELEM_VALUETAB = new ElementId("valuetab", 75);
	public static final ElementId ELEM_VARLIST_SYM = new ElementId("varlist_sym", 76);
	public static final ElementId ELEM_VARLIST_SYM_HEAD = new ElementId("varlist_sym_head", 77);
	public static final ElementId ELEM_OR_PAT = new ElementId("or_pat", 78);
	public static final ElementId ELEM_COMMIT = new ElementId("commit", 79);
	public static final ElementId ELEM_CONST_START = new ElementId("const_start", 80);
	public static final ElementId ELEM_CONST_NEXT = new ElementId("const_next", 81);
	public static final ElementId ELEM_CONST_NEXT2 = new ElementId("const_next2", 82);
	public static final ElementId ELEM_CONST_CURSPACE = new ElementId("const_curspace", 83);
	public static final ElementId ELEM_CONST_CURSPACE_SIZE =
		new ElementId("const_curspace_size", 84);
	public static final ElementId ELEM_CONST_FLOWREF = new ElementId("const_flowref", 85);
	public static final ElementId ELEM_CONST_FLOWREF_SIZE = new ElementId("const_flowref_size", 86);
	public static final ElementId ELEM_CONST_FLOWDEST = new ElementId("const_flowdest", 87);
	public static final ElementId ELEM_CONST_FLOWDEST_SIZE =
		new ElementId("const_flowdest_size", 88);

	/**
	 * Try to read the header bytes of the .sla format from the given stream. If the header bytes
	 * and the version byte match, \b true is returned, and the stream can be passed to the decoder.
	 * @param stream is the given stream
	 * @return true if the .sla header bytes are found
	 * @throws IOException for any errors reading from the stream
	 */
	public static boolean isSlaFormat(InputStream stream) throws IOException {
		byte[] header = new byte[4];
		int readLen = stream.read(header);
		if (readLen < 4) {
			return false;
		}
		if (header[0] != 's' || header[1] != 'l' || header[2] != 'a') {
			return false;
		}
		if (header[3] != FORMAT_VERSION) {
			return false;
		}
		return true;
	}

	/**
	 * Write a .sla file header,including the format version number to the given stream.
	 * @param stream is the given stream
	 * @throws IOException for problems writing to the stream
	 */
	public static void writeSlaHeader(OutputStream stream) throws IOException {
		stream.write("sla".getBytes());
		stream.write(FORMAT_VERSION);
	}

	/**
	 * Build the encoder for compressing and encoding a .sla file (as a stream).
	 * The given file is opened and a header is immediately written.  The returned
	 * encoder is ready immediately to receive the .sla elements and attributes.
	 * @param sleighFile is the .sla file (to be created)
	 * @return the encoder
	 * @throws IOException for any problems opening or writing to the file
	 */
	public static PackedEncode buildEncoder(ResourceFile sleighFile) throws IOException {
		OutputStream stream = sleighFile.getOutputStream();
		writeSlaHeader(stream);
		OutputStream compStream = new DeflaterOutputStream(stream);
		return new PackedEncode(compStream);
	}

	/**
	 * Build the decoder for decompressing and decoding the .sla file (as a stream).
	 * The given file is opened and the header bytes are checked.  The returned
	 * decoder is immediately ready to read.
	 * @param sleighFile is the given .sla file
	 * @return the decoder
	 * @throws IOException if the header is invalid or there are problems reading the file
	 */
	public static PackedDecode buildDecoder(ResourceFile sleighFile) throws IOException {
		InputStream stream = sleighFile.getInputStream();
		try {
			if (!isSlaFormat(stream)) {
				throw new IOException("Missing SLA format header");
			}
			InflaterInputStream inflaterStream = new InflaterInputStream(stream);
			PackedDecode decoder = new PackedDecode();
			decoder.open(MAX_FILE_SIZE, ".sla file loader");
			decoder.ingestStream(inflaterStream);
			decoder.endIngest();
			inflaterStream.close();
			return decoder;
		}
		finally {
			stream.close();
		}
	}
}
