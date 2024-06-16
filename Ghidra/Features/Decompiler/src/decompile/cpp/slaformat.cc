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
#include "slaformat.hh"

namespace ghidra {
namespace sla {
const int4 FORMAT_SCOPE = 1;
const int4 FORMAT_VERSION = 4;

// ATTRIB_CONTEXT = 1 is reserved
AttributeId ATTRIB_VAL = AttributeId("val", 2, FORMAT_SCOPE);
AttributeId ATTRIB_ID = AttributeId("id", 3, FORMAT_SCOPE);
AttributeId ATTRIB_SPACE = AttributeId("space", 4, FORMAT_SCOPE);
AttributeId ATTRIB_S = AttributeId("s", 5, FORMAT_SCOPE);
AttributeId ATTRIB_OFF = AttributeId("off", 6, FORMAT_SCOPE);
AttributeId ATTRIB_CODE = AttributeId("code", 7, FORMAT_SCOPE);
AttributeId ATTRIB_MASK = AttributeId("mask", 8, FORMAT_SCOPE);
AttributeId ATTRIB_INDEX = AttributeId("index", 9, FORMAT_SCOPE);
AttributeId ATTRIB_NONZERO = AttributeId("nonzero", 10, FORMAT_SCOPE);
AttributeId ATTRIB_PIECE = AttributeId("piece", 11, FORMAT_SCOPE);
AttributeId ATTRIB_NAME = AttributeId("name", 12, FORMAT_SCOPE);
AttributeId ATTRIB_SCOPE = AttributeId("scope", 13, FORMAT_SCOPE);
AttributeId ATTRIB_STARTBIT = AttributeId("startbit", 14, FORMAT_SCOPE);
AttributeId ATTRIB_SIZE = AttributeId("size", 15, FORMAT_SCOPE);
AttributeId ATTRIB_TABLE = AttributeId("table", 16, FORMAT_SCOPE);
AttributeId ATTRIB_CT = AttributeId("ct", 17, FORMAT_SCOPE);
AttributeId ATTRIB_MINLEN = AttributeId("minlen", 18, FORMAT_SCOPE);
AttributeId ATTRIB_BASE = AttributeId("base", 19, FORMAT_SCOPE);
AttributeId ATTRIB_NUMBER = AttributeId("number", 20, FORMAT_SCOPE);
AttributeId ATTRIB_CONTEXT = AttributeId("context", 21, FORMAT_SCOPE);
AttributeId ATTRIB_PARENT = AttributeId("parent", 22, FORMAT_SCOPE);
AttributeId ATTRIB_SUBSYM = AttributeId("subsym", 23, FORMAT_SCOPE);
AttributeId ATTRIB_LINE = AttributeId("line", 24, FORMAT_SCOPE);
AttributeId ATTRIB_SOURCE = AttributeId("source", 25, FORMAT_SCOPE);
AttributeId ATTRIB_LENGTH = AttributeId("length", 26, FORMAT_SCOPE);
AttributeId ATTRIB_FIRST = AttributeId("first", 27, FORMAT_SCOPE);
AttributeId ATTRIB_PLUS = AttributeId("plus", 28, FORMAT_SCOPE);
AttributeId ATTRIB_SHIFT = AttributeId("shift", 29, FORMAT_SCOPE);
AttributeId ATTRIB_ENDBIT = AttributeId("endbit", 30, FORMAT_SCOPE);
AttributeId ATTRIB_SIGNBIT = AttributeId("signbit", 31, FORMAT_SCOPE);
AttributeId ATTRIB_ENDBYTE = AttributeId("endbyte", 32, FORMAT_SCOPE);
AttributeId ATTRIB_STARTBYTE = AttributeId("startbyte", 33, FORMAT_SCOPE);

AttributeId ATTRIB_VERSION = AttributeId("version", 34, FORMAT_SCOPE);
AttributeId ATTRIB_BIGENDIAN = AttributeId("bigendian", 35, FORMAT_SCOPE);
AttributeId ATTRIB_ALIGN = AttributeId("align", 36, FORMAT_SCOPE);
AttributeId ATTRIB_UNIQBASE = AttributeId("uniqbase", 37, FORMAT_SCOPE);
AttributeId ATTRIB_MAXDELAY = AttributeId("maxdelay", 38, FORMAT_SCOPE);
AttributeId ATTRIB_UNIQMASK = AttributeId("uniqmask", 39, FORMAT_SCOPE);
AttributeId ATTRIB_NUMSECTIONS = AttributeId("numsections", 40, FORMAT_SCOPE);
AttributeId ATTRIB_DEFAULTSPACE = AttributeId("defaultspace", 41, FORMAT_SCOPE);
AttributeId ATTRIB_DELAY = AttributeId("delay", 42, FORMAT_SCOPE);
AttributeId ATTRIB_WORDSIZE = AttributeId("wordsize", 43, FORMAT_SCOPE);
AttributeId ATTRIB_PHYSICAL = AttributeId("physical", 44, FORMAT_SCOPE);
AttributeId ATTRIB_SCOPESIZE = AttributeId("scopesize", 45, FORMAT_SCOPE);
AttributeId ATTRIB_SYMBOLSIZE = AttributeId("symbolsize", 46, FORMAT_SCOPE);
AttributeId ATTRIB_VARNODE = AttributeId("varnode", 47, FORMAT_SCOPE);
AttributeId ATTRIB_LOW = AttributeId("low", 48, FORMAT_SCOPE);
AttributeId ATTRIB_HIGH = AttributeId("high", 49, FORMAT_SCOPE);
AttributeId ATTRIB_FLOW = AttributeId("flow", 50, FORMAT_SCOPE);
AttributeId ATTRIB_CONTAIN = AttributeId("contain", 51, FORMAT_SCOPE);
AttributeId ATTRIB_I = AttributeId("i", 52, FORMAT_SCOPE);
AttributeId ATTRIB_NUMCT = AttributeId("numct", 53, FORMAT_SCOPE);
AttributeId ATTRIB_SECTION = AttributeId("section", 54, FORMAT_SCOPE);
AttributeId ATTRIB_LABELS = AttributeId("labels", 55, FORMAT_SCOPE);

ElementId ELEM_CONST_REAL = ElementId("const_real", 1, FORMAT_SCOPE);
ElementId ELEM_VARNODE_TPL = ElementId("varnode_tpl", 2, FORMAT_SCOPE);
ElementId ELEM_CONST_SPACEID = ElementId("const_spaceid", 3, FORMAT_SCOPE);
ElementId ELEM_CONST_HANDLE = ElementId("const_handle", 4, FORMAT_SCOPE);
ElementId ELEM_OP_TPL = ElementId("op_tpl", 5, FORMAT_SCOPE);
ElementId ELEM_MASK_WORD = ElementId("mask_word", 6, FORMAT_SCOPE);
ElementId ELEM_PAT_BLOCK = ElementId("pat_block", 7, FORMAT_SCOPE);
ElementId ELEM_PRINT = ElementId("print", 8, FORMAT_SCOPE);
ElementId ELEM_PAIR = ElementId("pair", 9, FORMAT_SCOPE);
ElementId ELEM_CONTEXT_PAT = ElementId("context_pat", 10, FORMAT_SCOPE);
ElementId ELEM_NULL = ElementId("null", 11, FORMAT_SCOPE);
ElementId ELEM_OPERAND_EXP = ElementId("operand_exp", 12, FORMAT_SCOPE);
ElementId ELEM_OPERAND_SYM = ElementId("operand_sym", 13, FORMAT_SCOPE);
ElementId ELEM_OPERAND_SYM_HEAD = ElementId("operand_sym_head", 14, FORMAT_SCOPE);
ElementId ELEM_OPER = ElementId("oper", 15, FORMAT_SCOPE);
ElementId ELEM_DECISION = ElementId("decision", 16, FORMAT_SCOPE);
ElementId ELEM_OPPRINT = ElementId("opprint", 17, FORMAT_SCOPE);
ElementId ELEM_INSTRUCT_PAT = ElementId("instruct_pat", 18, FORMAT_SCOPE);
ElementId ELEM_COMBINE_PAT = ElementId("combine_pat", 19, FORMAT_SCOPE);
ElementId ELEM_CONSTRUCTOR = ElementId("constructor", 20, FORMAT_SCOPE);
ElementId ELEM_CONSTRUCT_TPL = ElementId("construct_tpl", 21, FORMAT_SCOPE);
ElementId ELEM_SCOPE = ElementId("scope", 22, FORMAT_SCOPE);
ElementId ELEM_VARNODE_SYM = ElementId("varnode_sym", 23, FORMAT_SCOPE);
ElementId ELEM_VARNODE_SYM_HEAD = ElementId("varnode_sym_head", 24, FORMAT_SCOPE);
ElementId ELEM_USEROP = ElementId("userop", 25, FORMAT_SCOPE);
ElementId ELEM_USEROP_HEAD = ElementId("userop_head", 26, FORMAT_SCOPE);
ElementId ELEM_TOKENFIELD = ElementId("tokenfield", 27, FORMAT_SCOPE);
ElementId ELEM_VAR = ElementId("var", 28, FORMAT_SCOPE);
ElementId ELEM_CONTEXTFIELD = ElementId("contextfield", 29, FORMAT_SCOPE);
ElementId ELEM_HANDLE_TPL = ElementId("handle_tpl", 30, FORMAT_SCOPE);
ElementId ELEM_CONST_RELATIVE = ElementId("const_relative", 31, FORMAT_SCOPE);
ElementId ELEM_CONTEXT_OP = ElementId("context_op", 32, FORMAT_SCOPE);

ElementId ELEM_SLEIGH = ElementId("sleigh", 33, FORMAT_SCOPE);
ElementId ELEM_SPACES = ElementId("spaces", 34, FORMAT_SCOPE);
ElementId ELEM_SOURCEFILES = ElementId("sourcefiles", 35, FORMAT_SCOPE);
ElementId ELEM_SOURCEFILE = ElementId("sourcefile", 36, FORMAT_SCOPE);
ElementId ELEM_SPACE = ElementId("space", 37, FORMAT_SCOPE);
ElementId ELEM_SYMBOL_TABLE = ElementId("symbol_table", 38, FORMAT_SCOPE);
ElementId ELEM_VALUE_SYM = ElementId("value_sym", 39, FORMAT_SCOPE);
ElementId ELEM_VALUE_SYM_HEAD = ElementId("value_sym_head", 40, FORMAT_SCOPE);
ElementId ELEM_CONTEXT_SYM = ElementId("context_sym", 41, FORMAT_SCOPE);
ElementId ELEM_CONTEXT_SYM_HEAD = ElementId("context_sym_head", 42, FORMAT_SCOPE);
ElementId ELEM_END_SYM = ElementId("end_sym", 43, FORMAT_SCOPE);
ElementId ELEM_END_SYM_HEAD = ElementId("end_sym_head", 44, FORMAT_SCOPE);
ElementId ELEM_SPACE_OTHER = ElementId("space_other", 45, FORMAT_SCOPE);
ElementId ELEM_SPACE_UNIQUE = ElementId("space_unique", 46, FORMAT_SCOPE);
ElementId ELEM_AND_EXP = ElementId("and_exp", 47, FORMAT_SCOPE);
ElementId ELEM_DIV_EXP = ElementId("div_exp", 48, FORMAT_SCOPE);
ElementId ELEM_LSHIFT_EXP = ElementId("lshift_exp", 49, FORMAT_SCOPE);
ElementId ELEM_MINUS_EXP = ElementId("minus_exp", 50, FORMAT_SCOPE);
ElementId ELEM_MULT_EXP = ElementId("mult_exp", 51, FORMAT_SCOPE);
ElementId ELEM_NOT_EXP = ElementId("not_exp", 52, FORMAT_SCOPE);
ElementId ELEM_OR_EXP = ElementId("or_exp", 53, FORMAT_SCOPE);
ElementId ELEM_PLUS_EXP = ElementId("plus_exp", 54, FORMAT_SCOPE);
ElementId ELEM_RSHIFT_EXP = ElementId("rshift_exp", 55, FORMAT_SCOPE);
ElementId ELEM_SUB_EXP = ElementId("sub_exp", 56, FORMAT_SCOPE);
ElementId ELEM_XOR_EXP = ElementId("xor_exp", 57, FORMAT_SCOPE);
ElementId ELEM_INTB = ElementId("intb", 58, FORMAT_SCOPE);
ElementId ELEM_END_EXP = ElementId("end_exp", 59, FORMAT_SCOPE);
ElementId ELEM_NEXT2_EXP = ElementId("next2_exp", 60, FORMAT_SCOPE);
ElementId ELEM_START_EXP = ElementId("start_exp", 61, FORMAT_SCOPE);
ElementId ELEM_EPSILON_SYM = ElementId("epsilon_sym", 62, FORMAT_SCOPE);
ElementId ELEM_EPSILON_SYM_HEAD = ElementId("epsilon_sym_head", 63, FORMAT_SCOPE);
ElementId ELEM_NAME_SYM = ElementId("name_sym", 64, FORMAT_SCOPE);
ElementId ELEM_NAME_SYM_HEAD = ElementId("name_sym_head", 65, FORMAT_SCOPE);
ElementId ELEM_NAMETAB = ElementId("nametab", 66, FORMAT_SCOPE);
ElementId ELEM_NEXT2_SYM = ElementId("next2_sym", 67, FORMAT_SCOPE);
ElementId ELEM_NEXT2_SYM_HEAD = ElementId("next2_sym_head", 68, FORMAT_SCOPE);
ElementId ELEM_START_SYM = ElementId("start_sym", 69, FORMAT_SCOPE);
ElementId ELEM_START_SYM_HEAD = ElementId("start_sym_head", 70, FORMAT_SCOPE);
ElementId ELEM_SUBTABLE_SYM = ElementId("subtable_sym", 71, FORMAT_SCOPE);
ElementId ELEM_SUBTABLE_SYM_HEAD = ElementId("subtable_sym_head", 72, FORMAT_SCOPE);
ElementId ELEM_VALUEMAP_SYM = ElementId("valuemap_sym", 73, FORMAT_SCOPE);
ElementId ELEM_VALUEMAP_SYM_HEAD = ElementId("valuemap_sym_head", 74, FORMAT_SCOPE);
ElementId ELEM_VALUETAB = ElementId("valuetab", 75, FORMAT_SCOPE);
ElementId ELEM_VARLIST_SYM = ElementId("varlist_sym", 76, FORMAT_SCOPE);
ElementId ELEM_VARLIST_SYM_HEAD = ElementId("varlist_sym_head", 77, FORMAT_SCOPE);
ElementId ELEM_OR_PAT = ElementId("or_pat", 78, FORMAT_SCOPE);
ElementId ELEM_COMMIT = ElementId("commit", 79, FORMAT_SCOPE);
ElementId ELEM_CONST_START = ElementId("const_start", 80, FORMAT_SCOPE);
ElementId ELEM_CONST_NEXT = ElementId("const_next", 81, FORMAT_SCOPE);
ElementId ELEM_CONST_NEXT2 = ElementId("const_next2", 82, FORMAT_SCOPE);
ElementId ELEM_CONST_CURSPACE = ElementId("const_curspace", 83, FORMAT_SCOPE);
ElementId ELEM_CONST_CURSPACE_SIZE = ElementId("const_curspace_size", 84, FORMAT_SCOPE);
ElementId ELEM_CONST_FLOWREF = ElementId("const_flowref", 85, FORMAT_SCOPE);
ElementId ELEM_CONST_FLOWREF_SIZE = ElementId("const_flowref_size", 86, FORMAT_SCOPE);
ElementId ELEM_CONST_FLOWDEST = ElementId("const_flowdest", 87, FORMAT_SCOPE);
ElementId ELEM_CONST_FLOWDEST_SIZE = ElementId("const_flowdest_size", 88, FORMAT_SCOPE);

/// The bytes of the header are read from the stream and verified against the required form and current version.
/// If the form matches, \b true is returned.  No additional bytes are read.
/// \param s is the given stream
/// \return \b true if a valid header is present
bool isSlaFormat(istream &s)

{
  uint1 header[4];
  s.read((char *)header,4);
  if (!s)
    return false;
  if (header[0] != 's' || header[1] != 'l' || header[2] != 'a')
    return false;
  if (header[3] != FORMAT_VERSION)
    return false;
  return true;
}

/// A valid header, including the format version number, is written to the stream.
/// \param s is the given stream
void writeSlaHeader(ostream &s)

{
  char header[4];
  header[0] = 's';
  header[1] = 'l';
  header[2] = 'a';
  header[3] = FORMAT_VERSION;
  s.write(header,4);
}

/// \param s is the backing stream that will receive the final bytes of the .sla file
/// \param level is the compression level
FormatEncode::FormatEncode(ostream &s,int4 level)
  : PackedEncode(compStream), compBuffer(s,level), compStream(&compBuffer)
{
  writeSlaHeader(s);
}

void FormatEncode::flush(void)

{
  compStream.flush();
}

const int4 FormatDecode::IN_BUFFER_SIZE = 4096;

/// \param spcManager is the (uninitialized) manager that will hold decoded address spaces
FormatDecode::FormatDecode(const AddrSpaceManager *spcManager)
  : PackedDecode(spcManager)
{
  inBuffer = new uint1[IN_BUFFER_SIZE];
}

FormatDecode::~FormatDecode(void)

{
  delete [] inBuffer;
}

void FormatDecode::ingestStream(istream &s)

{
  if (!isSlaFormat(s))
    throw LowlevelError("Missing SLA format header");
  Decompress decompressor;
  uint1 *outBuf;
  int4 outAvail = 0;

  while(!decompressor.isFinished()) {
    s.read((char *)inBuffer,IN_BUFFER_SIZE);
    int4 gcount = s.gcount();
    if (gcount == 0)
	break;
    decompressor.input(inBuffer,gcount);
    do {
      if (outAvail == 0) {
	outBuf = allocateNextInputBuffer(0);
	outAvail = BUFFER_SIZE;
      }
      outAvail = decompressor.inflate(outBuf + (BUFFER_SIZE - outAvail), outAvail);
    } while(outAvail == 0);

  }
  endIngest(BUFFER_SIZE - outAvail);
}

}	// End sla namespace
}	// End ghidra namespace
