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
/// \file slaformat.hh
/// \brief Encoding values for the SLA file format
#ifndef __SLAFORMAT__
#define __SLAFORMAT__

#include "compression.hh"
#include "marshal.hh"

namespace ghidra {
namespace sla {

extern const int4 FORMAT_SCOPE;		///< Grouping elements/attributes for SLA file format
extern const int4 FORMAT_VERSION;	///< Current version of the .sla file

extern AttributeId ATTRIB_VAL;		///< SLA format attribute "val"
extern AttributeId ATTRIB_ID;		///< SLA format attribute "id"
extern AttributeId ATTRIB_SPACE;	///< SLA format attribute "space"
extern AttributeId ATTRIB_S;		///< SLA format attribute "s"
extern AttributeId ATTRIB_OFF;		///< SLA format attribute "off"
extern AttributeId ATTRIB_CODE;		///< SLA format attribute "code"
extern AttributeId ATTRIB_MASK;		///< SLA format attribute "mask"
extern AttributeId ATTRIB_INDEX;	///< SLA format attribute "index"
extern AttributeId ATTRIB_NONZERO;	///< SLA format attribute "nonzero"
extern AttributeId ATTRIB_PIECE;	///< SLA format attribute "piece"
extern AttributeId ATTRIB_NAME;		///< SLA format attribute "name"
extern AttributeId ATTRIB_SCOPE;	///< SLA format attribute "scope"
extern AttributeId ATTRIB_STARTBIT;	///< SLA format attribute "startbit"
extern AttributeId ATTRIB_SIZE;		///< SLA format attribute "size"
extern AttributeId ATTRIB_TABLE;	///< SLA format attribute "table"
extern AttributeId ATTRIB_CT;		///< SLA format attribute "ct"
extern AttributeId ATTRIB_MINLEN;	///< SLA format attribute "minlen"
extern AttributeId ATTRIB_BASE;		///< SLA format attribute "base"
extern AttributeId ATTRIB_NUMBER;	///< SLA format attribute "number"
extern AttributeId ATTRIB_CONTEXT;	///< SLA format attribute "context"
extern AttributeId ATTRIB_PARENT;	///< SLA format attribute "parent"
extern AttributeId ATTRIB_SUBSYM;	///< SLA format attribute "subsym"
extern AttributeId ATTRIB_LINE;		///< SLA format attribute "line"
extern AttributeId ATTRIB_SOURCE;	///< SLA format attribute "source"
extern AttributeId ATTRIB_LENGTH;	///< SLA format attribute "length"
extern AttributeId ATTRIB_FIRST;	///< SLA format attribute "first"
extern AttributeId ATTRIB_PLUS;		///< SLA format attribute "plus"
extern AttributeId ATTRIB_SHIFT;	///< SLA format attribute "shift"
extern AttributeId ATTRIB_ENDBIT;	///< SLA format attribute "endbit"
extern AttributeId ATTRIB_SIGNBIT;	///< SLA format attribute "signbit"
extern AttributeId ATTRIB_ENDBYTE;	///< SLA format attribute "endbyte"
extern AttributeId ATTRIB_STARTBYTE;	///< SLA format attribute "startbyte"

extern AttributeId ATTRIB_VERSION;	///< SLA format attribute "version"
extern AttributeId ATTRIB_BIGENDIAN;	///< SLA format attribute "bigendian"
extern AttributeId ATTRIB_ALIGN;	///< SLA format attribute "align"
extern AttributeId ATTRIB_UNIQBASE;	///< SLA format attribute "uniqbase"
extern AttributeId ATTRIB_MAXDELAY;	///< SLA format attribute "maxdelay"
extern AttributeId ATTRIB_UNIQMASK;	///< SLA format attribute "uniqmask"
extern AttributeId ATTRIB_NUMSECTIONS;	///< SLA format attribute "numsections"
extern AttributeId ATTRIB_DEFAULTSPACE;	///< SLA format attribute "defaultspace"
extern AttributeId ATTRIB_DELAY;	///< SLA format attribute "delay"
extern AttributeId ATTRIB_WORDSIZE;	///< SLA format attribute "wordsize"
extern AttributeId ATTRIB_PHYSICAL;	///< SLA format attribute "physical"
extern AttributeId ATTRIB_SCOPESIZE;	///< SLA format attribute "scopesize"
extern AttributeId ATTRIB_SYMBOLSIZE;	///< SLA format attribute "symbolsize"
extern AttributeId ATTRIB_VARNODE;	///< SLA format attribute "varnode"
extern AttributeId ATTRIB_LOW;		///< SLA format attribute "low"
extern AttributeId ATTRIB_HIGH;		///< SLA format attribute "high"
extern AttributeId ATTRIB_FLOW;		///< SLA format attribute "flow"
extern AttributeId ATTRIB_CONTAIN;	///< SLA format attribute "contain"
extern AttributeId ATTRIB_I;		///< SLA format attribute "i"
extern AttributeId ATTRIB_NUMCT;	///< SLA format attribute "numct"
extern AttributeId ATTRIB_SECTION;	///< SLA format attribute "section"
extern AttributeId ATTRIB_LABELS;	///< SLA format attribute "labels"

extern ElementId ELEM_CONST_REAL;	///< SLA format element "const_real"
extern ElementId ELEM_VARNODE_TPL;	///< SLA format element "varnode_tpl"
extern ElementId ELEM_CONST_SPACEID;	///< SLA format element "const_spaceid"
extern ElementId ELEM_CONST_HANDLE;	///< SLA format element "const_handle"
extern ElementId ELEM_OP_TPL;		///< SLA format element "op_tpl"
extern ElementId ELEM_MASK_WORD;	///< SLA format element "mask_word"
extern ElementId ELEM_PAT_BLOCK;	///< SLA format element "pat_block"
extern ElementId ELEM_PRINT;		///< SLA format element "print"
extern ElementId ELEM_PAIR;		///< SLA format element "pair"
extern ElementId ELEM_CONTEXT_PAT;	///< SLA format element "context_pat"
extern ElementId ELEM_NULL;		///< SLA format element "null"
extern ElementId ELEM_OPERAND_EXP;	///< SLA format element "operand_exp"
extern ElementId ELEM_OPERAND_SYM;	///< SLA format element "operand_sym"
extern ElementId ELEM_OPERAND_SYM_HEAD;	///< SLA format element "operand_sym_head"
extern ElementId ELEM_OPER;		///< SLA format element "oper"
extern ElementId ELEM_DECISION;		///< SLA format element "decision"
extern ElementId ELEM_OPPRINT;		///< SLA format element "opprint"
extern ElementId ELEM_INSTRUCT_PAT;	///< SLA format element "instruct_pat"
extern ElementId ELEM_COMBINE_PAT;	///< SLA format element "combine_pat"
extern ElementId ELEM_CONSTRUCTOR;	///< SLA format element "constructor"
extern ElementId ELEM_CONSTRUCT_TPL;	///< SLA format element "construct_tpl"
extern ElementId ELEM_SCOPE;		///< SLA format element "scope"
extern ElementId ELEM_VARNODE_SYM;	///< SLA format element "varnode_sym"
extern ElementId ELEM_VARNODE_SYM_HEAD;	///< SLA format element "varnode_sym_head"
extern ElementId ELEM_USEROP;		///< SLA format element "userop"
extern ElementId ELEM_USEROP_HEAD;	///< SLA format element "userop_head"
extern ElementId ELEM_TOKENFIELD;	///< SLA format element "tokenfield"
extern ElementId ELEM_VAR;		///< SLA format element "var"
extern ElementId ELEM_CONTEXTFIELD;	///< SLA format element "contextfield"
extern ElementId ELEM_HANDLE_TPL;	///< SLA format element "handle_tpl"
extern ElementId ELEM_CONST_RELATIVE;	///< SLA format element "const_relative"
extern ElementId ELEM_CONTEXT_OP;	///< SLA format element "context_op"

extern ElementId ELEM_SLEIGH;		///< SLA format element "sleigh"
extern ElementId ELEM_SPACES;		///< SLA format element "spaces"
extern ElementId ELEM_SOURCEFILES;	///< SLA format element "sourcefiles"
extern ElementId ELEM_SOURCEFILE;	///< SLA format element "sourcefile"
extern ElementId ELEM_SPACE;		///< SLA format element "space"
extern ElementId ELEM_SYMBOL_TABLE;	///< SLA format element "symbol_table"
extern ElementId ELEM_VALUE_SYM;	///< SLA format element "value_sym"
extern ElementId ELEM_VALUE_SYM_HEAD;	///< SLA format element "value_sym_head"
extern ElementId ELEM_CONTEXT_SYM;	///< SLA format element "context_sym"
extern ElementId ELEM_CONTEXT_SYM_HEAD;	///< SLA format element "context_sym_head"
extern ElementId ELEM_END_SYM;		///< SLA format element "end_sym"
extern ElementId ELEM_END_SYM_HEAD;	///< SLA format element "end_sym_head"
extern ElementId ELEM_SPACE_OTHER;	///< SLA format element "space_other"
extern ElementId ELEM_SPACE_UNIQUE;	///< SLA format element "space_unique"
extern ElementId ELEM_AND_EXP;		///< SLA format element "and_exp"
extern ElementId ELEM_DIV_EXP;		///< SLA format element "div_exp"
extern ElementId ELEM_LSHIFT_EXP;	///< SLA format element "lshift_exp"
extern ElementId ELEM_MINUS_EXP;	///< SLA format element "minus_exp"
extern ElementId ELEM_MULT_EXP;		///< SLA format element "mult_exp"
extern ElementId ELEM_NOT_EXP;		///< SLA format element "not_exp"
extern ElementId ELEM_OR_EXP;		///< SLA format element "or_exp"
extern ElementId ELEM_PLUS_EXP;		///< SLA format element "plus_exp"
extern ElementId ELEM_RSHIFT_EXP;	///< SLA format element "rshift_exp"
extern ElementId ELEM_SUB_EXP;		///< SLA format element "sub_exp"
extern ElementId ELEM_XOR_EXP;		///< SLA format element "xor_exp"
extern ElementId ELEM_INTB;		///< SLA format element "intb"
extern ElementId ELEM_END_EXP;		///< SLA format element "end_exp"
extern ElementId ELEM_NEXT2_EXP;	///< SLA format element "next2_exp"
extern ElementId ELEM_START_EXP;	///< SLA format element "start_exp"
extern ElementId ELEM_EPSILON_SYM;	///< SLA format element "epsilon_sym"
extern ElementId ELEM_EPSILON_SYM_HEAD;	///< SLA format element "epsilon_sym_head"
extern ElementId ELEM_NAME_SYM;		///< SLA format element "name_sym"
extern ElementId ELEM_NAME_SYM_HEAD;	///< SLA format element "name_sym_head"
extern ElementId ELEM_NAMETAB;		///< SLA format element "nametab"
extern ElementId ELEM_NEXT2_SYM;	///< SLA format element "next2_sym"
extern ElementId ELEM_NEXT2_SYM_HEAD;	///< SLA format element "next2_sym_head"
extern ElementId ELEM_START_SYM;	///< SLA format element "start_sym"
extern ElementId ELEM_START_SYM_HEAD;	///< SLA format element "start_sym_head"
extern ElementId ELEM_SUBTABLE_SYM;	///< SLA format element "subtable_sym"
extern ElementId ELEM_SUBTABLE_SYM_HEAD;	///< SLA format element "subtable_sym_head"
extern ElementId ELEM_VALUEMAP_SYM;	///< SLA format element "valuemap_sym"
extern ElementId ELEM_VALUEMAP_SYM_HEAD;	///< SLA format element "valuemap_sym_head"
extern ElementId ELEM_VALUETAB;		///< SLA format element "valuetab"
extern ElementId ELEM_VARLIST_SYM;	///< SLA format element "varlist_sym"
extern ElementId ELEM_VARLIST_SYM_HEAD;	///< SLA format element "varlist_sym_head"
extern ElementId ELEM_OR_PAT;		///< SLA format element "or_pat"
extern ElementId ELEM_COMMIT;		///< SLA format element "commit"
extern ElementId ELEM_CONST_START;	///< SLA format element "const_start"
extern ElementId ELEM_CONST_NEXT;	///< SLA format element "const_next"
extern ElementId ELEM_CONST_NEXT2;	///< SLA format element "const_next2"
extern ElementId ELEM_CONST_CURSPACE;	///< SLA format element "curspace"
extern ElementId ELEM_CONST_CURSPACE_SIZE;	///< SLA format element "curspace_size"
extern ElementId ELEM_CONST_FLOWREF;	///< SLA format element "const_flowref"
extern ElementId ELEM_CONST_FLOWREF_SIZE;	///< SLA format element "const_flowref_size"
extern ElementId ELEM_CONST_FLOWDEST;	///< SLA format element "const_flowdest"
extern ElementId ELEM_CONST_FLOWDEST_SIZE;	///< SLA format element "const_flowdest_size"

extern bool isSlaFormat(istream &s);	///< Verify a .sla file header at the current point of the given stream
extern void writeSlaHeader(ostream &s);	///< Write a .sla file header to the given stream

/// \brief The encoder for the .sla file format
///
/// This provides the format header, does compression, and encodes the raw data elements/attributes.
class FormatEncode : public PackedEncode {
  CompressBuffer compBuffer;		///< The compression stream filter
  ostream compStream;			///< The front-end stream receiving uncompressed bytes
public:
  FormatEncode(ostream &s,int4 level);	///< Initialize an encoder at a specific compression level
  void flush(void);			///< Flush any buffered bytes in the encoder to the backing stream
};

/// \brief The decoder for the .sla file format
///
/// This verifies the .sla file header, does decompression, and decodes the raw data elements/attributes.
class FormatDecode : public PackedDecode {
  static const int4 IN_BUFFER_SIZE;	///< The size of the \e input buffer
  uint1 *inBuffer;			///< The \e input buffer
public:
  FormatDecode(const AddrSpaceManager *spcManager);	///< Initialize the decoder
  virtual ~FormatDecode(void);				///< Destructor
  virtual void ingestStream(istream &s);
};

}	// End namespace sla
}	// End namespace ghidra

#endif
