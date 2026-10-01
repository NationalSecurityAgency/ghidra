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

/**
 * An annotation for a specific collection of hierarchical data
 * <p>
 * This record parallels the XML concept of an element.  An ElementId describes a collection of data, where each
 * piece is annotated by a specific AttributeId.  In addition, each ElementId can contain zero or more child
 * ElementId objects, forming a hierarchy of annotated data.  Each ElementId has a name, which is unique at least
 * within the context of its parent ElementId. Internally this name is associated with an integer id. A special
 * AttributeId ATTRIB_CONTENT is used to label the XML element's text content, which is traditionally not labeled
 * as an attribute.
 *
 * @param name unique element name
 * @param id unique element ID
 */
package ghidra.app.plugin.core.decompiler.export;

import java.util.HashMap;
import java.util.Map;

public record PcodeElements(String name, int id) {

	// NB: This class parallels ElementId in FrameworkSoftwareModeling

	private static Map<String, PcodeElements> nlookupElementId = new HashMap<>();
	private static Map<Integer, PcodeElements> ilookupElementId = new HashMap<>();

	public PcodeElements {
		// add new element to lookup map
		if (null != nlookupElementId.put(name, this)) {
			throw new RuntimeException("Duplicate ElementId instance: " + name);
		}
		if (null != ilookupElementId.put(id, this)) {
			throw new RuntimeException("Duplicate ElementId instance: " + name);
		}
	}

	/**
	 * Find the id associated with a specific element name
	 * @param nm the element name
	 * @return the associated id
	 */
	public static PcodeElements find(String nm) {
		return nlookupElementId.getOrDefault(nm, ELEM_UNKNOWN);
	}

	public static PcodeElements find(Integer id) {
		return ilookupElementId.getOrDefault(id, ELEM_UNKNOWN);
	}

	public static final PcodeElements ELEM_DATA = new PcodeElements("data", 1);
	public static final PcodeElements ELEM_INPUT = new PcodeElements("input", 2);
	public static final PcodeElements ELEM_OFF = new PcodeElements("off", 3);
	public static final PcodeElements ELEM_OUTPUT = new PcodeElements("output", 4);
	public static final PcodeElements ELEM_RETURNADDRESS = new PcodeElements("returnaddress", 5);
	public static final PcodeElements ELEM_SYMBOL = new PcodeElements("symbol", 6);
	public static final PcodeElements ELEM_TARGET = new PcodeElements("target", 7);
	public static final PcodeElements ELEM_VAL = new PcodeElements("val", 8);
	public static final PcodeElements ELEM_VALUE = new PcodeElements("value", 9);
	public static final PcodeElements ELEM_VOID = new PcodeElements("void", 10);
	public static final PcodeElements ELEM_ADDR = new PcodeElements("addr", 11);

	// address
	public static final PcodeElements ELEM_RANGE = new PcodeElements("range", 12);
	public static final PcodeElements ELEM_RANGELIST = new PcodeElements("rangelist", 13);
	public static final PcodeElements ELEM_REGISTER = new PcodeElements("register", 14);
	public static final PcodeElements ELEM_SEQNUM = new PcodeElements("seqnum", 15);
	public static final PcodeElements ELEM_VARNODE = new PcodeElements("varnode", 16);

	// prettyprint
	public static final PcodeElements ELEM_BREAK = new PcodeElements("break", 17);
	public static final PcodeElements ELEM_CLANG_DOCUMENT = new PcodeElements("clang_document", 18);
	public static final PcodeElements ELEM_FUNCNAME = new PcodeElements("funcname", 19);
	public static final PcodeElements ELEM_FUNCPROTO = new PcodeElements("funcproto", 20);
	public static final PcodeElements ELEM_LABEL = new PcodeElements("label", 21);
	public static final PcodeElements ELEM_RETURN_TYPE = new PcodeElements("return_type", 22);
	public static final PcodeElements ELEM_STATEMENT = new PcodeElements("statement", 23);
	public static final PcodeElements ELEM_SYNTAX = new PcodeElements("syntax", 24);
	public static final PcodeElements ELEM_VARDECL = new PcodeElements("vardecl", 25);
	public static final PcodeElements ELEM_VARIABLE = new PcodeElements("variable", 26);

	// transform
	public static final PcodeElements ELEM_OP = new PcodeElements("op", 27);
	public static final PcodeElements ELEM_SLEIGH = new PcodeElements("sleigh", 28);
	public static final PcodeElements ELEM_SPACE = new PcodeElements("space", 29);
	public static final PcodeElements ELEM_SPACEID = new PcodeElements("spaceid", 30);
	public static final PcodeElements ELEM_SPACES = new PcodeElements("spaces", 31);
	public static final PcodeElements ELEM_SPACE_BASE = new PcodeElements("space_base", 32);
	public static final PcodeElements ELEM_SPACE_OTHER = new PcodeElements("space_other", 33);
	public static final PcodeElements ELEM_SPACE_OVERLAY = new PcodeElements("space_overlay", 34);
	public static final PcodeElements ELEM_SPACE_UNIQUE = new PcodeElements("space_unique", 35);
	public static final PcodeElements ELEM_TRUNCATE_SPACE = new PcodeElements("truncate_space", 36);

	// type
	public static final PcodeElements ELEM_ABSOLUTE_MAX_ALIGNMENT =
		new PcodeElements("absolute_max_alignment", 37);
	public static final PcodeElements ELEM_BITFIELD_PACKING =
		new PcodeElements("bitfield_packing", 38);
	public static final PcodeElements ELEM_CHAR_SIZE = new PcodeElements("char_size", 39);
	public static final PcodeElements ELEM_CHAR_TYPE = new PcodeElements("char_type", 40);
	public static final PcodeElements ELEM_CORETYPES = new PcodeElements("coretypes", 41);
	public static final PcodeElements ELEM_DATA_ORGANIZATION =
		new PcodeElements("data_organization", 42);
	public static final PcodeElements ELEM_DEF = new PcodeElements("def", 43);
	public static final PcodeElements ELEM_DEFAULT_ALIGNMENT =
		new PcodeElements("default_alignment", 44);
	public static final PcodeElements ELEM_DEFAULT_POINTER_ALIGNMENT =
		new PcodeElements("default_pointer_alignment", 45);
	public static final PcodeElements ELEM_DOUBLE_SIZE = new PcodeElements("double_size", 46);
	public static final PcodeElements ELEM_ENTRY = new PcodeElements("entry", 47);
	public static final PcodeElements ELEM_ENUM = new PcodeElements("enum", 48);
	public static final PcodeElements ELEM_FIELD = new PcodeElements("field", 49);
	public static final PcodeElements ELEM_FLOAT_SIZE = new PcodeElements("float_size", 50);
	public static final PcodeElements ELEM_INTEGER_SIZE = new PcodeElements("integer_size", 51);
	public static final PcodeElements ELEM_LONG_DOUBLE_SIZE =
		new PcodeElements("long_double_size", 52);
	public static final PcodeElements ELEM_LONG_LONG_SIZE = new PcodeElements("long_long_size", 53);
	public static final PcodeElements ELEM_LONG_SIZE = new PcodeElements("long_size", 54);
	public static final PcodeElements ELEM_MACHINE_ALIGNMENT =
		new PcodeElements("machine_alignment", 55);
	public static final PcodeElements ELEM_POINTER_SHIFT = new PcodeElements("pointer_shift", 56);
	public static final PcodeElements ELEM_POINTER_SIZE = new PcodeElements("pointer_size", 57);
	public static final PcodeElements ELEM_SHORT_SIZE = new PcodeElements("short_size", 58);
	public static final PcodeElements ELEM_SIZE_ALIGNMENT_MAP =
		new PcodeElements("size_alignment_map", 59);
	public static final PcodeElements ELEM_TYPE = new PcodeElements("type", 60);
	public static final PcodeElements ELEM_TYPE_ALIGNMENT_ENABLED =
		new PcodeElements("type_alignment_enabled", 61);
	public static final PcodeElements ELEM_TYPEGRP = new PcodeElements("typegrp", 62);
	public static final PcodeElements ELEM_TYPEREF = new PcodeElements("typeref", 63);
	public static final PcodeElements ELEM_USE_MS_CONVENTION =
		new PcodeElements("use_MS_convention", 64);
	public static final PcodeElements ELEM_WCHAR_SIZE = new PcodeElements("wchar_size", 65);
	public static final PcodeElements ELEM_ZERO_LENGTH_BOUNDARY =
		new PcodeElements("zero_length_boundary", 66);
	public static final PcodeElements ELEM_BITFIELD = new PcodeElements("bitfield", 289);

	// database
	public static final PcodeElements ELEM_COLLISION = new PcodeElements("collision", 67);
	public static final PcodeElements ELEM_DB = new PcodeElements("db", 68);
	public static final PcodeElements ELEM_EQUATESYMBOL = new PcodeElements("equatesymbol", 69);
	public static final PcodeElements ELEM_EXTERNREFSYMBOL =
		new PcodeElements("externrefsymbol", 70);
	public static final PcodeElements ELEM_FACETSYMBOL = new PcodeElements("facetsymbol", 71);
	public static final PcodeElements ELEM_FUNCTIONSHELL = new PcodeElements("functionshell", 72);
	public static final PcodeElements ELEM_HASH = new PcodeElements("hash", 73);
	public static final PcodeElements ELEM_HOLE = new PcodeElements("hole", 74);
	public static final PcodeElements ELEM_LABELSYM = new PcodeElements("labelsym", 75);
	public static final PcodeElements ELEM_MAPSYM = new PcodeElements("mapsym", 76);
	public static final PcodeElements ELEM_PARENT = new PcodeElements("parent", 77);
	public static final PcodeElements ELEM_PROPERTY_CHANGEPOINT =
		new PcodeElements("property_changepoint", 78);
	public static final PcodeElements ELEM_RANGEEQUALSSYMBOLS =
		new PcodeElements("rangeequalssymbols", 79);
	public static final PcodeElements ELEM_SCOPE = new PcodeElements("scope", 80);
	public static final PcodeElements ELEM_SYMBOLLIST = new PcodeElements("symbollist", 81);

	// variable
	public static final PcodeElements ELEM_HIGH = new PcodeElements("high", 82);

	// stringmanage
	public static final PcodeElements ELEM_BYTES = new PcodeElements("bytes", 83);
	public static final PcodeElements ELEM_STRING = new PcodeElements("string", 84);
	public static final PcodeElements ELEM_STRINGMANAGE = new PcodeElements("stringmanage", 85);

	// comment
	public static final PcodeElements ELEM_COMMENT = new PcodeElements("comment", 86);
	public static final PcodeElements ELEM_COMMENTDB = new PcodeElements("commentdb", 87);
	public static final PcodeElements ELEM_TEXT = new PcodeElements("text", 88);

	// pcodeinject
	public static final PcodeElements ELEM_ADDR_PCODE = new PcodeElements("addr_pcode", 89);
	public static final PcodeElements ELEM_BODY = new PcodeElements("body", 90);
	public static final PcodeElements ELEM_CALLFIXUP = new PcodeElements("callfixup", 91);
	public static final PcodeElements ELEM_CALLOTHERFIXUP = new PcodeElements("callotherfixup", 92);
	public static final PcodeElements ELEM_CASE_PCODE = new PcodeElements("case_pcode", 93);
	public static final PcodeElements ELEM_CONTEXT = new PcodeElements("context", 94);
	public static final PcodeElements ELEM_DEFAULT_PCODE = new PcodeElements("default_pcode", 95);
	public static final PcodeElements ELEM_INJECT = new PcodeElements("inject", 96);
	public static final PcodeElements ELEM_INJECTDEBUG = new PcodeElements("injectdebug", 97);
	public static final PcodeElements ELEM_INST = new PcodeElements("inst", 98);
	public static final PcodeElements ELEM_PAYLOAD = new PcodeElements("payload", 99);
	public static final PcodeElements ELEM_PCODE = new PcodeElements("pcode", 100);
	public static final PcodeElements ELEM_SIZE_PCODE = new PcodeElements("size_pcode", 101);

	// block
	public static final PcodeElements ELEM_BHEAD = new PcodeElements("bhead", 102);
	public static final PcodeElements ELEM_BLOCK = new PcodeElements("block", 103);
	public static final PcodeElements ELEM_BLOCKEDGE = new PcodeElements("blockedge", 104);
	public static final PcodeElements ELEM_EDGE = new PcodeElements("edge", 105);

	// paramid
	public static final PcodeElements ELEM_PARAMMEASURES = new PcodeElements("parammeasures", 106);
	public static final PcodeElements ELEM_PROTO = new PcodeElements("proto", 107);
	public static final PcodeElements ELEM_RANK = new PcodeElements("rank", 108);

	// cpool
	public static final PcodeElements ELEM_CONSTANTPOOL = new PcodeElements("constantpool", 109);
	public static final PcodeElements ELEM_CPOOLREC = new PcodeElements("cpoolrec", 110);
	public static final PcodeElements ELEM_REF = new PcodeElements("ref", 111);
	public static final PcodeElements ELEM_TOKEN = new PcodeElements("token", 112);

	// op
	public static final PcodeElements ELEM_IOP = new PcodeElements("iop", 113);
	public static final PcodeElements ELEM_UNIMPL = new PcodeElements("unimpl", 114);

	// funcdata
	public static final PcodeElements ELEM_AST = new PcodeElements("ast", 115);
	public static final PcodeElements ELEM_FUNCTION = new PcodeElements("function", 116);
	public static final PcodeElements ELEM_HIGHLIST = new PcodeElements("highlist", 117);
	public static final PcodeElements ELEM_JUMPTABLELIST = new PcodeElements("jumptablelist", 118);
	public static final PcodeElements ELEM_VARNODES = new PcodeElements("varnodes", 119);

	// globalcontext
	public static final PcodeElements ELEM_CONTEXT_DATA = new PcodeElements("context_data", 120);
	public static final PcodeElements ELEM_CONTEXT_POINTS =
		new PcodeElements("context_points", 121);
	public static final PcodeElements ELEM_CONTEXT_POINTSET =
		new PcodeElements("context_pointset", 122);
	public static final PcodeElements ELEM_CONTEXT_SET = new PcodeElements("context_set", 123);
	public static final PcodeElements ELEM_SET = new PcodeElements("set", 124);
	public static final PcodeElements ELEM_TRACKED_POINTSET =
		new PcodeElements("tracked_pointset", 125);
	public static final PcodeElements ELEM_TRACKED_SET = new PcodeElements("tracked_set", 126);

	// userop
	public static final PcodeElements ELEM_CONSTRESOLVE = new PcodeElements("constresolve", 127);
	public static final PcodeElements ELEM_JUMPASSIST = new PcodeElements("jumpassist", 128);
	public static final PcodeElements ELEM_SEGMENTOP = new PcodeElements("segmentop", 129);

	// architecture
	public static final PcodeElements ELEM_ADDRESS_SHIFT_AMOUNT =
		new PcodeElements("address_shift_amount", 130);
	public static final PcodeElements ELEM_AGGRESSIVETRIM =
		new PcodeElements("aggressivetrim", 131);
	public static final PcodeElements ELEM_COMPILER_SPEC = new PcodeElements("compiler_spec", 132);
	public static final PcodeElements ELEM_DATA_SPACE = new PcodeElements("data_space", 133);
	public static final PcodeElements ELEM_DEFAULT_MEMORY_BLOCKS =
		new PcodeElements("default_memory_blocks", 134);
	public static final PcodeElements ELEM_DEFAULT_PROTO = new PcodeElements("default_proto", 135);
	public static final PcodeElements ELEM_DEFAULT_SYMBOLS =
		new PcodeElements("default_symbols", 136);
	public static final PcodeElements ELEM_EVAL_CALLED_PROTOTYPE =
		new PcodeElements("eval_called_prototype", 137);
	public static final PcodeElements ELEM_EVAL_CURRENT_PROTOTYPE =
		new PcodeElements("eval_current_prototype", 138);
	public static final PcodeElements ELEM_EXPERIMENTAL_RULES =
		new PcodeElements("experimental_rules", 139);
	public static final PcodeElements ELEM_FLOWOVERRIDELIST =
		new PcodeElements("flowoverridelist", 140);
	public static final PcodeElements ELEM_FUNCPTR = new PcodeElements("funcptr", 141);
	public static final PcodeElements ELEM_GLOBAL = new PcodeElements("global", 142);
	public static final PcodeElements ELEM_INCIDENTALCOPY =
		new PcodeElements("incidentalcopy", 143);
	public static final PcodeElements ELEM_INFERPTRBOUNDS =
		new PcodeElements("inferptrbounds", 144);
	public static final PcodeElements ELEM_MODELALIAS = new PcodeElements("modelalias", 145);
	public static final PcodeElements ELEM_NOHIGHPTR = new PcodeElements("nohighptr", 146);
	public static final PcodeElements ELEM_PROCESSOR_SPEC =
		new PcodeElements("processor_spec", 147);
	public static final PcodeElements ELEM_PROGRAMCOUNTER =
		new PcodeElements("programcounter", 148);
	public static final PcodeElements ELEM_PROPERTIES = new PcodeElements("properties", 149);
	public static final PcodeElements ELEM_PROPERTY = new PcodeElements("property", 150);
	public static final PcodeElements ELEM_READONLY = new PcodeElements("readonly", 151);
	public static final PcodeElements ELEM_REGISTER_DATA = new PcodeElements("register_data", 152);
	public static final PcodeElements ELEM_RULE = new PcodeElements("rule", 153);
	public static final PcodeElements ELEM_SAVE_STATE = new PcodeElements("save_state", 154);
	public static final PcodeElements ELEM_SEGMENTED_ADDRESS =
		new PcodeElements("segmented_address", 155);
	public static final PcodeElements ELEM_SPACEBASE = new PcodeElements("spacebase", 156);
	public static final PcodeElements ELEM_SPECEXTENSIONS =
		new PcodeElements("specextensions", 157);
	public static final PcodeElements ELEM_STACKPOINTER = new PcodeElements("stackpointer", 158);
	public static final PcodeElements ELEM_VOLATILE = new PcodeElements("volatile", 159);

	// fspec
	public static final PcodeElements ELEM_GROUP = new PcodeElements("group", 160);
	public static final PcodeElements ELEM_INTERNALLIST = new PcodeElements("internallist", 161);
	public static final PcodeElements ELEM_KILLEDBYCALL = new PcodeElements("killedbycall", 162);
	public static final PcodeElements ELEM_LIKELYTRASH = new PcodeElements("likelytrash", 163);
	public static final PcodeElements ELEM_LOCALRANGE = new PcodeElements("localrange", 164);
	public static final PcodeElements ELEM_MODEL = new PcodeElements("model", 165);
	public static final PcodeElements ELEM_PARAM = new PcodeElements("param", 166);
	public static final PcodeElements ELEM_PARAMRANGE = new PcodeElements("paramrange", 167);
	public static final PcodeElements ELEM_PENTRY = new PcodeElements("pentry", 168);
	public static final PcodeElements ELEM_PROTOTYPE = new PcodeElements("prototype", 169);
	public static final PcodeElements ELEM_RESOLVEPROTOTYPE =
		new PcodeElements("resolveprototype", 170);
	public static final PcodeElements ELEM_RETPARAM = new PcodeElements("retparam", 171);
	public static final PcodeElements ELEM_RETURNSYM = new PcodeElements("returnsym", 172);
	public static final PcodeElements ELEM_UNAFFECTED = new PcodeElements("unaffected", 173);
	public static final PcodeElements ELEM_INTERNAL_STORAGE =
		new PcodeElements("internal_storage", 286);

	// options
	public static final PcodeElements ELEM_ALIASBLOCK = new PcodeElements("aliasblock", 174);
	public static final PcodeElements ELEM_ALLOWCONTEXTSET =
		new PcodeElements("allowcontextset", 175);
	public static final PcodeElements ELEM_ANALYZEFORLOOPS =
		new PcodeElements("analyzeforloops", 176);
	public static final PcodeElements ELEM_COMMENTHEADER = new PcodeElements("commentheader", 177);
	public static final PcodeElements ELEM_COMMENTINDENT = new PcodeElements("commentindent", 178);
	public static final PcodeElements ELEM_COMMENTINSTRUCTION =
		new PcodeElements("commentinstruction", 179);
	public static final PcodeElements ELEM_COMMENTSTYLE = new PcodeElements("commentstyle", 180);
	public static final PcodeElements ELEM_CONVENTIONPRINTING =
		new PcodeElements("conventionprinting", 181);
	public static final PcodeElements ELEM_CURRENTACTION = new PcodeElements("currentaction", 182);
	public static final PcodeElements ELEM_DEFAULTPROTOTYPE =
		new PcodeElements("defaultprototype", 183);
	public static final PcodeElements ELEM_ERRORREINTERPRETED =
		new PcodeElements("errorreinterpreted", 184);
	public static final PcodeElements ELEM_ERRORTOOMANYINSTRUCTIONS =
		new PcodeElements("errortoomanyinstructions", 185);
	public static final PcodeElements ELEM_ERRORUNIMPLEMENTED =
		new PcodeElements("errorunimplemented", 186);
	public static final PcodeElements ELEM_BADDATACOUNT = new PcodeElements("baddatacount", 290);
	public static final PcodeElements ELEM_EXTRAPOP = new PcodeElements("extrapop", 187);
	public static final PcodeElements ELEM_IGNOREUNIMPLEMENTED =
		new PcodeElements("ignoreunimplemented", 188);
	public static final PcodeElements ELEM_INDENTINCREMENT =
		new PcodeElements("indentincrement", 189);
	public static final PcodeElements ELEM_INFERCONSTPTR = new PcodeElements("inferconstptr", 190);
	public static final PcodeElements ELEM_INLINE = new PcodeElements("inline", 191);
	public static final PcodeElements ELEM_INPLACEOPS = new PcodeElements("inplaceops", 192);
	public static final PcodeElements ELEM_INTEGERFORMAT = new PcodeElements("integerformat", 193);
	public static final PcodeElements ELEM_JUMPLOAD = new PcodeElements("jumpload", 194);
	public static final PcodeElements ELEM_MAXINSTRUCTION =
		new PcodeElements("maxinstruction", 195);
	public static final PcodeElements ELEM_MAXLINEWIDTH = new PcodeElements("maxlinewidth", 196);
	public static final PcodeElements ELEM_NAMESPACESTRATEGY =
		new PcodeElements("namespacestrategy", 197);
	public static final PcodeElements ELEM_NOCASTPRINTING =
		new PcodeElements("nocastprinting", 198);
	public static final PcodeElements ELEM_NORETURN = new PcodeElements("noreturn", 199);
	public static final PcodeElements ELEM_NULLPRINTING = new PcodeElements("nullprinting", 200);
	public static final PcodeElements ELEM_OPTIONSLIST = new PcodeElements("optionslist", 201);
	public static final PcodeElements ELEM_PARAM1 = new PcodeElements("param1", 202);
	public static final PcodeElements ELEM_PARAM2 = new PcodeElements("param2", 203);
	public static final PcodeElements ELEM_PARAM3 = new PcodeElements("param3", 204);
	public static final PcodeElements ELEM_PROTOEVAL = new PcodeElements("protoeval", 205);
	public static final PcodeElements ELEM_SETACTION = new PcodeElements("setaction", 206);
	public static final PcodeElements ELEM_SETLANGUAGE = new PcodeElements("setlanguage", 207);
	public static final PcodeElements ELEM_STRUCTALIGN = new PcodeElements("structalign", 208);
	public static final PcodeElements ELEM_TOGGLERULE = new PcodeElements("togglerule", 209);
	public static final PcodeElements ELEM_WARNING = new PcodeElements("warning", 210);

	public static final PcodeElements ELEM_BRACEFORMAT = new PcodeElements("braceformat", 284);

	// jumptable
	public static final PcodeElements ELEM_BASICOVERRIDE = new PcodeElements("basicoverride", 211);
	public static final PcodeElements ELEM_DEST = new PcodeElements("dest", 212);
	public static final PcodeElements ELEM_JUMPTABLE = new PcodeElements("jumptable", 213);
	public static final PcodeElements ELEM_LOADTABLE = new PcodeElements("loadtable", 214);
	public static final PcodeElements ELEM_NORMADDR = new PcodeElements("normaddr", 215);
	public static final PcodeElements ELEM_NORMHASH = new PcodeElements("normhash", 216);
	public static final PcodeElements ELEM_STARTVAL = new PcodeElements("startval", 217);

	// override
	public static final PcodeElements ELEM_DEADCODEDELAY = new PcodeElements("deadcodedelay", 218);
	public static final PcodeElements ELEM_FLOW = new PcodeElements("flow", 219);
//	public static final ElementId ELEM_FORCEGOTO = new ElementId("forcegoto", 220);
	public static final PcodeElements ELEM_CALLDEST = new PcodeElements("calldest", 221);
//	public static final ElementId ELEM_MULTISTAGEJUMP = new ElementId("multistagejump", 222);
	public static final PcodeElements ELEM_OVERRIDE = new PcodeElements("override", 223);
	public static final PcodeElements ELEM_PROTOOVERRIDE = new PcodeElements("protooverride", 224);

	// prefersplit
	public static final PcodeElements ELEM_PREFERSPLIT = new PcodeElements("prefersplit", 225);

	// callgraph
	public static final PcodeElements ELEM_CALLGRAPH = new PcodeElements("callgraph", 226);
	public static final PcodeElements ELEM_NODE = new PcodeElements("node", 227);

	// varmap
	public static final PcodeElements ELEM_LOCALDB = new PcodeElements("localdb", 228);

	// ghidra_process
	public static final PcodeElements ELEM_DOC = new PcodeElements("doc", 229);

	// loadimage_xml
//	public static final ElementId ELEM_BINARYIMAGE = new ElementId("binaryimage", 230);
//	public static final ElementId ELEM_BYTECHUNK = new ElementId("bytechunk", 231);

	// sleigh_arch
//	public static final ElementId ELEM_COMPILER = new ElementId("compiler", 232);
//	public static final ElementId ELEM_DESCRIPTION = new ElementId("description", 233);
//	public static final ElementId ELEM_LANGUAGE = new ElementId("language", 234);
//	public static final ElementId ELEM_LANGUAGE_DEFINITIONS =
//		new ElementId("language_definitions", 235);

	// xml_arch
//	public static final ElementId ELEM_XML_SAVEFILE = new ElementId("xml_savefile", 236);

	// raw_arch
//	public static final ElementId ELEM_RAW_SAVEFILE = new ElementId("raw_savefile", 237);

	// ghidra_arch
	public static final int COMMAND_ISNAMEUSED = 239;
	public static final PcodeElements ELEM_COMMAND_ISNAMEUSED =
		new PcodeElements("command_isnameused", COMMAND_ISNAMEUSED);
	public static final int COMMAND_GETBYTES = 240;
	public static final PcodeElements ELEM_COMMAND_GETBYTES =
		new PcodeElements("command_getbytes", COMMAND_GETBYTES);
	public static final int COMMAND_GETCALLFIXUP = 241;
	public static final PcodeElements ELEM_COMMAND_GETCALLFIXUP =
		new PcodeElements("command_getcallfixup", COMMAND_GETCALLFIXUP);
	public static final int COMMAND_GETCALLMECH = 242;
	public static final PcodeElements ELEM_COMMAND_GETCALLMECH =
		new PcodeElements("command_getcallmech", COMMAND_GETCALLMECH);
	public static final int COMMAND_GETCALLOTHERFIXUP = 243;
	public static final PcodeElements ELEM_COMMAND_GETCALLOTHERFIXUP =
		new PcodeElements("command_getcallotherfixup", COMMAND_GETCALLOTHERFIXUP);
	public static final int COMMAND_GETCODELABEL = 244;
	public static final PcodeElements ELEM_COMMAND_GETCODELABEL =
		new PcodeElements("command_getcodelabel", COMMAND_GETCODELABEL);
	public static final int COMMAND_GETCOMMENTS = 245;
	public static final PcodeElements ELEM_COMMAND_GETCOMMENTS =
		new PcodeElements("command_getcomments", COMMAND_GETCOMMENTS);
	public static final int COMMAND_GETCPOOLREF = 246;
	public static final PcodeElements ELEM_COMMAND_GETCPOOLREF =
		new PcodeElements("command_getcpoolref", COMMAND_GETCPOOLREF);
	public static final int COMMAND_GETDATATYPE = 247;
	public static final PcodeElements ELEM_COMMAND_GETDATATYPE =
		new PcodeElements("command_getdatatype", COMMAND_GETDATATYPE);
	public static final int COMMAND_GETEXTERNALREF = 248;
	public static final PcodeElements ELEM_COMMAND_GETEXTERNALREF =
		new PcodeElements("command_getexternalref", COMMAND_GETEXTERNALREF);
	public static final int COMMAND_GETMAPPEDSYMBOLS = 249;
	public static final PcodeElements ELEM_COMMAND_GETMAPPEDSYMBOLS =
		new PcodeElements("command_getmappedsymbols", COMMAND_GETMAPPEDSYMBOLS);
	public static final int COMMAND_GETNAMESPACEPATH = 250;
	public static final PcodeElements ELEM_COMMAND_GETNAMESPACEPATH =
		new PcodeElements("command_getnamespacepath", COMMAND_GETNAMESPACEPATH);
	public static final int COMMAND_GETPCODE = 251;
	public static final PcodeElements ELEM_COMMAND_GETPCODE =
		new PcodeElements("command_getpcode", COMMAND_GETPCODE);
	public static final int COMMAND_GETPCODEEXECUTABLE = 252;
	public static final PcodeElements ELEM_COMMAND_GETPCODEEXECUTABLE =
		new PcodeElements("command_getpcodeexecutable", COMMAND_GETPCODEEXECUTABLE);
	public static final int COMMAND_GETREGISTER = 253;
	public static final PcodeElements ELEM_COMMAND_GETREGISTER =
		new PcodeElements("command_getregister", COMMAND_GETREGISTER);
	public static final int COMMAND_GETREGISTERNAME = 254;
	public static final PcodeElements ELEM_COMMAND_GETREGISTERNAME =
		new PcodeElements("command_getregistername", COMMAND_GETREGISTERNAME);
	public static final int COMMAND_GETSTRINGDATA = 255;
	public static final PcodeElements ELEM_COMMAND_GETSTRINGDATA =
		new PcodeElements("command_getstring", COMMAND_GETSTRINGDATA);
	public static final int COMMAND_GETTRACKEDREGISTERS = 256;
	public static final PcodeElements ELEM_COMMAND_GETTRACKEDREGISTERS =
		new PcodeElements("command_gettrackedregisters", COMMAND_GETTRACKEDREGISTERS);
	public static final int COMMAND_GETUSEROPNAME = 257;
	public static final PcodeElements ELEM_COMMAND_GETUSEROPNAME =
		new PcodeElements("command_getuseropname", COMMAND_GETUSEROPNAME);

	// signature
	public static final PcodeElements ELEM_BLOCKSIG = new PcodeElements("blocksig", 258);
	public static final PcodeElements ELEM_CALL = new PcodeElements("call", 259);
	public static final PcodeElements ELEM_GENSIG = new PcodeElements("gensig", 260);
	public static final PcodeElements ELEM_MAJOR = new PcodeElements("major", 261);
	public static final PcodeElements ELEM_MINOR = new PcodeElements("minor", 262);
	public static final PcodeElements ELEM_COPYSIG = new PcodeElements("copysig", 263);
	public static final PcodeElements ELEM_SETTINGS = new PcodeElements("settings", 264);
	public static final PcodeElements ELEM_SIG = new PcodeElements("sig", 265);
	public static final PcodeElements ELEM_SIGNATUREDESC = new PcodeElements("signaturedesc", 266);
	public static final PcodeElements ELEM_SIGNATURES = new PcodeElements("signatures", 267);
	public static final PcodeElements ELEM_SIGSETTINGS = new PcodeElements("sigsettings", 268);
	public static final PcodeElements ELEM_VARSIG = new PcodeElements("varsig", 269);

	public static final PcodeElements ELEM_SPLITDATATYPE = new PcodeElements("splitdatatype", 270);
	public static final PcodeElements ELEM_JUMPTABLEMAX = new PcodeElements("jumptablemax", 271);
	public static final PcodeElements ELEM_NANIGNORE = new PcodeElements("nanignore", 272);

	// modelrules
	public static final PcodeElements ELEM_DATATYPE = new PcodeElements("datatype", 273);
	public static final PcodeElements ELEM_CONSUME = new PcodeElements("consume", 274);
	public static final PcodeElements ELEM_CONSUME_EXTRA = new PcodeElements("consume_extra", 275);
	public static final PcodeElements ELEM_CONVERT_TO_PTR =
		new PcodeElements("convert_to_ptr", 276);
	public static final PcodeElements ELEM_GOTO_STACK = new PcodeElements("goto_stack", 277);
	public static final PcodeElements ELEM_JOIN = new PcodeElements("join", 278);
	public static final PcodeElements ELEM_DATATYPE_AT = new PcodeElements("datatype_at", 279);
	public static final PcodeElements ELEM_POSITION = new PcodeElements("position", 280);
	public static final PcodeElements ELEM_VARARGS = new PcodeElements("varargs", 281);
	public static final PcodeElements ELEM_HIDDEN_RETURN = new PcodeElements("hidden_return", 282);
	public static final PcodeElements ELEM_JOIN_PER_PRIMITIVE =
		new PcodeElements("join_per_primitive", 283);
	public static final PcodeElements ELEM_JOIN_DUAL_CLASS =
		new PcodeElements("join_dual_class", 285);
	public static final PcodeElements ELEM_EXTRA_STACK = new PcodeElements("extra_stack", 287);
	public static final PcodeElements ELEM_CONSUME_REMAINING =
		new PcodeElements("consume_remaining", 288);

	public static final PcodeElements ELEM_UNKNOWN = new PcodeElements("XMLunknown", 291);
}
