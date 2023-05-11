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
package ghidra.program.model.pcode;

/**
 * An annotation for a specific collection of hierarchical data
 *
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
public record ElementId(String name, int id) {

//	private static HashMap<String, ElementId> lookupElementId = new HashMap<>();

//	public ElementId {
//		// add new element to lookup map
//		if (null != lookupElementId.put(name, this)) {
//			throw new RuntimeException("Duplicate ElementId instance: " + name);
//		}
//	}

//	/**
//	 * Find the id associated with a specific element name
//	 * @param nm the element name
//	 * @return the associated id
//	 */
//	public static int find(String nm) {
//		ElementId res = lookupElementId.getOrDefault(nm, ELEM_UNKNOWN);
//		return res.id;
//	}

	public static final ElementId ELEM_DATA = new ElementId("data", 1);
	public static final ElementId ELEM_INPUT = new ElementId("input", 2);
	public static final ElementId ELEM_OFF = new ElementId("off", 3);
	public static final ElementId ELEM_OUTPUT = new ElementId("output", 4);
	public static final ElementId ELEM_RETURNADDRESS = new ElementId("returnaddress", 5);
	public static final ElementId ELEM_SYMBOL = new ElementId("symbol", 6);
	public static final ElementId ELEM_TARGET = new ElementId("target", 7);
	public static final ElementId ELEM_VAL = new ElementId("val", 8);
	public static final ElementId ELEM_VALUE = new ElementId("value", 9);
	public static final ElementId ELEM_VOID = new ElementId("void", 10);
	public static final ElementId ELEM_ADDR = new ElementId("addr", 11);

	// address
	public static final ElementId ELEM_RANGE = new ElementId("range", 12);
	public static final ElementId ELEM_RANGELIST = new ElementId("rangelist", 13);
	public static final ElementId ELEM_REGISTER = new ElementId("register", 14);
	public static final ElementId ELEM_SEQNUM = new ElementId("seqnum", 15);
	public static final ElementId ELEM_VARNODE = new ElementId("varnode", 16);

	// prettyprint
	public static final ElementId ELEM_BREAK = new ElementId("break", 17);
	public static final ElementId ELEM_CLANG_DOCUMENT = new ElementId("clang_document", 18);
	public static final ElementId ELEM_FUNCNAME = new ElementId("funcname", 19);
	public static final ElementId ELEM_FUNCPROTO = new ElementId("funcproto", 20);
	public static final ElementId ELEM_LABEL = new ElementId("label", 21);
	public static final ElementId ELEM_RETURN_TYPE = new ElementId("return_type", 22);
	public static final ElementId ELEM_STATEMENT = new ElementId("statement", 23);
	public static final ElementId ELEM_SYNTAX = new ElementId("syntax", 24);
	public static final ElementId ELEM_VARDECL = new ElementId("vardecl", 25);
	public static final ElementId ELEM_VARIABLE = new ElementId("variable", 26);

	// transform
	public static final ElementId ELEM_OP = new ElementId("op", 27);
	public static final ElementId ELEM_SLEIGH = new ElementId("sleigh", 28);
	public static final ElementId ELEM_SPACE = new ElementId("space", 29);
	public static final ElementId ELEM_SPACEID = new ElementId("spaceid", 30);
	public static final ElementId ELEM_SPACES = new ElementId("spaces", 31);
	public static final ElementId ELEM_SPACE_BASE = new ElementId("space_base", 32);
	public static final ElementId ELEM_SPACE_OTHER = new ElementId("space_other", 33);
	public static final ElementId ELEM_SPACE_OVERLAY = new ElementId("space_overlay", 34);
	public static final ElementId ELEM_SPACE_UNIQUE = new ElementId("space_unique", 35);
	public static final ElementId ELEM_TRUNCATE_SPACE = new ElementId("truncate_space", 36);

	// type
	public static final ElementId ELEM_ABSOLUTE_MAX_ALIGNMENT =
		new ElementId("absolute_max_alignment", 37);
	public static final ElementId ELEM_BITFIELD_PACKING = new ElementId("bitfield_packing", 38);
	public static final ElementId ELEM_CHAR_SIZE = new ElementId("char_size", 39);
	public static final ElementId ELEM_CHAR_TYPE = new ElementId("char_type", 40);
	public static final ElementId ELEM_CORETYPES = new ElementId("coretypes", 41);
	public static final ElementId ELEM_DATA_ORGANIZATION = new ElementId("data_organization", 42);
	public static final ElementId ELEM_DEF = new ElementId("def", 43);
	public static final ElementId ELEM_DEFAULT_ALIGNMENT = new ElementId("default_alignment", 44);
	public static final ElementId ELEM_DEFAULT_POINTER_ALIGNMENT =
		new ElementId("default_pointer_alignment", 45);
	public static final ElementId ELEM_DOUBLE_SIZE = new ElementId("double_size", 46);
	public static final ElementId ELEM_ENTRY = new ElementId("entry", 47);
	public static final ElementId ELEM_ENUM = new ElementId("enum", 48);
	public static final ElementId ELEM_FIELD = new ElementId("field", 49);
	public static final ElementId ELEM_FLOAT_SIZE = new ElementId("float_size", 50);
	public static final ElementId ELEM_INTEGER_SIZE = new ElementId("integer_size", 51);
	public static final ElementId ELEM_LONG_DOUBLE_SIZE = new ElementId("long_double_size", 52);
	public static final ElementId ELEM_LONG_LONG_SIZE = new ElementId("long_long_size", 53);
	public static final ElementId ELEM_LONG_SIZE = new ElementId("long_size", 54);
	public static final ElementId ELEM_MACHINE_ALIGNMENT = new ElementId("machine_alignment", 55);
	public static final ElementId ELEM_POINTER_SHIFT = new ElementId("pointer_shift", 56);
	public static final ElementId ELEM_POINTER_SIZE = new ElementId("pointer_size", 57);
	public static final ElementId ELEM_SHORT_SIZE = new ElementId("short_size", 58);
	public static final ElementId ELEM_SIZE_ALIGNMENT_MAP = new ElementId("size_alignment_map", 59);
	public static final ElementId ELEM_TYPE = new ElementId("type", 60);
	public static final ElementId ELEM_TYPE_ALIGNMENT_ENABLED =
		new ElementId("type_alignment_enabled", 61);
	public static final ElementId ELEM_TYPEGRP = new ElementId("typegrp", 62);
	public static final ElementId ELEM_TYPEREF = new ElementId("typeref", 63);
	public static final ElementId ELEM_USE_MS_CONVENTION = new ElementId("use_MS_convention", 64);
	public static final ElementId ELEM_WCHAR_SIZE = new ElementId("wchar_size", 65);
	public static final ElementId ELEM_ZERO_LENGTH_BOUNDARY =
		new ElementId("zero_length_boundary", 66);

	// database
	public static final ElementId ELEM_COLLISION = new ElementId("collision", 67);
	public static final ElementId ELEM_DB = new ElementId("db", 68);
	public static final ElementId ELEM_EQUATESYMBOL = new ElementId("equatesymbol", 69);
	public static final ElementId ELEM_EXTERNREFSYMBOL = new ElementId("externrefsymbol", 70);
	public static final ElementId ELEM_FACETSYMBOL = new ElementId("facetsymbol", 71);
	public static final ElementId ELEM_FUNCTIONSHELL = new ElementId("functionshell", 72);
	public static final ElementId ELEM_HASH = new ElementId("hash", 73);
	public static final ElementId ELEM_HOLE = new ElementId("hole", 74);
	public static final ElementId ELEM_LABELSYM = new ElementId("labelsym", 75);
	public static final ElementId ELEM_MAPSYM = new ElementId("mapsym", 76);
	public static final ElementId ELEM_PARENT = new ElementId("parent", 77);
	public static final ElementId ELEM_PROPERTY_CHANGEPOINT =
		new ElementId("property_changepoint", 78);
	public static final ElementId ELEM_RANGEEQUALSSYMBOLS = new ElementId("rangeequalssymbols", 79);
	public static final ElementId ELEM_SCOPE = new ElementId("scope", 80);
	public static final ElementId ELEM_SYMBOLLIST = new ElementId("symbollist", 81);

	// variable
	public static final ElementId ELEM_HIGH = new ElementId("high", 82);

	// stringmanage
	public static final ElementId ELEM_BYTES = new ElementId("bytes", 83);
	public static final ElementId ELEM_STRING = new ElementId("string", 84);
	public static final ElementId ELEM_STRINGMANAGE = new ElementId("stringmanage", 85);

	// comment
	public static final ElementId ELEM_COMMENT = new ElementId("comment", 86);
	public static final ElementId ELEM_COMMENTDB = new ElementId("commentdb", 87);
	public static final ElementId ELEM_TEXT = new ElementId("text", 88);

	// pcodeinject
	public static final ElementId ELEM_ADDR_PCODE = new ElementId("addr_pcode", 89);
	public static final ElementId ELEM_BODY = new ElementId("body", 90);
	public static final ElementId ELEM_CALLFIXUP = new ElementId("callfixup", 91);
	public static final ElementId ELEM_CALLOTHERFIXUP = new ElementId("callotherfixup", 92);
	public static final ElementId ELEM_CASE_PCODE = new ElementId("case_pcode", 93);
	public static final ElementId ELEM_CONTEXT = new ElementId("context", 94);
	public static final ElementId ELEM_DEFAULT_PCODE = new ElementId("default_pcode", 95);
	public static final ElementId ELEM_INJECT = new ElementId("inject", 96);
	public static final ElementId ELEM_INJECTDEBUG = new ElementId("injectdebug", 97);
	public static final ElementId ELEM_INST = new ElementId("inst", 98);
	public static final ElementId ELEM_PAYLOAD = new ElementId("payload", 99);
	public static final ElementId ELEM_PCODE = new ElementId("pcode", 100);
	public static final ElementId ELEM_SIZE_PCODE = new ElementId("size_pcode", 101);

	// block
	public static final ElementId ELEM_BHEAD = new ElementId("bhead", 102);
	public static final ElementId ELEM_BLOCK = new ElementId("block", 103);
	public static final ElementId ELEM_BLOCKEDGE = new ElementId("blockedge", 104);
	public static final ElementId ELEM_EDGE = new ElementId("edge", 105);

	// paramid
	public static final ElementId ELEM_PARAMMEASURES = new ElementId("parammeasures", 106);
	public static final ElementId ELEM_PROTO = new ElementId("proto", 107);
	public static final ElementId ELEM_RANK = new ElementId("rank", 108);

	// cpool
	public static final ElementId ELEM_CONSTANTPOOL = new ElementId("constantpool", 109);
	public static final ElementId ELEM_CPOOLREC = new ElementId("cpoolrec", 110);
	public static final ElementId ELEM_REF = new ElementId("ref", 111);
	public static final ElementId ELEM_TOKEN = new ElementId("token", 112);

	// op
	public static final ElementId ELEM_IOP = new ElementId("iop", 113);
	public static final ElementId ELEM_UNIMPL = new ElementId("unimpl", 114);

	// funcdata
	public static final ElementId ELEM_AST = new ElementId("ast", 115);
	public static final ElementId ELEM_FUNCTION = new ElementId("function", 116);
	public static final ElementId ELEM_HIGHLIST = new ElementId("highlist", 117);
	public static final ElementId ELEM_JUMPTABLELIST = new ElementId("jumptablelist", 118);
	public static final ElementId ELEM_VARNODES = new ElementId("varnodes", 119);

	// globalcontext
	public static final ElementId ELEM_CONTEXT_DATA = new ElementId("context_data", 120);
	public static final ElementId ELEM_CONTEXT_POINTS = new ElementId("context_points", 121);
	public static final ElementId ELEM_CONTEXT_POINTSET = new ElementId("context_pointset", 122);
	public static final ElementId ELEM_CONTEXT_SET = new ElementId("context_set", 123);
	public static final ElementId ELEM_SET = new ElementId("set", 124);
	public static final ElementId ELEM_TRACKED_POINTSET = new ElementId("tracked_pointset", 125);
	public static final ElementId ELEM_TRACKED_SET = new ElementId("tracked_set", 126);

	// userop
	public static final ElementId ELEM_CONSTRESOLVE = new ElementId("constresolve", 127);
	public static final ElementId ELEM_JUMPASSIST = new ElementId("jumpassist", 128);
	public static final ElementId ELEM_SEGMENTOP = new ElementId("segmentop", 129);

	// architecture
	public static final ElementId ELEM_ADDRESS_SHIFT_AMOUNT =
		new ElementId("address_shift_amount", 130);
	public static final ElementId ELEM_AGGRESSIVETRIM = new ElementId("aggressivetrim", 131);
	public static final ElementId ELEM_COMPILER_SPEC = new ElementId("compiler_spec", 132);
	public static final ElementId ELEM_DATA_SPACE = new ElementId("data_space", 133);
	public static final ElementId ELEM_DEFAULT_MEMORY_BLOCKS =
		new ElementId("default_memory_blocks", 134);
	public static final ElementId ELEM_DEFAULT_PROTO = new ElementId("default_proto", 135);
	public static final ElementId ELEM_DEFAULT_SYMBOLS = new ElementId("default_symbols", 136);
	public static final ElementId ELEM_EVAL_CALLED_PROTOTYPE =
		new ElementId("eval_called_prototype", 137);
	public static final ElementId ELEM_EVAL_CURRENT_PROTOTYPE =
		new ElementId("eval_current_prototype", 138);
	public static final ElementId ELEM_EXPERIMENTAL_RULES =
		new ElementId("experimental_rules", 139);
	public static final ElementId ELEM_FLOWOVERRIDELIST = new ElementId("flowoverridelist", 140);
	public static final ElementId ELEM_FUNCPTR = new ElementId("funcptr", 141);
	public static final ElementId ELEM_GLOBAL = new ElementId("global", 142);
	public static final ElementId ELEM_INCIDENTALCOPY = new ElementId("incidentalcopy", 143);
	public static final ElementId ELEM_INFERPTRBOUNDS = new ElementId("inferptrbounds", 144);
	public static final ElementId ELEM_MODELALIAS = new ElementId("modelalias", 145);
	public static final ElementId ELEM_NOHIGHPTR = new ElementId("nohighptr", 146);
	public static final ElementId ELEM_PROCESSOR_SPEC = new ElementId("processor_spec", 147);
	public static final ElementId ELEM_PROGRAMCOUNTER = new ElementId("programcounter", 148);
	public static final ElementId ELEM_PROPERTIES = new ElementId("properties", 149);
	public static final ElementId ELEM_PROPERTY = new ElementId("property", 150);
	public static final ElementId ELEM_READONLY = new ElementId("readonly", 151);
	public static final ElementId ELEM_REGISTER_DATA = new ElementId("register_data", 152);
	public static final ElementId ELEM_RULE = new ElementId("rule", 153);
	public static final ElementId ELEM_SAVE_STATE = new ElementId("save_state", 154);
	public static final ElementId ELEM_SEGMENTED_ADDRESS = new ElementId("segmented_address", 155);
	public static final ElementId ELEM_SPACEBASE = new ElementId("spacebase", 156);
	public static final ElementId ELEM_SPECEXTENSIONS = new ElementId("specextensions", 157);
	public static final ElementId ELEM_STACKPOINTER = new ElementId("stackpointer", 158);
	public static final ElementId ELEM_VOLATILE = new ElementId("volatile", 159);

	// fspec
	public static final ElementId ELEM_GROUP = new ElementId("group", 160);
	public static final ElementId ELEM_INTERNALLIST = new ElementId("internallist", 161);
	public static final ElementId ELEM_KILLEDBYCALL = new ElementId("killedbycall", 162);
	public static final ElementId ELEM_LIKELYTRASH = new ElementId("likelytrash", 163);
	public static final ElementId ELEM_LOCALRANGE = new ElementId("localrange", 164);
	public static final ElementId ELEM_MODEL = new ElementId("model", 165);
	public static final ElementId ELEM_PARAM = new ElementId("param", 166);
	public static final ElementId ELEM_PARAMRANGE = new ElementId("paramrange", 167);
	public static final ElementId ELEM_PENTRY = new ElementId("pentry", 168);
	public static final ElementId ELEM_PROTOTYPE = new ElementId("prototype", 169);
	public static final ElementId ELEM_RESOLVEPROTOTYPE = new ElementId("resolveprototype", 170);
	public static final ElementId ELEM_RETPARAM = new ElementId("retparam", 171);
	public static final ElementId ELEM_RETURNSYM = new ElementId("returnsym", 172);
	public static final ElementId ELEM_UNAFFECTED = new ElementId("unaffected", 173);

	// options
	public static final ElementId ELEM_ALIASBLOCK = new ElementId("aliasblock", 174);
	public static final ElementId ELEM_ALLOWCONTEXTSET = new ElementId("allowcontextset", 175);
	public static final ElementId ELEM_ANALYZEFORLOOPS = new ElementId("analyzeforloops", 176);
	public static final ElementId ELEM_COMMENTHEADER = new ElementId("commentheader", 177);
	public static final ElementId ELEM_COMMENTINDENT = new ElementId("commentindent", 178);
	public static final ElementId ELEM_COMMENTINSTRUCTION =
		new ElementId("commentinstruction", 179);
	public static final ElementId ELEM_COMMENTSTYLE = new ElementId("commentstyle", 180);
	public static final ElementId ELEM_CONVENTIONPRINTING =
		new ElementId("conventionprinting", 181);
	public static final ElementId ELEM_CURRENTACTION = new ElementId("currentaction", 182);
	public static final ElementId ELEM_DEFAULTPROTOTYPE = new ElementId("defaultprototype", 183);
	public static final ElementId ELEM_ERRORREINTERPRETED =
		new ElementId("errorreinterpreted", 184);
	public static final ElementId ELEM_ERRORTOOMANYINSTRUCTIONS =
		new ElementId("errortoomanyinstructions", 185);
	public static final ElementId ELEM_ERRORUNIMPLEMENTED =
		new ElementId("errorunimplemented", 186);
	public static final ElementId ELEM_EXTRAPOP = new ElementId("extrapop", 187);
	public static final ElementId ELEM_IGNOREUNIMPLEMENTED =
		new ElementId("ignoreunimplemented", 188);
	public static final ElementId ELEM_INDENTINCREMENT = new ElementId("indentincrement", 189);
	public static final ElementId ELEM_INFERCONSTPTR = new ElementId("inferconstptr", 190);
	public static final ElementId ELEM_INLINE = new ElementId("inline", 191);
	public static final ElementId ELEM_INPLACEOPS = new ElementId("inplaceops", 192);
	public static final ElementId ELEM_INTEGERFORMAT = new ElementId("integerformat", 193);
	public static final ElementId ELEM_JUMPLOAD = new ElementId("jumpload", 194);
	public static final ElementId ELEM_MAXINSTRUCTION = new ElementId("maxinstruction", 195);
	public static final ElementId ELEM_MAXLINEWIDTH = new ElementId("maxlinewidth", 196);
	public static final ElementId ELEM_NAMESPACESTRATEGY = new ElementId("namespacestrategy", 197);
	public static final ElementId ELEM_NOCASTPRINTING = new ElementId("nocastprinting", 198);
	public static final ElementId ELEM_NORETURN = new ElementId("noreturn", 199);
	public static final ElementId ELEM_NULLPRINTING = new ElementId("nullprinting", 200);
	public static final ElementId ELEM_OPTIONSLIST = new ElementId("optionslist", 201);
	public static final ElementId ELEM_PARAM1 = new ElementId("param1", 202);
	public static final ElementId ELEM_PARAM2 = new ElementId("param2", 203);
	public static final ElementId ELEM_PARAM3 = new ElementId("param3", 204);
	public static final ElementId ELEM_PROTOEVAL = new ElementId("protoeval", 205);
	public static final ElementId ELEM_SETACTION = new ElementId("setaction", 206);
	public static final ElementId ELEM_SETLANGUAGE = new ElementId("setlanguage", 207);
	public static final ElementId ELEM_STRUCTALIGN = new ElementId("structalign", 208);
	public static final ElementId ELEM_TOGGLERULE = new ElementId("togglerule", 209);
	public static final ElementId ELEM_WARNING = new ElementId("warning", 210);

	// jumptable
	public static final ElementId ELEM_BASICOVERRIDE = new ElementId("basicoverride", 211);
	public static final ElementId ELEM_DEST = new ElementId("dest", 212);
	public static final ElementId ELEM_JUMPTABLE = new ElementId("jumptable", 213);
	public static final ElementId ELEM_LOADTABLE = new ElementId("loadtable", 214);
	public static final ElementId ELEM_NORMADDR = new ElementId("normaddr", 215);
	public static final ElementId ELEM_NORMHASH = new ElementId("normhash", 216);
	public static final ElementId ELEM_STARTVAL = new ElementId("startval", 217);

	// override
	public static final ElementId ELEM_DEADCODEDELAY = new ElementId("deadcodedelay", 218);
	public static final ElementId ELEM_FLOW = new ElementId("flow", 219);
	public static final ElementId ELEM_FORCEGOTO = new ElementId("forcegoto", 220);
	public static final ElementId ELEM_INDIRECTOVERRIDE = new ElementId("indirectoverride", 221);
	public static final ElementId ELEM_MULTISTAGEJUMP = new ElementId("multistagejump", 222);
	public static final ElementId ELEM_OVERRIDE = new ElementId("override", 223);
	public static final ElementId ELEM_PROTOOVERRIDE = new ElementId("protooverride", 224);

	// prefersplit
	public static final ElementId ELEM_PREFERSPLIT = new ElementId("prefersplit", 225);

	// callgraph
	public static final ElementId ELEM_CALLGRAPH = new ElementId("callgraph", 226);
	public static final ElementId ELEM_NODE = new ElementId("node", 227);

	// varmap
	public static final ElementId ELEM_LOCALDB = new ElementId("localdb", 228);

	// ghidra_process
	public static final ElementId ELEM_DOC = new ElementId("doc", 229);

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
	public static final ElementId ELEM_COMMAND_ISNAMEUSED =
		new ElementId("command_isnameused", COMMAND_ISNAMEUSED);
	public static final int COMMAND_GETBYTES = 240;
	public static final ElementId ELEM_COMMAND_GETBYTES =
		new ElementId("command_getbytes", COMMAND_GETBYTES);
	public static final int COMMAND_GETCALLFIXUP = 241;
	public static final ElementId ELEM_COMMAND_GETCALLFIXUP =
		new ElementId("command_getcallfixup", COMMAND_GETCALLFIXUP);
	public static final int COMMAND_GETCALLMECH = 242;
	public static final ElementId ELEM_COMMAND_GETCALLMECH =
		new ElementId("command_getcallmech", COMMAND_GETCALLMECH);
	public static final int COMMAND_GETCALLOTHERFIXUP = 243;
	public static final ElementId ELEM_COMMAND_GETCALLOTHERFIXUP =
		new ElementId("command_getcallotherfixup", COMMAND_GETCALLOTHERFIXUP);
	public static final int COMMAND_GETCODELABEL = 244;
	public static final ElementId ELEM_COMMAND_GETCODELABEL =
		new ElementId("command_getcodelabel", COMMAND_GETCODELABEL);
	public static final int COMMAND_GETCOMMENTS = 245;
	public static final ElementId ELEM_COMMAND_GETCOMMENTS =
		new ElementId("command_getcomments", COMMAND_GETCOMMENTS);
	public static final int COMMAND_GETCPOOLREF = 246;
	public static final ElementId ELEM_COMMAND_GETCPOOLREF =
		new ElementId("command_getcpoolref", COMMAND_GETCPOOLREF);
	public static final int COMMAND_GETDATATYPE = 247;
	public static final ElementId ELEM_COMMAND_GETDATATYPE =
		new ElementId("command_getdatatype", COMMAND_GETDATATYPE);
	public static final int COMMAND_GETEXTERNALREF = 248;
	public static final ElementId ELEM_COMMAND_GETEXTERNALREF =
		new ElementId("command_getexternalref", COMMAND_GETEXTERNALREF);
	public static final int COMMAND_GETMAPPEDSYMBOLS = 249;
	public static final ElementId ELEM_COMMAND_GETMAPPEDSYMBOLS =
		new ElementId("command_getmappedsymbols", COMMAND_GETMAPPEDSYMBOLS);
	public static final int COMMAND_GETNAMESPACEPATH = 250;
	public static final ElementId ELEM_COMMAND_GETNAMESPACEPATH =
		new ElementId("command_getnamespacepath", COMMAND_GETNAMESPACEPATH);
	public static final int COMMAND_GETPCODE = 251;
	public static final ElementId ELEM_COMMAND_GETPCODE =
		new ElementId("command_getpcode", COMMAND_GETPCODE);
	public static final int COMMAND_GETPCODEEXECUTABLE = 252;
	public static final ElementId ELEM_COMMAND_GETPCODEEXECUTABLE =
		new ElementId("command_getpcodeexecutable", COMMAND_GETPCODEEXECUTABLE);
	public static final int COMMAND_GETREGISTER = 253;
	public static final ElementId ELEM_COMMAND_GETREGISTER =
		new ElementId("command_getregister", COMMAND_GETREGISTER);
	public static final int COMMAND_GETREGISTERNAME = 254;
	public static final ElementId ELEM_COMMAND_GETREGISTERNAME =
		new ElementId("command_getregistername", COMMAND_GETREGISTERNAME);
	public static final int COMMAND_GETSTRINGDATA = 255;
	public static final ElementId ELEM_COMMAND_GETSTRINGDATA =
		new ElementId("command_getstring", COMMAND_GETSTRINGDATA);
	public static final int COMMAND_GETTRACKEDREGISTERS = 256;
	public static final ElementId ELEM_COMMAND_GETTRACKEDREGISTERS =
		new ElementId("command_gettrackedregisters", COMMAND_GETTRACKEDREGISTERS);
	public static final int COMMAND_GETUSEROPNAME = 257;
	public static final ElementId ELEM_COMMAND_GETUSEROPNAME =
		new ElementId("command_getuseropname", COMMAND_GETUSEROPNAME);

	public static final ElementId ELEM_SPLITDATATYPE = new ElementId("splitdatatype", 270);
	public static final ElementId ELEM_UNKNOWN = new ElementId("XMLunknown", 271);
}
