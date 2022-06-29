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

import java.util.HashMap;

/**
 * An annotation for a specific collection of hierarchical data
 *
 * This class parallels the XML concept of an element.  An ElementId describes a collection of data, where each
 * piece is annotated by a specific AttributeId.  In addition, each ElementId can contain zero or more child
 * ElementId objects, forming a hierarchy of annotated data.  Each ElementId has a name, which is unique at least
 * within the context of its parent ElementId. Internally this name is associated with an integer id. A special
 * AttributeId ATTRIB_CONTENT is used to label the XML element's text content, which is traditionally not labeled
 * as an attribute.
 */
public class ElementId {
	private static HashMap<String, Integer> lookupElementId = new HashMap<>();
	private String name;						// The name of the element
	private int id;								// The (internal) id of the element

	public ElementId(String nm, int i) {
		name = nm;
		id = i;
		lookupElementId.put(nm, i);
	}

	public String getName() {
		return name;
	}

	public int getId() {
		return id;
	}

	/**
	 * Find the id associated with a specific element name
	 * @param nm the element name
	 * @return the associated id
	 */
	public static int find(String nm) {
		Integer res = lookupElementId.get(nm);
		if (res != null) {
			return res.intValue();
		}
		return ELEM_UNKNOWN.id;
	}

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

	// address
	public static final ElementId ELEM_ADDR = new ElementId("addr", 11);
	public static final ElementId ELEM_RANGE = new ElementId("range", 12);
	public static final ElementId ELEM_RANGELIST = new ElementId("rangelist", 13);
	public static final ElementId ELEM_REGISTER = new ElementId("register", 14);
	public static final ElementId ELEM_SEQNUM = new ElementId("seqnum", 15);
	public static final ElementId ELEM_VARNODE = new ElementId("varnode", 16);

	// architecture
	public static final ElementId ELEM_ADDRESS_SHIFT_AMOUNT =
		new ElementId("address_shift_amount", 17);
	public static final ElementId ELEM_AGGRESSIVETRIM = new ElementId("aggressivetrim", 18);
	public static final ElementId ELEM_COMPILER_SPEC = new ElementId("compiler_spec", 19);
	public static final ElementId ELEM_DATA_SPACE = new ElementId("data_space", 20);
	public static final ElementId ELEM_DEFAULT_MEMORY_BLOCKS =
		new ElementId("default_memory_blocks", 21);
	public static final ElementId ELEM_DEFAULT_PROTO = new ElementId("default_proto", 22);
	public static final ElementId ELEM_DEFAULT_SYMBOLS = new ElementId("default_symbols", 23);
	public static final ElementId ELEM_EVAL_CALLED_PROTOTYPE =
		new ElementId("eval_called_prototype", 24);
	public static final ElementId ELEM_EVAL_CURRENT_PROTOTYPE =
		new ElementId("eval_current_prototype", 25);
	public static final ElementId ELEM_EXPERIMENTAL_RULES = new ElementId("experimental_rules", 26);
	public static final ElementId ELEM_FLOWOVERRIDELIST = new ElementId("flowoverridelist", 27);
	public static final ElementId ELEM_FUNCPTR = new ElementId("funcptr", 28);
	public static final ElementId ELEM_GLOBAL = new ElementId("global", 29);
	public static final ElementId ELEM_INCIDENTALCOPY = new ElementId("incidentalcopy", 30);
	public static final ElementId ELEM_INFERPTRBOUNDS = new ElementId("inferptrbounds", 31);
	public static final ElementId ELEM_MODELALIAS = new ElementId("modelalias", 32);
	public static final ElementId ELEM_NOHIGHPTR = new ElementId("nohighptr", 33);
	public static final ElementId ELEM_PROCESSOR_SPEC = new ElementId("processor_spec", 34);
	public static final ElementId ELEM_PROGRAMCOUNTER = new ElementId("programcounter", 35);
	public static final ElementId ELEM_PROPERTIES = new ElementId("properties", 36);
	public static final ElementId ELEM_READONLY = new ElementId("readonly", 37);
	public static final ElementId ELEM_REGISTER_DATA = new ElementId("register_data", 38);
	public static final ElementId ELEM_RULE = new ElementId("rule", 39);
	public static final ElementId ELEM_SAVE_STATE = new ElementId("save_state", 40);
	public static final ElementId ELEM_SEGMENTED_ADDRESS = new ElementId("segmented_address", 41);
	public static final ElementId ELEM_SPACEBASE = new ElementId("spacebase", 42);
	public static final ElementId ELEM_SPECEXTENSIONS = new ElementId("specextensions", 43);
	public static final ElementId ELEM_STACKPOINTER = new ElementId("stackpointer", 44);
	public static final ElementId ELEM_VOLATILE = new ElementId("volatile", 45);

	// block
	public static final ElementId ELEM_BHEAD = new ElementId("bhead", 47);
	public static final ElementId ELEM_BLOCK = new ElementId("block", 48);
	public static final ElementId ELEM_BLOCKEDGE = new ElementId("blockedge", 49);
	public static final ElementId ELEM_EDGE = new ElementId("edge", 50);

	// callgraph
	public static final ElementId ELEM_CALLGRAPH = new ElementId("callgraph", 51);
	public static final ElementId ELEM_NODE = new ElementId("node", 52);

	// comment
	public static final ElementId ELEM_COMMENT = new ElementId("comment", 53);
	public static final ElementId ELEM_COMMENTDB = new ElementId("commentdb", 54);
	public static final ElementId ELEM_TEXT = new ElementId("text", 55);

	// cpool
	public static final ElementId ELEM_CONSTANTPOOL = new ElementId("constantpool", 56);
	public static final ElementId ELEM_CPOOLREC = new ElementId("cpoolrec", 57);
	public static final ElementId ELEM_REF = new ElementId("ref", 58);
	public static final ElementId ELEM_TOKEN = new ElementId("token", 59);

	// database
	public static final ElementId ELEM_COLLISION = new ElementId("collision", 60);
	public static final ElementId ELEM_DB = new ElementId("db", 61);
	public static final ElementId ELEM_EQUATESYMBOL = new ElementId("equatesymbol", 62);
	public static final ElementId ELEM_EXTERNREFSYMBOL = new ElementId("externrefsymbol", 63);
	public static final ElementId ELEM_FACETSYMBOL = new ElementId("facetsymbol", 64);
	public static final ElementId ELEM_FUNCTIONSHELL = new ElementId("functionshell", 65);
	public static final ElementId ELEM_HASH = new ElementId("hash", 66);
	public static final ElementId ELEM_HOLE = new ElementId("hole", 67);
	public static final ElementId ELEM_LABELSYM = new ElementId("labelsym", 68);
	public static final ElementId ELEM_MAPSYM = new ElementId("mapsym", 69);
	public static final ElementId ELEM_PARENT = new ElementId("parent", 70);
	public static final ElementId ELEM_PROPERTY_CHANGEPOINT =
		new ElementId("property_changepoint", 71);
	public static final ElementId ELEM_RANGEEQUALSSYMBOLS = new ElementId("rangeequalssymbols", 72);
	public static final ElementId ELEM_SCOPE = new ElementId("scope", 73);
	public static final ElementId ELEM_SYMBOLLIST = new ElementId("symbollist", 74);

	// fspec
	public static final ElementId ELEM_GROUP = new ElementId("group", 75);
	public static final ElementId ELEM_INTERNALLIST = new ElementId("internallist", 76);
	public static final ElementId ELEM_KILLEDBYCALL = new ElementId("killedbycall", 77);
	public static final ElementId ELEM_LIKELYTRASH = new ElementId("likelytrash", 78);
	public static final ElementId ELEM_LOCALRANGE = new ElementId("localrange", 79);
	public static final ElementId ELEM_MODEL = new ElementId("model", 80);
	public static final ElementId ELEM_PARAM = new ElementId("param", 81);
	public static final ElementId ELEM_PARAMRANGE = new ElementId("paramrange", 82);
	public static final ElementId ELEM_PENTRY = new ElementId("pentry", 83);
	public static final ElementId ELEM_PROTOTYPE = new ElementId("prototype", 84);
	public static final ElementId ELEM_RESOLVEPROTOTYPE = new ElementId("resolveprototype", 85);
	public static final ElementId ELEM_RETPARAM = new ElementId("retparam", 86);
	public static final ElementId ELEM_RETURNSYM = new ElementId("returnsym", 87);
	public static final ElementId ELEM_UNAFFECTED = new ElementId("unaffected", 88);

	// funcdata
	public static final ElementId ELEM_AST = new ElementId("ast", 89);
	public static final ElementId ELEM_FUNCTION = new ElementId("function", 90);
	public static final ElementId ELEM_HIGHLIST = new ElementId("highlist", 91);
	public static final ElementId ELEM_JUMPTABLELIST = new ElementId("jumptablelist", 92);
	public static final ElementId ELEM_VARNODES = new ElementId("varnodes", 93);

	// globalcontext
	public static final ElementId ELEM_CONTEXT_DATA = new ElementId("context_data", 94);
	public static final ElementId ELEM_CONTEXT_POINTS = new ElementId("context_points", 95);
	public static final ElementId ELEM_CONTEXT_POINTSET = new ElementId("context_pointset", 96);
	public static final ElementId ELEM_CONTEXT_SET = new ElementId("context_set", 97);
	public static final ElementId ELEM_SET = new ElementId("set", 98);
	public static final ElementId ELEM_TRACKED_POINTSET = new ElementId("tracked_pointset", 99);
	public static final ElementId ELEM_TRACKED_SET = new ElementId("tracked_set", 100);

	// jumptable
	public static final ElementId ELEM_BASICOVERRIDE = new ElementId("basicoverride", 101);
	public static final ElementId ELEM_DEST = new ElementId("dest", 102);
	public static final ElementId ELEM_JUMPTABLE = new ElementId("jumptable", 103);
	public static final ElementId ELEM_LOADTABLE = new ElementId("loadtable", 104);
	public static final ElementId ELEM_NORMADDR = new ElementId("normaddr", 105);
	public static final ElementId ELEM_NORMHASH = new ElementId("normhash", 106);
	public static final ElementId ELEM_STARTVAL = new ElementId("startval", 107);

	// op
	public static final ElementId ELEM_IOP = new ElementId("iop", 110);

	// options
	public static final ElementId ELEM_ALIASBLOCK = new ElementId("aliasblock", 111);
	public static final ElementId ELEM_ALLOWCONTEXTSET = new ElementId("allowcontextset", 112);
	public static final ElementId ELEM_ANALYZEFORLOOPS = new ElementId("analyzeforloops", 113);
	public static final ElementId ELEM_COMMENTHEADER = new ElementId("commentheader", 114);
	public static final ElementId ELEM_COMMENTINDENT = new ElementId("commentindent", 115);
	public static final ElementId ELEM_COMMENTINSTRUCTION =
		new ElementId("commentinstruction", 116);
	public static final ElementId ELEM_COMMENTSTYLE = new ElementId("commentstyle", 117);
	public static final ElementId ELEM_CONVENTIONPRINTING =
		new ElementId("conventionprinting", 118);
	public static final ElementId ELEM_CURRENTACTION = new ElementId("currentaction", 119);
	public static final ElementId ELEM_DEFAULTPROTOTYPE = new ElementId("defaultprototype", 120);
	public static final ElementId ELEM_ERRORREINTERPRETED =
		new ElementId("errorreinterpreted", 121);
	public static final ElementId ELEM_ERRORTOOMANYINSTRUCTIONS =
		new ElementId("errortoomanyinstructions", 122);
	public static final ElementId ELEM_ERRORUNIMPLEMENTED =
		new ElementId("errorunimplemented", 123);
	public static final ElementId ELEM_EXTRAPOP = new ElementId("extrapop", 124);
	public static final ElementId ELEM_IGNOREUNIMPLEMENTED =
		new ElementId("ignoreunimplemented", 125);
	public static final ElementId ELEM_INDENTINCREMENT = new ElementId("indentincrement", 126);
	public static final ElementId ELEM_INFERCONSTPTR = new ElementId("inferconstptr", 127);
	public static final ElementId ELEM_INLINE = new ElementId("inline", 128);
	public static final ElementId ELEM_INPLACEOPS = new ElementId("inplaceops", 129);
	public static final ElementId ELEM_INTEGERFORMAT = new ElementId("integerformat", 130);
	public static final ElementId ELEM_JUMPLOAD = new ElementId("jumpload", 131);
	public static final ElementId ELEM_MAXINSTRUCTION = new ElementId("maxinstruction", 132);
	public static final ElementId ELEM_MAXLINEWIDTH = new ElementId("maxlinewidth", 133);
	public static final ElementId ELEM_NAMESPACESTRATEGY = new ElementId("namespacestrategy", 134);
	public static final ElementId ELEM_NOCASTPRINTING = new ElementId("nocastprinting", 135);
	public static final ElementId ELEM_NORETURN = new ElementId("noreturn", 136);
	public static final ElementId ELEM_NULLPRINTING = new ElementId("nullprinting", 137);
	public static final ElementId ELEM_OPTIONSLIST = new ElementId("optionslist", 138);
	public static final ElementId ELEM_PARAM1 = new ElementId("param1", 139);
	public static final ElementId ELEM_PARAM2 = new ElementId("param2", 140);
	public static final ElementId ELEM_PARAM3 = new ElementId("param3", 141);
	public static final ElementId ELEM_PROTOEVAL = new ElementId("protoeval", 142);
	public static final ElementId ELEM_SETACTION = new ElementId("setaction", 143);
	public static final ElementId ELEM_SETLANGUAGE = new ElementId("setlanguage", 144);
	public static final ElementId ELEM_STRUCTALIGN = new ElementId("structalign", 145);
	public static final ElementId ELEM_TOGGLERULE = new ElementId("togglerule", 146);
	public static final ElementId ELEM_WARNING = new ElementId("warning", 147);

	// override
	public static final ElementId ELEM_DEADCODEDELAY = new ElementId("deadcodedelay", 148);
	public static final ElementId ELEM_FLOW = new ElementId("flow", 149);
	public static final ElementId ELEM_FORCEGOTO = new ElementId("forcegoto", 150);
	public static final ElementId ELEM_INDIRECTOVERRIDE = new ElementId("indirectoverride", 151);
	public static final ElementId ELEM_MULTISTAGEJUMP = new ElementId("multistagejump", 152);
	public static final ElementId ELEM_OVERRIDE = new ElementId("override", 153);
	public static final ElementId ELEM_PROTOOVERRIDE = new ElementId("protooverride", 154);

	// paramid
	public static final ElementId ELEM_PARAMMEASURES = new ElementId("parammeasures", 155);
	public static final ElementId ELEM_PROTO = new ElementId("proto", 156);
	public static final ElementId ELEM_RANK = new ElementId("rank", 157);

	// pcodeinject
	public static final ElementId ELEM_ADDR_PCODE = new ElementId("addr_pcode", 158);
	public static final ElementId ELEM_BODY = new ElementId("body", 159);
	public static final ElementId ELEM_CALLFIXUP = new ElementId("callfixup", 160);
	public static final ElementId ELEM_CALLOTHERFIXUP = new ElementId("callotherfixup", 161);
	public static final ElementId ELEM_CASE_PCODE = new ElementId("case_pcode", 162);
	public static final ElementId ELEM_CONTEXT = new ElementId("context", 163);
	public static final ElementId ELEM_DEFAULT_PCODE = new ElementId("default_pcode", 164);
	public static final ElementId ELEM_INJECT = new ElementId("inject", 165);
	public static final ElementId ELEM_INJECTDEBUG = new ElementId("injectdebug", 166);
	public static final ElementId ELEM_INST = new ElementId("inst", 167);
	public static final ElementId ELEM_PAYLOAD = new ElementId("payload", 168);
	public static final ElementId ELEM_PCODE = new ElementId("pcode", 169);
	public static final ElementId ELEM_SIZE_PCODE = new ElementId("size_pcode", 170);

	// prefersplit
	public static final ElementId ELEM_PREFERSPLIT = new ElementId("prefersplit", 171);

	// stringmanage
	public static final ElementId ELEM_BYTES = new ElementId("bytes", 177);
	public static final ElementId ELEM_STRING = new ElementId("string", 178);
	public static final ElementId ELEM_STRINGMANAGE = new ElementId("stringmanage", 179);

	// translate
	public static final ElementId ELEM_OP = new ElementId("op", 180);
	public static final ElementId ELEM_SLEIGH = new ElementId("sleigh", 181);
	public static final ElementId ELEM_SPACE = new ElementId("space", 182);
	public static final ElementId ELEM_SPACEID = new ElementId("spaceid", 183);
	public static final ElementId ELEM_SPACES = new ElementId("spaces", 184);
	public static final ElementId ELEM_SPACE_BASE = new ElementId("space_base", 185);
	public static final ElementId ELEM_SPACE_OTHER = new ElementId("space_other", 186);
	public static final ElementId ELEM_SPACE_OVERLAY = new ElementId("space_overlay", 187);
	public static final ElementId ELEM_SPACE_UNIQUE = new ElementId("space_unique", 188);
	public static final ElementId ELEM_TRUNCATE_SPACE = new ElementId("truncate_space", 189);

	// type
	public static final ElementId ELEM_CORETYPES = new ElementId("coretypes", 190);
	public static final ElementId ELEM_DATA_ORGANIZATION = new ElementId("data_organization", 191);
	public static final ElementId ELEM_DEF = new ElementId("def", 192);
	public static final ElementId ELEM_ENTRY = new ElementId("entry", 193);
	public static final ElementId ELEM_ENUM = new ElementId("enum", 194);
	public static final ElementId ELEM_FIELD = new ElementId("field", 195);
	public static final ElementId ELEM_INTEGER_SIZE = new ElementId("integer_size", 196);
	public static final ElementId ELEM_LONG_SIZE = new ElementId("long_size", 197);
	public static final ElementId ELEM_SIZE_ALIGNMENT_MAP =
		new ElementId("size_alignment_map", 198);
	public static final ElementId ELEM_TYPE = new ElementId("type", 199);
	public static final ElementId ELEM_TYPEGRP = new ElementId("typegrp", 200);
	public static final ElementId ELEM_TYPEREF = new ElementId("typeref", 201);

	// userop
	public static final ElementId ELEM_CONSTRESOLVE = new ElementId("constresolve", 202);
	public static final ElementId ELEM_JUMPASSIST = new ElementId("jumpassist", 203);
	public static final ElementId ELEM_SEGMENTOP = new ElementId("segmentop", 204);

	// variable
	public static final ElementId ELEM_HIGH = new ElementId("high", 205);

	// varmap
	public static final ElementId ELEM_LOCALDB = new ElementId("localdb", 206);

	// prettyprint
	public static final ElementId ELEM_BREAK = new ElementId("break", 208);
	public static final ElementId ELEM_CLANG_DOCUMENT = new ElementId("clang_document", 209);
	public static final ElementId ELEM_FUNCNAME = new ElementId("funcname", 210);
	public static final ElementId ELEM_FUNCPROTO = new ElementId("funcproto", 211);
	public static final ElementId ELEM_LABEL = new ElementId("label", 212);
	public static final ElementId ELEM_RETURN_TYPE = new ElementId("return_type", 213);
	public static final ElementId ELEM_STATEMENT = new ElementId("statement", 214);
	public static final ElementId ELEM_SYNTAX = new ElementId("syntax", 215);
	public static final ElementId ELEM_VARDECL = new ElementId("vardecl", 216);
	public static final ElementId ELEM_VARIABLE = new ElementId("variable", 217);

	// ghidra_process
	public static final ElementId ELEM_DOC = new ElementId("doc", 218);

	public static final ElementId ELEM_UNKNOWN = new ElementId("XMLunknown", 231);
}
