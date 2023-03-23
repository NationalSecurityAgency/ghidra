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
 * An annotation for a data element being transferred to/from a stream
 *
 * This class parallels the XML concept of an attribute on an element. An AttributeId describes
 * a particular piece of data associated with an ElementId.  The defining characteristic of the AttributeId is
 * its name.  Internally this name is associated with an integer id.  The name (and id) uniquely determine
 * the data being labeled, within the context of a specific ElementId.  Within this context, an AttributeId labels either
 *   - An unsigned integer
 *   - A signed integer
 *   - A boolean value
 *   - A string
 *
 * The same AttributeId can be used to label a different type of data when associated with a different ElementId.
 * 
 * @param name unique attribute name
 * @param id unqiue attribute ID
 */
public record AttributeId(String name, int id) {

//	private static HashMap<String, AttributeId> lookupAttributeId = new HashMap<>();

//	public AttributeId {
//		// add new attribute to lookup map
//		if (null != lookupAttributeId.put(name, this)) {
//			throw new RuntimeException("Duplicate AttributeId: " + name);
//		}
//	}

//	/**
//	 * Find the id associated with a specific attribute name
//	 * @param nm the attribute name
//	 * @return the associated id
//	 */
//	public static int find(String nm) {
//		AttributeId res = lookupAttributeId.getOrDefault(nm, ATTRIB_UNKNOWN);
//		return res.id;
//	}

	// Common attributes.  Attributes with multiple uses
	public static final AttributeId ATTRIB_CONTENT = new AttributeId("XMLcontent", 1);
	public static final AttributeId ATTRIB_ALIGN = new AttributeId("align", 2);
	public static final AttributeId ATTRIB_BIGENDIAN = new AttributeId("bigendian", 3);
	public static final AttributeId ATTRIB_CONSTRUCTOR = new AttributeId("constructor", 4);
	public static final AttributeId ATTRIB_DESTRUCTOR = new AttributeId("destructor", 5);
	public static final AttributeId ATTRIB_EXTRAPOP = new AttributeId("extrapop", 6);
	public static final AttributeId ATTRIB_FORMAT = new AttributeId("format", 7);
	public static final AttributeId ATTRIB_HIDDENRETPARM = new AttributeId("hiddenretparm", 8);
	public static final AttributeId ATTRIB_ID = new AttributeId("id", 9);
	public static final AttributeId ATTRIB_INDEX = new AttributeId("index", 10);
	public static final AttributeId ATTRIB_INDIRECTSTORAGE = new AttributeId("indirectstorage", 11);
	public static final AttributeId ATTRIB_METATYPE = new AttributeId("metatype", 12);
	public static final AttributeId ATTRIB_MODEL = new AttributeId("model", 13);
	public static final AttributeId ATTRIB_NAME = new AttributeId("name", 14);
	public static final AttributeId ATTRIB_NAMELOCK = new AttributeId("namelock", 15);
	public static final AttributeId ATTRIB_OFFSET = new AttributeId("offset", 16);
	public static final AttributeId ATTRIB_READONLY = new AttributeId("readonly", 17);
	public static final AttributeId ATTRIB_REF = new AttributeId("ref", 18);
	public static final AttributeId ATTRIB_SIZE = new AttributeId("size", 19);
	public static final AttributeId ATTRIB_SPACE = new AttributeId("space", 20);
	public static final AttributeId ATTRIB_THISPTR = new AttributeId("thisptr", 21);
	public static final AttributeId ATTRIB_TYPE = new AttributeId("type", 22);
	public static final AttributeId ATTRIB_TYPELOCK = new AttributeId("typelock", 23);
	public static final AttributeId ATTRIB_VAL = new AttributeId("val", 24);
	public static final AttributeId ATTRIB_VALUE = new AttributeId("value", 25);
	public static final AttributeId ATTRIB_WORDSIZE = new AttributeId("wordsize", 26);

	// address
	public static final AttributeId ATTRIB_FIRST = new AttributeId("first", 27);
	public static final AttributeId ATTRIB_LAST = new AttributeId("last", 28);
	public static final AttributeId ATTRIB_UNIQ = new AttributeId("uniq", 29);

	// varnode
	public static final AttributeId ATTRIB_ADDRTIED = new AttributeId("addrtied", 30);
	public static final AttributeId ATTRIB_GRP = new AttributeId("grp", 31);
	public static final AttributeId ATTRIB_INPUT = new AttributeId("input", 32);
	public static final AttributeId ATTRIB_PERSISTS = new AttributeId("persists", 33);
	public static final AttributeId ATTRIB_UNAFF = new AttributeId("unaff", 34);

	// prettyprint
	public static final AttributeId ATTRIB_BLOCKREF = new AttributeId("blockref", 35);
	public static final AttributeId ATTRIB_CLOSE = new AttributeId("close", 36);
	public static final AttributeId ATTRIB_COLOR = new AttributeId("color", 37);
	public static final AttributeId ATTRIB_INDENT = new AttributeId("indent", 38);
	public static final AttributeId ATTRIB_OFF = new AttributeId("off", 39);
	public static final AttributeId ATTRIB_OPEN = new AttributeId("open", 40);
	public static final AttributeId ATTRIB_OPREF = new AttributeId("opref", 41);
	public static final AttributeId ATTRIB_VARREF = new AttributeId("varref", 42);

	// translate
	public static final AttributeId ATTRIB_CODE = new AttributeId("code", 43);
	public static final AttributeId ATTRIB_CONTAIN = new AttributeId("contain", 44);
	public static final AttributeId ATTRIB_DEFAULTSPACE = new AttributeId("defaultspace", 45);
	public static final AttributeId ATTRIB_UNIQBASE = new AttributeId("uniqbase", 46);

	// type
	public static final AttributeId ATTRIB_ALIGNMENT = new AttributeId("alignment", 47);
	public static final AttributeId ATTRIB_ARRAYSIZE = new AttributeId("arraysize", 48);
	public static final AttributeId ATTRIB_CHAR = new AttributeId("char", 49);
	public static final AttributeId ATTRIB_CORE = new AttributeId("core", 50);
	public static final AttributeId ATTRIB_ENUM = new AttributeId("enum", 51);
	public static final AttributeId ATTRIB_ENUMSIGNED = new AttributeId("enumsigned", 52);
	public static final AttributeId ATTRIB_ENUMSIZE = new AttributeId("enumsize", 53);
	public static final AttributeId ATTRIB_INTSIZE = new AttributeId("intsize", 54);
	public static final AttributeId ATTRIB_LONGSIZE = new AttributeId("longsize", 55);
	public static final AttributeId ATTRIB_OPAQUESTRING = new AttributeId("opaquestring", 56);
	public static final AttributeId ATTRIB_SIGNED = new AttributeId("signed", 57);
	public static final AttributeId ATTRIB_STRUCTALIGN = new AttributeId("structalign", 58);
	public static final AttributeId ATTRIB_UTF = new AttributeId("utf", 59);
	public static final AttributeId ATTRIB_VARLENGTH = new AttributeId("varlength", 60);

	// database
	public static final AttributeId ATTRIB_CAT = new AttributeId("cat", 61);
	public static final AttributeId ATTRIB_FIELD = new AttributeId("field", 62);
	public static final AttributeId ATTRIB_MERGE = new AttributeId("merge", 63);
	public static final AttributeId ATTRIB_SCOPEIDBYNAME = new AttributeId("scopeidbyname", 64);
	public static final AttributeId ATTRIB_VOLATILE = new AttributeId("volatile", 65);

	// variable
	public static final AttributeId ATTRIB_CLASS = new AttributeId("class", 66);
	public static final AttributeId ATTRIB_REPREF = new AttributeId("repref", 67);
	public static final AttributeId ATTRIB_SYMREF = new AttributeId("symref", 68);

	// stringmanage
	public static final AttributeId ATTRIB_TRUNC = new AttributeId("trunc", 69);

	// pcodeinject
	public static final AttributeId ATTRIB_DYNAMIC = new AttributeId("dynamic", 70);
	public static final AttributeId ATTRIB_INCIDENTALCOPY = new AttributeId("incidentalcopy", 71);
	public static final AttributeId ATTRIB_INJECT = new AttributeId("inject", 72);
	public static final AttributeId ATTRIB_PARAMSHIFT = new AttributeId("paramshift", 73);
	public static final AttributeId ATTRIB_TARGETOP = new AttributeId("targetop", 74);

	// block
	public static final AttributeId ATTRIB_ALTINDEX = new AttributeId("altindex", 75);
	public static final AttributeId ATTRIB_DEPTH = new AttributeId("depth", 76);
	public static final AttributeId ATTRIB_END = new AttributeId("end", 77);
	public static final AttributeId ATTRIB_OPCODE = new AttributeId("opcode", 78);
	public static final AttributeId ATTRIB_REV = new AttributeId("rev", 79);

	// cpool
	public static final AttributeId ATTRIB_A = new AttributeId("a", 80);
	public static final AttributeId ATTRIB_B = new AttributeId("b", 81);
	public static final AttributeId ATTRIB_LENGTH = new AttributeId("length", 82);
	public static final AttributeId ATTRIB_TAG = new AttributeId("tag", 83);

	// funcdata
	public static final AttributeId ATTRIB_NOCODE = new AttributeId("nocode", 84);

	// userop
	public static final AttributeId ATTRIB_FARPOINTER = new AttributeId("farpointer", 85);
	public static final AttributeId ATTRIB_INPUTOP = new AttributeId("inputop", 86);
	public static final AttributeId ATTRIB_OUTPUTOP = new AttributeId("outputop", 87);
	public static final AttributeId ATTRIB_USEROP = new AttributeId("userop", 88);

	// space
	public static final AttributeId ATTRIB_BASE = new AttributeId("base", 89);
	public static final AttributeId ATTRIB_DEADCODEDELAY = new AttributeId("deadcodedelay", 90);
	public static final AttributeId ATTRIB_DELAY = new AttributeId("delay", 91);
	public static final AttributeId ATTRIB_LOGICALSIZE = new AttributeId("logicalsize", 92);
	public static final AttributeId ATTRIB_PHYSICAL = new AttributeId("physical", 93);
	public static final AttributeId ATTRIB_PIECE = new AttributeId("piece", 94);

	// architecture
	public static final AttributeId ATTRIB_ADJUSTVMA = new AttributeId("adjustvma", 103);
	public static final AttributeId ATTRIB_ENABLE = new AttributeId("enable", 104);
	public static final AttributeId ATTRIB_GROUP = new AttributeId("group", 105);
	public static final AttributeId ATTRIB_GROWTH = new AttributeId("growth", 106);
	public static final AttributeId ATTRIB_KEY = new AttributeId("key", 107);
	public static final AttributeId ATTRIB_LOADERSYMBOLS = new AttributeId("loadersymbols", 108);
	public static final AttributeId ATTRIB_PARENT = new AttributeId("parent", 109);
	public static final AttributeId ATTRIB_REGISTER = new AttributeId("register", 110);
	public static final AttributeId ATTRIB_REVERSEJUSTIFY = new AttributeId("reversejustify", 111);
	public static final AttributeId ATTRIB_SIGNEXT = new AttributeId("signext", 112);
	public static final AttributeId ATTRIB_STYLE = new AttributeId("style", 113);

	// fspec
	public static final AttributeId ATTRIB_CUSTOM = new AttributeId("custom", 114);
	public static final AttributeId ATTRIB_DOTDOTDOT = new AttributeId("dotdotdot", 115);
	public static final AttributeId ATTRIB_EXTENSION = new AttributeId("extension", 116);
	public static final AttributeId ATTRIB_HASTHIS = new AttributeId("hasthis", 117);
	public static final AttributeId ATTRIB_INLINE = new AttributeId("inline", 118);
	public static final AttributeId ATTRIB_KILLEDBYCALL = new AttributeId("killedbycall", 119);
	public static final AttributeId ATTRIB_MAXSIZE = new AttributeId("maxsize", 120);
	public static final AttributeId ATTRIB_MINSIZE = new AttributeId("minsize", 121);
	public static final AttributeId ATTRIB_MODELLOCK = new AttributeId("modellock", 122);
	public static final AttributeId ATTRIB_NORETURN = new AttributeId("noreturn", 123);
	public static final AttributeId ATTRIB_POINTERMAX = new AttributeId("pointermax", 124);
	public static final AttributeId ATTRIB_SEPARATEFLOAT = new AttributeId("separatefloat", 125);
	public static final AttributeId ATTRIB_STACKSHIFT = new AttributeId("stackshift", 126);
	public static final AttributeId ATTRIB_STRATEGY = new AttributeId("strategy", 127);
	public static final AttributeId ATTRIB_THISBEFORERETPOINTER =
		new AttributeId("thisbeforeretpointer", 128);
	public static final AttributeId ATTRIB_VOIDLOCK = new AttributeId("voidlock", 129);

	// transform
	public static final AttributeId ATTRIB_VECTOR_LANE_SIZES =
		new AttributeId("vector_lane_sizes", 130);

	// jumptable
	public static final AttributeId ATTRIB_LABEL = new AttributeId("label", 131);
	public static final AttributeId ATTRIB_NUM = new AttributeId("num", 132);

	// varmap
	public static final AttributeId ATTRIB_LOCK = new AttributeId("lock", 133);
	public static final AttributeId ATTRIB_MAIN = new AttributeId("main", 134);

	// loadimage_xml
//	public static final AttributeId ATTRIB_ARCH = new AttributeId("arch", 135);

	// sleigh_arch
//	public static final AttributeId ATTRIB_DEPRECATED = new AttributeId("deprecated", 136);
//	public static final AttributeId ATTRIB_ENDIAN = new AttributeId("endian", 137);
//	public static final AttributeId ATTRIB_PROCESSOR = new AttributeId("processor", 138);
//	public static final AttributeId ATTRIB_PROCESSORSPEC = new AttributeId("processorspec", 139);
//	public static final AttributeId ATTRIB_SLAFILE = new AttributeId("slafile", 140);
//	public static final AttributeId ATTRIB_SPEC = new AttributeId("spec", 141);
//	public static final AttributeId ATTRIB_TARGET = new AttributeId("target", 142);
//	public static final AttributeId ATTRIB_VARIANT = new AttributeId("variant", 143);
//	public static final AttributeId ATTRIB_VERSION = new AttributeId("version", 144);

// public static final AttributeId ATTRIB_ADDRESS = new AttributeId("address", 148);
	public static final AttributeId ATTRIB_UNKNOWN = new AttributeId("XMLunknown", 149);
}
