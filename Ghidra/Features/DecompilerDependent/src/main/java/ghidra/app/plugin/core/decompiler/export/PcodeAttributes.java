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
 * An annotation for a data element being transferred to/from a stream
 * <p>
 * This class parallels the XML concept of an attribute on an element. An PcodeAttributes describes
 * a particular piece of data associated with an ElementId.  The defining characteristic of the PcodeAttributes is
 * its name.  Internally this name is associated with an integer id.  The name (and id) uniquely determine
 * the data being labeled, within the context of a specific ElementId.  Within this context, an PcodeAttributes labels either
 * <ul>
 *   <li>An unsigned integer</li>
 *   <li>A signed integer</li>
 *   <li>A boolean value</li>
 *   <li>A string</li>
 * </ul>
 * <p>
 * The same PcodeAttributes can be used to label a different type of data when associated with a different ElementId.
 * 
 * @param name unique attribute name
 * @param id unqiue attribute ID
 */
package ghidra.app.plugin.core.decompiler.export;

import java.util.HashMap;
import java.util.Map;

public record PcodeAttributes(String name, int id, DecoderMethods method) {

	// NB: This class parallels AttributeId in FrameworkSoftwareModeling

	private static Map<String, PcodeAttributes> nlookupPcodeAttributes = new HashMap<>();
	private static Map<Integer, PcodeAttributes> ilookupPcodeAttributes = new HashMap<>();

	public PcodeAttributes {
		// add new attribute to lookup map
		if (null != nlookupPcodeAttributes.put(name, this)) {
			throw new RuntimeException("Duplicate PcodeAttributes: " + name);
		}
		if (null != ilookupPcodeAttributes.put(id, this)) {
			throw new RuntimeException("Duplicate PcodeAttributes: " + name);
		}
	}

	/**
	 * Find the id associated with a specific attribute name
	 * @param nm the attribute name
	 * @return the associated id
	 */
	public static PcodeAttributes find(String nm) {
		return nlookupPcodeAttributes.getOrDefault(nm, ATTRIB_UNKNOWN);
	}

	public static PcodeAttributes find(int id) {
		return ilookupPcodeAttributes.getOrDefault(id, ATTRIB_UNKNOWN);
	}

	// Common attributes.  Attributes with multiple uses
	public static final PcodeAttributes ATTRIB_CONTENT =
		new PcodeAttributes("XMLcontent", 1, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_ALIGN =
		new PcodeAttributes("align", 2, DecoderMethods.READ_SINT);
	public static final PcodeAttributes ATTRIB_BIGENDIAN =
		new PcodeAttributes("bigendian", 3, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_CONSTRUCTOR =
		new PcodeAttributes("constructor", 4, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_DESTRUCTOR =
		new PcodeAttributes("destructor", 5, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_EXTRAPOP =
		new PcodeAttributes("extrapop", 6, DecoderMethods.READ_SINT);
	public static final PcodeAttributes ATTRIB_FORMAT =
		new PcodeAttributes("format", 7, DecoderMethods.READ_UINT);
	public static final PcodeAttributes ATTRIB_HIDDENRETPARM =
		new PcodeAttributes("hiddenretparm", 8, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_ID =
		new PcodeAttributes("id", 9, DecoderMethods.READ_UINT);
	public static final PcodeAttributes ATTRIB_INDEX =
		new PcodeAttributes("index", 10, DecoderMethods.READ_SINT);
	public static final PcodeAttributes ATTRIB_INDIRECTSTORAGE =
		new PcodeAttributes("indirectstorage", 11, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_METATYPE =
		new PcodeAttributes("metatype", 12, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_MODEL =
		new PcodeAttributes("model", 13, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_NAME =
		new PcodeAttributes("name", 14, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_NAMELOCK =
		new PcodeAttributes("namelock", 15, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_OFFSET =
		new PcodeAttributes("offset", 16, DecoderMethods.READ_UINT);  // ??
	public static final PcodeAttributes ATTRIB_READONLY =
		new PcodeAttributes("readonly", 17, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_REF =
		new PcodeAttributes("ref", 18, DecoderMethods.READ_UINT);
	public static final PcodeAttributes ATTRIB_SIZE =
		new PcodeAttributes("size", 19, DecoderMethods.READ_SINT);
	public static final PcodeAttributes ATTRIB_SPACE =
		new PcodeAttributes("space", 20, DecoderMethods.READ_SPACE);
	public static final PcodeAttributes ATTRIB_THISPTR =
		new PcodeAttributes("thisptr", 21, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_TYPE =
		new PcodeAttributes("type", 22, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_TYPELOCK =
		new PcodeAttributes("typelock", 23, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_VAL =
		new PcodeAttributes("val", 24, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_VALUE =
		new PcodeAttributes("value", 25, DecoderMethods.READ_SINT);
	public static final PcodeAttributes ATTRIB_WORDSIZE =
		new PcodeAttributes("wordsize", 26, DecoderMethods.READ_STRING);

	// address
	public static final PcodeAttributes ATTRIB_FIRST =
		new PcodeAttributes("first", 27, DecoderMethods.READ_UINT);
	public static final PcodeAttributes ATTRIB_LAST =
		new PcodeAttributes("last", 28, DecoderMethods.READ_UINT);
	public static final PcodeAttributes ATTRIB_UNIQ =
		new PcodeAttributes("uniq", 29, DecoderMethods.READ_UINT);

	// varnode
	public static final PcodeAttributes ATTRIB_ADDRTIED =
		new PcodeAttributes("addrtied", 30, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_GRP =
		new PcodeAttributes("grp", 31, DecoderMethods.READ_SINT);
	public static final PcodeAttributes ATTRIB_INPUT =
		new PcodeAttributes("input", 32, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_PERSISTS =
		new PcodeAttributes("persists", 33, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_UNAFF =
		new PcodeAttributes("unaff", 34, DecoderMethods.READ_BOOL);

	// prettyprint
	public static final PcodeAttributes ATTRIB_BLOCKREF =
		new PcodeAttributes("blockref", 35, DecoderMethods.READ_SINT);
	public static final PcodeAttributes ATTRIB_CLOSE =
		new PcodeAttributes("close", 36, DecoderMethods.READ_SINT);
	public static final PcodeAttributes ATTRIB_COLOR =
		new PcodeAttributes("color", 37, DecoderMethods.READ_UINT);
	public static final PcodeAttributes ATTRIB_INDENT =
		new PcodeAttributes("indent", 38, DecoderMethods.READ_SINT);
	public static final PcodeAttributes ATTRIB_OFF =
		new PcodeAttributes("off", 39, DecoderMethods.READ_SINT); // READ_UINT?
	public static final PcodeAttributes ATTRIB_OPEN =
		new PcodeAttributes("open", 40, DecoderMethods.READ_SINT);
	public static final PcodeAttributes ATTRIB_OPREF =
		new PcodeAttributes("opref", 41, DecoderMethods.READ_UINT);
	public static final PcodeAttributes ATTRIB_VARREF =
		new PcodeAttributes("varref", 42, DecoderMethods.READ_UINT);

	// translate
	public static final PcodeAttributes ATTRIB_CODE =
		new PcodeAttributes("code", 43, DecoderMethods.READ_OPCODE);
	public static final PcodeAttributes ATTRIB_CONTAIN =
		new PcodeAttributes("contain", 44, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_DEFAULTSPACE =
		new PcodeAttributes("defaultspace", 45, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_UNIQBASE =
		new PcodeAttributes("uniqbase", 46, DecoderMethods.READ_STRING);

	// type
	public static final PcodeAttributes ATTRIB_ALIGNMENT =
		new PcodeAttributes("alignment", 47, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_ARRAYSIZE =
		new PcodeAttributes("arraysize", 48, DecoderMethods.READ_SINT);
	public static final PcodeAttributes ATTRIB_CHAR =
		new PcodeAttributes("char", 49, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_CORE =
		new PcodeAttributes("core", 50, DecoderMethods.READ_BOOL);
//	public static final PcodeAttributes ATTRIB_ENUM = 
//	     new PcodeAttributes("enum", 51, DecoderMethods.READ_STRING);	  // deprecated
	public static final PcodeAttributes ATTRIB_INCOMPLETE =
		new PcodeAttributes("incomplete", 52, DecoderMethods.READ_STRING);
//	public static final PcodeAttributes ATTRIB_ENUMSIZE = 
//	 	new PcodeAttributes("enumsize", 53, DecoderMethods.READ_STRING);  // deprecated
//	public static final PcodeAttributes ATTRIB_INTSIZE = 
//		new PcodeAttributes("intsize", 54, DecoderMethods.READ_STRING);   // deprecated
//	public static final PcodeAttributes ATTRIB_LONGSIZE = 
//		new PcodeAttributes("longsize", 55, DecoderMethods.READ_STRING);  // deprecated
	public static final PcodeAttributes ATTRIB_OPAQUESTRING =
		new PcodeAttributes("opaquestring", 56, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_SIGNED =
		new PcodeAttributes("signed", 57, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_STRUCTALIGN =
		new PcodeAttributes("structalign", 58, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_UTF =
		new PcodeAttributes("utf", 59, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_VARLENGTH =
		new PcodeAttributes("varlength", 60, DecoderMethods.READ_STRING);

	// database
	public static final PcodeAttributes ATTRIB_CAT =
		new PcodeAttributes("cat", 61, DecoderMethods.READ_SINT);
	public static final PcodeAttributes ATTRIB_FIELD =
		new PcodeAttributes("field", 62, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_MERGE =
		new PcodeAttributes("merge", 63, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_SCOPEIDBYNAME =
		new PcodeAttributes("scopeidbyname", 64, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_VOLATILE =
		new PcodeAttributes("volatile", 65, DecoderMethods.READ_BOOL);

	// variable
	public static final PcodeAttributes ATTRIB_CLASS =
		new PcodeAttributes("class", 66, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_REPREF =
		new PcodeAttributes("repref", 67, DecoderMethods.READ_UINT);
	public static final PcodeAttributes ATTRIB_SYMREF =
		new PcodeAttributes("symref", 68, DecoderMethods.READ_UINT);

	// stringmanage
	public static final PcodeAttributes ATTRIB_TRUNC =
		new PcodeAttributes("trunc", 69, DecoderMethods.READ_STRING);

	// pcodeinject
	public static final PcodeAttributes ATTRIB_DYNAMIC =
		new PcodeAttributes("dynamic", 70, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_INCIDENTALCOPY =
		new PcodeAttributes("incidentalcopy", 71, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_INJECT =
		new PcodeAttributes("inject", 72, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_PARAMSHIFT =
		new PcodeAttributes("paramshift", 73, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_TARGETOP =
		new PcodeAttributes("targetop", 74, DecoderMethods.READ_STRING);

	// block
	public static final PcodeAttributes ATTRIB_ALTINDEX =
		new PcodeAttributes("altindex", 75, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_DEPTH =
		new PcodeAttributes("depth", 76, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_END =
		new PcodeAttributes("end", 77, DecoderMethods.READ_SINT);
	public static final PcodeAttributes ATTRIB_OPCODE =
		new PcodeAttributes("opcode", 78, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_REV =
		new PcodeAttributes("rev", 79, DecoderMethods.READ_SINT);

	// cpool
	public static final PcodeAttributes ATTRIB_A =
		new PcodeAttributes("a", 80, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_B =
		new PcodeAttributes("b", 81, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_LENGTH =
		new PcodeAttributes("length", 82, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_TAG =
		new PcodeAttributes("tag", 83, DecoderMethods.READ_STRING);

	// funcdata
	public static final PcodeAttributes ATTRIB_NOCODE =
		new PcodeAttributes("nocode", 84, DecoderMethods.READ_STRING);

	// userop
	public static final PcodeAttributes ATTRIB_FARPOINTER =
		new PcodeAttributes("farpointer", 85, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_INPUTOP =
		new PcodeAttributes("inputop", 86, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_OUTPUTOP =
		new PcodeAttributes("outputop", 87, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_USEROP =
		new PcodeAttributes("userop", 88, DecoderMethods.READ_STRING);

	// space
	public static final PcodeAttributes ATTRIB_BASE =
		new PcodeAttributes("base", 89, DecoderMethods.READ_STRING);
//	public static final PcodeAttributes ATTRIB_DEADCODEDELAY = 
//		new PcodeAttributes("deadcodedelay", 90, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_DELAY =
		new PcodeAttributes("delay", 91, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_LOGICALSIZE =
		new PcodeAttributes("logicalsize", 92, DecoderMethods.READ_UINT);
	public static final PcodeAttributes ATTRIB_PHYSICAL =
		new PcodeAttributes("physical", 93, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_PIECE =
		new PcodeAttributes("piece", 94, DecoderMethods.READ_STRING);

	// architecture
	public static final PcodeAttributes ATTRIB_ADJUSTVMA =
		new PcodeAttributes("adjustvma", 103, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_ENABLE =
		new PcodeAttributes("enable", 104, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_GROUP =
		new PcodeAttributes("group", 105, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_GROWTH =
		new PcodeAttributes("growth", 106, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_KEY =
		new PcodeAttributes("key", 107, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_LOADERSYMBOLS =
		new PcodeAttributes("loadersymbols", 108, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_PARENT =
		new PcodeAttributes("parent", 109, DecoderMethods.READ_UINT);
	public static final PcodeAttributes ATTRIB_REGISTER =
		new PcodeAttributes("register", 110, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_REVERSEJUSTIFY =
		new PcodeAttributes("reversejustify", 111, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_SIGNEXT =
		new PcodeAttributes("signext", 112, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_STYLE =
		new PcodeAttributes("style", 113, DecoderMethods.READ_STRING);

	// fspec
	public static final PcodeAttributes ATTRIB_CUSTOM =
		new PcodeAttributes("custom", 114, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_DOTDOTDOT =
		new PcodeAttributes("dotdotdot", 115, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_EXTENSION =
		new PcodeAttributes("extension", 116, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_HASTHIS =
		new PcodeAttributes("hasthis", 117, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_INLINE =
		new PcodeAttributes("inline", 118, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_KILLEDBYCALL =
		new PcodeAttributes("killedbycall", 119, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_MAXSIZE =
		new PcodeAttributes("maxsize", 120, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_MINSIZE =
		new PcodeAttributes("minsize", 121, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_MODELLOCK =
		new PcodeAttributes("modellock", 122, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_NORETURN =
		new PcodeAttributes("noreturn", 123, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_POINTERMAX =
		new PcodeAttributes("pointermax", 124, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_SEPARATEFLOAT =
		new PcodeAttributes("separatefloat", 125, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_STACKSHIFT =
		new PcodeAttributes("stackshift", 126, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_STRATEGY =
		new PcodeAttributes("strategy", 127, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_THISBEFORERETPOINTER =
		new PcodeAttributes("thisbeforeretpointer", 128, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_VOIDLOCK =
		new PcodeAttributes("voidlock", 129, DecoderMethods.READ_BOOL);

	// transform
	public static final PcodeAttributes ATTRIB_VECTOR_LANE_SIZES =
		new PcodeAttributes("vector_lane_sizes", 130, DecoderMethods.READ_STRING);

	// jumptable
	public static final PcodeAttributes ATTRIB_LABEL =
		new PcodeAttributes("label", 131, DecoderMethods.READ_UINT);
	public static final PcodeAttributes ATTRIB_NUM =
		new PcodeAttributes("num", 132, DecoderMethods.READ_STRING);

	// varmap
	public static final PcodeAttributes ATTRIB_LOCK =
		new PcodeAttributes("lock", 133, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_MAIN =
		new PcodeAttributes("main", 134, DecoderMethods.READ_SPACE);

	// loadimage_xml
//	public static final PcodeAttributes ATTRIB_ARCH = 
//		new PcodeAttributes("arch", 135);

	// sleigh_arch
//	public static final PcodeAttributes ATTRIB_DEPRECATED = 
//		new PcodeAttributes("deprecated", 136);
//	public static final PcodeAttributes ATTRIB_ENDIAN = 
//		new PcodeAttributes("endian", 137);
//	public static final PcodeAttributes ATTRIB_PROCESSOR = 
//		new PcodeAttributes("processor", 138);
//	public static final PcodeAttributes ATTRIB_PROCESSORSPEC = 
//		new PcodeAttributes("processorspec", 139);
//	public static final PcodeAttributes ATTRIB_SLAFILE = 
//		new PcodeAttributes("slafile", 140);
//	public static final PcodeAttributes ATTRIB_SPEC = 
//		new PcodeAttributes("spec", 141);
//	public static final PcodeAttributes ATTRIB_TARGET = 
//		new PcodeAttributes("target", 142);
//	public static final PcodeAttributes ATTRIB_VARIANT = 
//		new PcodeAttributes("variant", 143);
//	public static final PcodeAttributes ATTRIB_VERSION = 
//		new PcodeAttributes("version", 144);

	// signature
	public static final PcodeAttributes ATTRIB_BADDATA =
		new PcodeAttributes("baddata", 145, DecoderMethods.READ_BOOL);
	public static final PcodeAttributes ATTRIB_HASH =
		new PcodeAttributes("hash", 146, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_UNIMPL =
		new PcodeAttributes("unimpl", 147, DecoderMethods.READ_BOOL);

// public static final PcodeAttributes ATTRIB_ADDRESS = 
//		new PcodeAttributes("address", 148, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_STORAGE =
		new PcodeAttributes("storage", 149, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_STACKSPILL =
		new PcodeAttributes("stackspill", 150, DecoderMethods.READ_STRING);

	// modelrules

	public static final PcodeAttributes ATTRIB_SIZES =
		new PcodeAttributes("sizes", 151, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_BACKFILL =
		new PcodeAttributes("backfill", 152, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_MAX_PRIMITIVES =
		new PcodeAttributes("maxprimitives", 153, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_REVERSESIGNIF =
		new PcodeAttributes("reversesignif", 154, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_MATCHSIZE =
		new PcodeAttributes("matchsize", 155, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_AFTER_BYTES =
		new PcodeAttributes("afterbytes", 156, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_AFTER_STORAGE =
		new PcodeAttributes("afterstorage", 157, DecoderMethods.READ_STRING);
	public static final PcodeAttributes ATTRIB_FILL_ALTERNATE =
		new PcodeAttributes("fillalternate", 158, DecoderMethods.READ_STRING);

	public static final PcodeAttributes ATTRIB_UNKNOWN =
		new PcodeAttributes("XMLunknown", 159, DecoderMethods.READ_STRING);

}
