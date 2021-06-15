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

import java.util.ArrayList;
import java.util.Arrays;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.DecompilerLanguage;
import ghidra.program.model.listing.Program;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 *
 * Class for making Ghidra DataTypes suitable for use with pcode
 * 
 * 
 */
public class PcodeDataTypeManager {

	private static class TypeMap {
		public DataType dt;			// Full datatype object
		public String name;			// Name of the datatype on decompiler side
		public String metatype;		// extra decompiler metatype information for the type
		public long id;				// Calculated id for type

		public TypeMap(DecompilerLanguage lang, DataType d, String meta) {
			dt = d;
			if (d instanceof BuiltIn) {
				name = ((BuiltIn) d).getDecompilerDisplayName(lang);
			}
			else {
				name = d.getName();
			}
			metatype = meta;
			id = hashName(name);
		}

		public TypeMap(DataType d, String nm, String meta) {
			dt = d;
			name = nm;
			metatype = meta;
			id = hashName(name);
		}

		/**
		 * Hashing scheme for decompiler core datatypes that are not in the database
		 * Must match Datatype::hashName in the decompiler
		 * @param name is base name of the datatype
		 * @return the hash value
		 */
		public static long hashName(String name) {
			long res = 123;
			for (int i = 0; i < name.length(); ++i) {
				res = (res << 8) | (res >>> 56);
				res += name.charAt(i);
				if ((res & 1) == 0) {
					res ^= 0x00000000feabfeabL; // Some kind of feedback
				}
			}
			res |= 0x8000000000000000L; // Make sure the hash is negative (to distinguish it from database id's)
			return res;
		}
	}

	private Program program;
	private DataTypeManager progDataTypes;		// DataTypes from a particular program
	private DataTypeManager builtInDataTypes = BuiltInDataTypeManager.getDataTypeManager();
	private DataOrganization dataOrganization;
	private DecompilerLanguage displayLanguage;
	private boolean voidInputIsVarargs;			// true if we should consider void parameter lists as varargs
	// Some C header conventions use an empty prototype to mean a
	// varargs function. Locking in void can cause data-flow to get
	// truncated. This boolean controls whether we lock it in or not
	private TypeMap[] coreBuiltin;				// Core decompiler datatypes and how they map to full datatype objects
	private VoidDataType voidDt;
	private int pointerWordSize;				// Wordsize to assign to all pointer datatypes

	public PcodeDataTypeManager(Program prog) {

		program = prog;
		progDataTypes = prog.getDataTypeManager();
		dataOrganization = progDataTypes.getDataOrganization();
		voidInputIsVarargs = true;				// By default, do not lock-in void parameter lists
		displayLanguage = prog.getCompilerSpec().getDecompilerOutputLanguage();
		if (displayLanguage != DecompilerLanguage.C_LANGUAGE) {
			voidInputIsVarargs = false;
		}
		generateCoreTypes();
		sortCoreTypes();
		pointerWordSize = ((SleighLanguage) prog.getLanguage()).getDefaultPointerWordSize();
	}

	public Program getProgram() {
		return program;
	}

	public DataType findUndefined(int size) {
//		if (size==1)
//			return dtMap.get("undefined");
		return Undefined.getUndefinedDataType(size);
	}

	/**
	 * Find a base/built-in data-type with the given name and/or id.  If an id is provided and
	 * a corresponding data-type exists, this data-type is returned. Otherwise the first
	 * built-in data-type with a matching name is returned
	 * @param nm name of data-type
	 * @param idstr is an optional string containing a data-type id number
	 * @return the data-type object or null if no matching data-type exists
	 */
	public DataType findBaseType(String nm, String idstr) {
		long id = 0;
		if (idstr != null) {
			id = SpecXmlUtils.decodeLong(idstr);
			if (id > 0) {
				DataType dt = progDataTypes.getDataType(id);
				if (dt != null) {
					return dt;
				}
			}
			else {
				int index = findTypeById(id);
				if (index >= 0) {
					return coreBuiltin[index].dt;
				}
			}
		}
		// If we don't have a good id, it may be a builtin type that is not yet placed in the program
		ArrayList<DataType> datatypes = new ArrayList<>();
		builtInDataTypes.findDataTypes(nm, datatypes);
		if (datatypes.size() != 0) {
			return datatypes.get(0).clone(progDataTypes);
		}
		if (nm.equals("code")) {		// A special datatype, the decompiler needs
			return DataType.DEFAULT;
		}
		return null;
	}

	/**
	 * Get the data type that corresponds to the given XML element.
	 * @param parser the xml parser
	 * @return the read data type
	 * @throws PcodeXMLException if the data type could be resolved from the 
	 * element 
	 */
	public DataType readXMLDataType(XmlPullParser parser) throws PcodeXMLException {
		XmlElement el = parser.start("type", "void", "typeref");
		try {
			if (el == null) {
				throw new PcodeXMLException("Bad <type> tag");
			}

			if (el.getName().equals("void")) {
				return voidDt;
			}
			if (el.getName().equals("typeref")) {
				return findBaseType(el.getAttribute("name"), el.getAttribute("id"));
			}
			String name = el.getAttribute("name");
			if (name.length() != 0) {
				return findBaseType(name, el.getAttribute("id"));
			}
			String meta = el.getAttribute("metatype");
			DataType restype = null;
			if (meta.equals("ptr")) {
				int size = SpecXmlUtils.decodeInt(el.getAttribute("size"));
				if (parser.peek().isStart()) {
					DataType dt = readXMLDataType(parser);
					boolean useDefaultSize = (size == dataOrganization.getPointerSize() ||
						size > PointerDataType.MAX_POINTER_SIZE_BYTES);
					restype = new PointerDataType(dt, useDefaultSize ? -1 : size, progDataTypes);
				}
			}
			else if (meta.equals("array")) {
				int arrsize = SpecXmlUtils.decodeInt(el.getAttribute("arraysize"));
				if (parser.peek().isStart()) {
					DataType dt = readXMLDataType(parser);
					if (dt == null || dt.getLength() == 0) {
						dt = DataType.DEFAULT;
					}
					restype = new ArrayDataType(dt, arrsize, dt.getLength(), progDataTypes);
				}
			}
			else if (meta.equals("spacebase")) {				// Typically the type of "the whole stack"
				parser.discardSubTree();  // get rid of unused "addr" element
				return voidDt;
			}
			else if (meta.equals("struct")) {
				// we now can reach here with the decompiler inventing structures, apparently
				// this is a band-aid so that we don't blow up
				// just make an undefined data type of the appropriate size
				int size = SpecXmlUtils.decodeInt(el.getAttribute("size"));
				return Undefined.getUndefinedDataType(size);
				// OLD COMMENT:
				// Structures should always be named so we should never reach here
				// if all the structures are contained in ghidra. I should probably add the
				// parsing here so the decompiler can pass new structures into ghidra
			}
			else if (meta.equals("int")) {
				int size = SpecXmlUtils.decodeInt(el.getAttribute("size"));
				return AbstractIntegerDataType.getSignedDataType(size, progDataTypes);
			}
			else if (meta.equals("uint")) {
				int size = SpecXmlUtils.decodeInt(el.getAttribute("size"));
				return AbstractIntegerDataType.getUnsignedDataType(size, progDataTypes);
			}
			else if (meta.equals("float")) {
				int size = SpecXmlUtils.decodeInt(el.getAttribute("size"));
				return AbstractFloatDataType.getFloatDataType(size, progDataTypes);
			}
			else {	// We typically reach here if the decompiler invents a new type
					// probably an unknown with a non-standard size
				int size = SpecXmlUtils.decodeInt(el.getAttribute("size"));
				return Undefined.getUndefinedDataType(size).clone(progDataTypes);
			}
			if (restype == null) {
				throw new PcodeXMLException("Unable to resolve DataType");
			}
			return restype;
		}
		finally {
			parser.discardSubTree(el);
//	        parser.end(el);
		}
	}

	/**
	 * Generate an XML tag describing the given data-type. Most data-types produce a {@code <type>} tag,
	 * fully describing the data-type. Where possible a {@code <typeref>} tag is produced, which just gives
	 * the name of the data-type, deferring a full description of the data-type. For certain simple or
	 * nameless data-types, a {@code <type>} tag is emitted giving a full description.
	 * @param type is the data-type to be converted
	 * @param size is the size in bytes of the specific instance of the data-type
	 * @return a StringBuilder containing the XML tag
	 */
	public StringBuilder buildTypeRef(DataType type, int size) {
		if (type != null && type.getDataTypeManager() != progDataTypes) {
			type = type.clone(progDataTypes);
		}
		if ((type instanceof VoidDataType) || (type == null)) {
			return buildType(type, size);
		}
		if (type instanceof AbstractIntegerDataType) {
			return buildType(type, size);
		}
		if (type instanceof Pointer) {
			return buildType(type, size);
		}
		if (type instanceof Array) {
			return buildType(type, size);
		}
		if (type instanceof FunctionDefinition) {
			long id = progDataTypes.getID(type);
			if (id <= 0) {
				// Its possible the FunctionDefinition was built on the fly and is not
				// a permanent data-type of the program with an ID.  In this case, we can't
				// construct a <typeref> tag but must build a full <type> tag.
				return buildType(type, size);
			}
			size = 1;
		}
		else if (type.getLength() <= 0) {
			return buildType(type, size);
		}
		StringBuilder resBuf = new StringBuilder();
		resBuf.append("<typeref");
		if (type instanceof BuiltIn) {
			SpecXmlUtils.xmlEscapeAttribute(resBuf, "name",
				((BuiltIn) type).getDecompilerDisplayName(displayLanguage));
		}
		else {
			SpecXmlUtils.xmlEscapeAttribute(resBuf, "name", type.getName());
			// Get id of type associated with program, will return -1 if not associated (builtin)
			long id = progDataTypes.getID(type);
			if (id > 0) {
				SpecXmlUtils.encodeUnsignedIntegerAttribute(resBuf, "id", id);
			}
			if (type.getLength() <= 0 && size > 0) {
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", size);
			}
		}
		resBuf.append("/>");
		return resBuf;
	}

	private StringBuilder getCharTypeRef(int size) {
		if (size == dataOrganization.getCharSize()) {
			return new StringBuilder("<typeref name=\"char\"/>"); // could have size 1 or 2
		}
		if (size == dataOrganization.getWideCharSize()) {
			return new StringBuilder("<typeref name=\"wchar_t\"/>");
		}
		if (size == 2) {
			return new StringBuilder("<typeref name=\"wchar16\"/>");
		}
		if (size == 4) {
			return new StringBuilder("<typeref name=\"wchar32\"/>");
		}
		if (size == 1) {
			return new StringBuilder("<typeref name=\"byte\"/>");
		}
		throw new IllegalArgumentException("Unsupported character size");
	}

	private void appendOpaqueString(StringBuilder resBuf, DataType type, int size) {
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "struct");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", size);
		SpecXmlUtils.encodeBooleanAttribute(resBuf, "opaquestring", true);
		SpecXmlUtils.encodeBooleanAttribute(resBuf, "varlength", true);
		resBuf.append(">\n");
		resBuf.append("<field name=\"unknown_data1\"");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "offset", 0);
		resBuf.append("> <typeref name=\"byte\"/></field>\n");
		size -= 1;
		resBuf.append("<field name=\"opaque_data\"");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "offset", 1);
		resBuf.append("> <type");
		SpecXmlUtils.encodeStringAttribute(resBuf, "name", "");
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "array");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", size);
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "arraysize", size);
		resBuf.append("><typeref name=\"byte\"/></type>");
		resBuf.append("</field>\n");
	}

	private String buildTypeInternal(DataType origType, int size) {		// Build all of type except name attribute
		DataType type;
		if (origType instanceof TypeDef) {
			type = ((TypeDef) origType).getBaseDataType();
		}
		else {
			type = origType;
		}
		StringBuilder resBuf = new StringBuilder();
		if (type instanceof Pointer) {
			if (origType == type) {
				SpecXmlUtils.encodeStringAttribute(resBuf, "name", "");
			}
			else {
				appendNameIdAttributes(resBuf, origType);
			}
			SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "ptr");
			int ptrLen = type.getLength();
			if (ptrLen <= 0) {
				ptrLen = size;
			}
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", ptrLen);
			if (pointerWordSize != 1) {
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "wordsize", pointerWordSize);
			}
			resBuf.append('>');
			DataType ptrto = ((Pointer) type).getDataType();

			if (ptrto != null && ptrto.getDataTypeManager() != progDataTypes) {
				ptrto = ptrto.clone(progDataTypes);
			}

			StringBuilder ptrtoTypeRef;
			if (ptrto == null) {
				ptrtoTypeRef = buildTypeRef(DefaultDataType.dataType, 1);
			}
			else if (ptrto instanceof AbstractStringDataType) {
				if ((ptrto instanceof StringDataType) ||
					(type instanceof TerminatedStringDataType)) {	// Convert pointer to string
					ptrtoTypeRef = getCharTypeRef(dataOrganization.getCharSize()); // to pointer to char
				}
				else if (ptrto instanceof StringUTF8DataType) {	// Convert pointer to string
					// TODO: Need to ensure that UTF8 decoding applies
					ptrtoTypeRef = getCharTypeRef(1); // to pointer to char
				}
				else if ((ptrto instanceof UnicodeDataType) ||
					(ptrto instanceof TerminatedUnicodeDataType)) {
					ptrtoTypeRef = getCharTypeRef(2);
				}
				else if ((ptrto instanceof Unicode32DataType) ||
					(ptrto instanceof TerminatedUnicode32DataType)) {
					ptrtoTypeRef = getCharTypeRef(4);
				}
				else {
					ptrtoTypeRef = new StringBuilder();
					ptrtoTypeRef.append("<type");
					appendNameIdAttributes(ptrtoTypeRef, ptrto);
					appendOpaqueString(ptrtoTypeRef, ptrto, 16384);
					ptrtoTypeRef.append("</type>\n");
				}
			}
			else if (ptrto instanceof FunctionDefinition) {
				// FunctionDefinition may have size of -1, do not translate to undefined
				ptrtoTypeRef = buildTypeRef(ptrto, ptrto.getLength());
			}
			else if (ptrto.getLength() < 0 && !(ptrto instanceof FunctionDefinition)) {
				ptrtoTypeRef = buildTypeRef(Undefined1DataType.dataType, 1);
			}
			else {
				ptrtoTypeRef = buildTypeRef(ptrto, ptrto.getLength());
			}
			resBuf.append(ptrtoTypeRef);
		}
		else if (type instanceof Array) {
			if (origType == type) {
				SpecXmlUtils.encodeStringAttribute(resBuf, "name", "");
			}
			else {
				appendNameIdAttributes(resBuf, origType);
			}
			int sz = type.getLength();
			if (sz == 0) {
				sz = size;
			}
			SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "array");
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", sz);
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "arraysize",
				((Array) type).getNumElements());
			resBuf.append('>');
			resBuf.append(
				buildTypeRef(((Array) type).getDataType(), ((Array) type).getElementLength()));
		}
		else if (type instanceof Structure) {
			appendNameIdAttributes(resBuf, origType);
			// if size is 0, insert an Undefined4 component
			//
			int sz = type.getLength();
			if (sz == 0) {
				type = new StructureDataType(type.getCategoryPath(), type.getName(), 1);
				sz = type.getLength();
			}
			SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "struct");
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", sz);
			resBuf.append(">\n");
			DataTypeComponent[] comps = ((Structure) type).getDefinedComponents();
			for (DataTypeComponent comp : comps) {
				if (comp.isBitFieldComponent()) {
					// TODO: bitfields are not yet supported by decompiler
					continue;
				}
				resBuf.append("<field");
				String field_name = comp.getFieldName();
				if (field_name == null) {
					field_name = comp.getDefaultFieldName();
				}
				SpecXmlUtils.xmlEscapeAttribute(resBuf, "name", field_name);
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "offset", comp.getOffset());
				resBuf.append('>');
				DataType fieldtype = comp.getDataType();
				resBuf.append(buildTypeRef(fieldtype, comp.getLength()));
				resBuf.append("</field>\n");
			}
			// TODO: trailing flexible array component not yet supported
		}
		else if (type instanceof Enum) {
			appendNameIdAttributes(resBuf, origType);
			Enum enumDt = (Enum) type;
			long[] keys = enumDt.getValues();
			String metatype = "uint";
			for (long key : keys) {
				if (key < 0) {
					metatype = "int";
					break;
				}
			}
			SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", metatype);
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", enumDt.getLength());
			SpecXmlUtils.encodeBooleanAttribute(resBuf, "enum", true);
			resBuf.append(">\n");
			for (long key : keys) {
				resBuf.append("<val");
				SpecXmlUtils.xmlEscapeAttribute(resBuf, "name", enumDt.getName(key));
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "value", key);
				resBuf.append("/>");
			}
		}
		else if (type instanceof CharDataType) {
			appendNameIdAttributes(resBuf, origType);
			boolean signed = ((CharDataType) type).isSigned();
			int sz = type.getLength();
			if (sz <= 0) {
				sz = size;
			}
			SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", signed ? "int" : "uint");
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", sz);
			if (sz == 1) {
				SpecXmlUtils.encodeBooleanAttribute(resBuf, "char", true);
			}
			else {
				SpecXmlUtils.encodeBooleanAttribute(resBuf, "utf", true);
			}
			resBuf.append('>');
		}
		else if (type instanceof WideCharDataType || type instanceof WideChar16DataType ||
			type instanceof WideChar32DataType) {
			appendNameIdAttributes(resBuf, origType);
			SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "int");
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", type.getLength());
			SpecXmlUtils.encodeBooleanAttribute(resBuf, "utf", true);
			resBuf.append('>');
		}
		else if (type instanceof AbstractStringDataType) {
			if ((type instanceof StringDataType) || (type instanceof TerminatedStringDataType)) {
				SpecXmlUtils.encodeStringAttribute(resBuf, "name", "");
				SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "array");
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", size);
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "arraysize", size);
				resBuf.append('>');
				resBuf.append(getCharTypeRef(dataOrganization.getCharSize()));
			}
			else if (type instanceof StringUTF8DataType) {
				SpecXmlUtils.encodeStringAttribute(resBuf, "name", "");
				SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "array");
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", size);
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "arraysize", size);
				resBuf.append('>');
				resBuf.append(getCharTypeRef(1)); // TODO: Need to ensure that UTF8 decoding applies
			}
			else if ((type instanceof UnicodeDataType) ||
				(type instanceof TerminatedUnicodeDataType)) {
				SpecXmlUtils.encodeStringAttribute(resBuf, "name", "");
				SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "array");
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", size);
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "arraysize", size / 2);
				resBuf.append('>');
				resBuf.append(getCharTypeRef(2));
			}
			else if ((type instanceof Unicode32DataType) ||
				(type instanceof TerminatedUnicode32DataType)) {
				SpecXmlUtils.encodeStringAttribute(resBuf, "name", "");
				SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "array");
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", size);
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "arraysize", size / 4);
				resBuf.append('>');
				resBuf.append(getCharTypeRef(4));
			}
			else {
				appendNameIdAttributes(resBuf, type);
				appendOpaqueString(resBuf, type, size);
			}
		}
		else if (type instanceof FunctionDefinition) {
			if (size <= 0) {
				size = 1;
			}
			appendNameIdAttributes(resBuf, origType);
			SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "code");
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", 1);	// Force size of 1
			resBuf.append('>');
			FunctionDefinition fdef = (FunctionDefinition) type;
			CompilerSpec cspec = program.getCompilerSpec();
			FunctionPrototype fproto = new FunctionPrototype(fdef, cspec, voidInputIsVarargs);
			fproto.buildPrototypeXML(resBuf, this);
		}
		else if (type instanceof BooleanDataType) {
			appendNameIdAttributes(resBuf, origType);
			SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "bool");
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", type.getLength());
			resBuf.append('>');
		}
		else if (type instanceof AbstractIntegerDataType) { // must handle char and bool above
			boolean signed = ((AbstractIntegerDataType) type).isSigned();
			int sz = type.getLength();
			if (sz <= 0) {
				sz = size;
			}
			appendNameIdAttributes(resBuf, origType);
			SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", signed ? "int" : "uint");
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", sz);
			resBuf.append('>');
		}
		else if (type instanceof AbstractFloatDataType) {
			appendNameIdAttributes(resBuf, origType);
			SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "float");
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", type.getLength());
			resBuf.append('>');
		}
		else {
			int sz = type.getLength();
			boolean isVarLength = false;
			if (sz <= 0) {
				sz = size;
				isVarLength = true;
			}
			appendNameIdAttributes(resBuf, origType);
			if (sz < 16) {
				SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "unknown");
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", sz);
				resBuf.append('>');
			}
			else {
				// Build an "opaque" structure with no fields
				SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "struct");
				SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", sz);
				if (isVarLength) {
					SpecXmlUtils.encodeBooleanAttribute(resBuf, "varlength", isVarLength);
				}
				resBuf.append('>');
			}
		}
		return resBuf.toString();
	}

	private void appendNameIdAttributes(StringBuilder resBuf, DataType type) {
		if (type instanceof BuiltIn) {
			SpecXmlUtils.xmlEscapeAttribute(resBuf, "name",
				((BuiltIn) type).getDecompilerDisplayName(displayLanguage));
		}
		else {
			SpecXmlUtils.xmlEscapeAttribute(resBuf, "name", type.getName());
			long id = progDataTypes.getID(type);
			if (id > 0) {
				SpecXmlUtils.encodeUnsignedIntegerAttribute(resBuf, "id", id);
			}
		}
	}

	/**
	 * Build an XML document string representing the type information for a data type
	 * 
	 * @param type data type to build XML for
	 * @param size size of the data type
	 * 
	 * @return XML string document
	 */
	public StringBuilder buildType(DataType type, int size) {
		if (type != null && type.getDataTypeManager() != progDataTypes) {
			type = type.clone(progDataTypes);
		}
		StringBuilder resBuf = new StringBuilder();
		if ((type instanceof VoidDataType) || (type == null)) {
			return resBuf.append("<void/>");
		}
		resBuf.append("<type");
		resBuf.append(buildTypeInternal(type, size));
		resBuf.append("</type>");
		return resBuf;
	}

	/**
	 * Build an XML document string representing the Structure or Typedef to Structure that has
	 *  its size reported as zero.
	 * 
	 * @param type data type to build XML for
	 * 
	 * @return XML string document
	 */
	public StringBuilder buildStructTypeZeroSizeOveride(DataType type) {
		StringBuilder resBuf = new StringBuilder();
		if (!((type instanceof Structure) || ((type instanceof TypeDef) &&
			(((TypeDef) type).getBaseDataType() instanceof Structure)))) {
			return resBuf; //empty.  Could throw AssertException.
		}
		resBuf.append("<type");
		SpecXmlUtils.xmlEscapeAttribute(resBuf, "name", type.getDisplayName());
		resBuf.append(" id=\"0x" + Long.toHexString(progDataTypes.getID(type)) + "\"");
		resBuf.append(" metatype=\"struct\" size=\"0\"></type>");
		return resBuf;
	}

	private void generateCoreTypes() {
		voidDt = new VoidDataType(progDataTypes);
		ArrayList<TypeMap> typeList = new ArrayList<>();
		typeList.add(new TypeMap(DataType.DEFAULT, "undefined", " metatype=\"unknown\""));

		for (DataType dt : Undefined.getUndefinedDataTypes()) {
			typeList.add(new TypeMap(displayLanguage, dt, " metatype=\"unknown\""));
		}
		for (DataType dt : AbstractIntegerDataType.getSignedDataTypes(progDataTypes)) {
			typeList.add(
				new TypeMap(displayLanguage, dt.clone(progDataTypes), " metatype=\"int\""));
		}
		for (DataType dt : AbstractIntegerDataType.getUnsignedDataTypes(progDataTypes)) {
			typeList.add(
				new TypeMap(displayLanguage, dt.clone(progDataTypes), " metatype=\"uint\""));
		}
		for (DataType dt : AbstractFloatDataType.getFloatDataTypes(progDataTypes)) {
			typeList.add(new TypeMap(displayLanguage, dt, " metatype=\"float\""));
		}

		typeList.add(new TypeMap(DataType.DEFAULT, "code", " metatype=\"code\""));

		// Set "char" datatype
		DataType charDataType = new CharDataType(progDataTypes);

		String charMetatype = null;
		if (charDataType instanceof CharDataType && ((CharDataType) charDataType).isSigned()) {
			charMetatype = " metatype=\"int\"";
		}
		else {
			charMetatype = " metatype=\"uint\"";
		}
		if (charDataType.getLength() == 1) {
			charMetatype = charMetatype + " char=\"true\"";
		}
		else {
			charMetatype = charMetatype + " utf=\"true\"";
		}
		typeList.add(new TypeMap(displayLanguage, charDataType, charMetatype));

		// Set up the "wchar_t" datatype
		WideCharDataType wideDataType = new WideCharDataType(progDataTypes);
		typeList.add(new TypeMap(displayLanguage, wideDataType, " metatype=\"int\" utf=\"true\""));

		if (wideDataType.getLength() != 2) {
			typeList.add(new TypeMap(displayLanguage, new WideChar16DataType(progDataTypes),
				" metatype=\"int\" utf=\"true\""));
		}
		if (wideDataType.getLength() != 4) {
			typeList.add(new TypeMap(displayLanguage, new WideChar32DataType(progDataTypes),
				" metatype=\"int\" utf=\"true\""));
		}

		DataType boolDataType = new BooleanDataType(progDataTypes);
		typeList.add(new TypeMap(displayLanguage, boolDataType, " metatype=\"bool\""));

		coreBuiltin = new TypeMap[typeList.size()];
		typeList.toArray(coreBuiltin);
	}

	private void sortCoreTypes() {
		Arrays.sort(coreBuiltin, (o1, o2) -> Long.compare(o1.id, o2.id));
	}

	/**
	 * Search for a core-type by id
	 * @param id to search for
	 * @return the index of the matching TypeMap or -1
	 */
	private int findTypeById(long id) {
		int min = 0;
		int max = coreBuiltin.length - 1;
		while (min <= max) {
			int mid = (min + max) / 2;
			TypeMap typeMap = coreBuiltin[mid];
			if (id == typeMap.id) {
				return mid;
			}
			if (id < typeMap.id) {
				max = mid - 1;
			}
			else {
				min = mid + 1;
			}
		}
		return -1;
	}

	/**
	 * Build the coretypes xml element
	 * @return coretypes xml element
	 */
	public String buildCoreTypes() {

		StringBuilder buf = new StringBuilder();
		buf.append("<coretypes>\n");

		buf.append("<void/>\n");

		for (TypeMap typeMap : coreBuiltin) {
			buf.append("<type name=\"");
			buf.append(typeMap.name);
			buf.append("\" size=\"");
			buf.append(Integer.toString(typeMap.dt.getLength()));
			buf.append('\"');
			buf.append(typeMap.metatype);
			buf.append(" id=\"");					// Encode special id ( <0 for builtins )
			buf.append(Long.toString(typeMap.id));
			buf.append("\"/>\n");
		}

		buf.append("</coretypes>\n");

		return buf.toString();
	}
}
