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
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.database.data.PointerTypedefInspector;
import ghidra.program.model.address.AddressSpace;
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
 * Class for marshaling DataType objects to and from the Decompiler.
 * 
 */
public class PcodeDataTypeManager {

	/**
	 * A mapping between a DataType and its (name,id) on the decompiler side
	 */
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
		XmlElement el = parser.start("type", "void", "typeref", "def");
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
			if (el.getName().equals("def")) {
				String nameStr = el.getAttribute("name");
				String idStr = el.getAttribute("id");
				parser.discardSubTree();	// Get rid of unused <typeref>
				return findBaseType(nameStr, idStr);
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
	 * Get the inner data-type being referred to by an offset from a relative/shifted pointer.
	 * Generally we expect the base of the relative pointer to be a structure and the offset
	 * refers to a (possibly nested) field. In this case, we return the data-type of the field.
	 * Otherwise return an "undefined" data-type.
	 * @param base is the base data-type of the relative pointer
	 * @param offset is the offset into the base data-type
	 * @return the inner data-type
	 */
	public static DataType findPointerRelativeInner(DataType base, int offset) {
		if (base instanceof TypeDef) {
			base = ((TypeDef) base).getBaseDataType();
		}
		while (base instanceof Structure) {
			DataTypeComponent component = ((Structure) base).getComponentContaining(offset);
			if (component == null) {
				break;
			}
			base = component.getDataType();
			offset -= component.getOffset();
			if (offset == 0) {
				return base;
			}
		}
		return Undefined1DataType.dataType;
	}

	/**
	 * Build XML for the void data-type
	 * @param resBuf is the stream to write to
	 */
	private void buildVoid(StringBuilder resBuf) {
		resBuf.append("<void/>");
	}

	/**
	 * Build XML for a Pointer data-type
	 * @param resBuf is the stream to write to
	 * @param type is the Pointer data-type
	 * @param spc if non-null, is the specific address space associated with the pointer
	 * @param typeDef if non-null is the base TypeDef for this special form pointer
	 * @param size if non-zero, is the size of the data-type in context
	 */
	private void buildPointer(StringBuilder resBuf, Pointer type, AddressSpace spc, TypeDef typeDef,
			int size) {
		resBuf.append("<type");
		if (typeDef == null) {
			SpecXmlUtils.encodeStringAttribute(resBuf, "name", "");
		}
		else {
			appendNameIdAttributes(resBuf, typeDef);	// Use the typedef name and id
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
		if (spc != null) {
			SpecXmlUtils.encodeStringAttribute(resBuf, "space", spc.getName());
		}
		resBuf.append('>');
		DataType ptrto = type.getDataType();

		if (ptrto != null && ptrto.getDataTypeManager() != progDataTypes) {
			ptrto = ptrto.clone(progDataTypes);
		}

		if (ptrto == null) {
			buildTypeRef(resBuf, DefaultDataType.dataType, 1);
		}
		else if (ptrto instanceof AbstractStringDataType) {
			if ((ptrto instanceof StringDataType) || (type instanceof TerminatedStringDataType)) {	// Convert pointer to string
				appendCharTypeRef(resBuf, dataOrganization.getCharSize()); // to pointer to char
			}
			else if (ptrto instanceof StringUTF8DataType) {	// Convert pointer to string
				// TODO: Need to ensure that UTF8 decoding applies
				appendCharTypeRef(resBuf, 1); // to pointer to char
			}
			else if ((ptrto instanceof UnicodeDataType) ||
				(ptrto instanceof TerminatedUnicodeDataType)) {
				appendCharTypeRef(resBuf, 2);
			}
			else if ((ptrto instanceof Unicode32DataType) ||
				(ptrto instanceof TerminatedUnicode32DataType)) {
				appendCharTypeRef(resBuf, 4);
			}
			else {
				buildOpaqueString(resBuf, ptrto, 16384);
			}
		}
		else if (ptrto instanceof FunctionDefinition) {
			// FunctionDefinition may have size of -1, do not translate to undefined
			buildTypeRef(resBuf, ptrto, ptrto.getLength());
		}
		else if (ptrto.getLength() < 0 && !(ptrto instanceof FunctionDefinition)) {
			buildTypeRef(resBuf, Undefined1DataType.dataType, 1);
		}
		else {
			buildTypeRef(resBuf, ptrto, ptrto.getLength());
		}
		resBuf.append("</type>");
	}

	/**
	 * Build an XML representation of a pointer with an associated offset relative to a base data-type.
	 * The pointer is encoded as a TypeDef (of a Pointer). The "pointed to" object is the base data-type,
	 * the relative offset is passed in, and other properties come from the TypeDef.
	 * @param resBuf is the output buffer accumulating the XML
	 * @param type is the TypeDef encoding the relative pointer
	 * @param offset is the relative offset (already extracted from the TypeDef)
	 * @param space if non-null, is a specific address space associated with the pointer
	 */
	private void buildPointerRelative(StringBuilder resBuf, TypeDef type, long offset,
			AddressSpace space) {
		Pointer pointer = (Pointer) type.getBaseDataType();
		resBuf.append("<type");
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "ptrrel");
		appendNameIdAttributes(resBuf, type);
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", pointer.getLength());
		if (pointerWordSize != 1) {
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "wordsize", pointerWordSize);
		}
		if (space != null) {
			SpecXmlUtils.encodeStringAttribute(resBuf, "space", space.getName());
		}
		resBuf.append(">\n");
		DataType parent = pointer.getDataType();
		DataType ptrto = findPointerRelativeInner(parent, (int) offset);
		buildTypeRef(resBuf, ptrto, 1);
		buildTypeRef(resBuf, parent, 1);
		resBuf.append("\n<off>").append(offset).append("</off>\n");
		resBuf.append("</type>");
	}

	/**
	 * Build XML for an Array data-type
	 * @param resBuf is the stream to write to
	 * @param type is the Array data-type
	 * @param size if non-zero, is the size of the data-type in context
	 */
	private void buildArray(StringBuilder resBuf, Array type, int size) {
		if (type.isZeroLength()) {
			// TODO: Zero-element arrays not yet supported
			buildOpaqueDataType(resBuf, type, size);
			return;
		}
		resBuf.append("<type");
		SpecXmlUtils.encodeStringAttribute(resBuf, "name", "");
		int sz = type.getLength();
		if (sz == 0) {
			sz = size;
		}
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "array");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", sz);
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "arraysize", type.getNumElements());
		resBuf.append('>');
		buildTypeRef(resBuf, type.getDataType(), type.getElementLength());
		resBuf.append("</type>");
	}

	/**
	 * Build XML for a Structure data-type
	 * @param resBuf is the stream to write to
	 * @param type is the Structure data-type
	 * @param size if non-zero, is the size of the data-type in context
	 */
	private void buildStructure(StringBuilder resBuf, Structure type, int size) {
		resBuf.append("<type");
		appendNameIdAttributes(resBuf, type);
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
		DataTypeComponent[] comps = type.getDefinedComponents();
		for (DataTypeComponent comp : comps) {
			if (comp.isBitFieldComponent() || comp.getLength() == 0) {
				// TODO: bitfields, zero-length components and zero-element arrays are not yet supported by decompiler
				continue;
			}
			resBuf.append("<field");
			String field_name = comp.getFieldName();
			if (field_name == null || field_name.length() == 0) {
				field_name = comp.getDefaultFieldName();
			}
			SpecXmlUtils.xmlEscapeAttribute(resBuf, "name", field_name);
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "offset", comp.getOffset());
			resBuf.append('>');
			DataType fieldtype = comp.getDataType();
			buildTypeRef(resBuf, fieldtype, comp.getLength());
			resBuf.append("</field>\n");
		}
		resBuf.append("</type>");
	}

	/**
	 * Build XML for a Union data-type
	 * @param resBuf is the stream to write to
	 * @param unionType is the Union data-type
	 */
	public void buildUnion(StringBuilder resBuf, Union unionType) {
		resBuf.append("<type");
		appendNameIdAttributes(resBuf, unionType);
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "union");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", unionType.getLength());
		resBuf.append(">\n");
		DataTypeComponent[] comps = unionType.getDefinedComponents();
		for (DataTypeComponent comp : comps) {
			if (comp.getLength() == 0) {
				continue;
			}
			resBuf.append("<field");
			String field_name = comp.getFieldName();
			if (field_name == null || field_name.length() == 0) {
				field_name = comp.getDefaultFieldName();
			}
			SpecXmlUtils.xmlEscapeAttribute(resBuf, "name", field_name);
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "offset", comp.getOffset());
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "id", comp.getOrdinal());
			resBuf.append('>');
			DataType fieldtype = comp.getDataType();
			buildTypeRef(resBuf, fieldtype, comp.getLength());
			resBuf.append("</field>\n");
		}
		resBuf.append("</type>");
	}

	/**
	 * Build XML for an Enum data-type
	 * @param resBuf is the stream to write to
	 * @param type is the Enum data-type
	 * @param size if non-zero, is the size of the data-type in context
	 */
	private void buildEnum(StringBuilder resBuf, Enum type, int size) {
		resBuf.append("<type");
		appendNameIdAttributes(resBuf, type);
		long[] keys = type.getValues();
		String metatype = "uint";
		for (long key : keys) {
			if (key < 0) {
				metatype = "int";
				break;
			}
		}
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", metatype);
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", type.getLength());
		SpecXmlUtils.encodeBooleanAttribute(resBuf, "enum", true);
		resBuf.append(">\n");
		for (long key : keys) {
			resBuf.append("<val");
			SpecXmlUtils.xmlEscapeAttribute(resBuf, "name", type.getName(key));
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "value", key);
			resBuf.append("/>");
		}
		resBuf.append("</type>");
	}

	/**
	 * Build XML for a character data-type
	 * @param resBuf is the stream to write to
	 * @param type is the character data-type
	 * @param size if non-zero, is the size of the data-type in context
	 */
	private void buildCharDataType(StringBuilder resBuf, CharDataType type, int size) {
		resBuf.append("<type");
		appendNameIdAttributes(resBuf, type);
		boolean signed = type.isSigned();
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
		resBuf.append("</type>");
	}

	/**
	 * Build XML for a wide character data-type
	 * @param resBuf is the stream to write to
	 * @param type is the Pointer data-type
	 */
	private void buildWideCharDataType(StringBuilder resBuf, DataType type) {
		resBuf.append("<type");
		appendNameIdAttributes(resBuf, type);
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "int");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", type.getLength());
		SpecXmlUtils.encodeBooleanAttribute(resBuf, "utf", true);
		resBuf.append('>');
		resBuf.append("</type>");
	}

	/**
	 * Build XML for a string of char data-type
	 * @param resBuf is the stream to write to
	 * @param size is the length of the string
	 */
	private void buildStringDataType(StringBuilder resBuf, int size) {
		resBuf.append("<type");
		SpecXmlUtils.encodeStringAttribute(resBuf, "name", "");
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "array");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", size);
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "arraysize", size);
		resBuf.append('>');
		appendCharTypeRef(resBuf, dataOrganization.getCharSize());
		resBuf.append("</type>");
	}

	/**
	 * Build XML for a UTF8 encoded string data-type
	 * @param resBuf is the stream to write to
	 * @param size is the length of the string (in bytes)
	 */
	private void buildStringUTF8DataType(StringBuilder resBuf, int size) {
		resBuf.append("<type");
		SpecXmlUtils.encodeStringAttribute(resBuf, "name", "");
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "array");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", size);
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "arraysize", size);
		resBuf.append('>');
		appendCharTypeRef(resBuf, 1); // TODO: Need to ensure that UTF8 decoding applies
		resBuf.append("</type>");
	}

	/**
	 * Build XML for a UTF16 encoded string data-type
	 * @param resBuf is the stream to write to
	 * @param size is the length of the string (in bytes)
	 */
	private void buildUnicodeDataType(StringBuilder resBuf, int size) {
		resBuf.append("<type");
		SpecXmlUtils.encodeStringAttribute(resBuf, "name", "");
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "array");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", size);
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "arraysize", size / 2);
		resBuf.append('>');
		appendCharTypeRef(resBuf, 2);
		resBuf.append("</type>");
	}

	/**
	 * Build XML for a UTF32 encoded string data-type
	 * @param resBuf is the stream to write to
	 * @param size is the length of the string (in bytes)
	 */
	private void buildUnicode32DataType(StringBuilder resBuf, int size) {
		resBuf.append("<type");
		SpecXmlUtils.encodeStringAttribute(resBuf, "name", "");
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "array");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", size);
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "arraysize", size / 4);
		resBuf.append('>');
		appendCharTypeRef(resBuf, 4);
		resBuf.append("</type>");
	}

	/**
	 * Build XML for a FunctionDefinition data-type
	 * @param resBuf is the stream to write to
	 * @param type is the FunctionDefinition data-type
	 */
	private void buildFunctionDefinition(StringBuilder resBuf, FunctionDefinition type) {
		resBuf.append("<type");
		appendNameIdAttributes(resBuf, type);
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "code");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", 1);	// Force size of 1
		resBuf.append('>');
		CompilerSpec cspec = program.getCompilerSpec();
		FunctionPrototype fproto = new FunctionPrototype(type, cspec, voidInputIsVarargs);
		fproto.buildPrototypeXML(resBuf, this);
		resBuf.append("</type>");
	}

	/**
	 * Build XML for a boolean data-type
	 * @param resBuf is the stream to write to
	 * @param type is the boolean data-type
	 */
	private void buildBooleanDataType(StringBuilder resBuf, DataType type) {
		resBuf.append("<type");
		appendNameIdAttributes(resBuf, type);
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "bool");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", type.getLength());
		resBuf.append('>');
		resBuf.append("</type>");
	}

	/**
	 * Build XML for an integer data-type
	 * @param resBuf is the stream to write to
	 * @param type is the integer data-type
	 * @param size if non-zero, is the size of the data-type in context
	 */
	private void buildAbstractIntegerDataType(StringBuilder resBuf, AbstractIntegerDataType type,
			int size) {
		resBuf.append("<type");
		boolean signed = type.isSigned();
		int sz = type.getLength();
		if (sz <= 0) {
			sz = size;
		}
		appendNameIdAttributes(resBuf, type);
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", signed ? "int" : "uint");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", sz);
		resBuf.append('>');
		resBuf.append("</type>");
	}

	/**
	 * Build XML for a floating-point data-type
	 * @param resBuf is the stream to write to
	 * @param type is the floating-point data-type
	 */
	private void buildAbstractFloatDataType(StringBuilder resBuf, DataType type) {
		resBuf.append("<type");
		appendNameIdAttributes(resBuf, type);
		SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "float");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", type.getLength());
		resBuf.append('>');
		resBuf.append("</type>");
	}

	/**
	 * Build XML for a data-type whose internals are opaque (to the Decompiler)
	 * @param resBuf is the stream to write to
	 * @param type is the opaque data-type
	 * @param size if non-zero, is the size of the data-type in context
	 */
	private void buildOpaqueDataType(StringBuilder resBuf, DataType type, int size) {
		resBuf.append("<type");
		int sz = type.getLength();
		boolean isVarLength = false;
		if (sz <= 0) {
			sz = size;
			isVarLength = true;
		}
		appendNameIdAttributes(resBuf, type);
		if (sz < 16) {
			SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "unknown");
		}
		else {
			// Build an "opaque" structure with no fields
			SpecXmlUtils.encodeStringAttribute(resBuf, "metatype", "struct");
		}
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", sz);
		if (isVarLength) {
			SpecXmlUtils.encodeBooleanAttribute(resBuf, "varlength", true);
		}
		resBuf.append('>');
		resBuf.append("</type>");
	}

	/**
	 * Build XML for a string data-type whose internals are opaque (to the Decompiler)
	 * @param resBuf is the stream to write to
	 * @param type is the opaque string
	 * @param size is the length of the string (in bytes)
	 */
	private void buildOpaqueString(StringBuilder resBuf, DataType type, int size) {
		resBuf.append("<type");
		appendNameIdAttributes(resBuf, type);
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
		resBuf.append("</type>");
	}

	/**
	 * Build an XML document string representing the Structure that has
	 *  its size reported as zero.
	 * 
	 * @param type data type to build XML for
	 * 
	 * @return XML string document
	 */
	public StringBuilder buildCompositeZeroSizePlaceholder(DataType type) {
		StringBuilder resBuf = new StringBuilder();
		String metaString;
		if (type instanceof Structure) {
			metaString = "struct";
		}
		else if (type instanceof Union) {
			metaString = "union";
		}
		else {
			return resBuf; //empty.  Could throw AssertException.
		}
		resBuf.append("<type");
		SpecXmlUtils.xmlEscapeAttribute(resBuf, "name", type.getDisplayName());
		resBuf.append(" id=\"0x" + Long.toHexString(progDataTypes.getID(type)) + "\" metatype=\"");
		resBuf.append(metaString);
		resBuf.append("\" size=\"0\"></type>");
		return resBuf;
	}

	/**
	 * Build an XML representation of a TypeDef data-type.  Generally this sends
	 * a \<def> tag with a \<typeref> reference to the underlying data-type being typedefed,
	 * but we check for Settings on the TypeDef object that can indicate
	 * specialty data-types with their own XML format.
	 * @param resBuf is the output buffer accumulating the XML
	 * @param type is the TypeDef to build the XML for
	 * @param size is the size of the data-type for the specific instantiation
	 */
	private void buildTypeDef(StringBuilder resBuf, TypeDef type, int size) {
		DataType refType = type.getDataType();
		String format = null;
		int sz = refType.getLength();
		if (sz <= 0) {
			sz = size;
		}
		if (type.isPointer()) {
			if (hasUnsupportedTypedefSettings(type)) {
				// switch refType to undefined type if pointer-typedef settings are unsupported
				refType = Undefined.getUndefinedDataType(sz);
			}
			else {
				AddressSpace space = PointerTypedefInspector.getPointerAddressSpace(type,
					program.getAddressFactory());
				long offset = PointerTypedefInspector.getPointerComponentOffset(type);
				if (offset != 0) {
					buildPointerRelative(resBuf, type, offset, space);
					return;
				}
				if (space != null) {
					// Cannot use space, unless we are build an actual Pointer
					// Its possible that refType is still a TypeDef
					refType = type.getBaseDataType();
					buildPointer(resBuf, (Pointer) refType, space, type, size);
					return;
				}
			}
		}
		else {
			if (FormatSettingsDefinition.DEF.hasValue(type.getDefaultSettings())) {
				format = FormatSettingsDefinition.DEF.getValueString(type.getDefaultSettings());
				if (format.length() > 4) {
					format = format.substring(0, 3);
				}
			}
		}

		resBuf.append("<def");
		appendNameIdAttributes(resBuf, type);
		if (format != null) {
			SpecXmlUtils.encodeStringAttribute(resBuf, "format", format);
		}
		resBuf.append('>');

		buildTypeRef(resBuf, refType, sz);
		resBuf.append("</def>");
		return;
	}

	/**
	 * Generate an XML tag describing the given data-type. Most data-types produce a {@code <type>} tag,
	 * fully describing the data-type. Where possible a {@code <typeref>} tag is produced, which just gives
	 * the name of the data-type, deferring a full description of the data-type. For certain simple or
	 * nameless data-types, a {@code <type>} tag is emitted giving a full description.
	 * @param resBuf is the stream to append the tag to
	 * @param type is the data-type to be converted
	 * @param size is the size in bytes of the specific instance of the data-type
	 */
	public void buildTypeRef(StringBuilder resBuf, DataType type, int size) {
		if (type != null && type.getDataTypeManager() != progDataTypes) {
			type = type.clone(progDataTypes);
		}
		if ((type instanceof VoidDataType) || (type == null)) {
			buildType(resBuf, type, size);
			return;
		}
		if (type instanceof AbstractIntegerDataType) {
			buildType(resBuf, type, size);
			return;
		}
		if (type instanceof Pointer) {
			buildType(resBuf, type, size);
			return;
		}
		if (type instanceof Array) {
			buildType(resBuf, type, size);
			return;
		}
		if (type instanceof FunctionDefinition) {
			long id = progDataTypes.getID(type);
			if (id <= 0) {
				// Its possible the FunctionDefinition was built on the fly and is not
				// a permanent data-type of the program with an ID.  In this case, we can't
				// construct a <typeref> tag but must build a full <type> tag.
				buildType(resBuf, type, size);
				return;
			}
			size = 1;
		}
		else if (type.getLength() <= 0) {
			buildType(resBuf, type, size);
			return;
		}
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
	}

	/**
	 * Check for data-type settings that the Decompiler does not support
	 * @param type is the data-type whose settings are checked
	 * @return true if the data-type does have unsupported settings
	 */
	private static boolean hasUnsupportedTypedefSettings(TypeDef type) {
		return (PointerTypedefInspector.getPointerType(type) != PointerType.DEFAULT ||
			PointerTypedefInspector.hasPointerBitShift(type) ||
			PointerTypedefInspector.hasPointerBitMask(type));
	}

	/**
	 * Append the name and id associated with a given data-type to an XML stream
	 * @param resBuf is the stream to append to
	 * @param type is the given data-type
	 */
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
	 * Append an XML reference for a character data-type, based on the size in bytes
	 * @param resBuf is the stream to append to
	 * @param size is the requested size of the character data-type
	 */
	private void appendCharTypeRef(StringBuilder resBuf, int size) {
		if (size == dataOrganization.getCharSize()) {
			resBuf.append("<typeref name=\"char\"/>"); // could have size 1 or 2
			return;
		}
		if (size == dataOrganization.getWideCharSize()) {
			resBuf.append("<typeref name=\"wchar_t\"/>");
			return;
		}
		if (size == 2) {
			resBuf.append("<typeref name=\"wchar16\"/>");
			return;
		}
		if (size == 4) {
			resBuf.append("<typeref name=\"wchar32\"/>");
			return;
		}
		if (size == 1) {
			resBuf.append("<typeref name=\"byte\"/>");
			return;
		}
		throw new IllegalArgumentException("Unsupported character size");
	}

	/**
	 * Build an XML document string representing the type information for a data type
	 * 
	 * @param resBuf is the stream to append the document to
	 * @param type data type to build XML for
	 * @param size size of the data type
	 */
	public void buildType(StringBuilder resBuf, DataType type, int size) {
		if (type != null && type.getDataTypeManager() != progDataTypes) {
			type = type.clone(progDataTypes);
		}
		if ((type instanceof VoidDataType) || (type == null)) {
			buildVoid(resBuf);
		}
		else if (type instanceof TypeDef) {
			buildTypeDef(resBuf, (TypeDef) type, size);
		}
		else if (type instanceof Pointer) {
			buildPointer(resBuf, (Pointer) type, null, null, size);
		}
		else if (type instanceof Array) {
			buildArray(resBuf, (Array) type, size);
		}
		else if (type instanceof Structure) {
			buildStructure(resBuf, (Structure) type, size);
		}
		else if (type instanceof Union) {
			buildUnion(resBuf, (Union) type);
		}
		else if (type instanceof Enum) {
			buildEnum(resBuf, (Enum) type, size);
		}
		else if (type instanceof CharDataType) {
			buildCharDataType(resBuf, (CharDataType) type, size);
		}
		else if (type instanceof WideCharDataType || type instanceof WideChar16DataType ||
			type instanceof WideChar32DataType) {
			buildWideCharDataType(resBuf, type);
		}
		else if (type instanceof AbstractStringDataType) {
			if ((type instanceof StringDataType) || (type instanceof TerminatedStringDataType)) {
				buildStringDataType(resBuf, size);
			}
			else if (type instanceof StringUTF8DataType) {
				buildStringUTF8DataType(resBuf, size);
			}
			else if ((type instanceof UnicodeDataType) ||
				(type instanceof TerminatedUnicodeDataType)) {
				buildUnicodeDataType(resBuf, size);
			}
			else if ((type instanceof Unicode32DataType) ||
				(type instanceof TerminatedUnicode32DataType)) {
				buildUnicode32DataType(resBuf, size);
			}
			else {
				buildOpaqueString(resBuf, type, size);
			}
		}
		else if (type instanceof FunctionDefinition) {
			buildFunctionDefinition(resBuf, (FunctionDefinition) type);
		}
		else if (type instanceof BooleanDataType) {
			buildBooleanDataType(resBuf, type);
		}
		else if (type instanceof AbstractIntegerDataType) { // must handle char and bool above
			buildAbstractIntegerDataType(resBuf, (AbstractIntegerDataType) type, size);
		}
		else if (type instanceof AbstractFloatDataType) {
			buildAbstractFloatDataType(resBuf, type);
		}
		else {
			buildOpaqueDataType(resBuf, type, size);
		}
	}

	/**
	 * Build the list of core data-types. Data-types that are always available to the Decompiler
	 * and are associated with a (metatype,size) pair.
	 * 
	 */
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

	/**
	 * Sort the list of core data-types based their id
	 */
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
	 * Build the coretypes XML element
	 * @return coretypes XML element
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
