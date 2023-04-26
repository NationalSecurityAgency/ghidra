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

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
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
		public boolean isChar;		// Is this a character data-type
		public boolean isUtf;		// Is this a UTF encoded character data-type
		public long id;				// Calculated id for type

		public TypeMap(DecompilerLanguage lang, DataType d, String meta, boolean isChar,
				boolean isUtf) {
			dt = d;
			if (d instanceof BuiltIn) {
				name = ((BuiltIn) d).getDecompilerDisplayName(lang);
			}
			else {
				name = d.getName();
			}
			metatype = meta;
			this.isChar = isChar;
			this.isUtf = isUtf;
			id = hashName(name);
		}

		public TypeMap(DataType d, String nm, String meta, boolean isChar, boolean isUtf) {
			dt = d;
			name = nm;
			metatype = meta;
			this.isChar = isChar;
			this.isUtf = isUtf;
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
	 * @param id is an optional data-type id number
	 * @return the data-type object or null if no matching data-type exists
	 */
	public DataType findBaseType(String nm, long id) {
		if (id != 0) {
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
	 * Decode a data-type from the stream
	 * @param decoder is the stream decoder
	 * @return the decoded data-type object
	 * @throws DecoderException for invalid encodings 
	 */
	public DataType decodeDataType(Decoder decoder) throws DecoderException {
		int el = decoder.openElement();
		if (el == ELEM_VOID.id()) {
			decoder.closeElement(el);
			return voidDt;
		}
		String name = "";
		long id = 0;
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == ATTRIB_NAME.id()) {
				name = decoder.readString();
			}
			else if (attribId == ATTRIB_ID.id()) {
				id = decoder.readUnsignedInteger();
			}
		}
		if (el == ELEM_TYPEREF.id()) {
			decoder.closeElement(el);
			return findBaseType(name, id);
		}
		if (el == ELEM_DEF.id()) {
			decoder.closeElementSkipping(el);
			return findBaseType(name, id);
		}
		if (el != ELEM_TYPE.id()) {
			throw new DecoderException("Expecting <type> element");
		}

		if (name.length() != 0) {
			decoder.closeElementSkipping(el);
			return findBaseType(name, id);
		}
		String meta = decoder.readString(ATTRIB_METATYPE);
		DataType restype = null;
		if (meta.equals("ptr")) {
			int size = (int) decoder.readSignedInteger(ATTRIB_SIZE);
			if (decoder.peekElement() != 0) {
				DataType dt = decodeDataType(decoder);
				boolean useDefaultSize = (size == dataOrganization.getPointerSize() ||
					size > PointerDataType.MAX_POINTER_SIZE_BYTES);
				restype = new PointerDataType(dt, useDefaultSize ? -1 : size, progDataTypes);
			}
		}
		else if (meta.equals("array")) {
			int arrsize = (int) decoder.readSignedInteger(ATTRIB_ARRAYSIZE);
			if (decoder.peekElement() != 0) {
				DataType dt = decodeDataType(decoder);
				if (dt == null || dt.getLength() == 0) {
					dt = DataType.DEFAULT;
				}
				restype = new ArrayDataType(dt, arrsize, dt.getLength(), progDataTypes);
			}
		}
		else if (meta.equals("spacebase")) {		// Typically the type of "the whole stack"
			decoder.closeElementSkipping(el);  		// get rid of unused "addr" element
			return voidDt;
		}
		else if (meta.equals("struct")) {
			// We reach here if the decompiler invents a structure, apparently
			// this is a band-aid so that we don't blow up
			// just make an undefined data type of the appropriate size
			int size = (int) decoder.readSignedInteger(ATTRIB_SIZE);
			decoder.closeElementSkipping(el);
			return Undefined.getUndefinedDataType(size);
		}
		else if (meta.equals("int")) {
			int size = (int) decoder.readSignedInteger(ATTRIB_SIZE);
			decoder.closeElement(el);
			return AbstractIntegerDataType.getSignedDataType(size, progDataTypes);
		}
		else if (meta.equals("uint")) {
			int size = (int) decoder.readSignedInteger(ATTRIB_SIZE);
			decoder.closeElement(el);
			return AbstractIntegerDataType.getUnsignedDataType(size, progDataTypes);
		}
		else if (meta.equals("float")) {
			int size = (int) decoder.readSignedInteger(ATTRIB_SIZE);
			decoder.closeElement(el);
			// NOTE: Float lookup by length must use "raw" encoding size since
			return AbstractFloatDataType.getFloatDataType(size, progDataTypes);
		}
		else if (meta.equals("partunion")) {
			int size = (int) decoder.readSignedInteger(ATTRIB_SIZE);
			int offset = (int) decoder.readSignedInteger(ATTRIB_OFFSET);
			DataType dt = decodeDataType(decoder);
			decoder.closeElement(el);
			return new PartialUnion(progDataTypes, dt, offset, size);
		}
		else {	// We typically reach here if the decompiler invents a new type
				// probably an unknown with a non-standard size
			int size = (int) decoder.readSignedInteger(ATTRIB_SIZE);
			decoder.closeElementSkipping(el);
			return Undefined.getUndefinedDataType(size).clone(progDataTypes);
		}
		if (restype == null) {
			throw new DecoderException("Unable to resolve DataType");
		}
		decoder.closeElementSkipping(el);
		return restype;
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
	 * Encode the void data-type to the stream
	 * @param encoder is the stream encoder
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeVoid(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_VOID);
		encoder.closeElement(ELEM_VOID);
	}

	/**
	 * Encode a Pointer data-type to the stream.
	 * @param encoder is the stream encoder
	 * @param type is the Pointer data-type
	 * @param spc if non-null, is the specific address space associated with the pointer
	 * @param typeDef if non-null is the base TypeDef for this special form pointer
	 * @param size if non-zero, is the size of the data-type in context
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodePointer(Encoder encoder, Pointer type, AddressSpace spc, TypeDef typeDef,
			int size) throws IOException {
		encoder.openElement(ELEM_TYPE);
		if (typeDef == null) {
			encoder.writeString(ATTRIB_NAME, "");
		}
		else {
			encodeNameIdAttributes(encoder, typeDef);	// Use the typedef name and id
		}
		encoder.writeString(ATTRIB_METATYPE, "ptr");
		int ptrLen = type.getLength();
		if (ptrLen <= 0) {
			ptrLen = size;
		}
		encoder.writeSignedInteger(ATTRIB_SIZE, ptrLen);
		if (pointerWordSize != 1) {
			encoder.writeUnsignedInteger(ATTRIB_WORDSIZE, pointerWordSize);
		}
		if (spc != null) {
			encoder.writeSpace(ATTRIB_SPACE, spc);
		}
		DataType ptrto = type.getDataType();

		if (ptrto != null && ptrto.getDataTypeManager() != progDataTypes) {
			ptrto = ptrto.clone(progDataTypes);
		}

		if (ptrto == null) {
			encodeTypeRef(encoder, DefaultDataType.dataType, 1);
		}
		else if (ptrto instanceof AbstractStringDataType) {
			if ((ptrto instanceof StringDataType) || (type instanceof TerminatedStringDataType)) {	// Convert pointer to string
				encodeCharTypeRef(encoder, dataOrganization.getCharSize()); // to pointer to char
			}
			else if (ptrto instanceof StringUTF8DataType) {	// Convert pointer to string
				// TODO: Need to ensure that UTF8 decoding applies
				encodeCharTypeRef(encoder, 1); // to pointer to char
			}
			else if ((ptrto instanceof UnicodeDataType) ||
				(ptrto instanceof TerminatedUnicodeDataType)) {
				encodeCharTypeRef(encoder, 2);
			}
			else if ((ptrto instanceof Unicode32DataType) ||
				(ptrto instanceof TerminatedUnicode32DataType)) {
				encodeCharTypeRef(encoder, 4);
			}
			else {
				encodeOpaqueString(encoder, ptrto, 16384);
			}
		}
		else if (ptrto instanceof FunctionDefinition) {
			// FunctionDefinition may have size of -1, do not translate to undefined
			encodeTypeRef(encoder, ptrto, ptrto.getLength());
		}
		else if (ptrto.getLength() < 0 && !(ptrto instanceof FunctionDefinition)) {
			encodeTypeRef(encoder, Undefined1DataType.dataType, 1);
		}
		else {
			encodeTypeRef(encoder, ptrto, ptrto.getLength());
		}
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a pointer with an associated offset relative to a base data-type to stream.
	 * The pointer is encoded as a TypeDef (of a Pointer). The "pointed to" object is the base data-type,
	 * the relative offset is passed in, and other properties come from the TypeDef.
	 * @param encoder is the stream encoder
	 * @param type is the TypeDef encoding the relative pointer
	 * @param offset is the relative offset (already extracted from the TypeDef)
	 * @param space if non-null, is a specific address space associated with the pointer
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodePointerRelative(Encoder encoder, TypeDef type, long offset,
			AddressSpace space) throws IOException {
		Pointer pointer = (Pointer) type.getBaseDataType();
		encoder.openElement(ELEM_TYPE);
		encoder.writeString(ATTRIB_METATYPE, "ptrrel");
		encodeNameIdAttributes(encoder, type);
		encoder.writeSignedInteger(ATTRIB_SIZE, pointer.getLength());
		if (pointerWordSize != 1) {
			encoder.writeUnsignedInteger(ATTRIB_WORDSIZE, pointerWordSize);
		}
		if (space != null) {
			encoder.writeSpace(ATTRIB_SPACE, space);
		}
		DataType parent = pointer.getDataType();
		DataType ptrto = findPointerRelativeInner(parent, (int) offset);
		encodeTypeRef(encoder, ptrto, 1);
		encodeTypeRef(encoder, parent, 1);
		encoder.openElement(ELEM_OFF);
		encoder.writeSignedInteger(ATTRIB_CONTENT, offset);
		encoder.closeElement(ELEM_OFF);
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode an Array data-type to stream.
	 * @param encoder is the stream encoder
	 * @param type is the Array data-type
	 * @param size if non-zero, is the size of the data-type in context
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeArray(Encoder encoder, Array type, int size) throws IOException {
		if (type.isZeroLength()) {
			// TODO: Zero-element arrays not yet supported
			encodeOpaqueDataType(encoder, type, size);
			return;
		}
		encoder.openElement(ELEM_TYPE);
		encoder.writeString(ATTRIB_NAME, "");
		int sz = type.getLength();
		if (sz == 0) {
			sz = size;
		}
		encoder.writeString(ATTRIB_METATYPE, "array");
		encoder.writeSignedInteger(ATTRIB_SIZE, sz);
		encoder.writeSignedInteger(ATTRIB_ARRAYSIZE, type.getNumElements());
		encodeTypeRef(encoder, type.getDataType(), type.getElementLength());
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a Structure data-type to stream
	 * @param encoder is the stream encoder
	 * @param type is the Structure data-type
	 * @param size if non-zero, is the size of the data-type in context
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeStructure(Encoder encoder, Structure type, int size) throws IOException {
		encoder.openElement(ELEM_TYPE);
		encodeNameIdAttributes(encoder, type);
		// if size is 0, insert an Undefined4 component
		//
		int sz = type.getLength();
		if (sz == 0) {
			type = new StructureDataType(type.getCategoryPath(), type.getName(), 1);
			sz = type.getLength();
		}
		encoder.writeString(ATTRIB_METATYPE, "struct");
		encoder.writeSignedInteger(ATTRIB_SIZE, sz);
		DataTypeComponent[] comps = type.getDefinedComponents();
		for (DataTypeComponent comp : comps) {
			if (comp.isBitFieldComponent() || comp.getLength() == 0) {
				// TODO: bitfields, zero-length components and zero-element arrays are not yet supported by decompiler
				continue;
			}
			encoder.openElement(ELEM_FIELD);
			String field_name = comp.getFieldName();
			if (field_name == null || field_name.length() == 0) {
				field_name = comp.getDefaultFieldName();
			}
			encoder.writeString(ATTRIB_NAME, field_name);
			encoder.writeSignedInteger(ATTRIB_OFFSET, comp.getOffset());
			DataType fieldtype = comp.getDataType();
			encodeTypeRef(encoder, fieldtype, comp.getLength());
			encoder.closeElement(ELEM_FIELD);
		}
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a Union data-type to the stream
	 * @param encoder is the stream encoder
	 * @param unionType is the Union data-type
	 * @throws IOException for errors in the underlying stream
	 */
	public void encodeUnion(Encoder encoder, Union unionType) throws IOException {
		encoder.openElement(ELEM_TYPE);
		encodeNameIdAttributes(encoder, unionType);
		encoder.writeString(ATTRIB_METATYPE, "union");
		encoder.writeSignedInteger(ATTRIB_SIZE, unionType.getLength());
		DataTypeComponent[] comps = unionType.getDefinedComponents();
		for (DataTypeComponent comp : comps) {
			if (comp.getLength() == 0) {
				continue;
			}
			encoder.openElement(ELEM_FIELD);
			String field_name = comp.getFieldName();
			if (field_name == null || field_name.length() == 0) {
				field_name = comp.getDefaultFieldName();
			}
			encoder.writeString(ATTRIB_NAME, field_name);
			encoder.writeSignedInteger(ATTRIB_OFFSET, comp.getOffset());
			encoder.writeSignedInteger(ATTRIB_ID, comp.getOrdinal());
			DataType fieldtype = comp.getDataType();
			encodeTypeRef(encoder, fieldtype, comp.getLength());
			encoder.closeElement(ELEM_FIELD);
		}
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode an Enum data-type to the stream.
	 * @param encoder is the stream encoder
	 * @param type is the Enum data-type
	 * @param size if non-zero, is the size of the data-type in context
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeEnum(Encoder encoder, Enum type, int size) throws IOException {
		encoder.openElement(ELEM_TYPE);
		encodeNameIdAttributes(encoder, type);
		long[] keys = type.getValues();
		String metatype = "uint";
		for (long key : keys) {
			if (key < 0) {
				metatype = "int";
				break;
			}
		}
		encoder.writeString(ATTRIB_METATYPE, metatype);
		encoder.writeSignedInteger(ATTRIB_SIZE, type.getLength());
		encoder.writeBool(ATTRIB_ENUM, true);
		for (long key : keys) {
			encoder.openElement(ELEM_VAL);
			encoder.writeString(ATTRIB_NAME, type.getName(key));
			encoder.writeSignedInteger(ATTRIB_VALUE, key);
			encoder.closeElement(ELEM_VAL);
		}
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a character data-type to the stream
	 * @param encoder is the stream encoder
	 * @param type is the character data-type
	 * @param size if non-zero, is the size of the data-type in context
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeCharDataType(Encoder encoder, CharDataType type, int size)
			throws IOException {
		encoder.openElement(ELEM_TYPE);
		encodeNameIdAttributes(encoder, type);
		boolean signed = type.isSigned();
		int sz = type.getLength();
		if (sz <= 0) {
			sz = size;
		}
		encoder.writeString(ATTRIB_METATYPE, signed ? "int" : "uint");
		encoder.writeSignedInteger(ATTRIB_SIZE, sz);
		if (sz == 1) {
			encoder.writeBool(ATTRIB_CHAR, true);
		}
		else {
			encoder.writeBool(ATTRIB_UTF, true);
		}
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a wide character data-type to the stream
	 * @param encoder is the stream encoder
	 * @param type is the Pointer data-type
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeWideCharDataType(Encoder encoder, DataType type) throws IOException {
		encoder.openElement(ELEM_TYPE);
		encodeNameIdAttributes(encoder, type);
		encoder.writeString(ATTRIB_METATYPE, "int");
		encoder.writeSignedInteger(ATTRIB_SIZE, type.getLength());
		encoder.writeBool(ATTRIB_UTF, true);
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a string of char data-type to the stream.
	 * @param encoder is the stream encoder
	 * @param size is the length of the string
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeStringDataType(Encoder encoder, int size) throws IOException {
		encoder.openElement(ELEM_TYPE);
		encoder.writeString(ATTRIB_NAME, "");
		encoder.writeString(ATTRIB_METATYPE, "array");
		encoder.writeSignedInteger(ATTRIB_SIZE, size);
		encoder.writeSignedInteger(ATTRIB_ARRAYSIZE, size);
		encodeCharTypeRef(encoder, dataOrganization.getCharSize());
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a UTF8 encoded string data-type to the stream
	 * @param encoder is the stream encoder
	 * @param size is the length of the string (in bytes)
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeStringUTF8DataType(Encoder encoder, int size) throws IOException {
		encoder.openElement(ELEM_TYPE);
		encoder.writeString(ATTRIB_NAME, "");
		encoder.writeString(ATTRIB_METATYPE, "array");
		encoder.writeSignedInteger(ATTRIB_SIZE, size);
		encoder.writeSignedInteger(ATTRIB_ARRAYSIZE, size);
		encodeCharTypeRef(encoder, 1); // TODO: Need to ensure that UTF8 decoding applies
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a UTF16 encoded string data-type to the stream
	 * @param encoder is the stream encoder
	 * @param size is the length of the string (in bytes)
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeUnicodeDataType(Encoder encoder, int size) throws IOException {
		encoder.openElement(ELEM_TYPE);
		encoder.writeString(ATTRIB_NAME, "");
		encoder.writeString(ATTRIB_METATYPE, "array");
		encoder.writeSignedInteger(ATTRIB_SIZE, size);
		encoder.writeSignedInteger(ATTRIB_ARRAYSIZE, size / 2);
		encodeCharTypeRef(encoder, 2);
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a UTF32 encoded string data-type to the stream
	 * @param encoder is the stream encoder
	 * @param size is the length of the string (in bytes)
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeUnicode32DataType(Encoder encoder, int size) throws IOException {
		encoder.openElement(ELEM_TYPE);
		encoder.writeString(ATTRIB_NAME, "");
		encoder.writeString(ATTRIB_METATYPE, "array");
		encoder.writeSignedInteger(ATTRIB_SIZE, size);
		encoder.writeSignedInteger(ATTRIB_ARRAYSIZE, size / 4);
		encodeCharTypeRef(encoder, 4);
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a FunctionDefinition data-type to the stream.
	 * @param encoder is the stream encoder
	 * @param type is the FunctionDefinition data-type
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeFunctionDefinition(Encoder encoder, FunctionDefinition type)
			throws IOException {
		encoder.openElement(ELEM_TYPE);
		encodeNameIdAttributes(encoder, type);
		encoder.writeString(ATTRIB_METATYPE, "code");
		encoder.writeSignedInteger(ATTRIB_SIZE, 1);		// Force size of 1
		CompilerSpec cspec = program.getCompilerSpec();
		FunctionPrototype fproto = new FunctionPrototype(type, cspec, voidInputIsVarargs);
		fproto.encodePrototype(encoder, this);
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a boolean data-type to the stream
	 * @param encoder is the stream encoder
	 * @param type is the boolean data-type
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeBooleanDataType(Encoder encoder, DataType type) throws IOException {
		encoder.openElement(ELEM_TYPE);
		encodeNameIdAttributes(encoder, type);
		encoder.writeString(ATTRIB_METATYPE, "bool");
		encoder.writeSignedInteger(ATTRIB_SIZE, type.getLength());
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode an integer data-type to the stream
	 * @param encoder is the stream encoder
	 * @param type is the integer data-type
	 * @param size if non-zero, is the size of the data-type in context
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeAbstractIntegerDataType(Encoder encoder, AbstractIntegerDataType type,
			int size) throws IOException {
		encoder.openElement(ELEM_TYPE);
		boolean signed = type.isSigned();
		int sz = type.getLength();
		if (sz <= 0) {
			sz = size;
		}
		encodeNameIdAttributes(encoder, type);
		encoder.writeString(ATTRIB_METATYPE, signed ? "int" : "uint");
		encoder.writeSignedInteger(ATTRIB_SIZE, sz);
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a floating-point data-type to the stream
	 * @param encoder is the stream encoder
	 * @param type is the floating-point data-type
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeAbstractFloatDataType(Encoder encoder, DataType type) throws IOException {
		encoder.openElement(ELEM_TYPE);
		encodeNameIdAttributes(encoder, type);
		encoder.writeString(ATTRIB_METATYPE, "float");
		encoder.writeSignedInteger(ATTRIB_SIZE, type.getLength());
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a data-type whose internals are opaque (to the Decompiler) to stream.
	 * @param encoder is the stream encoder
	 * @param type is the opaque data-type
	 * @param size if non-zero, is the size of the data-type in context
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeOpaqueDataType(Encoder encoder, DataType type, int size) throws IOException {
		encoder.openElement(ELEM_TYPE);
		int sz = type.getLength();
		boolean isVarLength = false;
		if (sz <= 0) {
			sz = size;
			isVarLength = true;
		}
		encodeNameIdAttributes(encoder, type);
		if (sz < 16) {
			encoder.writeString(ATTRIB_METATYPE, "unknown");
		}
		else {
			// Build an "opaque" structure with no fields
			encoder.writeString(ATTRIB_METATYPE, "struct");
		}
		encoder.writeSignedInteger(ATTRIB_SIZE, sz);
		if (isVarLength) {
			encoder.writeBool(ATTRIB_VARLENGTH, true);
		}
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a string data-type whose internals are opaque (to the Decompiler) to stream.
	 * @param encoder is the stream encoder
	 * @param type is the opaque string
	 * @param size is the length of the string (in bytes)
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeOpaqueString(Encoder encoder, DataType type, int size) throws IOException {
		encoder.openElement(ELEM_TYPE);
		encodeNameIdAttributes(encoder, type);
		encoder.writeString(ATTRIB_METATYPE, "struct");
		encoder.writeSignedInteger(ATTRIB_SIZE, size);
		encoder.writeBool(ATTRIB_OPAQUESTRING, true);
		encoder.writeBool(ATTRIB_VARLENGTH, true);
		encoder.openElement(ELEM_FIELD);
		encoder.writeString(ATTRIB_NAME, "unknown_data1");
		encoder.writeSignedInteger(ATTRIB_OFFSET, 0);
		encoder.openElement(ELEM_TYPEREF);
		encoder.writeString(ATTRIB_NAME, "byte");
		encoder.closeElement(ELEM_TYPEREF);
		encoder.closeElement(ELEM_FIELD);
		size -= 1;
		encoder.openElement(ELEM_FIELD);
		encoder.writeString(ATTRIB_NAME, "opaque_data");
		encoder.writeSignedInteger(ATTRIB_OFFSET, 1);
		encoder.openElement(ELEM_TYPE);
		encoder.writeString(ATTRIB_NAME, "");
		encoder.writeString(ATTRIB_METATYPE, "array");
		encoder.writeSignedInteger(ATTRIB_SIZE, size);
		encoder.writeSignedInteger(ATTRIB_ARRAYSIZE, size);
		encoder.openElement(ELEM_TYPEREF);
		encoder.writeString(ATTRIB_NAME, "byte");
		encoder.closeElement(ELEM_TYPEREF);
		encoder.closeElement(ELEM_TYPE);
		encoder.closeElement(ELEM_FIELD);
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a Structure to the stream that has its size reported as zero.
	 * @param encoder is the stream encoder
	 * @param type data type to encode
	 * @throws IOException for errors in the underlying stream
	 */
	public void encodeCompositeZeroSizePlaceholder(Encoder encoder, DataType type)
			throws IOException {
		String metaString;
		if (type instanceof Structure) {
			metaString = "struct";
		}
		else if (type instanceof Union) {
			metaString = "union";
		}
		else {
			return; //empty.  Could throw AssertException.
		}
		encoder.openElement(ELEM_TYPE);
		encoder.writeString(ATTRIB_NAME, type.getDisplayName());
		encoder.writeUnsignedInteger(ATTRIB_ID, progDataTypes.getID(type));
		encoder.writeString(ATTRIB_METATYPE, metaString);
		encoder.writeSignedInteger(ATTRIB_SIZE, 0);
		encoder.closeElement(ELEM_TYPE);
	}

	/**
	 * Encode a TypeDef data-type to the stream.  Generally this sends
	 * a \<def> element with a \<typeref> reference to the underlying data-type being typedefed,
	 * but we check for Settings on the TypeDef object that can indicate
	 * specialty data-types with their own encodings.
	 * @param encoder is the stream encoder
	 * @param type is the TypeDef to build the XML for
	 * @param size is the size of the data-type for the specific instantiation
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeTypeDef(Encoder encoder, TypeDef type, int size) throws IOException {
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
					encodePointerRelative(encoder, type, offset, space);
					return;
				}
				if (space != null) {
					// Cannot use space, unless we are build an actual Pointer
					// Its possible that refType is still a TypeDef
					refType = type.getBaseDataType();
					encodePointer(encoder, (Pointer) refType, space, type, size);
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

		encoder.openElement(ELEM_DEF);
		encodeNameIdAttributes(encoder, type);
		if (format != null) {
			encoder.writeString(ATTRIB_FORMAT, format);
		}

		encodeTypeRef(encoder, refType, sz);
		encoder.closeElement(ELEM_DEF);
	}

	/**
	 * Encode a reference to the given data-type to stream. Most data-types produce a
	 * {@code <type>} element, fully describing the data-type. Where possible a {@code <typeref>}
	 * element is produced, which just encodes the name of the data-type, deferring a full
	 * description of the data-type. For certain simple or nameless data-types, a {@code <type>}
	 * element is emitted giving a full description.
	 * @param encoder is the stream encoder
	 * @param type is the data-type to be converted
	 * @param size is the size in bytes of the specific instance of the data-type
	 * @throws IOException for errors in the underlying stream
	 */
	public void encodeTypeRef(Encoder encoder, DataType type, int size) throws IOException {
		if (type != null && type.getDataTypeManager() != progDataTypes) {
			type = type.clone(progDataTypes);
		}
		if ((type instanceof VoidDataType) || (type == null)) {
			encodeType(encoder, type, size);
			return;
		}
		if (type instanceof AbstractIntegerDataType) {
			encodeType(encoder, type, size);
			return;
		}
		if (type instanceof Pointer) {
			encodeType(encoder, type, size);
			return;
		}
		if (type instanceof Array) {
			encodeType(encoder, type, size);
			return;
		}
		if (type instanceof FunctionDefinition) {
			long id = progDataTypes.getID(type);
			if (id <= 0) {
				// Its possible the FunctionDefinition was built on the fly and is not
				// a permanent data-type of the program with an ID.  In this case, we can't
				// construct a <typeref> element but must build a full <type> element.
				encodeType(encoder, type, size);
				return;
			}
			size = 1;
		}
		else if (type.getLength() <= 0) {
			encodeType(encoder, type, size);
			return;
		}
		encoder.openElement(ELEM_TYPEREF);
		if (type instanceof BuiltIn) {
			encoder.writeString(ATTRIB_NAME,
				((BuiltIn) type).getDecompilerDisplayName(displayLanguage));
		}
		else {
			encoder.writeString(ATTRIB_NAME, type.getName());
			// Get id of type associated with program, will return -1 if not associated (builtin)
			long id = progDataTypes.getID(type);
			if (id > 0) {
				encoder.writeUnsignedInteger(ATTRIB_ID, id);
			}
			if (type.getLength() <= 0 && size > 0) {
				encoder.writeSignedInteger(ATTRIB_SIZE, size);
			}
		}
		encoder.closeElement(ELEM_TYPEREF);
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
	 * Encode the name and id associated with a given data-type to a stream as attributes
	 * of the current element.
	 * @param encoder is the stream encoder
	 * @param type is the given data-type
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeNameIdAttributes(Encoder encoder, DataType type) throws IOException {
		if (type instanceof BuiltIn) {
			encoder.writeString(ATTRIB_NAME,
				((BuiltIn) type).getDecompilerDisplayName(displayLanguage));
		}
		else {
			encoder.writeString(ATTRIB_NAME, type.getName());
			long id = progDataTypes.getID(type);
			if (id > 0) {
				encoder.writeUnsignedInteger(ATTRIB_ID, id);
			}
		}
	}

	/**
	 * Encode a reference element for a character data-type, based on the size in bytes to a stream.
	 * @param encoder is the stream encoder
	 * @param size is the requested size of the character data-type
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeCharTypeRef(Encoder encoder, int size) throws IOException {
		if (size == dataOrganization.getCharSize()) {
			encoder.openElement(ELEM_TYPEREF);
			encoder.writeString(ATTRIB_NAME, "char");	// could have size 1 or 2
			encoder.closeElement(ELEM_TYPEREF);
			return;
		}
		if (size == dataOrganization.getWideCharSize()) {
			encoder.openElement(ELEM_TYPEREF);
			encoder.writeString(ATTRIB_NAME, "wchar_t");
			encoder.closeElement(ELEM_TYPEREF);
			return;
		}
		if (size == 2) {
			encoder.openElement(ELEM_TYPEREF);
			encoder.writeString(ATTRIB_NAME, "wchar16");
			encoder.closeElement(ELEM_TYPEREF);
			return;
		}
		if (size == 4) {
			encoder.openElement(ELEM_TYPEREF);
			encoder.writeString(ATTRIB_NAME, "wchar32");
			encoder.closeElement(ELEM_TYPEREF);
			return;
		}
		if (size == 1) {
			encoder.openElement(ELEM_TYPEREF);
			encoder.writeString(ATTRIB_NAME, "byte");
			encoder.closeElement(ELEM_TYPEREF);
			return;
		}
		throw new IllegalArgumentException("Unsupported character size");
	}

	/**
	 * Encode information for a data-type to the stream
	 * 
	 * @param encoder is the stream encoder
	 * @param type is the data-type to encode
	 * @param size is the size of the data-type
	 * @throws IOException for errors in the underlying stream
	 */
	public void encodeType(Encoder encoder, DataType type, int size) throws IOException {
		if (type != null && type.getDataTypeManager() != progDataTypes) {
			type = type.clone(progDataTypes);
		}
		if ((type instanceof VoidDataType) || (type == null)) {
			encodeVoid(encoder);
		}
		else if (type instanceof TypeDef) {
			encodeTypeDef(encoder, (TypeDef) type, size);
		}
		else if (type instanceof Pointer) {
			encodePointer(encoder, (Pointer) type, null, null, size);
		}
		else if (type instanceof Array) {
			encodeArray(encoder, (Array) type, size);
		}
		else if (type instanceof Structure) {
			encodeStructure(encoder, (Structure) type, size);
		}
		else if (type instanceof Union) {
			encodeUnion(encoder, (Union) type);
		}
		else if (type instanceof Enum) {
			encodeEnum(encoder, (Enum) type, size);
		}
		else if (type instanceof CharDataType) {
			encodeCharDataType(encoder, (CharDataType) type, size);
		}
		else if (type instanceof WideCharDataType || type instanceof WideChar16DataType ||
			type instanceof WideChar32DataType) {
			encodeWideCharDataType(encoder, type);
		}
		else if (type instanceof AbstractStringDataType) {
			if ((type instanceof StringDataType) || (type instanceof TerminatedStringDataType)) {
				encodeStringDataType(encoder, size);
			}
			else if (type instanceof StringUTF8DataType) {
				encodeStringUTF8DataType(encoder, size);
			}
			else if ((type instanceof UnicodeDataType) ||
				(type instanceof TerminatedUnicodeDataType)) {
				encodeUnicodeDataType(encoder, size);
			}
			else if ((type instanceof Unicode32DataType) ||
				(type instanceof TerminatedUnicode32DataType)) {
				encodeUnicode32DataType(encoder, size);
			}
			else {
				encodeOpaqueString(encoder, type, size);
			}
		}
		else if (type instanceof FunctionDefinition) {
			encodeFunctionDefinition(encoder, (FunctionDefinition) type);
		}
		else if (type instanceof BooleanDataType) {
			encodeBooleanDataType(encoder, type);
		}
		else if (type instanceof AbstractIntegerDataType) { // must handle char and bool above
			encodeAbstractIntegerDataType(encoder, (AbstractIntegerDataType) type, size);
		}
		else if (type instanceof AbstractFloatDataType) {
			encodeAbstractFloatDataType(encoder, type);
		}
		else {
			encodeOpaqueDataType(encoder, type, size);
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
		typeList.add(new TypeMap(DataType.DEFAULT, "undefined", "unknown", false, false));

		for (DataType dt : Undefined.getUndefinedDataTypes()) {
			typeList.add(new TypeMap(displayLanguage, dt, "unknown", false, false));
		}
		for (DataType dt : AbstractIntegerDataType.getSignedDataTypes(progDataTypes)) {
			typeList.add(
				new TypeMap(displayLanguage, dt.clone(progDataTypes), "int", false, false));
		}
		for (DataType dt : AbstractIntegerDataType.getUnsignedDataTypes(progDataTypes)) {
			typeList.add(
				new TypeMap(displayLanguage, dt.clone(progDataTypes), "uint", false, false));
		}
		for (DataType dt : AbstractFloatDataType.getFloatDataTypes(progDataTypes)) {
			typeList.add(new TypeMap(displayLanguage, dt, "float", false, false));
		}

		typeList.add(new TypeMap(DataType.DEFAULT, "code", "code", false, false));

		// Set "char" datatype
		DataType charDataType = new CharDataType(progDataTypes);

		String charMetatype = null;
		boolean isChar = false;
		boolean isUtf = false;
		if (charDataType instanceof CharDataType && ((CharDataType) charDataType).isSigned()) {
			charMetatype = "int";
		}
		else {
			charMetatype = "uint";
		}
		if (charDataType.getLength() == 1) {
			isChar = true;
		}
		else {
			isUtf = true;
		}
		typeList.add(new TypeMap(displayLanguage, charDataType, charMetatype, isChar, isUtf));

		// Set up the "wchar_t" datatype
		WideCharDataType wideDataType = new WideCharDataType(progDataTypes);
		typeList.add(new TypeMap(displayLanguage, wideDataType, "int", false, true));

		if (wideDataType.getLength() != 2) {
			typeList.add(new TypeMap(displayLanguage, new WideChar16DataType(progDataTypes), "int",
				false, true));
		}
		if (wideDataType.getLength() != 4) {
			typeList.add(new TypeMap(displayLanguage, new WideChar32DataType(progDataTypes), "int",
				false, true));
		}

		DataType boolDataType = new BooleanDataType(progDataTypes);
		typeList.add(new TypeMap(displayLanguage, boolDataType, "bool", false, false));

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
	 * Encode the coretypes to the stream
	 * @param encoder is the stream encoder
	 * @throws IOException for errors in the underlying stream
	 */
	public void encodeCoreTypes(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_CORETYPES);
		encoder.openElement(ELEM_VOID);
		encoder.closeElement(ELEM_VOID);

		for (TypeMap typeMap : coreBuiltin) {
			encoder.openElement(ELEM_TYPE);
			encoder.writeString(ATTRIB_NAME, typeMap.name);
			encoder.writeSignedInteger(ATTRIB_SIZE, typeMap.dt.getLength());
			encoder.writeString(ATTRIB_METATYPE, typeMap.metatype);
			if (typeMap.isChar) {
				encoder.writeBool(ATTRIB_CHAR, true);
			}
			if (typeMap.isUtf) {
				encoder.writeBool(ATTRIB_UTF, true);
			}
			// Encode special id ( <0 for builtins )
			encoder.writeSignedInteger(ATTRIB_ID, typeMap.id);
			encoder.closeElement(ELEM_TYPE);
		}
		encoder.closeElement(ELEM_CORETYPES);
	}
}
