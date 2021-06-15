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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.*;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbLog;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.PrimitiveMsType;
import ghidra.program.model.data.*;
import ghidra.util.exception.AssertException;

/**
 * Takes care of allocating unique instances of primitive data types for the {@link PdbApplicator},
 * and is used principally by the many instances of {@link PrimitiveTypeApplier}.
 */
public class PdbPrimitiveTypeApplicator {

	private final static DataType NO_TYPE_DATATYPE =
		new TypedefDataType("<NoType>", Undefined1DataType.dataType);

	//==============================================================================================
	private DataTypeManager dataTypeManager;

	//==============================================================================================
	private DataType voidGhidraPrimitive = null;
	private DataType charGhidraPrimitive = null;
	private DataType signedCharGhidraPrimitive = null;
	private DataType unsignedCharGhidraPrimitive = null;

	//private Map<Integer, DataType> booleanGhidraPrimitives = new HashMap<>();
	private Map<Integer, DataType> integralGhidraPrimitives = new HashMap<>();
	private Map<Integer, DataType> unsignedIntegralGhidraPrimitives = new HashMap<>();
	private Map<Integer, DataType> floatGhidraPrimitives = new HashMap<>();
	private Map<Integer, DataType> complexGhidraPrimitives = new HashMap<>();

	private Map<String, DataType> otherPrimitives = new HashMap<>();

	//==============================================================================================
	/**
	 * Constructor
	 * @param dataTypeManager The {@link DataTypeManager} associated with these types.
	 */
	public PdbPrimitiveTypeApplicator(DataTypeManager dataTypeManager) {
		Objects.requireNonNull(dataTypeManager, "dataTypeManager cannot be null");
		this.dataTypeManager = dataTypeManager;
	}

	/**
	 * Returns the {@link DataTypeManager} associated with this analyzer. 
	 * @return DataTypeManager which this analyzer is using.
	 */
	private DataTypeManager getDataTypeManager() {
		return dataTypeManager;
	}

	DataType resolve(DataType dataType) {
		return getDataTypeManager().resolve(dataType,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
	}

	//==============================================================================================
	DataType getNoType(PrimitiveMsType type) {
		return NO_TYPE_DATATYPE;
	}

	DataType getVoidType() {
		if (voidGhidraPrimitive == null) {
			DataType dataType = new VoidDataType(getDataTypeManager());
			voidGhidraPrimitive = resolve(dataType);
		}
		return voidGhidraPrimitive;
	}

	DataType getCharType() {
		if (charGhidraPrimitive == null) {
			DataType dataType = new CharDataType(getDataTypeManager());
			charGhidraPrimitive = resolve(dataType);
		}
		return charGhidraPrimitive;
	}

	DataType getSignedCharType() {
		if (signedCharGhidraPrimitive == null) {
			DataType dataType = new SignedCharDataType(getDataTypeManager());
			signedCharGhidraPrimitive = resolve(dataType);
		}
		return signedCharGhidraPrimitive;
	}

	DataType getUnsignedCharType() {
		if (unsignedCharGhidraPrimitive == null) {
			DataType dataType = new UnsignedCharDataType(getDataTypeManager());
			unsignedCharGhidraPrimitive = resolve(dataType);
		}
		return unsignedCharGhidraPrimitive;
	}

	DataType getUnicode16Type() {
		// For now, we are returning WideChar16 for Unicode16.
		return new WideChar16DataType(getDataTypeManager());
	}

	DataType getUnicode32Type() {
		// For now, we are returning WideChar32 for Unicode32.
		return new WideChar32DataType(getDataTypeManager());
	}

	WideCharDataType getWideCharType() {
		return new WideCharDataType(getDataTypeManager());
	}

	DataType get8BitIntegerType() {
		String name = "int8";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getIntegerSize() == 1) {
			type = IntegerDataType.dataType;
		}
		else {
			type = createTypedef(name, getIntegralType(1));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get8BitUnsignedIntegerType() {
		String name = "uint8";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getIntegerSize() == 1) {
			type = UnsignedIntegerDataType.dataType;
		}
		else {
			type = createTypedef(name, getUnsignedIntegralType(1));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get16BitIntegerType() {
		String name = "int16";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getIntegerSize() == 2) {
			type = IntegerDataType.dataType;
		}
		else {
			type = createTypedef(name, getIntegralType(2));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get16BitUnsignedIntegerType() {
		String name = "uint16";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getIntegerSize() == 2) {
			type = UnsignedIntegerDataType.dataType;
		}
		else {
			type = createTypedef(name, getUnsignedIntegralType(2));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get16BitShortType() {
		String name = "short16";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getShortSize() == 2) {
			type = ShortDataType.dataType;
		}
		else {
			type = createTypedef(name, getIntegralType(2));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get16BitUnsignedShortType() {
		String name = "ushort16";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getShortSize() == 2) {
			type = UnsignedShortDataType.dataType;
		}
		else {
			type = createTypedef(name, getUnsignedIntegralType(2));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get32BitIntegerType() {
		String name = "int32";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getIntegerSize() == 4) {
			type = IntegerDataType.dataType;
		}
		else {
			type = createTypedef(name, getIntegralType(4));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get32BitUnsignedIntegerType() {
		String name = "uint32";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getIntegerSize() == 4) {
			type = UnsignedIntegerDataType.dataType;
		}
		else {
			type = createTypedef(name, getUnsignedIntegralType(4));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get32BitLongType() {
		String name = "long32";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getLongSize() == 4) {
			type = LongDataType.dataType;
		}
		else {
			type = createTypedef(name, getIntegralType(4));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get32BitUnsignedLongType() {
		String name = "ulong32";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getLongSize() == 4) {
			type = UnsignedLongDataType.dataType;
		}
		else {
			type = createTypedef(name, getUnsignedIntegralType(4));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get64BitLongType() {
		String name = "long64";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getLongSize() == 8) {
			type = LongDataType.dataType;
		}
		else {
			type = createTypedef(name, getIntegralType(8));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get64BitUnsignedLongType() {
		String name = "ulong64";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getLongSize() == 8) {
			type = UnsignedLongDataType.dataType;
		}
		else {
			type = createTypedef(name, getUnsignedIntegralType(8));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get64BitIntegerType() {
		String name = "int64";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getIntegerSize() == 8) {
			type = IntegerDataType.dataType;
		}
		else {
			type = createTypedef(name, getIntegralType(8));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get64BitUnsignedIntegerType() {
		String name = "uint64";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getIntegerSize() == 8) {
			type = UnsignedIntegerDataType.dataType;
		}
		else {
			type = createTypedef(name, getUnsignedIntegralType(8));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get128BitLongType() {
		String name = "ulong128";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getLongSize() == 16) {
			type = LongDataType.dataType;
		}
		else {
			type = createTypedef(name, getIntegralType(16));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get128BitUnsignedLongType() {
		String name = "ulong128";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getLongSize() == 16) {
			type = UnsignedLongDataType.dataType;
		}
		else {
			type = createTypedef(name, getUnsignedIntegralType(16));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get128BitIntegerType() {
		String name = "int128";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getIntegerSize() == 16) {
			type = IntegerDataType.dataType;
		}
		else {
			type = createTypedef(name, getIntegralType(16));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get128BitUnsignedIntegerType() {
		String name = "uint128";
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		DataType type;
		if (getDataTypeManager().getDataOrganization().getIntegerSize() == 16) {
			type = UnsignedIntegerDataType.dataType;
		}
		else {
			type = createTypedef(name, getUnsignedIntegralType(16));
		}
		DataType resolved = resolve(type);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	private DataType createTypedef(String name, DataType dataType) {
		DataType typedefDataType = new TypedefDataType(name, dataType);
		return resolve(typedefDataType);
	}

	DataType createTypedefNamedSizedType(String name, int size) {
		DataType dataType = new TypedefDataType(name, Undefined.getUndefinedDataType(size));
		return resolve(dataType);
	}

	DataType createTypedefNamedSizedType(PrimitiveMsType type) {
		return createTypedefNamedSizedType(type.getName(), type.getTypeSize());
	}

	DataType createUnmappedPdbType(PrimitiveMsType type) {
		String name = String.format("UnmappedPdbType%04X", type.getNumber());
		return createTypedefNamedSizedType(name, 1);
	}

	private DataType getIntegralType(int size) {
		DataType dataType = integralGhidraPrimitives.get(size);
		if (dataType != null) {
			return dataType;
		}
		DataType resolved =
			resolve(AbstractIntegerDataType.getSignedDataType(size, getDataTypeManager()));
		integralGhidraPrimitives.put(size, resolved);
		return resolved;
	}

	private DataType getUnsignedIntegralType(int size) {
		DataType dataType = unsignedIntegralGhidraPrimitives.get(size);
		if (dataType != null) {
			return dataType;
		}
		DataType resolved =
			resolve(AbstractIntegerDataType.getUnsignedDataType(size, getDataTypeManager()));
		unsignedIntegralGhidraPrimitives.put(size, resolved);
		return resolved;
	}

	DataType get16BitRealType() {
		return getRealType(2, "float16");
	}

	DataType get32BitRealType() {
		return getRealType(4, "float32");
	}

	DataType get32BitPartialPrecisionRealType() {
		// TODO: Do we have / can we craft this type?
		return createTypedefNamedSizedType("T_REAL32PP", 4);
	}

	DataType get48BitRealType() {
		return getRealType(6, "float48");
	}

	DataType get64BitRealType() {
		return getRealType(8, "float64");
	}

	DataType get80BitRealType() {
		return getRealType(10, "float80");
	}

	DataType get128BitRealType() {
		return getRealType(16, "float128");
	}

	/* 
	 * First get type from "other" list, which are typedefs to underlying primitives. If it does
	 * not exist, then find the proper underlying primitive, create the typedef, and cache this
	 * newly minted (typedef) unique primitive type.
	 */
	private DataType getRealType(int size, String name) {
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		dataType = floatGhidraPrimitives.get(size);
		DataType resolved;
		if (dataType == null) {
			resolved = resolve(AbstractFloatDataType.getFloatDataType(size, getDataTypeManager()));
			floatGhidraPrimitives.put(size, resolved);
			if (resolved instanceof Undefined) { // Not a real type implemented in Ghidra.
				DataType type = createTypedef(name, resolved);
				resolved = resolve(type);
			}
		}
		else {
			resolved = dataType;
		}
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	DataType get16BitComplexType() {
		return getComplexType(16);
	}

	DataType get32BitComplexType() {
		return getComplexType(4);
	}

	DataType get32BitPartialPrecisionComplexType() {
		return createTypedefNamedSizedType("T_CPLX32PP", 8);
	}

	DataType get48BitComplexType() {
		return getComplexType(48);
	}

	DataType get64BitComplexType() {
		return getComplexType(8);
	}

	DataType get80BitComplexType() {
		return getComplexType(10);
	}

	DataType get128BitComplexType() {
		return getComplexType(128);
	}

	private DataType getComplexType(int size) {
		DataType dataType = complexGhidraPrimitives.get(size);
		if (dataType != null) {
			return dataType;
		}
		switch (size) {
			case 32:
				// Case 32 is presumably 32 bits per real/imag. This is 4 bytes each, or 8
				// bytes total
				// Use the internal type.
				dataType = new Complex8DataType(getDataTypeManager());
				break;
			case 64:
				// Case 64 is presumably 64 bits per real/imag. This is 8 bytes each, or 16
				// bytes total
				// Use the internal type.
				dataType = new Complex16DataType(getDataTypeManager());
				break;
			case 80:
				// TODO: Replace with Complex20DataType when it is available.
				dataType = createTypedefNamedSizedType("T_CPLX80", 20);
				break;
			case 128:
				// Case 128 is presumably 128 bits per real/imag. This is 16 bytes each, or 32
				// bytes total
				// Use the internal type.
				dataType = new Complex32DataType(getDataTypeManager());
				break;
			default:
				String message = "Programming error: Complex size not supported" + size;
				PdbLog.message(message);
				throw new AssertException(message);
		}
		DataType resolved = resolve(dataType);
		complexGhidraPrimitives.put(size, resolved);
		return resolved;
	}

	DataType get8BitBooleanType() {
		return getBooleanType(1, "T_BOOL08");
	}

	DataType get16BitBooleanType() {
		return getBooleanType(2, "T_BOOL16");
	}

	DataType get32BitBooleanType() {
		return getBooleanType(4, "T_BOOL32");
	}

	DataType get64BitBooleanType() {
		return getBooleanType(8, "T_BOOL64");
	}

	DataType get128BitBooleanType() {
		return getBooleanType(16, "T_BOOL128");
	}

	/* 
	 * First get type from "other" list, which are typedefs to underlying primitives. If it does
	 * not exist, then find the proper underlying primitive, create the typedef, and cache this
	 * newly minted (typedef) unique primitive type.
	 */
	private DataType getBooleanType(int size, String name) {
		DataType dataType = otherPrimitives.get(name);
		if (dataType != null) {
			return dataType;
		}
		if (size == getBooleanSize()) { // TODO: see TODO inside called method.
			dataType = new BooleanDataType(getDataTypeManager());
		}
		else {
			dataType = getIntegralType(size);
		}
		DataType resolved = resolve(dataType);
		otherPrimitives.put(name, resolved);
		return resolved;
	}

	/*
	 * Mimics a Ghidra getBoolean type that has a data organizationhierarchy for which one can
	 * call getSize() on the type to determine the size of the boolean on the current
	 * architecture.
	 */
	private int getBooleanSize() {
		return 1;
		// TODO: change to the following line when it is available.
		//return applicator.getDataTypeManager().getDataOrganization().getBooleanSize();
	}

	private Pointer getPointerType(int ptrSize, DataType baseType) {
		if (getDataTypeManager().getDataOrganization().getPointerSize() == ptrSize) {
			return getDataTypeManager().getPointer(baseType);
		}
		return getDataTypeManager().getPointer(baseType, ptrSize);
	}

	Pointer get16NearPointerType(PrimitiveMsType type, DataType baseType) {
		return getPointerType(type.getTypeSize(), baseType);
	}

	Pointer get1616FarPointerType(PrimitiveMsType type, DataType baseType) {
		return getPointerType(type.getTypeSize(), baseType);
	}

	Pointer get1616HugePointerType(PrimitiveMsType type, DataType baseType) {
		return getPointerType(type.getTypeSize(), baseType);
	}

	Pointer get32PointerType(PrimitiveMsType type, DataType baseType) {
		return getPointerType(type.getTypeSize(), baseType);
	}

	Pointer get1632PointerType(PrimitiveMsType type, DataType baseType) {
		return getPointerType(type.getTypeSize(), baseType);
	}

	Pointer get64PointerType(PrimitiveMsType type, DataType baseType) {
		return getPointerType(type.getTypeSize(), baseType);
	}

	Pointer get128PointerType(PrimitiveMsType type, DataType baseType) {
		return getPointerType(type.getTypeSize(), baseType);
	}
}
