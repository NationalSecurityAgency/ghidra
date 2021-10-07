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
package ghidra.app.util.bin.format.pe.cli.blobs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.CliRepresentable;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.*;
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexTypeDefOrRef;
import ghidra.program.model.data.*;
import ghidra.util.exception.InvalidInputException;

public abstract class CliAbstractSig extends CliBlob implements CliRepresentable {

	public static final String PATH = "/PE/CLI/Blobs/Signatures";

	public CliAbstractSig(CliBlob blob) {
		super(blob);
	}

	@Override
	public abstract DataType getContentsDataType();

	@Override
	public abstract String getContentsName();

	@Override
	public abstract String getContentsComment();

	/** This is the method that subclasses should override. If stream is null, the method must not cause a NullPointerException,
	 * i.e. it must handle this as if there was no stream to begin with.
	 */
	protected abstract String getRepresentationCommon(CliStreamMetadata stream, boolean isShort);

	@Override
	public final String getRepresentation() {
		return getRepresentationCommon(null, false);
	}

	@Override
	public final String getShortRepresentation() {
		return getRepresentationCommon(null, true);
	}

	@Override
	public final String getRepresentation(CliStreamMetadata stream) {
		return getRepresentationCommon(stream, false);
	}

	@Override
	public final String getShortRepresentation(CliStreamMetadata stream) {
		return getRepresentationCommon(stream, true);
	}

	protected String getRepresentationOf(CliRepresentable obj, CliStreamMetadata stream,
			boolean isShort) {
		if (isShort) {
			if (stream != null) {
				return obj.getShortRepresentation(stream);
			}
			return obj.getShortRepresentation();
		}

		if (stream != null) {
			return obj.getRepresentation(stream);
		}

		return obj.getRepresentation();
	}

	public static class CliTypeCodeDataType extends EnumDataType {
		private static final long serialVersionUID = 1L;

		public static final String PATH = "/PE/CLI/Types";

		public final static CliTypeCodeDataType dataType = new CliTypeCodeDataType();

		public CliTypeCodeDataType() {
			super(new CategoryPath(PATH), "TypeCode", 1);

			for (CliElementType c : CliElementType.values()) {
				add(c.toString(), c.id());
			}
		}
	}

	public static DataType convertTypeCodeToDataType(CliElementType typeCode) {
		/*
		TODO:
		ELEMENT_TYPE_VALUETYPE(0x11),
		ELEMENT_TYPE_VAR(0x13), // "Class type variable VAR"
		(0x16),

		ELEMENT_TYPE_MVAR(0x1e), // Method type variable MVAR

		ELEMENT_TYPE_INTERNAL(0x21), // Internal (generated internally, "will not be persisted in any way")
		ELEMENT_TYPE_MAX(0x22),

		*/

		switch (typeCode) {
			case ELEMENT_TYPE_VOID:
				return VoidDataType.dataType;

			case ELEMENT_TYPE_BOOLEAN:
				return BooleanDataType.dataType;
			case ELEMENT_TYPE_CHAR:
				return CharDataType.dataType;
			case ELEMENT_TYPE_I1:
				return SignedByteDataType.dataType;
			case ELEMENT_TYPE_U1:
				return ByteDataType.dataType;

			case ELEMENT_TYPE_I2:
				return ShortDataType.dataType;
			case ELEMENT_TYPE_U2:
				return UnsignedShortDataType.dataType;

			case ELEMENT_TYPE_I4:
				return IntegerDataType.dataType;
			case ELEMENT_TYPE_U4:
				return UnsignedIntegerDataType.dataType;

			case ELEMENT_TYPE_R4:
				return Float4DataType.dataType;
			case ELEMENT_TYPE_R8:
				return Float8DataType.dataType;

			case ELEMENT_TYPE_I8:
				return LongLongDataType.dataType;
			case ELEMENT_TYPE_U8:
				return UnsignedLongLongDataType.dataType;

			// TODO: Does this change for native architectures other than 32-bit?
			case ELEMENT_TYPE_I:
				return IntegerDataType.dataType;
			case ELEMENT_TYPE_U:
				return UnsignedIntegerDataType.dataType;

			case ELEMENT_TYPE_PTR:
				return PointerDataType.dataType;
			case ELEMENT_TYPE_FNPTR:
				return PointerDataType.dataType;

			case ELEMENT_TYPE_STRING:
				return new PointerDataType(new CharDataType());
			case ELEMENT_TYPE_ARRAY:
			case ELEMENT_TYPE_SZARRAY:
			case ELEMENT_TYPE_VAR:
			case ELEMENT_TYPE_MVAR:
				return new PointerDataType(new ByteDataType());

			case ELEMENT_TYPE_OBJECT: // System.Object
			case ELEMENT_TYPE_CLASS:
			case ELEMENT_TYPE_VALUETYPE:
			case ELEMENT_TYPE_GENERICINST:
				return PointerDataType.dataType;

			case ELEMENT_TYPE_SENTINEL:
				return Undefined1DataType.dataType;

			default:
				return VoidDataType.dataType;
		}
	}

	public enum CliElementType {
		ELEMENT_TYPE_END(0x0), // "Marks end of list"
		ELEMENT_TYPE_VOID(0x1),
		ELEMENT_TYPE_BOOLEAN(0x2),
		ELEMENT_TYPE_CHAR(0x3),
		ELEMENT_TYPE_I1(0x4), // CLI names these by number of bytes (e.g. I4, U2, I1)
		ELEMENT_TYPE_U1(0x5),
		ELEMENT_TYPE_I2(0x6),
		ELEMENT_TYPE_U2(0x7),
		ELEMENT_TYPE_I4(0x8),
		ELEMENT_TYPE_U4(0x9),
		ELEMENT_TYPE_I8(0xa),
		ELEMENT_TYPE_U8(0xb),
		ELEMENT_TYPE_R4(0xc), // R refers to float types
		ELEMENT_TYPE_R8(0xd),
		ELEMENT_TYPE_STRING(0xe),

		ELEMENT_TYPE_PTR(0xf),
		ELEMENT_TYPE_BYREF(0x10), // ByRef flag in paramters

		ELEMENT_TYPE_VALUETYPE(0x11),
		ELEMENT_TYPE_CLASS(0x12),
		ELEMENT_TYPE_VAR(0x13), // "Class type variable VAR"
		ELEMENT_TYPE_ARRAY(0x14),
		ELEMENT_TYPE_GENERICINST(0x15), // Signifies a variable uses a Generic
		ELEMENT_TYPE_TYPEDBYREF(0x16), // A fully specified ByRef type

		ELEMENT_TYPE_I(0x18), // native integer size
		ELEMENT_TYPE_U(0x19), // native unsigned integer size
		ELEMENT_TYPE_FNPTR(0x1b),
		ELEMENT_TYPE_OBJECT(0x1c), // System.Object
		ELEMENT_TYPE_SZARRAY(0x1d), // Single dimension zero lower bound array
		ELEMENT_TYPE_MVAR(0x1e), // Method type variable MVAR

		ELEMENT_TYPE_CMOD_REQD(0x1f), // only for binding. C modifier required.
		ELEMENT_TYPE_CMOD_OPT(0x20), // only for binding. C modifier optional.

		ELEMENT_TYPE_INTERNAL(0x21), // Internal (generated internally, "will not be persisted in any way")
		ELEMENT_TYPE_MAX(0x22),

		ELEMENT_TYPE_MODIFIER(0x40),
		ELEMENT_TYPE_SENTINEL(0x41), // Sentinel in MethodRefs
		ELEMENT_TYPE_PINNED(0x45); // Constrained variable

		private final int id;

		CliElementType(int id) {
			this.id = id;
		}

		public int id() {
			return id;
		}

		public static CliElementType fromInt(int id) {
			CliElementType[] values = CliElementType.values();
			for (CliElementType value : values) {
				if (value.id == id) {
					return value;
				}
			}
			return null;
		}
	}

	public abstract class CliSigType implements CliRepresentable {
		protected CliElementType baseTypeCode;

		public static final String PATH = "/PE/CLI/Types";

		public CliSigType(CliElementType typeCode) {
			this.baseTypeCode = typeCode;
		}

		@Override
		public abstract String getRepresentation();

		@Override
		public String getRepresentation(CliStreamMetadata stream) {
			return getRepresentation();
		}

		@Override
		public String getShortRepresentation() {
			return getRepresentation();
		}

		@Override
		public String getShortRepresentation(CliStreamMetadata stream) {
			return getRepresentation(stream);
		}

		public abstract DataType getDefinitionDataType();

		public DataType getExecutionDataType() {
			return convertTypeCodeToDataType(baseTypeCode);
		}
	}

	public class CliTypePrimitive extends CliSigType {
		public CliTypePrimitive(CliElementType typeCode) {
			super(typeCode);
		}

		@Override
		public String getRepresentation() {
			return baseTypeCode.toString();
		}

		@Override
		public DataType getDefinitionDataType() {
			return CliTypeCodeDataType.dataType;
		}
	}

	public class CliTypeArray extends CliSigType {
		private CliSigType arrayType;
		private CliArrayShape arrayShape;

		public CliTypeArray(BinaryReader reader, CliElementType typeCode)
				throws IOException, InvalidInputException {
			super(typeCode);
			CliElementType valueCode = CliElementType.fromInt(reader.readNextByte());

			switch (valueCode) {
				case ELEMENT_TYPE_VALUETYPE:
					arrayType = new CliTypeValueType(reader, typeCode);
					break;

				case ELEMENT_TYPE_CLASS:
					arrayType = new CliTypeClass(reader, typeCode);
					break;

				case ELEMENT_TYPE_FNPTR:
					arrayType = new CliTypeFnPtr(reader, typeCode);
					break;

				case ELEMENT_TYPE_GENERICINST:
					arrayType = new CliTypeGenericInst(reader, typeCode);
					break;

				case ELEMENT_TYPE_MVAR:
				case ELEMENT_TYPE_VAR:
					arrayType = new CliTypeVarOrMvar(reader, typeCode);
					break;

				case ELEMENT_TYPE_PTR:
					arrayType = new CliTypePtr(reader, typeCode);
					break;

				case ELEMENT_TYPE_SZARRAY: // Single dimensional, zero-based array, e.g. a vector
					arrayType = new CliTypeSzArray(reader, typeCode);
					break;

				case ELEMENT_TYPE_ARRAY:
					arrayType = new CliTypeArray(reader, typeCode);
					break;

				default:
					arrayType = new CliTypePrimitive(valueCode);
					break;
			}

			arrayShape = new CliArrayShape(reader);
		}

		@Override
		public String getRepresentation() {
			return String.format("Array %s %s", arrayType.toString(),
				arrayShape.getRepresentation());
		}

		@Override
		public DataType getDefinitionDataType() {
			StructureDataType struct = new StructureDataType(new CategoryPath(PATH), "Array", 0);
			struct.add(CliTypeCodeDataType.dataType, "Array",
				String.format("Fixed value: 0x%x", CliElementType.ELEMENT_TYPE_ARRAY.id()));
			if (arrayType instanceof CliTypePrimitive) {
				struct.add(CliTypeCodeDataType.dataType, "Type", "Type of array");
			}
			else {
				struct.add(arrayType.getDefinitionDataType(), "ValueType", "Class token");
			}
			struct.add(arrayShape.getDefinitionDataType(), "ArrayShape", null);
			return struct;
		}
	}

	public class CliTypeClass extends CliSigType {
		private int encodedType;
		private int typeBytes;

		public CliTypeClass(BinaryReader reader, CliElementType typeCode) throws IOException {
			super(typeCode);
			long origIndex = reader.getPointerIndex();
			encodedType = decodeCompressedUnsignedInt(reader);
			typeBytes = (int) (reader.getPointerIndex() - origIndex);
		}

		@Override
		public String getRepresentation() {
			return Integer.toHexString(encodedType);
		}

		private String getRepresentation(CliStreamMetadata stream, boolean shortRep) {
			try {
				if (stream != null) {
					CliAbstractTable table =
						stream.getTable(CliIndexTypeDefOrRef.getTableName(encodedType));
					if (table == null) {
						return "[ErrorRetrievingTable]";
					}
					CliAbstractTableRow row =
						table.getRow(CliIndexTypeDefOrRef.getRowIndex(encodedType));
					if (row == null) {
						return "[ErrorRetrievingRow]";
					}
					if (shortRep) {
						return row.getShortRepresentation();
					}
					return row.getRepresentation();
				}
				return "[ErrorRepresentingClassReference]";
			}
			catch (InvalidInputException e) {
				e.printStackTrace();
			}
			return "[ErrorRepresentingClassReference]";
		}

		@Override
		public String getRepresentation(CliStreamMetadata stream) {
			return getRepresentation(null, false);
		}

		@Override
		public String getShortRepresentation(CliStreamMetadata stream) {
			return getRepresentation(stream, true);
		}

		@Override
		public DataType getDefinitionDataType() {
			StructureDataType struct = new StructureDataType(new CategoryPath(PATH), "Class", 0);
			struct.add(CliTypeCodeDataType.dataType, "Class", "Class");
			struct.add(getDataTypeForBytes(typeBytes), "Type", "TypeDefOrRefOrSpecEncoded");
			return struct;
		}
	}

	public class CliTypeFnPtr extends CliSigType {
		private long dataOffset;

		private CliRetType retType;
		private CliParam params[];
		private int sizeOfCount;
		private byte flags;
		private int genericParamCount;
		private int sizeOfGenericCount;

		private int sentinelIndex; // SENTINEL is before the parameter index in this field

		private final int FNPTR_FLAGS_DEFAULT = 0x00;
		private final int FNPTR_FLAGS_VARARG = 0x05;
		private final int FNPTR_FLAGS_GENERIC = 0x10;
		private final int FNPTR_FLAGS_HASTHIS = 0x20;
		private final int FNPTR_FLAGS_EXPLICITTHIS = 0x40;

		public CliTypeFnPtr(BinaryReader reader, CliElementType typeCode) throws IOException {
			super(typeCode);

			sentinelIndex = -1;

			dataOffset = reader.getPointerIndex();

			// Flags is similar to a MethodDef unless vararg is used.
			flags = reader.readNextByte();

			if ((flags & FNPTR_FLAGS_GENERIC) == FNPTR_FLAGS_GENERIC) {
				long origIndex = reader.getPointerIndex();
				genericParamCount = decodeCompressedUnsignedInt(reader);
				sizeOfGenericCount = (int) (reader.getPointerIndex() - origIndex);
			}

			long origIndex = reader.getPointerIndex();
			int paramCount = decodeCompressedUnsignedInt(reader);
			this.sizeOfCount = (int) (reader.getPointerIndex() - origIndex);

			try {
				retType = new CliRetType(reader);
			}
			catch (InvalidInputException e) {
				retType = null;
			}
			params = new CliParam[paramCount];

			for (int i = 0; i < paramCount; i++) {
				if (reader.peekNextByte() == CliElementType.ELEMENT_TYPE_SENTINEL.id()) {
					reader.readNextByte();
					sentinelIndex = i;
				}
				try {
					params[i] = new CliParam(reader);
				}
				catch (InvalidInputException e) {
					params[i] = null;
				}
			}
		}

		@Override
		public String getRepresentation() {
			return "FnPtr " /*+ sig.getRepresentation()*/;
		}

		@Override
		public String getShortRepresentation() {
			return "FnPtr " /*+ sig.getShortRepresentation()*/;
		}

		@Override
		public DataType getDefinitionDataType() {
			StructureDataType struct =
				new StructureDataType(new CategoryPath(PATH), "FnPtr_" + dataOffset, 0);
			struct.add(CliTypeCodeDataType.dataType, CliElementType.ELEMENT_TYPE_FNPTR.toString(),
				"");
			struct.add(BYTE, "Flags", "ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS");

			if (genericParamCount > 0) {
				struct.add(getDataTypeForBytes(sizeOfGenericCount), "GenParamCount",
					"Number of generic paramameters for the method");
			}
			struct.add(getDataTypeForBytes(sizeOfCount), "ParamCount",
				"Number of parameter types to follow RetType");
			struct.add(retType.getDefinitionDataType(), "RetType", null);

			for (int i = 0; i < params.length; i++) {
				struct.add(params[i].getDefinitionDataType(), "Param" + i, null);
			}
			return struct;
		}
	}

	public class CliTypeGenericInst extends CliSigType {
		private CliElementType firstType;
		private int encodedType;
		private int typeSizeBytes;
		private int genArgCount;
		private int countSizeBytes;
		private List<CliSigType> argTypes = new ArrayList<>();

		public CliTypeGenericInst(BinaryReader reader, CliElementType typeCode) throws IOException {
			super(typeCode);
			firstType = CliElementType.fromInt(reader.readNextByte()); // Should be Class or ValueType
			long origIndex = reader.getPointerIndex();
			encodedType = decodeCompressedUnsignedInt(reader);
			typeSizeBytes = (int) (reader.getPointerIndex() - origIndex);
			origIndex = reader.getPointerIndex();
			genArgCount = decodeCompressedUnsignedInt(reader);
			countSizeBytes = (int) (reader.getPointerIndex() - origIndex);
			for (int i = 0; i < genArgCount; i++) {
				try {
					argTypes.add(readCliType(reader));
				}
				catch (InvalidInputException e) {
					e.printStackTrace();
					// Do not add to types
				}
			}
		}

		private String getRepresentation(CliStreamMetadata stream, boolean shortRep) {
			String argTypesRep = "";
			for (int i = 0; i < genArgCount; i++) {
				argTypesRep += argTypes.get(i).getRepresentation();
				if (i != genArgCount - 1) {
					argTypesRep += ", ";
				}
			}

			String typeRep = Integer.toHexString(encodedType);
			if (stream != null) {
				try {
					CliAbstractTableRow row =
						stream.getTable(CliIndexTypeDefOrRef.getTableName(encodedType))
								.getRow(CliIndexTypeDefOrRef.getRowIndex(encodedType));
					if (shortRep) {
						typeRep = row.getShortRepresentation();
					}
					else {
						typeRep = row.getRepresentation();
					}
				}
				catch (InvalidInputException e) {
					e.printStackTrace();
				}
			}

			return String.format("%s %s %d %s", firstType.toString(), typeRep, genArgCount,
				argTypesRep);
		}

		@Override
		public String getRepresentation() {
			return getRepresentation(null);
		}

		@Override
		public String getRepresentation(CliStreamMetadata stream) {
			return getRepresentation(stream, false);
		}

		@Override
		public String getShortRepresentation(CliStreamMetadata stream) {
			return getRepresentation(stream, true);
		}

		@Override
		public DataType getDefinitionDataType() {
			StructureDataType struct = new StructureDataType(new CategoryPath(PATH),
				"GenericInstType" + argTypes.toString(), 0);
			// TODO: the toString() is included in the above line so GenericInst types can contain other GenericInst's, otherwise this is prohibited by StructureDataType
			struct.add(CliTypeCodeDataType.dataType, "GenericInst", "GenericInst");
			struct.add(CliTypeCodeDataType.dataType, "ClassOrValueType", "Class or ValueType");
			struct.add(getDataTypeForBytes(typeSizeBytes), "Type", "TypeDefOrRefOrSpecEncoded");
			struct.add(getDataTypeForBytes(countSizeBytes), "GenArgCount",
				"Number of generics to follow");
			for (CliSigType type : argTypes) {
				struct.add(type.getDefinitionDataType(), "Type", "Generic Type");
			}
			return struct;
		}
	}

	public class CliTypeVarOrMvar extends CliSigType {
		private long dataOffset;
		private int number;
		private int numberBytes;

		public CliTypeVarOrMvar(BinaryReader reader, CliElementType typeCode) throws IOException {
			super(typeCode);

			dataOffset = reader.getPointerIndex();
			number = decodeCompressedUnsignedInt(reader);

			long endIndex = reader.getPointerIndex();
			numberBytes = (int) (endIndex - dataOffset);
		}

		@Override
		public String getRepresentation() {
			return String.format("%s %d", baseTypeCode.toString(), number);
		}

		@Override
		public DataType getDefinitionDataType() {
			StructureDataType struct = new StructureDataType(new CategoryPath(PATH),
				baseTypeCode.toString() + "_" + dataOffset, 0);
			struct.add(CliTypeCodeDataType.dataType, baseTypeCode.toString(), "");
			struct.add(getDataTypeForBytes(numberBytes), "number", null);
			return struct;
		}
	}

	public class CliTypePtr extends CliSigType {
		private List<CliCustomMod> customMods = new ArrayList<>();
		private CliSigType type;
		private long dataOffset;

		public CliTypePtr(BinaryReader reader, CliElementType typeCode)
				throws IOException, InvalidInputException {
			super(typeCode);

			dataOffset = reader.getPointerIndex();

			while (CliCustomMod.isCustomMod(reader)) {
				customMods.add(new CliCustomMod(reader));
			}

			type = readCliType(reader);
		}

		public CliSigType getType() {
			return type;
		}

		@Override
		public String getRepresentation() {
			String modsRep = "";
			for (CliCustomMod mod : customMods) {
				modsRep += mod.toString() + ", ";
			}
			modsRep = modsRep.substring(0, modsRep.length() - 2);
			return String.format("Ptr %s %s", modsRep, type.toString());
		}

		@Override
		public DataType getDefinitionDataType() {
			StructureDataType struct = new StructureDataType(new CategoryPath(PATH),
				CliElementType.ELEMENT_TYPE_PTR.toString() + "_" + dataOffset, 0);
			struct.add(CliTypeCodeDataType.dataType, CliElementType.ELEMENT_TYPE_PTR.toString(),
				"");

			for (CliCustomMod mod : customMods) {
				struct.add(mod.getDefinitionDataType());
			}

			struct.add(type.getDefinitionDataType(), type.baseTypeCode.toString(), "");

			return struct;
		}
	}

	public class CliTypeSzArray extends CliSigType {
		private List<CliCustomMod> customMods = new ArrayList<>();
		private CliSigType type;

		public CliTypeSzArray(BinaryReader reader, CliElementType typeCode)
				throws IOException, InvalidInputException {
			super(typeCode);

			while (CliCustomMod.isCustomMod(reader)) {
				customMods.add(new CliCustomMod(reader));
			}

			type = readCliType(reader);
		}

		@Override
		public String getRepresentation(CliStreamMetadata stream) {
			String typeRep;
			if (stream == null) {
				typeRep = type.getRepresentation();
			}
			else {
				typeRep = type.getRepresentation(stream);
			}

			String modsRep = "";
			for (CliCustomMod mod : customMods) {
				modsRep += mod.toString() + ", ";
			}
			if (customMods.size() > 0) {
				modsRep = modsRep.substring(0, modsRep.length() - 2); // Remove last comma+space
			}
			return String.format("SzArray %s %s", modsRep, typeRep);
		}

		@Override
		public String getRepresentation() {
			return getRepresentation(null);
		}

		@Override
		public DataType getDefinitionDataType() {
			StructureDataType struct = new StructureDataType(new CategoryPath(PATH), "SzArray", 0);
			struct.add(CliTypeCodeDataType.dataType, "TypeCode", "SzArray");
			for (CliCustomMod mod : customMods) {
				struct.add(mod.getDefinitionDataType());
			}
			struct.add(type.getDefinitionDataType(), "Type", "type or void");
			return struct;
		}
	}

	public class CliTypeValueType extends CliSigType {
		private int encodedType;
		private int typeBytes;

		public CliTypeValueType(BinaryReader reader, CliElementType typeCode) throws IOException {
			super(typeCode);

			long origIndex = reader.getPointerIndex();
			encodedType = decodeCompressedUnsignedInt(reader);

			long endIndex = reader.getPointerIndex();
			typeBytes = (int) (endIndex - origIndex);
		}

		public CliTypeTable getTable() {
			try {
				return CliIndexTypeDefOrRef.getTableName(encodedType);
			}
			catch (InvalidInputException e) {
				return null;
			}
		}

		public int getRowIndex() {
			return CliIndexTypeDefOrRef.getRowIndex(encodedType);
		}

		@Override
		public String getRepresentation() {
			return "ValueType " + Integer.toHexString(encodedType);
		}

		public String getRepresentation(CliStreamMetadata stream, boolean shortRep) {
			try {
				CliAbstractTableRow row =
					stream.getTable(CliIndexTypeDefOrRef.getTableName(encodedType))
							.getRow(CliIndexTypeDefOrRef.getRowIndex(encodedType));

				return "ValueType " +
					(shortRep ? row.getShortRepresentation() : row.getRepresentation());
			}
			catch (InvalidInputException e) {
				e.printStackTrace();
			}
			return "";
		}

		@Override
		public String getRepresentation(CliStreamMetadata stream) {
			return getRepresentation(stream, false);
		}

		@Override
		public String getShortRepresentation(CliStreamMetadata stream) {
			return getRepresentation(stream, true);
		}

		@Override
		public DataType getDefinitionDataType() {
			String tableName = getTable().name();

			StructureDataType struct =
				new StructureDataType(new CategoryPath(PATH), "ValueType", 0);
			struct.add(CliTypeCodeDataType.dataType, "ValueType", "ValueType");
			struct.add(getDataTypeForBytes(typeBytes), "TypeDefOrRefEncoded",
				tableName + ": Row 0x" + Integer.toHexString(getRowIndex()));

			return struct;
		}

	}

	public CliSigType readCliType(BinaryReader reader) throws IOException, InvalidInputException {
		byte typeByte = reader.readNextByte();
		CliElementType typeCode = CliElementType.fromInt(typeByte);
		if (typeCode == null) {
			throw new InvalidInputException("TypeCode not found at reader index " +
				reader.getPointerIndex() + ". Are you in the right place? (" + typeByte + ")");
		}
		switch (typeCode) {
			case ELEMENT_TYPE_ARRAY:
				return new CliTypeArray(reader, typeCode);

			case ELEMENT_TYPE_CLASS:
				return new CliTypeClass(reader, typeCode);

			case ELEMENT_TYPE_FNPTR:
				return new CliTypeFnPtr(reader, typeCode);

			case ELEMENT_TYPE_GENERICINST:
				return new CliTypeGenericInst(reader, typeCode);

			case ELEMENT_TYPE_MVAR:
			case ELEMENT_TYPE_VAR:
				return new CliTypeVarOrMvar(reader, typeCode);

			case ELEMENT_TYPE_PTR:
				return new CliTypePtr(reader, typeCode);

			case ELEMENT_TYPE_SZARRAY: // Single dimensional, zero-based array, e.g. a vector
				return new CliTypeSzArray(reader, typeCode);

			case ELEMENT_TYPE_VALUETYPE:
				return new CliTypeValueType(reader, typeCode);

			default:
				// Other types: nothing follows
				return new CliTypePrimitive(typeCode);
		}
	}

	// The CustomMod signature part contains a required CMOD
	// option (CMOD_OPT or CMOD_REQD) then a compressed TypeDefOrRefOrSpecEncoded
	public static class CliCustomMod implements CliRepresentable {
		private CliElementType cmod;
		private int encodedType;
		private int sizeOfCount;

		public static boolean isCustomMod(BinaryReader reader) throws IOException {
			return (reader.peekNextByte() == CliElementType.ELEMENT_TYPE_CMOD_OPT.id() ||
				reader.peekNextByte() == CliElementType.ELEMENT_TYPE_CMOD_REQD.id());
		}

		public CliCustomMod(BinaryReader reader) throws IOException {
			cmod = CliElementType.fromInt(reader.readNextByte());

			long origIndex = reader.getPointerIndex();
			encodedType = decodeCompressedUnsignedInt(reader);

			long endIndex = reader.getPointerIndex();
			sizeOfCount = (int) (endIndex - origIndex);
		}

		public CliElementType getCMOD() {
			return cmod;
		}

		public int getTypeEncoded() {
			return encodedType;
		}

		public CliTypeTable getTable() {
			try {
				return CliIndexTypeDefOrRef.getTableName(encodedType);
			}
			catch (InvalidInputException e) {
				return null;
			}
		}

		public int getRowIndex() {
			return CliIndexTypeDefOrRef.getRowIndex(encodedType);
		}

		public CliAbstractTableRow getRow(CliStreamMetadata stream) {
			return stream.getTable(getTable()).getRow(getRowIndex());
		}

		public DataType getDefinitionDataType() {
			StructureDataType struct =
				new StructureDataType(new CategoryPath(PATH), "CustomMod", 0);

			String tableName = getTable().name();

			struct.add(CliTypeCodeDataType.dataType, cmod.toString(), null);
			struct.add(getDataTypeForBytes(this.sizeOfCount), "TypeDefOrRefEncoded",
				tableName + ": Row 0x" + Integer.toHexString(getRowIndex()));
			return struct;
		}

		@Override
		public String getRepresentation(CliStreamMetadata stream) {
			return String.format("%s %s", cmod.toString(), getRow(stream));
		}

		@Override
		public String getRepresentation() {
			return String.format("%s %x", cmod.toString(), encodedType);
		}

		@Override
		public String getShortRepresentation() {
			return getRepresentation();
		}

		@Override
		public String getShortRepresentation(CliStreamMetadata stream) {
			return getRepresentation(stream);
		}
	}

	// The only possible constraint is ELEMENT_TYPE_PINNED (CliTypeCode.Pinned)
	public static class CliConstraint implements CliRepresentable {
		private CliElementType constraint;

		public static boolean isConstraint(BinaryReader reader) throws IOException {
			return (reader.peekNextByte() == CliElementType.ELEMENT_TYPE_PINNED.id());
		}

		public CliConstraint(BinaryReader reader) throws IOException {
			constraint = CliElementType.fromInt(reader.readNextByte());
		}

		public CliElementType getConstraint() {
			return constraint;
		}

		@Override
		public String getRepresentation() {
			if (constraint == CliElementType.ELEMENT_TYPE_PINNED) {
				return constraint.toString();
			}
			return String.format("Invalid Constraint (%s - %x)", constraint.toString(),
				constraint.id());
		}

		@Override
		public String getShortRepresentation() {
			return getRepresentation();
		}

		@Override
		public String getRepresentation(CliStreamMetadata stream) {
			return getRepresentation();
		}

		@Override
		public String getShortRepresentation(CliStreamMetadata stream) {
			return getRepresentation();
		}
	}

	// The only possible result is ELEMENT_TYPE_BYREF
	public static class CliByRef implements CliRepresentable {
		private CliElementType byRef;

		public static boolean isByRef(BinaryReader reader) throws IOException {
			return (reader.peekNextByte() == CliElementType.ELEMENT_TYPE_BYREF.id());
		}

		public CliByRef(BinaryReader reader) throws IOException {
			byRef = CliElementType.fromInt(reader.readNextByte());
		}

		public CliElementType getByRef() {
			return byRef;
		}

		@Override
		public String getRepresentation() {
			if (byRef == CliElementType.ELEMENT_TYPE_BYREF) {
				return byRef.toString();
			}
			return String.format("Invalid ByRef (%s - %x)", byRef.toString(), byRef.id());
		}

		@Override
		public String getShortRepresentation() {
			return getRepresentation();
		}

		@Override
		public String getRepresentation(CliStreamMetadata stream) {
			return getRepresentation();
		}

		@Override
		public String getShortRepresentation(CliStreamMetadata stream) {
			return getRepresentation();
		}
	}

	public class CliTypeBase implements CliRepresentable {
		private List<CliRepresentable> modifiers = new ArrayList<>();

		private CliSigType type;

		private long dataOffset = 0;
		private boolean isVoidAllowed = false;

		public CliTypeBase(BinaryReader reader, boolean isRetType)
				throws IOException, InvalidInputException {
			dataOffset = reader.getPointerIndex();

			this.isVoidAllowed = isRetType;

			// Check for any of the modifiers, which can repeat out of order
			// before encountering the base type
			while (CliCustomMod.isCustomMod(reader) || CliConstraint.isConstraint(reader) ||
				CliByRef.isByRef(reader)) {

				// Get any custom modifiers
				while (CliCustomMod.isCustomMod(reader)) {
					modifiers.add(new CliCustomMod(reader));
				}

				// Check to see if it's a constrained variable
				if (CliConstraint.isConstraint(reader)) {
					modifiers.add(new CliConstraint(reader));
				}

				// Check to see if it's a ByRef
				if (CliByRef.isByRef(reader)) {
					modifiers.add(new CliByRef(reader));
				}
			}

			type = readCliType(reader);
		}

		public CliSigType getType() {
			return type;
		}

		public List<CliCustomMod> getCustomMods() {
			List<CliCustomMod> customMods = new ArrayList<CliCustomMod>();
			for (CliRepresentable mod : modifiers) {
				if (mod instanceof CliCustomMod) {
					customMods.add((CliCustomMod) mod);
				}
			}

			return customMods;
		}

		public boolean isByRef() {
			for (CliRepresentable mod : modifiers) {
				if (mod instanceof CliByRef) {
					return true;
				}
			}
			return false;
		}

		public boolean isConstrained() {
			for (CliRepresentable mod : modifiers) {
				if (mod instanceof CliConstraint) {
					return true;
				}
			}
			return false;
		}

		private String getRepresentationCommon(CliStreamMetadata stream, boolean shortRep) {
			String rep = "";

			for (CliRepresentable mod : modifiers) {
				if (mod instanceof CliCustomMod) {
					CliCustomMod customMod = (CliCustomMod) mod;
					rep += customMod.getRepresentation() + "; ";
				}
				else if (mod instanceof CliConstraint) {
					rep += "constrained ";
				}
				else if (mod instanceof CliByRef) {
					rep += "byref ";
				}
			}

			// The one special case value we have is the SENTINEL, which
			// we represent as "..." to denote that VarArgs might be passed
			// after the declared parameters
			if (type.baseTypeCode == CliElementType.ELEMENT_TYPE_SENTINEL) {
				rep = "...";
			}
			else {
				rep += getRepresentationOf(type, stream, shortRep);
			}

			return rep;
		}

		@Override
		public String getRepresentation() {
			return getRepresentationCommon(null, false);
		}

		@Override
		public String getRepresentation(CliStreamMetadata stream) {
			return getRepresentationCommon(stream, false);
		}

		@Override
		public String getShortRepresentation() {
			return getRepresentationCommon(null, true);
		}

		@Override
		public String getShortRepresentation(CliStreamMetadata stream) {
			return getRepresentationCommon(stream, true);
		}

		public DataType getDefinitionDataType() {
			StructureDataType struct =
				new StructureDataType(new CategoryPath(PATH), "Type_" + dataOffset, 0);

			for (CliRepresentable mod : modifiers) {
				if (mod instanceof CliCustomMod) {
					CliCustomMod customMod = (CliCustomMod) mod;
					struct.add(customMod.getDefinitionDataType(), "CustomMod", null);
				}
				else if (mod instanceof CliConstraint) {
					struct.add(CliTypeCodeDataType.dataType,
						CliElementType.ELEMENT_TYPE_PINNED.toString(), "Constrained");
				}
				else if (mod instanceof CliByRef) {
					struct.add(CliTypeCodeDataType.dataType,
						CliElementType.ELEMENT_TYPE_BYREF.toString(), "By Reference");
				}
			}

			struct.add(type.getDefinitionDataType(), type.baseTypeCode.toString(), null);
			return struct;
		}

		public DataType getExecutionDataType() {
			return type.getExecutionDataType();
		}
	}

	public class CliParam extends CliTypeBase {
		public CliParam(BinaryReader reader) throws IOException, InvalidInputException {
			super(reader, false);
		}
	}

	public class CliRetType extends CliTypeBase {
		public CliRetType(BinaryReader reader) throws IOException, InvalidInputException {
			super(reader, true);
		}
	}

	public class CliArrayShape {
		private int rank;
		private int rankBytes;
		private int numSizes;
		private int numSizesBytes;
		private int size[];
		private int sizeBytes[];
		private int numLoBounds;
		private int numLoBoundsBytes;
		private int loBound[];
		private int loBoundBytes[];

		public CliArrayShape(BinaryReader reader) throws IOException {
			long origIndex = reader.getPointerIndex();
			rank = decodeCompressedUnsignedInt(reader);
			rankBytes = (int) (reader.getPointerIndex() - origIndex);
			origIndex = reader.getPointerIndex();

			numSizes = decodeCompressedUnsignedInt(reader);
			numSizesBytes = (int) (reader.getPointerIndex() - origIndex);
			origIndex = reader.getPointerIndex();

			size = new int[numSizes];
			sizeBytes = new int[numSizes];
			for (int i = 0; i < numSizes; i++) {
				size[i] = decodeCompressedUnsignedInt(reader);
				sizeBytes[i] = (int) (reader.getPointerIndex() - origIndex);
				origIndex = reader.getPointerIndex();
			}

			numLoBounds = decodeCompressedUnsignedInt(reader);
			numLoBoundsBytes = (int) (reader.getPointerIndex() - origIndex);
			origIndex = reader.getPointerIndex();

			loBound = new int[numLoBounds];
			loBoundBytes = new int[numLoBounds];
			for (int i = 0; i < numLoBounds; i++) {
				loBound[i] = decodeCompressedUnsignedInt(reader);
				loBoundBytes[i] = (int) (reader.getPointerIndex() - origIndex);
				origIndex = reader.getPointerIndex();
			}
		}

		public DataType getDefinitionDataType() {
			StructureDataType struct =
				new StructureDataType(new CategoryPath(PATH), "ArrayShape", 0);
			struct.add(getDataTypeForBytes(rankBytes), "Rank", "Number of dimensions in array");
			struct.add(getDataTypeForBytes(numSizesBytes), "NumSizes", "Number of sizes to follow");
			for (int i = 0; i < sizeBytes.length; i++) {
				struct.add(getDataTypeForBytes(sizeBytes[i]), "Size" + i, "Coded integer size");
			}
			struct.add(getDataTypeForBytes(numLoBoundsBytes), "NumLoBounds",
				"Number of lower bounds in array");
			for (int i = 0; i < loBoundBytes.length; i++) {
				struct.add(getDataTypeForBytes(loBoundBytes[i]), "LoBound" + i,
					"Coded integer lower bound");
			}
			return struct;
		}

		public String getRepresentation() {
			return "ArrayShapeNotYetRepresented"; // TODO: Give back  a pretty representation of ArrayShape
		}
	}
}
