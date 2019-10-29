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
package ghidra.program.database.data;

import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

/**
 * <code>BitFieldDBDataType</code> extends BitFieldDataType for DataTypeManagerDB use.
 * This class provides the ability to generate a datatype ID and reconstruct a bit-field
 * datatype from an ID.
 */
class BitFieldDBDataType extends BitFieldDataType {

	// Bit Field ID Encoding (expressed as the following 4-bit nibble fields):  XXTTTTTTTTBBOOSS
	//
	// XX - reserved for datatype manager table ID
	// TTTTTTTT - TypeDef/Enum ID (32-bits, excludes table ID, applies to resolved TypeDef/Enum only)
	// BB - Encoded base type (8-bits, consists of the following bit fields: xttsbbbb)
	//      x - 1-bit, unused
	//      t - 2-bit, =0: base type only, =1:TypeDef used, =2: enum used, =3: abstract-int
	//      s - 1-bit, storage +1 (NOT-USED! - may be re-purposed by future schema change)
	//      xxxx - 4-bits, unused 
	// OO - bit offset (i.e., right-shift factor, relative to packing base type)
	// SS - bit field size in bits

	private static final int BIT_OFFSET_SHIFT = 8;
	private static final int BASE_TYPE_SHIFT = 16;
	private static final int DATATYPE_INDEX_SHIFT = 24;

	public static final long MAX_DATATYPE_INDEX = 0xffffffffL; // 32-bits

	private static final long ID_TO_INDEX_MASK = ~-(1L << DataTypeManagerDB.DATA_TYPE_KIND_SHIFT);

	/**
	 * Construct DB resident bitfield.  Minimal storage size and effective bit size will 
	 * be computed based upon specified parameters. 
	 * @param baseDataType base data type (integer/enum type or typedef to same).  This
	 * bitfield will adopt the same datatype manager as this base type.
	 * @param bitSize size of bit-field expressed as number of bits (0..255).  The effective 
	 * bit size may be reduced based upon the specified base datatype size.
	 * @param bitOffset right shift factor within storage unit when viewed as a big-endian dd
	 * scalar value.  Based upon minimal storage bitOffset should be in the range 0 to 7.
	 * @throws InvalidDataTypeException
	 */
	BitFieldDBDataType(DataType baseDataType, int bitSize, int bitOffset)
			throws InvalidDataTypeException {
		// must avoid cloning of baseDataType during construction!
		super(baseDataType, bitSize, bitOffset);
	}

	private static enum BaseDatatypeKind {
		NONE(0), TYPEDEF(1), ENUM(2), INTEGER(3);
		final int id;

		BaseDatatypeKind(int id) {
			this.id = id;
		}

		static BaseDatatypeKind getKind(int value) {
			for (BaseDatatypeKind kind : values()) {
				if (kind.id == value) {
					return kind;
				}
			}
			return NONE;
		}
	}

	/**
	 * Get a generated ID for this bit-field which is suitable for reconstruction
	 * via the {@link #getBitFieldDataType(long)} method.  This ID encodes the base
	 * datatype (including typedef/enum and packing data), 
	 * bit-size and bit-offset.  The upper byte of the ID will always be zero and 
	 * is reserved for use by the DataTypeManager.
	 * <p>
	 * The ability to reference base datatypes (e.g., TypeDef, Enum) is currently limited 
	 * (i.e. 32-bit base datatype ID).
	 * @param bitfieldDt the resolved bitfield datatype whose ID is needed.  This must first be
	 * resolved by a DataTypeManagerDB.
	 * @return bit-field ID
	 */
	static final long getId(BitFieldDataType bitfieldDt) {
		DataTypeManager dtm = bitfieldDt.getDataTypeManager();
		if (!(dtm instanceof DataTypeManagerDB)) {
			throw new AssertException("bitfieldDt must first be resolved");
		}

		BaseDatatypeKind dataTypeKind = BaseDatatypeKind.NONE;
		long dataTypeIndex = 0;
		DataType baseDataType = bitfieldDt.getBaseDataType();
		if (baseDataType instanceof TypeDef) {
			dataTypeKind = BaseDatatypeKind.TYPEDEF;
		}
		else if (baseDataType instanceof Enum) {
			dataTypeKind = BaseDatatypeKind.ENUM;
		}
		else if (baseDataType instanceof AbstractIntegerDataType) {
			dataTypeKind = BaseDatatypeKind.INTEGER;
		}
		if (dataTypeKind != BaseDatatypeKind.NONE) {
			dataTypeIndex = getResolvedDataTypeIndex(baseDataType, (DataTypeManagerDB) dtm);
			if (dataTypeIndex == DataTypeManager.NULL_DATATYPE_ID) {
				Msg.debug(BitFieldDBDataType.class,
					"Bit-Field data type not resolved: " + baseDataType.getName());
				dataTypeIndex = MAX_DATATYPE_INDEX;
				dataTypeKind = BaseDatatypeKind.NONE;
			}
			else if (dataTypeIndex >= MAX_DATATYPE_INDEX) {
				// TypeDef index exceeds 32-bit limit
				Msg.debug(BitFieldDBDataType.class,
					"Bit-Field data type index out of range: " + baseDataType.getName());
				dataTypeIndex = MAX_DATATYPE_INDEX;
				dataTypeKind = BaseDatatypeKind.NONE;
			}
		}
		long id = (dataTypeIndex << DATATYPE_INDEX_SHIFT) |
			(getBaseTypeEncodedField(bitfieldDt, dataTypeKind) << BASE_TYPE_SHIFT) |
			(bitfieldDt.getBitOffset() << BIT_OFFSET_SHIFT) | bitfieldDt.getDeclaredBitSize();
		return id;
	}

	private static final long getBaseTypeEncodedField(BitFieldDataType bitFieldDt,
			BaseDatatypeKind dataTypeKind) {
		int nominalStorageSize = BitFieldDataType.getMinimumStorageSize(bitFieldDt.getBitSize());
		boolean extraStorageUsed = bitFieldDt.getStorageSize() > nominalStorageSize;
		return (dataTypeKind.id << 5) | (extraStorageUsed ? 0x10L : 0L);
	}

	/**
	 * Get a bit-field datatype instance for a given ID.  The upper byte of the ID will be ignored.
	 * @param id bit-field datatype ID
	 * @param dtm data type manager
	 * @return bit-field data type
	 */
	static final BitFieldDataType getBitFieldDataType(long id, DataTypeManagerDB dtm) {

		int bitSize = (int) (id & 0xff); // 8-bits
		int bitOffset = (int) ((id >> BIT_OFFSET_SHIFT) & 0xff); // 8-bits
		int baseTypeInfo = (int) ((id >> BASE_TYPE_SHIFT) & 0xff); // 8-bit encoded field

		BaseDatatypeKind baseDataTypeKind = BaseDatatypeKind.getKind((baseTypeInfo >> 5) & 3);
//		boolean extraStorageUsed = (baseTypeInfo & 0x10) != 0;

		DataType baseDataType = null;
		long dataTypeIndex = (id >> DATATYPE_INDEX_SHIFT) & MAX_DATATYPE_INDEX; // 32-bits
		if (baseDataTypeKind != BaseDatatypeKind.NONE && dataTypeIndex != MAX_DATATYPE_INDEX) {
			if (baseDataTypeKind == BaseDatatypeKind.TYPEDEF) {
				baseDataType = getTypeDef(dataTypeIndex, dtm);
			}
			else if (baseDataTypeKind == BaseDatatypeKind.ENUM) {
				baseDataType = getEnum(dataTypeIndex, dtm);
			}
			else {
				baseDataType = getIntegerType(dataTypeIndex, dtm);
			}
		}
		try {
			if (baseDataType == null) {
				// use integer datatype on failure
				baseDataType = IntegerDataType.dataType.clone(dtm);
			}
//			int effectiveBitSize = getEffectiveBitSize(bitSize, baseDataType.getLength());
//			int storageSize = getMinimumStorageSize(effectiveBitSize);
//			if (extraStorageUsed) {
//				++storageSize;
//			}
			return new BitFieldDBDataType(baseDataType, bitSize, bitOffset);
		}
		catch (InvalidDataTypeException e) {
			return null;
		}
	}

	private static final long getResolvedDataTypeIndex(DataType dataType, DataTypeManagerDB dtm) {

		long dataTypeId = dtm.getID(dataType);
		if (dataTypeId == DataTypeManager.NULL_DATATYPE_ID) {
			return DataTypeManager.NULL_DATATYPE_ID;
		}
		return dataTypeId & ID_TO_INDEX_MASK;
	}

	/**
	 * Get the TypeDef which corresponds to the specified typeDefIndex and the 
	 * specified data type manager.
	 * @param typeDefIndex base data type index used by bit-field
	 * @param primitiveBaseDataType expected primitive base datatype
	 * @param dtm data type manager
	 * @return TypeDef data type or null if not found
	 */
	private static final TypeDef getTypeDef(long typeDefIndex, DataTypeManager dtm) {
		long dataTypeId =
			((long) DataTypeManagerDB.TYPEDEF << DataTypeManagerDB.DATA_TYPE_KIND_SHIFT) |
				typeDefIndex;
		DataType dataType = dtm.getDataType(dataTypeId);
		if (!(dataType instanceof TypeDef)) {
			return null;
		}
		TypeDef typeDefDt = (TypeDef) dataType;
		DataType dt = typeDefDt.getBaseDataType();
		if (dt instanceof Enum) {
			// TODO: how restrictive should we be on matching enum size?
			return typeDefDt;
		}
		if (dt instanceof AbstractIntegerDataType) {
			return typeDefDt;
		}
		return null; // unsupported typedef
	}

	/**
	 * Get the Enum which corresponds to the specified enumIndex and the 
	 * specified data type manager.
	 * @param enumIndex enum data type index used by bit-field
	 * @param dtm data type manager
	 * @return Enum data type or null if not found
	 */
	private static final Enum getEnum(long enumIndex, DataTypeManager dtm) {
		long dataTypeId =
			((long) DataTypeManagerDB.ENUM << DataTypeManagerDB.DATA_TYPE_KIND_SHIFT) | enumIndex;
		DataType dataType = dtm.getDataType(dataTypeId);
		if (!(dataType instanceof Enum)) {
			return null;
		}
		return (Enum) dataType;
	}

	/**
	 * Get the integer base type which corresponds to the specified intTypeIndex and the 
	 * specified data type manager.
	 * @param intTypeIndex base data type index used by bit-field
	 * @param dtm data type manager
	 * @return integer data type or null if not found
	 */
	private static final AbstractIntegerDataType getIntegerType(long intTypeIndex,
			DataTypeManager dtm) {
		long dataTypeId =
			((long) DataTypeManagerDB.BUILT_IN << DataTypeManagerDB.DATA_TYPE_KIND_SHIFT) |
				intTypeIndex;
		DataType dataType = dtm.getDataType(dataTypeId);
		if (!(dataType instanceof AbstractIntegerDataType)) {
			return null;
		}
		return (AbstractIntegerDataType) dataType;
	}
}
