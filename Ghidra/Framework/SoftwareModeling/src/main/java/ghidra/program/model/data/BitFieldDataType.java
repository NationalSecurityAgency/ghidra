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
package ghidra.program.model.data;

import java.math.BigInteger;

import ghidra.docking.settings.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.DataConverter;
import ghidra.util.exception.AssertException;
import utilities.util.ArrayUtilities;

/**
 * <code>BitFieldDataType</code> provides a means of defining a minimally sized bit-field
 * for use within data structures.  The length (i.e., storage size) of this bitfield datatype is
 * the minimum number of bytes required to contain the bitfield at its specified offset.
 * The effective bit-size of a bitfield will be limited by the size of the base
 * datatype whose size may be controlled by its associated datatype manager and data organization
 * (e.g., {@link IntegerDataType}). 
 * <p>
 * NOTE: Instantiation of this datatype implementation is intended for internal use only.  
 * Creating and manipulating bitfields should be accomplished directly via Structure or Union 
 * bitfield methods.
 */
public class BitFieldDataType extends AbstractDataType {

	private static final int MAX_BIT_LENGTH = 255;

	private final DataType baseDataType; // bit-field definition data type which corresponds to baseType
	private final int bitSize; // number of bits, reflects declaration which may exceed base type size
	private final int effectiveBitSize; // number of bits constrained by size of base type

	// The bitOffset is established during packing and reflects the right-shift amount within the
	// normalized big-endian view of the allocated byte storage as defined by the corresponding 
	// composite DataTypeComponent.
	private final int bitOffset; // indicates right-shift within big-endian view of component storage (range: 0..7) 
	private final int storageSize; // minimal component storage size to which bitOffset applies

	protected Settings defaultSettings;

	/**
	 * Construct a bit-field type based upon a specified base type.  The baseDataType will
	 * take precedence if specified.  Either baseType or baseDatatype must be specified.
	 * @param baseDataType base data type (integer/enum type or typedef to same).  This
	 * bitfield will adopt the same datatype manager as this base type.
	 * @param bitSize size of bit-field expressed as number of bits (0..255).  The effective 
	 * bit size may be reduced based upon the specified base datatype size.
	 * @param bitOffset right shift factor within storage unit when viewed as a big-endian dd
	 * scalar value.  Based upon minimal storage bitOffset should be in the range 0 to 7.
	 * @throws InvalidDataTypeException 
	 */
	protected BitFieldDataType(DataType baseDataType, int bitSize, int bitOffset)
			throws InvalidDataTypeException {
		super(CategoryPath.ROOT, baseDataType.getName() + ":" + bitSize,
			baseDataType.getDataTypeManager());
		checkBaseDataType(baseDataType);
		if (bitSize < 0 || bitSize > MAX_BIT_LENGTH) {
			throw new InvalidDataTypeException("unsupported bit size: " + bitSize);
		}
		if (bitOffset < 0 || bitOffset > 7) {
			throw new InvalidDataTypeException("unsupported minimal bit offset: " + bitOffset);
		}
		this.baseDataType = baseDataType;
		this.bitSize = bitSize;
		this.bitOffset = bitOffset;
		effectiveBitSize = getEffectiveBitSize(bitSize, this.baseDataType.getLength());
		storageSize = getMinimumStorageSize(effectiveBitSize, bitOffset);
		this.defaultSettings = this.baseDataType.getDefaultSettings();
	}

	/**
	 * Construct a bit-field type based upon a supported baseDataType.
	 * @param baseDataType a supported primitive integer data type or TypeDef to such a type.
	 * The baseType must already be cloned to the target datatype manager.
	 * @param bitSize size of bit-field expressed as number of bits
	 * @throws InvalidDataTypeException if specified baseDataType is not permitted
	 */
	protected BitFieldDataType(DataType baseDataType, int bitSize) throws InvalidDataTypeException {
		this(baseDataType, bitSize, 0);
	}

	/**
	 * Determine if this bit-field has a zero length (i.e., alignment field)
	 * @return true if this bit-field has a zero length 
	 */
	public boolean isZeroLengthField() {
		return bitSize == 0;
	}

	/**
	 * Get the effective bit-size based upon the specified base type size.  A bit size
	 * larger than the base type size will truncated to the base type size.
	 * @param declaredBitSize
	 * @param baseTypeByteSize
	 * @return effective bit-size
	 */
	public static int getEffectiveBitSize(int declaredBitSize, int baseTypeByteSize) {
		return Math.min(8 * baseTypeByteSize, declaredBitSize);
	}

	/**
	 * Get the minimum storage size in bytes for a given size in bits.
	 * This does not consider the bit offset which may increase the required 
	 * storage.
	 * @param bitSize number of bits within bitfield
	 * @return minimum storage size in bytes
	 */
	public static int getMinimumStorageSize(int bitSize) {
		return getMinimumStorageSize(bitSize, 0);
	}

	/**
	 * Get the minimum storage size in bytes for a given size in bits with 
	 * the specified bitOffset (lsb position within big endian storage)
	 * @param bitSize number of bits within bitfield
	 * @param bitOffset normalized bitfield offset within storage (lsb)
	 * @return minimum storage size in bytes
	 */
	public static int getMinimumStorageSize(int bitSize, int bitOffset) {
		if (bitSize == 0) {
			return 1;
		}
		return (bitSize + (bitOffset % 8) + 7) / 8;
	}

	/**
	 * Check a bitfield base datatype
	 * @param baseDataType bitfield base data type (Enum, AbstractIntegerDataType and derived TypeDefs permitted)
	 * @throws InvalidDataTypeException if baseDataType is invalid as a bitfield base type.
	 */
	public static void checkBaseDataType(DataType baseDataType) throws InvalidDataTypeException {
		if (!isValidBaseDataType(baseDataType)) {
			throw new InvalidDataTypeException(
				"Unsupported base data type for bitfield: " + baseDataType.getName());
		}
	}

	/**
	 * Check if a specified baseDataType is valid for use with a bitfield
	 * @param baseDataType bitfield base data type (Enum, AbstractIntegerDataType and derived TypeDefs permitted)
	 * @return true if baseDataType is valid else false
	 */
	public static boolean isValidBaseDataType(DataType baseDataType) {
		if (baseDataType instanceof TypeDef) {
			baseDataType = ((TypeDef) baseDataType).getBaseDataType();
		}
		if (baseDataType instanceof Enum) {
			return true;
		}
		if (baseDataType instanceof AbstractIntegerDataType) {
			return true;
		}
		return false;
	}

	@Override
	public void addParent(DataType dt) {
		if ((baseDataType instanceof TypeDef) || (baseDataType instanceof Enum)) {
			baseDataType.addParent(dt); // add composite as parent of baseDataType
		}
	}

	/**
	 * Get the size of the base data type based upon the associated data organization.
	 * @return base type size
	 */
	public int getBaseTypeSize() {
		return baseDataType.getLength();
	}

	/**
	 * Get the packing storage size in bytes associated with this bit-field which may be
	 * larger than the base type associated with the fields original definition.
	 * Returned value is the same as {@link #getLength()}.
	 * @return packing storage size in bytes
	 */
	public int getStorageSize() {
		return storageSize;
	}

	/**
	 * Get the effective bit size of this bit-field which may not exceed the size of the
	 * base datatype.
	 * @return bit size
	 */
	public int getBitSize() {
		return effectiveBitSize;
	}

	/**
	 * Get the declared bit size of this bit-field which may be larger than the effective
	 * size which could be truncated.
	 * @return bit size as defined by the field construction/declaration.
	 */
	public int getDeclaredBitSize() {
		return bitSize;
	}

	/**
	 * Get the bit offset of the least-significant bit relative to bit-0 of the
	 * base datatype (i.e., least significant bit).  This corresponds to the
	 * right-shift amount within the base data type when viewed as a big-endian value.
	 * @return bit offset
	 */
	public int getBitOffset() {
		return bitOffset;
	}

	/**
	 * Get the base datatype associated with this bit-field 
	 * (e.g., int, long, etc., or TypeDef to supported base type)
	 * @return base data type
	 */
	public DataType getBaseDataType() {
		return baseDataType;
	}

	/**
	 * Get the base datatype associated with this bit-field 
	 * (e.g., int, long, etc., or TypeDef to supported base type)
	 * @return base data type
	 */
	public AbstractIntegerDataType getPrimitiveBaseDataType() {
		// assumes proper enforcement during construction
		DataType dt = baseDataType;
		if (baseDataType instanceof TypeDef) {
			dt = ((TypeDef) baseDataType).getBaseDataType();
		}
		if (dt instanceof Enum) {
			// TODO: uncertain if we should use signed or unsigned, although size
			// is most important
			dt = AbstractIntegerDataType.getUnsignedDataType(((Enum) dt).getLength(), dataMgr);
		}
		return (AbstractIntegerDataType) dt;
	}

	/**
	 * Gets a list of all the settingsDefinitions used by this datatype.
	 * @return a list of the settingsDefinitions used by this datatype.
	 */
	@Override
	public final SettingsDefinition[] getSettingsDefinitions() {
		return baseDataType.getSettingsDefinitions();
	}

	@Override
	public final boolean isEquivalent(DataType dt) {
		if (dt == this) {
			return true;
		}
		if (dt == null) {
			return false;
		}
		if (!(dt instanceof BitFieldDataType)) {
			return false;
		}
		BitFieldDataType otherBitField = (BitFieldDataType) dt;
		// Specific packing and use of typedef ignored for equivalence check
		return otherBitField.bitSize == bitSize &&
			baseDataType.isEquivalent(otherBitField.baseDataType);
	}

	@Override
	public final int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + baseDataType.hashCode();
		result = prime * result + bitOffset;
		result = prime * result + bitSize;
		return result;
	}

	@Override
	public final boolean equals(Object obj) {
		if (!(obj instanceof BitFieldDataType)) {
			return false;
		}
		BitFieldDataType otherDt = (BitFieldDataType) obj;
		return (otherDt.getDataTypeManager() == getDataTypeManager()) && isEquivalent(otherDt) &&
			(bitOffset == otherDt.bitOffset) && (storageSize == otherDt.storageSize) &&
			baseDataType.equals(otherDt.baseDataType);
	}

	@Override
	public Settings getDefaultSettings() {
		return defaultSettings;
	}

	/**
	 * Returns a clone of this built-in DataType
	 * @see ghidra.program.model.data.DataType#copy(ghidra.program.model.data.DataTypeManager)
	 */
	@Override
	public final DataType copy(DataTypeManager dtm) {
		return clone(dtm);
	}

	/**
	 * Clone this bitfield to a new datatype manager.  This may change the effective bit
	 * size and storage size of the resulting datatype based upon the data organization
	 * of the specified dtm.
	 * @param dtm target datatype manager
	 * @return new instance or same instance of dtm is unchanged.
	 */
	@Override
	public BitFieldDataType clone(DataTypeManager dtm) {
		if (dtm == dataMgr) {
			return this;
		}
		try {
			return new BitFieldDataType(baseDataType.clone(dtm), bitSize, bitOffset);
		}
		catch (InvalidDataTypeException e) {
			throw new AssertException("unexpected", e);
		}
	}

	@Override
	public int getLength() {
		return storageSize;
	}

	@Override
	public String getDescription() {
		StringBuffer sbuf = new StringBuffer();
		sbuf.append(Integer.toString(effectiveBitSize));
		sbuf.append("-bit ");
		DataType dt = getBaseDataType();
		sbuf.append(dt.getDisplayName());
		sbuf.append(" bitfield");
		if (effectiveBitSize != bitSize) {
			sbuf.append(" (declared as ");
			sbuf.append(Integer.toString(bitSize));
			sbuf.append("-bits)");
		}
		return sbuf.toString();
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		if (effectiveBitSize == 0) {
			return new Scalar(0, 0);
		}
		AbstractIntegerDataType primitiveBaseDataType = getPrimitiveBaseDataType();
		boolean isSigned = primitiveBaseDataType.isSigned();
		BigInteger big = getBigIntegerValue(buf, isSigned, settings);
		if (big == null) {
			return null;
		}
		if (effectiveBitSize <= 64) {
			return new Scalar(effectiveBitSize, big.longValue(), isSigned);
		}
		return big;
	}

	private BigInteger getBigIntegerValue(MemBuffer buf, boolean isSigned, Settings settings) {
		if (effectiveBitSize == 0) {
			return BigInteger.ZERO;
		}
		try {

			byte[] bytes = new byte[storageSize];
			if (buf.getBytes(bytes, 0) != storageSize) {
				return null;
			}

			if (!EndianSettingsDefinition.ENDIAN.isBigEndian(settings, buf)) {
				bytes = ArrayUtilities.reverse(bytes);
			}

			BigInteger big = buf.getBigInteger(0, storageSize, false);
			BigInteger pow = BigInteger.valueOf(2).pow(effectiveBitSize);
			BigInteger mask = pow.subtract(BigInteger.ONE);
			big = big.shiftRight(bitOffset).and(mask);
			if (isSigned && big.testBit(effectiveBitSize - 1)) {
				big = big.subtract(pow);
			}
			return big;
		}
		catch (Exception e) {
			// ignore
		}
		return null;
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return baseDataType.getValueClass(settings);
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		if (bitSize == 0) {
			return "";
		}
		AbstractIntegerDataType primitiveBaseDataType = getPrimitiveBaseDataType();
		boolean isSigned = primitiveBaseDataType.isSigned();
		BigInteger big = getBigIntegerValue(buf, isSigned, settings);
		if (big == null) {
			return "??";
		}
		DataType dt = baseDataType;
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		if (dt instanceof Enum) {
			return ((Enum) dt).getRepresentation(big, settings, effectiveBitSize);
		}
		AbstractIntegerDataType intDT = (AbstractIntegerDataType) dt;
		if (intDT.getFormatSettingsDefinition().getFormat(
			settings) == FormatSettingsDefinition.CHAR) {
			if (big.signum() < 0) {
				big = big.add(BigInteger.valueOf(2).pow(effectiveBitSize));
			}
			int bytesLen = BitFieldDataType.getMinimumStorageSize(effectiveBitSize);
			byte[] bytes = DataConverter.getInstance(buf.isBigEndian()).getBytes(big, bytesLen);

			return StringDataInstance.getCharRepresentation(this, bytes, settings);
		}

		return intDT.getRepresentation(big, settings, effectiveBitSize);
	}

	@Override
	public void setDefaultSettings(Settings settings) {
		this.defaultSettings = settings;
	}

	@Override
	public int getAlignment() {
		return baseDataType.getAlignment();
	}

	@Override
	public String toString() {
		return getDisplayName() + "(storage:" + storageSize + ",bitOffset:" + bitOffset + ")";
	}
}
