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
import java.nio.charset.MalformedInputException;
import java.nio.charset.UnmappableCharacterException;

import ghidra.docking.settings.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.data.StringRenderParser.StringParseException;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.StringFormat;
import utilities.util.ArrayUtilities;

/**
 * Base type for integer data types such as {@link CharDataType chars}, {@link IntegerDataType
 * ints}, and {@link LongDataType longs}.
 * <p>
 * If {@link FormatSettingsDefinition#getFormat(Settings)} indicates that this is a
 * {@link FormatSettingsDefinition#CHAR CHAR} type, the {@link ArrayStringable} methods will treat
 * an array of this data type as a string.
 */
public abstract class AbstractIntegerDataType extends BuiltIn implements ArrayStringable {

	static final String C_SIGNED_CHAR = "signed char";
	static final String C_UNSIGNED_CHAR = "unsigned char";
	static final String C_SIGNED_SHORT = "short";
	static final String C_UNSIGNED_SHORT = "unsigned short";
	static final String C_SIGNED_INT = "int";
	static final String C_UNSIGNED_INT = "unsigned int";
	static final String C_SIGNED_LONG = "long";
	static final String C_UNSIGNED_LONG = "unsigned long";
	static final String C_SIGNED_LONGLONG = "long long";
	static final String C_UNSIGNED_LONGLONG = "unsigned long long";

	protected static final PaddingSettingsDefinition PADDING = PaddingSettingsDefinition.DEF;
	protected static final EndianSettingsDefinition ENDIAN = EndianSettingsDefinition.DEF;
	protected static final DataTypeMnemonicSettingsDefinition MNEMONIC =
		DataTypeMnemonicSettingsDefinition.DEF;

	private static SettingsDefinition[] SETTINGS_DEFS =
		{ FormatSettingsDefinition.DEF_HEX, PADDING, ENDIAN, MNEMONIC };

	private final boolean signed;

	/**
	 * Constructor
	 * 
	 * @param name a unique signed/unsigned data-type name (also used as the mnemonic)
	 * @param signed true if signed, false if unsigned
	 * @param dtm data-type manager whose data organization should be used
	 */
	public AbstractIntegerDataType(String name, boolean signed, DataTypeManager dtm) {
		super(null, name, dtm);
		this.signed = signed;
	}

	/**
	 * Return the Format settings definition included in the settings definition array
	 * 
	 * @see #getSettingsDefinitions()
	 * @return Format settings definition included in the settings definition array
	 */
	protected FormatSettingsDefinition getFormatSettingsDefinition() {
		return FormatSettingsDefinition.DEF_HEX;
	}

	@Override
	protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return SETTINGS_DEFS;
	}

	/**
	 * @return true if this is a signed integer data-type
	 */
	public boolean isSigned() {
		return signed;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return name.toUpperCase();
	}

	@Override
	public String getMnemonic(Settings settings) {
		int mnemonicStyle = MNEMONIC.getMnemonicStyle(settings);
		if (mnemonicStyle == DataTypeMnemonicSettingsDefinition.ASSEMBLY) {
			return getAssemblyMnemonic();
		}
		if (mnemonicStyle == DataTypeMnemonicSettingsDefinition.CSPEC) {
			return getCMnemonic();
		}
		return name;
	}

	/**
	 * @return the Assembly style data-type declaration for this data-type.
	 */
	public String getAssemblyMnemonic() {
		return name;
	}

	/**
	 * @return the C style data-type mnemonic for this data-type. NOTE: currently the same as
	 *         getCDeclaration().
	 */
	public String getCMnemonic() {
		String str = getCDeclaration();
		return str != null ? str : name;
	}

	/**
	 * @return the C style data-type declaration for this data-type. Null is returned if no
	 *         appropriate declaration exists.
	 */
	public String getCDeclaration() {
		int size = getLength();
		if (size <= 0) {
			return null;
		}
		DataOrganization dataOrganization = getDataOrganization();
		if (size == dataOrganization.getCharSize()) {
			return signed ? C_SIGNED_CHAR : C_UNSIGNED_CHAR;
		}
		if (size == dataOrganization.getIntegerSize()) {
			return signed ? C_SIGNED_INT : C_UNSIGNED_INT;
		}
		if (size == dataOrganization.getShortSize()) {
			return signed ? C_SIGNED_SHORT : C_UNSIGNED_SHORT;
		}
		if (size == dataOrganization.getLongSize()) {
			return signed ? C_SIGNED_LONG : C_UNSIGNED_LONG;
		}
		if (size == dataOrganization.getLongLongSize()) {
			return signed ? C_SIGNED_LONGLONG : C_UNSIGNED_LONGLONG;
		}
		return null;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {

		int size = getLength();
		if (size <= 0) {
			return null;
		}

		byte[] bytes = new byte[size];
		if (buf.getBytes(bytes, 0) != size) {
			return null;
		}

		if (!ENDIAN.isBigEndian(settings, buf)) {
			bytes = ArrayUtilities.reverse(bytes);
		}

		if (size > 8) {
			if (!isSigned()) {
				// ensure that bytes are treated as unsigned
				byte[] unsignedBytes = new byte[bytes.length + 1];
				System.arraycopy(bytes, 0, unsignedBytes, 1, bytes.length);
				bytes = unsignedBytes;
			}
			return new BigInteger(bytes);
		}

		// Use long when possible
		long val = 0;
		for (byte b : bytes) {
			val = (val << 8) + (b & 0x0ffL);
		}
		return new Scalar(size * 8, val, isSigned());
	}

	protected BigInteger castValueToEncode(Object value) throws DataTypeEncodeException {
		if (value instanceof BigInteger) {
			return (BigInteger) value;
		}
		if (value instanceof Scalar) {
			return ((Scalar) value).getBigInteger();
		}
		if (value instanceof Byte || value instanceof Short || value instanceof Character ||
			value instanceof Integer || value instanceof Long) {
			return BigInteger.valueOf(((Number) value).longValue());
		}
		throw new DataTypeEncodeException("Unsupported value type", value, this);
	}

	@Override
	public boolean isEncodable() {
		return true;
	}

	@Override
	public byte[] encodeValue(Object value, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException {
		if (length == -1) {
			length = getLength();
		}
		if (length != getLength()) {
			throw new DataTypeEncodeException("Length mismatch", value, this);
		}
		BigInteger bigValue = castValueToEncode(value);
		byte[] encoding = Utils.bigIntegerToBytes(bigValue, length, isSigned());
		if (!ENDIAN.isBigEndian(settings, buf)) {
			ArrayUtilities.reverse(encoding);
		}
		return encoding;
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		if (getLength() > 8) {
			return BigInteger.class;
		}
		return Scalar.class;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {

		int size = getLength();
		if (size <= 0) {
			size = length;
			if (size <= 0) {
				return "??";
			}
		}

		byte[] bytes = new byte[size];
		if (buf.getBytes(bytes, 0) != size) {
			return "??";
		}

		if (!ENDIAN.isBigEndian(settings, buf)) {
			bytes = ArrayUtilities.reverse(bytes);
		}

		BigInteger value = new BigInteger(bytes);

		if (getFormatSettingsDefinition().getFormat(settings) == FormatSettingsDefinition.CHAR) {
			return StringDataInstance.getCharRepresentation(this, bytes, settings);
		}

		return getRepresentation(value, settings, 8 * length);
	}

	/**
	 * Get integer representation of the big-endian value.
	 * <p>
	 * Does not handle CHAR format, use
	 * {@link StringDataInstance#getCharRepresentation(DataType, byte[], Settings)}
	 * 
	 * @param bigInt BigInteger value with the appropriate sign
	 * @param settings integer format settings (PADDING, FORMAT, etc.)
	 * @param bitLength number of value bits to be used from bigInt
	 * @return formatted integer string
	 */
	/*package*/ String getRepresentation(BigInteger bigInt, Settings settings, int bitLength) {

		int format = getFormatSettingsDefinition().getFormat(settings);
		boolean padded = PADDING.isPadded(settings);

		boolean negative = bigInt.signum() < 0;

		if (negative && (!signed || (format != FormatSettingsDefinition.DECIMAL))) {
			// force use of unsigned value
			bigInt = bigInt.add(BigInteger.valueOf(2).pow(bitLength));
		}

		String valStr;
		int nominalLen;

		switch (format) {
			default:
			case FormatSettingsDefinition.HEX:
				valStr = bigInt.toString(16).toUpperCase() + "h";
				nominalLen = (bitLength + 3) / 4;
				break;
			case FormatSettingsDefinition.DECIMAL:
				return bigInt.toString(10);
			case FormatSettingsDefinition.BINARY:
				valStr = bigInt.toString(2) + "b";
				nominalLen = bitLength;
				break;
			case FormatSettingsDefinition.OCTAL:
				valStr = bigInt.toString(8) + "o";
				nominalLen = (bitLength + 2) / 3;
				break;
		}

		if (padded) {
			// +1 to account for format suffix char
			valStr = StringFormat.padIt(valStr, nominalLen + 1, (char) 0, true);
		}
		return valStr;
	}

	@Override
	public byte[] encodeRepresentation(String repr, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException {
		int format = getFormatSettingsDefinition().getFormat(settings);
		BigInteger value;
		int radix;
		String suffix;
		switch (format) {
			case FormatSettingsDefinition.CHAR:
				StringDataInstance sdi =
					StringDataInstance.getStringDataInstance(this, buf, settings, getLength());
				try {
					return sdi.encodeReplacementFromCharRepresentation(repr);
				}
				catch (MalformedInputException | UnmappableCharacterException
						| StringParseException e) {
					throw new DataTypeEncodeException(repr, this, e);
				}
			case FormatSettingsDefinition.HEX:
				radix = 16;
				suffix = "h";
				break;
			case FormatSettingsDefinition.DECIMAL:
				radix = 10;
				suffix = "";
			case FormatSettingsDefinition.BINARY:
				radix = 2;
				suffix = "b";
			case FormatSettingsDefinition.OCTAL:
				radix = 8;
				suffix = "o";
			default:
				throw new AssertionError();
		}

		if (!repr.endsWith(suffix)) {
			throw new DataTypeEncodeException("value must have " + suffix + " suffix", repr, this);
		}
		try {
			value = new BigInteger(repr.substring(0, repr.length() - suffix.length()), radix);
		}
		catch (Exception e) {
			throw new DataTypeEncodeException(repr, this, e);
		}
		return encodeValue(value, buf, settings, length);
	}

	@Override
	public boolean hasStringValue(Settings settings) {
		int format = getFormatSettingsDefinition().getFormat(settings);
		return format == FormatSettingsDefinition.CHAR;
	}

	@Override
	public String getArrayDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		if (hasStringValue(settings) && buf.isInitializedMemory()) {
			return new StringDataInstance(this, settings, buf, len, true).getLabel(
				AbstractStringDataType.DEFAULT_ABBREV_PREFIX + "_",
				AbstractStringDataType.DEFAULT_LABEL_PREFIX, AbstractStringDataType.DEFAULT_LABEL,
				options);
		}
		return null;
	}

	@Override
	public String getArrayDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options, int offcutOffset) {
		if (hasStringValue(settings) && buf.isInitializedMemory()) {
			return new StringDataInstance(this, settings, buf, len, true).getOffcutLabelString(
				AbstractStringDataType.DEFAULT_ABBREV_PREFIX + "_",
				AbstractStringDataType.DEFAULT_LABEL_PREFIX, AbstractStringDataType.DEFAULT_LABEL,
				options, offcutOffset);
		}
		return null;
	}

	/**
	 * @return the data-type with the opposite signedness from this data-type. For example, this
	 *         method on IntegerDataType will return an instance of UnsignedIntegerDataType.
	 */
	public abstract AbstractIntegerDataType getOppositeSignednessDataType();

	@Override
	public boolean isEquivalent(DataType dt) {
		return dt.getClass().equals(getClass());
	}

	private static AbstractIntegerDataType[] signedTypes;
	private static AbstractIntegerDataType[] unsignedTypes;

	/**
	 * An "map" of the first 8 (by size) signed integer data types, where the element at index
	 * <code>i</code> points to the datatype of size <code>i+1</code>, with additional types with no
	 * size restriction appended after the first 8.
	 *
	 * @return array of all signed integer types (char and bool types excluded)
	 */
	private static AbstractIntegerDataType[] getSignedTypes() {
		if (signedTypes == null) {
			signedTypes = new AbstractIntegerDataType[] { SignedByteDataType.dataType,
				SignedWordDataType.dataType, Integer3DataType.dataType,
				SignedDWordDataType.dataType, Integer5DataType.dataType, Integer6DataType.dataType,
				Integer7DataType.dataType, SignedQWordDataType.dataType,
				Integer16DataType.dataType };
		}
		return signedTypes;
	}

	/**
	 * An "map" of the first 8 (by size) unsigned integer data types, where the element at index
	 * <code>i</code> points to the datatype of size <code>i+1</code>, with additional types with no
	 * size restriction appended after the first 8.
	 *
	 * @return array of all unsigned integer types (char and bool types excluded)
	 */
	private static AbstractIntegerDataType[] getUnsignedTypes() {
		if (unsignedTypes == null) {
			unsignedTypes = new AbstractIntegerDataType[] { ByteDataType.dataType,
				WordDataType.dataType, UnsignedInteger3DataType.dataType, DWordDataType.dataType,
				UnsignedInteger5DataType.dataType, UnsignedInteger6DataType.dataType,
				UnsignedInteger7DataType.dataType, QWordDataType.dataType,
				UnsignedInteger16DataType.dataType };
		}
		return unsignedTypes;
	}

	/**
	 * Get a Signed Integer data-type instance of the requested size
	 * 
	 * @param size data type size, sizes greater than 8 (and other than 16) will cause an
	 *            SignedByteDataType[size] (i.e., Array) to be returned.
	 * @param dtm optional program data-type manager, if specified a generic data-type will be
	 *            returned if possible.
	 * @return signed integer data type
	 */
	public static DataType getSignedDataType(int size, DataTypeManager dtm) {
		if (size < 1) {
			return DefaultDataType.dataType;
		}
		if (size == 16) {
			return Integer16DataType.dataType;
		}
		if (size > 8) {
			return new ArrayDataType(SignedByteDataType.dataType, size, 1);
		}
		if (dtm != null) {
			DataOrganization dataOrganization = dtm.getDataOrganization();
			if (dataOrganization != null) {
				if (size == dataOrganization.getIntegerSize()) {
					return IntegerDataType.dataType.clone(dtm);
				}
				if (size == dataOrganization.getShortSize()) {
					return ShortDataType.dataType.clone(dtm);
				}
				if (size == dataOrganization.getLongSize()) {
					return LongDataType.dataType.clone(dtm);
				}
				if (size == dataOrganization.getLongLongSize()) {
					return LongLongDataType.dataType.clone(dtm);
				}
			}
		}
		return getSignedTypes()[size - 1];
	}

	/**
	 * Returns all built-in signed integer data-types.
	 * 
	 * @param dtm optional program data-type manager, if specified generic data-types will be
	 *            returned in place of fixed-sized data-types.
	 * @return array of all signed integer types (char and bool types excluded)
	 */
	public static AbstractIntegerDataType[] getSignedDataTypes(DataTypeManager dtm) {
		AbstractIntegerDataType[] dataTypes = getSignedTypes().clone();
		if (dtm != null) {
			DataOrganization dataOrganization = dtm.getDataOrganization();
			if (dataOrganization != null) {
				int index = dataOrganization.getLongLongSize() - 1;
				if (index >= 0 && index < 8) {
					dataTypes[index] = LongLongDataType.dataType.clone(dtm);
				}
				index = dataOrganization.getLongSize() - 1;
				if (index >= 0 && index < 8) {
					dataTypes[index] = LongDataType.dataType.clone(dtm);
				}
				index = dataOrganization.getShortSize() - 1;
				if (index >= 0 && index < 8) {
					dataTypes[index] = ShortDataType.dataType.clone(dtm);
				}
				index = dataOrganization.getIntegerSize() - 1;
				if (index >= 0 && index < 8) {
					dataTypes[index] = IntegerDataType.dataType.clone(dtm);
				}
			}
		}
		return dataTypes;
	}

	/**
	 * Get a Unsigned Integer data-type instance of the requested size
	 * 
	 * @param size data type size, sizes greater than 8 (and other than 16) will cause an undefined
	 *            type to be returned.
	 * @param dtm optional program data-type manager, if specified a generic data-type will be
	 *            returned if possible.
	 * @return unsigned integer data type
	 */
	public static DataType getUnsignedDataType(int size, DataTypeManager dtm) {
		if (size < 1) {
			return DefaultDataType.dataType;
		}
		if (size == 16) {
			return UnsignedInteger16DataType.dataType;
		}
		if (size > 8) {
			return Undefined.getUndefinedDataType(size);
		}
		if (dtm != null) {
			DataOrganization dataOrganization = dtm.getDataOrganization();
			if (dataOrganization != null) {
				if (size == dataOrganization.getIntegerSize()) {
					return UnsignedIntegerDataType.dataType.clone(dtm);
				}
				if (size == dataOrganization.getShortSize()) {
					return UnsignedShortDataType.dataType.clone(dtm);
				}
				if (size == dataOrganization.getLongSize()) {
					return UnsignedLongDataType.dataType.clone(dtm);
				}
				if (size == dataOrganization.getLongLongSize()) {
					return UnsignedLongLongDataType.dataType.clone(dtm);
				}
			}
		}
		return getUnsignedTypes()[size - 1];
	}

	/**
	 * Returns all built-in unsigned integer data-types
	 * 
	 * @param dtm optional program data-type manager, if specified generic data-types will be
	 *            returned in place of fixed-sized data-types.
	 * @return array of all unsigned integer types (char and bool types excluded)
	 */
	public static AbstractIntegerDataType[] getUnsignedDataTypes(DataTypeManager dtm) {
		AbstractIntegerDataType[] dataTypes = getUnsignedTypes().clone();
		if (dtm != null) {
			DataOrganization dataOrganization = dtm.getDataOrganization();
			if (dataOrganization != null) {
				int index = dataOrganization.getLongLongSize() - 1;
				if (index >= 0 && index < 8) {
					dataTypes[index] = UnsignedLongLongDataType.dataType.clone(dtm);
				}
				index = dataOrganization.getLongSize() - 1;
				if (index >= 0 && index < 8) {
					dataTypes[index] = UnsignedLongDataType.dataType.clone(dtm);
				}
				index = dataOrganization.getShortSize() - 1;
				if (index >= 0 && index < 8) {
					dataTypes[index] = UnsignedShortDataType.dataType.clone(dtm);
				}
				index = dataOrganization.getIntegerSize() - 1;
				if (index >= 0 && index < 8) {
					dataTypes[index] = UnsignedIntegerDataType.dataType.clone(dtm);
				}
			}
		}
		return dataTypes;
	}

}
