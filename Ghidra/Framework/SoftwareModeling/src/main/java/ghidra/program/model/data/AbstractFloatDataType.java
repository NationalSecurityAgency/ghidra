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
import java.util.TreeMap;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.pcode.floatformat.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.mem.MemBuffer;

/**
 * Provides a definition of a Float within a program.
 */
public abstract class AbstractFloatDataType extends BuiltIn {

	// TODO: Add FloatDisplayPrecisionSettingsDefinition
	private static SettingsDefinition[] SETTINGS_DEFS = {};

	private final FloatFormat floatFormat;
	private final int encodedLength;

	private String description;

	/**
	 * Abstract float datatype constructor
	 * @param name name of the float datatype.
	 * @param encodedLength the floating encoding length as number of 8-bit bytes.
	 * @param dtm associated datatype manager which dictates the {@link DataOrganization} to
	 * be used.  This argument may be null to adopt the default data organization.
	 */
	public AbstractFloatDataType(String name, int encodedLength, DataTypeManager dtm) {
		super(null, name, dtm);
		if (encodedLength < 1) {
			throw new IllegalArgumentException("Invalid encoded length: " + encodedLength);
		}
		this.encodedLength = encodedLength;
		FloatFormat format = null;
		try {
			// Establish float format
			format = FloatFormatFactory.getFloatFormat(getLength());
		}
		catch (UnsupportedFloatFormatException e) {
			// ignore
		}
		floatFormat = format;
	}

	@Override
	public String getMnemonic(Settings settings) {
		return name;
	}

	protected final String buildIEEE754StandardDescription() {
		StringBuilder buf = new StringBuilder("IEEE 754 floating-point type (");
		int bitLen = encodedLength * 8;
		buf.append(Integer.toString(bitLen));
		buf.append("-bit / ");
		buf.append(Integer.toString(encodedLength));
		buf.append("-byte format, aligned-length is ");
		buf.append(Integer.toString(getAlignedLength()));
		buf.append("-bytes)");
		return buf.toString();
	}

	protected String buildDescription() {
		return buildIEEE754StandardDescription();
	}

	@Override
	public final String getDescription() {
		if (description == null) {
			description = buildDescription();
		}
		return description;
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return BigFloat.class;
	}

	/**
	 * Get the encoded length (number of 8-bit bytes) of this float datatype.
	 * 
	 * @return encoded length of this float datatype.
	 */
	@Override
	public final int getLength() {
		return encodedLength;
	}

	@Override
	public BigFloat getValue(MemBuffer buf, Settings settings, int length) {
		try {
			int len = getLength(); // use type length (ignore length arg)
			if (floatFormat == null) {
				return null;
			}
			byte[] bytes = new byte[len];
			if (buf.getBytes(bytes, 0) != len) {
				return null;
			}
			if (len <= 8) {
				long value = Utils.bytesToLong(bytes, len, buf.isBigEndian());
				return floatFormat.decodeBigFloat(value);
			}
			BigInteger value = Utils.bytesToBigInteger(bytes, len, buf.isBigEndian(), false);
			return floatFormat.decodeBigFloat(value);
		}
		catch (UnsupportedFloatFormatException e) {
			return null;
		}
	}

	@Override
	public boolean isEncodable() {
		return floatFormat != null;
	}

	@Override
	public byte[] encodeValue(Object value, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException {
		// value expected as Number or BigFloat object
		try {
			int len = getLength();
			if (floatFormat == null) {
				throw new DataTypeEncodeException(
					"Unsupported float format (" + len + " bytes)", value, this);
			}
			if ((len == 8 || len == 4) && (value instanceof Number)) {
				double doubleValue = ((Number) value).doubleValue();
				long encoding = floatFormat.getEncoding(doubleValue);
				return Utils.longToBytes(encoding, len, buf.isBigEndian());
			}
			if (!(value instanceof BigFloat)) {
				throw new DataTypeEncodeException(
					"non-standard float length requires BigFloat type", value, this);
			}
			BigInteger encoding = floatFormat.getEncoding((BigFloat) value);
			return Utils.bigIntegerToBytes(encoding, len, buf.isBigEndian());
		}
		catch (DataTypeEncodeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new DataTypeEncodeException(value, this, e);
		}
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		BigFloat value = getValue(buf, settings, length);
		if (value == null) {
			return "??";
		}
		return floatFormat != null ? floatFormat.toDecimalString(value, true) : value.toString();
	}

	@Override
	public byte[] encodeRepresentation(String repr, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException {
		try {
			int len = getLength();
			if (floatFormat == null) {
				throw new DataTypeEncodeException(
					"Unsupported float format (" + len + " bytes)", repr, this);
			}
			if (length == 8 || length == 4) {
				double doubleValue = Double.parseDouble(repr);
				return encodeValue(doubleValue, buf, settings, length);
			}
			BigFloat bf = floatFormat.getBigFloat(repr);
			floatFormat.round(bf);
			return encodeValue(bf, buf, settings, length);
		}
		catch (DataTypeEncodeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new DataTypeEncodeException(repr, this, e);
		}
	}

	@Override
	protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return SETTINGS_DEFS;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return name.toUpperCase();
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		// NOTE: There are a variety of naming conventions for fixed-length floats
		// so we will just use our name and rely on user to edit to suit there needs.
		return hasLanguageDependantLength() ? null : name;
	}

	private static TreeMap<Integer, AbstractFloatDataType> floatTypes; // fixed-size float types

	/**
	 * Returns all built-in fixed-sized float data-types
	 */
	private synchronized static TreeMap<Integer, AbstractFloatDataType> getFloatTypes() {
		if (floatTypes == null) {
			// unsupported sizes filled-in with a null
			floatTypes = new TreeMap<Integer, AbstractFloatDataType>();
			floatTypes.put(Float2DataType.dataType.getLength(), Float2DataType.dataType);
			floatTypes.put(Float4DataType.dataType.getLength(), Float4DataType.dataType);
			floatTypes.put(Float8DataType.dataType.getLength(), Float8DataType.dataType);
			floatTypes.put(Float10DataType.dataType.getLength(), Float10DataType.dataType);
			floatTypes.put(Float16DataType.dataType.getLength(), Float16DataType.dataType);
		}
		return floatTypes;
	}

	/**
	 * Get a Float data-type instance with the requested raw format size in bytes. It is important that the
	 * "raw" format size is specified since the {@link DataType#getAlignedLength() aligned-length}
	 * used by compilers (e.g., {@code sizeof()}) may be larger and duplicated across different 
	 * float formats.  Example: an 80-bit (10-byte) float may have an aligned-length of 12 or 16-bytes 
	 * based upon alignment requirements of a given compiler.  This can result in multiple float
	 * types having the same aligned-length.
	 * 
	 * @param rawFormatByteSize raw float format size, unsupported sizes will cause an undefined 
	 * 				type to be returned.
	 * @param dtm optional program data-type manager, if specified a generic data-type will be
	 *            	returned if possible (i.e., float, double, long double).
	 * @return float data type of specified size
	 */
	public static DataType getFloatDataType(int rawFormatByteSize, DataTypeManager dtm) {
		if (rawFormatByteSize < 1) {
			return DefaultDataType.dataType;
		}
		if (dtm != null) {
			DataOrganization dataOrganization = dtm.getDataOrganization();
			if (dataOrganization != null) {
				if (rawFormatByteSize == dataOrganization.getFloatSize()) {
					return FloatDataType.dataType.clone(dtm);
				}
				if (rawFormatByteSize == dataOrganization.getDoubleSize()) {
					return DoubleDataType.dataType.clone(dtm);
				}
				if (rawFormatByteSize == dataOrganization.getLongDoubleSize()) {
					return LongDoubleDataType.dataType.clone(dtm);
				}
			}
		}
		DataType dt = getFloatTypes().get(rawFormatByteSize);
		if (dt == null) {
			return Undefined.getUndefinedDataType(rawFormatByteSize);
		}
		return dt;
	}

	/**
	 * Returns all built-in floating-point data types
	 * 
	 * @param dtm optional program data-type manager, if specified generic data-types will be
	 *            returned in place of fixed-sized data-types.
	 * @return array of floating-point data types
	 */
	public static AbstractFloatDataType[] getFloatDataTypes(DataTypeManager dtm) {
		TreeMap<Integer, AbstractFloatDataType> floatMap = getFloatTypes();
		TreeMap<Integer, AbstractFloatDataType> newFloatMap = floatMap;
		if (dtm != null) {
			DataOrganization dataOrganization = dtm.getDataOrganization();
			if (dataOrganization != null) {
				newFloatMap = new TreeMap<Integer, AbstractFloatDataType>();
				newFloatMap.put(dataOrganization.getFloatSize(),
					(AbstractFloatDataType) FloatDataType.dataType.clone(dtm));
				if (!newFloatMap.containsKey(dataOrganization.getDoubleSize())) {
					newFloatMap.put(dataOrganization.getDoubleSize(),
						(AbstractFloatDataType) DoubleDataType.dataType.clone(dtm));
				}
				if (!newFloatMap.containsKey(dataOrganization.getLongDoubleSize())) {
					newFloatMap.put(dataOrganization.getLongDoubleSize(),
						(AbstractFloatDataType) LongDoubleDataType.dataType.clone(dtm));
				}
				for (int size : floatMap.keySet()) {
					if (!newFloatMap.containsKey(size)) {
						newFloatMap.put(size,
							(AbstractFloatDataType) floatMap.get(size).clone(dtm));
					}
				}
			}
		}
		AbstractFloatDataType[] floatTypeArray = new AbstractFloatDataType[newFloatMap.size()];
		newFloatMap.values().toArray(floatTypeArray);
		return floatTypeArray;
	}
}
