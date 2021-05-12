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

import java.math.BigDecimal;
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

	private final static long serialVersionUID = 1;

	private static SettingsDefinition[] SETTINGS_DEFS = {};

	public AbstractFloatDataType(String name, DataTypeManager dtm) {
		super(null, name, dtm);
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getMnemonic(Settings)
	 */
	@Override
	public String getMnemonic(Settings settings) {
		return name;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	@Override
	public String getDescription() {
		return "IEEE-754 Float";
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		try {
			int len = getLength(); // use type length (ignore length arg)
			FloatFormat floatFormat = FloatFormatFactory.getFloatFormat(len);
			byte[] bytes = new byte[len];
			if (buf.getBytes(bytes, 0) != len) {
				return null;
			}
			if (len <= 8) {
				long value = Utils.bytesToLong(bytes, len, buf.isBigEndian());
				double doubleValue = floatFormat.getHostFloat(value);
				switch (len) {
					case 2:
						return (short) doubleValue;
					case 4:
						return (float) doubleValue;
				}
				return doubleValue;
			}
			BigInteger value = Utils.bytesToBigInteger(bytes, len, buf.isBigEndian(), false);
			BigDecimal decValue = floatFormat.round(floatFormat.getHostFloat(value));
			return decValue;
		}
		catch (UnsupportedFloatFormatException e) {
			return null;
		}
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getRepresentation(MemBuffer, Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		Object obj = getValue(buf, settings, length);
		if (obj == null) {
			return "??";
		}
		return obj.toString();
	}

	/**
	 * @see ghidra.program.model.data.BuiltIn#getBuiltInSettingsDefinitions()
	 */
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
			floatTypes.put(2, Float2DataType.dataType);
			floatTypes.put(4, Float4DataType.dataType);
			floatTypes.put(8, Float8DataType.dataType);
			floatTypes.put(10, Float10DataType.dataType);
			floatTypes.put(16, Float16DataType.dataType);
		}
		return floatTypes;
	}

	/**
	 * Get a Float data-type instance of the requested size
	 * @param size data type size, unsupported sizes will cause an undefined type to be returned.
	 * @param dtm optional program data-type manager, if specified
	 * a generic data-type will be returned if possible (i.e., float, double, long double).
	 * @return float data type of specified size
	 */
	public static DataType getFloatDataType(int size, DataTypeManager dtm) {
		if (size < 1) {
			return DefaultDataType.dataType;
		}
		if (dtm != null) {
			DataOrganization dataOrganization = dtm.getDataOrganization();
			if (dataOrganization != null) {
				if (size == dataOrganization.getFloatSize()) {
					return FloatDataType.dataType.clone(dtm);
				}
				if (size == dataOrganization.getDoubleSize()) {
					return DoubleDataType.dataType.clone(dtm);
				}
				if (size == dataOrganization.getLongDoubleSize()) {
					return LongDoubleDataType.dataType.clone(dtm);
				}
			}
		}
		DataType dt = getFloatTypes().get(size);
		if (dt == null) {
			return Undefined.getUndefinedDataType(size);
		}
		return dt;
	}

	/**
	 * Returns all built-in float data-types
	 * @param dtm optional program data-type manager, if specified
	 * generic data-types will be returned in place of fixed-sized data-types.
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
