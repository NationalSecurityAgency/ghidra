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
/*
 * Created on Mar 7, 2005
 */
package ghidra.app.util.datatype.microsoft;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.ProcessorContext;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.*;
import ghidra.util.classfinder.ClassTranslator;

/**
 * 
 *
 */
public class GuidDataType extends BuiltIn {

	static {
		ClassTranslator.put(
			"ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.dataTypes.GuidDataType",
			GuidDataType.class.getName());
		ClassTranslator.put("ghidra.app.util.bin.format.microsoft.GuidDataType",
			GuidDataType.class.getName());
	}

	/**
	 * Provides a definition of a GUID within a program.
	 */
	private final static long serialVersionUID = 1;
	private static final String NAME = "GUID";

	private static final EndianSettingsDefinition ENDIAN = EndianSettingsDefinition.DEF;
	private static SettingsDefinition[] SETTINGS_DEFS = { ENDIAN };

	public static final int SIZE = 16;
	public static final String KEY = "GUID_NAME";

	private static String cachedGuidString;
	private static String cachedGuidName;

	/**
	 * Creates a Double Word data type.
	 */
	public GuidDataType() {
		this(null);
	}

	public GuidDataType(DataTypeManager dtm) {
		super(null, NAME, dtm);
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getMnemonic(Settings)
	 */
	public String getMnemonic(Settings settings) {
		return NAME;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	public int getLength() {
		return SIZE;
	}

	/**
	 * @see ghidra.program.model.data.DataType#isDynamicallySized()
	 */
	public boolean isDynamicallySized() {
		return false;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	public String getDescription() {
		return NAME;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return getString(buf, settings);
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getRepresentation(MemBuffer, Settings, int)
	 */
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return getString(buf, settings);
	}

	/**
	 * @see ghidra.program.model.data.BuiltIn#getBuiltInSettingsDefinitions()
	 */
	@Override
	protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return SETTINGS_DEFS;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.ByteDataType#getString(ProcessorContext, Settings)
	 */
	protected String getString(MemBuffer buf, Settings settings) {

		Object guidName = settings.getValue(KEY);
		String delim = "-";

		byte[] bytes = new byte[16];
		long[] data = new long[4];

		boolean isBigEndian = ENDIAN.isBigEndian(settings, buf);
		DataConverter conv =
			isBigEndian ? (DataConverter) new BigEndianDataConverter()
					: (DataConverter) new LittleEndianDataConverter();

		if (buf.getBytes(bytes, 0) != bytes.length) {
			if (guidName != null) {
				return (String) guidName;
			}
			return "??";
		}

		for (int i = 0; i < data.length; i++) {
			data[i] = 0xFFFFFFFFL & conv.getInt(bytes, i * 4);
			conv.getBytes((int) data[i], bytes, i * 4);
		}

		String retVal;
		retVal = Conv.toHexString((int) data[0]) + delim;
		retVal += Conv.toHexString((short) (data[1])) + delim;
		retVal += Conv.toHexString((short) (data[1] >> 16)) + delim;
		for (int i = 0; i < 4; i++) {
			retVal += Conv.toHexString((byte) (data[2] >> i * 8));
			if (i == 1)
				retVal += delim;
		}
		for (int i = 0; i < 4; i++) {
			retVal += Conv.toHexString((byte) (data[3] >> i * 8));
		}
//		retVal = retVal.toUpperCase();
		if (guidName == null) {
			guidName = getGuidName(retVal);
		}
		if (guidName != null) {
			return guidName + " " + retVal;
		}
		return retVal;
	}

	private String getGuidName(String guidString) {
		if (guidString.equals(cachedGuidString)) {
			return cachedGuidName;
		}
		cachedGuidString = guidString;
		GuidInfo guidInfo = GuidUtil.getKnownGuid(guidString);
		if (guidInfo != null) {
			cachedGuidName = guidInfo.getName();
		}
		else {
			cachedGuidName = null;
		}
		return cachedGuidName;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return NAME;
	}

	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new GuidDataType(dtm);
	}
}
