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

import static ghidra.program.model.data.CharsetSettingsDefinition.CHARSET;
import static ghidra.program.model.data.RenderUnicodeSettingsDefinition.RENDER;
import static ghidra.program.model.data.TranslationSettingsDefinition.TRANSLATION;

import java.nio.charset.CoderResult;

import ghidra.docking.settings.*;
import ghidra.program.model.mem.MemBuffer;

/**
 * Common base class for all Ghidra string {@link DataType}s.
 * <p>
 * See {@link StringDataType} for information about string variations and configuration details.
 * <p>
 * Sub-classes generally only need to implement a constructor that calls the mega-constructor
 * {@link #AbstractStringDataType(String, String, String, String, String, String, String, DataType, StringLayoutEnum, DataTypeManager)
 * AbstractStringDataType.AbstractStringDataType(lots,of,params)} and the
 * {@link DataType#clone(DataTypeManager) } method.
 * <p>
 *
 */
abstract public class AbstractStringDataType extends BuiltIn
		implements Dynamic, DataTypeWithCharset {
	public static final SettingsDefinition[] COMMON_STRING_SETTINGS_DEFS = { TRANSLATION, RENDER };
	public static final SettingsDefinition[] COMMON_WITH_CHARSET_STRING_SETTINGS_DEFS =
		SettingsDefinition.concat(COMMON_STRING_SETTINGS_DEFS, CHARSET);

	public static final String DEFAULT_UNICODE_LABEL = "UNICODE";
	public static final String DEFAULT_UNICODE_LABEL_PREFIX = "UNI";
	public static final String DEFAULT_UNICODE_ABBREV_PREFIX = "u";

	public static final String DEFAULT_LABEL = "STRING";
	public static final String DEFAULT_LABEL_PREFIX = "STR";
	public static final String DEFAULT_ABBREV_PREFIX = "s";

	/**
	 * A symbolic name to signal that the null value being passed for the charset name param
	 * indicates that the default charset (ie. ASCII) should be used.
	 */
	public static final String USE_CHARSET_DEF_DEFAULT = null;

	/**
	 * The name of the character set used to convert bytes into java native Strings.
	 * <p>
	 * If null, the {@link CharsetSettingsDefinition settings} attached to the data instance will be
	 * queried for a charset, which will default to ASCII if not present.
	 */
	private final String charsetName;
	/**
	 * List of {@link SettingsDefinition} that this datatype supports.
	 */
	private final SettingsDefinition[] settingsDefinition;
	/**
	 * Mnemonic for this datatype
	 */
	private final String mnemonic;
	/**
	 * Description for this datatype
	 */
	private final String description;
	/**
	 * Replacement datatype for this datatype
	 */
	private final DataType replacementDataType;

	/**
	 * Enum that controls how the string is laid out in memory.
	 */
	private final StringLayoutEnum stringLayout;

	/**
	 * String used as a prefix to the data instance location when creating a label when there is a
	 * problem accessing the string data.
	 * <p>
	 * Example: "STRING" produces something like: "STRING_00410ea0"
	 * <p>
	 * This string should be the longest when compared to label prefix and abbrev label prefix.
	 */
	private final String defaultLabel;
	/**
	 * String used as a prefix to the data instance location when creating a label.
	 * <p>
	 * Example: "STR" produces something like: "STR_00410ea0"
	 * <p>
	 * This string should be a medium length when compared to label and abbrev label prefix.
	 */
	private final String defaultLabelPrefix;
	/**
	 * String used as a prefix to a portion of the actual string data when creating a label.
	 * <p>
	 * Example: "s" produces something like: "s_Hello_World_00410ea0"
	 * <p>
	 * This string should be the shortest length when compared to label and label prefix.
	 */
	private final String defaultAbbrevLabelPrefix;

	/**
	 * Protected constructor used by derived types to provide all their datatype details.
	 * <p>
	 * 
	 * @param name Name of this datatype
	 * @param mnemonic Mnemonic of this datatype
	 * @param defaultLabel Label string for this datatype. See {@link #defaultLabel}.
	 * @param defaultLabelPrefix Label prefix string for this datatype. See
	 *            {@link #defaultLabelPrefix}.
	 * @param defaultAbbrevLabelPrefix Abbreviated label prefix for this datatype. See
	 *            {@link #defaultAbbrevLabelPrefix}.
	 * @param description Description of this datatype.
	 * @param charsetName Charset name for this string datatype. If null the settings of the data
	 *            instance will be queried for a {@link CharsetSettingsDefinition charset}.
	 * @param replacementDataType Replacement {@link DataType}.
	 * @param stringLayout {@link StringLayoutEnum stringLayout} controls how the string is laid out
	 *            in memory.
	 * @param dtm {@link DataTypeManager} for this datatype, null ok.
	 */
	protected AbstractStringDataType(String name, String mnemonic, String defaultLabel,
			String defaultLabelPrefix, String defaultAbbrevLabelPrefix, String description,
			String charsetName, DataType replacementDataType, StringLayoutEnum stringLayout,
			DataTypeManager dtm) {
		super(null, name, dtm);
		this.mnemonic = mnemonic;
		this.defaultLabel = defaultLabel;
		this.defaultLabelPrefix = defaultLabelPrefix;
		this.defaultAbbrevLabelPrefix = defaultAbbrevLabelPrefix;
		this.description = description;
		this.settingsDefinition = (charsetName != null) ? COMMON_STRING_SETTINGS_DEFS
				: COMMON_WITH_CHARSET_STRING_SETTINGS_DEFS;
		this.charsetName = charsetName;
		this.replacementDataType = replacementDataType;
		this.stringLayout = stringLayout;
	}

	@Override
	public String getMnemonic(Settings settings) {
		return mnemonic;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return defaultLabelPrefix;
	}

	@Override
	public String getDefaultAbbreviatedLabelPrefix() {
		return defaultAbbrevLabelPrefix;
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return settingsDefinition;
	}

	/**
	 * Creates a new {@link StringDataInstance} using the bytes in the supplied MemBuffer and
	 * options provided by this DataType.
	 * <p>
	 * 
	 * @param buf the data.
	 * @param settings the settings to use for the representation.
	 * @param length the number of bytes to represent.
	 * @return a new {@link StringDataInstance}, never null.
	 */
	public StringDataInstance getStringDataInstance(MemBuffer buf, Settings settings, int length) {
		return new StringDataInstance(this, settings, buf, length);
	}

	/**
	 * @return {@link StringLayoutEnum} settinEnum stringLayoutype.
	 */
	public StringLayoutEnum getStringLayout() {
		return stringLayout;
	}

	@Override
	public String getCharsetName(Settings settings) {
		if (charsetName != null) {
			return charsetName;
		}
		return CharsetSettingsDefinition.CHARSET.getCharset(settings,
			StringDataInstance.DEFAULT_CHARSET_NAME);
	}

	@Override
	public int getLength() {
		return -1;
	}

	@Override
	public boolean canSpecifyLength() {
		return true;
	}

	@Override
	public int getLength(MemBuffer buf, int maxLength) {
		// TODO: when does buf == null?
		// TODO: round result to paddedCharSize if buf == null
		return getStringDataInstance(buf, SettingsImpl.NO_SETTINGS, maxLength).getStringLength();
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return String.class;
	}

	@Override
	public boolean isEncodable() {
		return true;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return getStringDataInstance(buf, settings, length).getStringValue();
	}

	@Override
	public byte[] encodeValue(Object value, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException {
		if (!(value instanceof CharSequence)) {
			throw new DataTypeEncodeException("Requires CharSequence", value, this);
		}
		try {
			StringDataInstance sdi = getStringDataInstance(buf, settings, length);
			return sdi.encodeReplacementFromStringValue((CharSequence) value);
		}
		catch (Exception e) {
			throw new DataTypeEncodeException(value, this, e);
		}
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return getStringDataInstance(buf, settings, length).getStringRepresentation();
	}

	@Override
	public byte[] encodeRepresentation(String repr, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException {
		try {
			StringDataInstance sdi = getStringDataInstance(buf, settings, length);
			return sdi.encodeReplacementFromStringRepresentation(repr);
		}
		catch (Throwable e) {
			throw new DataTypeEncodeException(repr, this, e);
		}
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		return getStringDataInstance(buf, settings, len).getLabel(defaultAbbrevLabelPrefix + "_",
			defaultLabelPrefix, defaultLabel, options);
	}

	@Override
	public String getDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options, int offcutLength) {
		return getStringDataInstance(buf, settings, len).getOffcutLabelString(
			defaultAbbrevLabelPrefix + "_", defaultLabelPrefix, defaultLabel, options,
			offcutLength);
	}

	@Override
	public DataType getReplacementBaseType() {
		return replacementDataType;
	}
}
