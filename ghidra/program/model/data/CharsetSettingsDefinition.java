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

import java.util.*;

import ghidra.docking.settings.*;

/**
 *  {@link SettingsDefinition} for setting the charset of a string instance.
 *  <p>
 *  Charsets control how raw bytes are converted to native java String instances.
 *  <p>
 *  {@link CharsetInfo} controls the list of character sets that the user is shown.
 */
public class CharsetSettingsDefinition implements EnumSettingsDefinition {

	private static final String CHARSET_SETTING_NAME = "charset";

	/**
	 * Backward compatible to the setting from MBCS data type.  This
	 * setting value will be cleared whenever the charset is changed.
	 */
	private static final String DEPRECATED_ENCODING_SETTING_NAME = "encoding";

	/**
	 * Backward compatible to the setting from MBCS data type.  This
	 * setting value will be cleared whenever the charset is changed.
	 */
	private static final String DEPRECATED_LANGUAGE_SETTING_NAME = "language";

	private static final String CHARSET_NAME = "Charset";

	public static final CharsetSettingsDefinition CHARSET = new CharsetSettingsDefinition();

	/**
	 * Backward compatibility to map old MBCS (language_index, charset_index) tuples to a
	 * simple charset_name value.
	 * <p>
	 */
	private static Map<Long, List<String>> languageToCharsetIndexMap = new HashMap<>();

	private final String[] ordinalToString;
	private final Map<String, Integer> stringToOrdinal = new HashMap<>();

	private CharsetSettingsDefinition() {
		ordinalToString = CharsetInfo.getInstance().getCharsetNames();
		for (int i = 0; i < ordinalToString.length; i++) {
			stringToOrdinal.put(ordinalToString[i], i);
		}
	}

	public String getCharset(Settings settings, String defaultValue) {
		String cs = settings.getString(CHARSET_SETTING_NAME);
		if (cs == null) {
			cs = getDeprecatedEncodingValue(settings);
		}
		return (cs != null) ? cs : defaultValue;
	}

	private String getDeprecatedEncodingValue(Settings settings) {
		Long langIndex = settings.getLong(DEPRECATED_LANGUAGE_SETTING_NAME);
		Long encodingIndex = settings.getLong(DEPRECATED_ENCODING_SETTING_NAME);

		if (langIndex == null || encodingIndex == null) {
			return null;
		}

		List<String> encodings = languageToCharsetIndexMap.get(langIndex);
		return (encodings != null) && (encodingIndex >= 0 && encodingIndex < encodings.size())
				? encodings.get(encodingIndex.intValue())
				: null;
	}

	public void setCharset(Settings settings, String charset) {
		if (charset == null || charset.isEmpty()) {
			settings.clearSetting(CHARSET_SETTING_NAME);
		}
		else {
			settings.setString(CHARSET_SETTING_NAME, charset);
		}
		settings.clearSetting(DEPRECATED_ENCODING_SETTING_NAME);
		settings.clearSetting(DEPRECATED_LANGUAGE_SETTING_NAME);
	}

	@Override
	public int getChoice(Settings settings) {
		return stringToOrdinal.getOrDefault(getCharset(settings, null), 0);
	}

	@Override
	public void setChoice(Settings settings, int ordinalOfValue) {
		if (ordinalOfValue < 0 || ordinalOfValue >= ordinalToString.length) {
			settings.clearSetting(CHARSET_SETTING_NAME);
		}
		else {
			settings.setString(CHARSET_SETTING_NAME, ordinalToString[ordinalOfValue]);
		}
		settings.clearSetting(DEPRECATED_ENCODING_SETTING_NAME);
		settings.clearSetting(DEPRECATED_LANGUAGE_SETTING_NAME);
	}

	@Override
	public String[] getDisplayChoices(Settings settings) {
		return ordinalToString;
	}

	@Override
	public String getName() {
		return CHARSET_NAME;
	}

	@Override
	public String getDescription() {
		return "Character set";
	}

	@Override
	public String getDisplayChoice(int ordinalOfValue, Settings s1) {
		return ordinalToString[ordinalOfValue];
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(CHARSET_SETTING_NAME);
	}

	@Override
	public void copySetting(Settings settings, Settings destSettings) {
		String s = settings.getString(CHARSET_SETTING_NAME);
		if (s == null) {
			destSettings.clearSetting(CHARSET_SETTING_NAME);
		}
		else {
			destSettings.setString(CHARSET_SETTING_NAME, s);
		}
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(CHARSET_SETTING_NAME) != null ||
			setting.getValue(DEPRECATED_ENCODING_SETTING_NAME) != null;
	}

	//-----------------------------------------------------------------------------------

	/**
	 * Sets a static lookup table that maps from old deprecated (language,encoding) index
	 * values to a charset name.
	 * <p>
	 * The old index values were used by old-style MBCS data type.
	 *
	 * @param mappingValues map of language_id to list of charset names.
	 */
	public static void setStaticEncodingMappingValues(Map<Long, List<String>> mappingValues) {
		languageToCharsetIndexMap.clear();
		languageToCharsetIndexMap.putAll(mappingValues);
	}
}
