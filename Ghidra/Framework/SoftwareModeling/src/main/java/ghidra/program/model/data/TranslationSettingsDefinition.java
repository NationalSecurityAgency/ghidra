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

import ghidra.docking.settings.JavaEnumSettingsDefinition;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.TranslationSettingsDefinition.TRANSLATION_ENUM;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.exception.DuplicateNameException;

/**
 *  SettingsDefinition for translation display, handles both the toggle of
 *  "show" vs "don't show", as well as accessing the translated value.
 */
public class TranslationSettingsDefinition extends JavaEnumSettingsDefinition<TRANSLATION_ENUM> {
	public static final TranslationSettingsDefinition TRANSLATION =
		new TranslationSettingsDefinition();

	public enum TRANSLATION_ENUM {
		SHOW_ORIGINAL("show original"), SHOW_TRANSLATED("show translated");

		private final String s;

		private TRANSLATION_ENUM(String s) {
			this.s = s;
		}

		@Override
		public String toString() {
			return s;
		}

		public TRANSLATION_ENUM invert() {
			return this == SHOW_ORIGINAL ? SHOW_TRANSLATED : SHOW_ORIGINAL;
		}
	}

	/**
	 * setting that stores the boolean toggle state for "show original" / "show translated"
	 */
	private static final String SHOW_TRANSLATED_TOGGLE_SETTING_NAME = "translated";

	private TranslationSettingsDefinition() {
		super(SHOW_TRANSLATED_TOGGLE_SETTING_NAME, "Translation",
			"Selects the display of translated strings", TRANSLATION_ENUM.SHOW_ORIGINAL);
	}

	public boolean isShowTranslated(Settings settings) {
		return getEnumValue(settings) == TRANSLATION_ENUM.SHOW_TRANSLATED;
	}

	public void setShowTranslated(Settings settings, boolean shouldShowTranslatedValue) {
		setEnumValue(settings, shouldShowTranslatedValue ? TRANSLATION_ENUM.SHOW_TRANSLATED
				: TRANSLATION_ENUM.SHOW_ORIGINAL);
	}

	/*
	 * Helper methods for managing stored translated string values using a Property Map named "StringTranslations".
	 * Deprecated use of settings map will continue to be checked if value in property map not found
	 */

	public static String TRANSLATION_PROPERTY_MAP_NAME = "StringTranslations";

	private static final String DEPRECATED_TRANSLATED_VALUE_SETTING_NAME = "translation";

	/**
	 * Determine if a translated string value has been set at the specified address.
	 * @param data defined string data which may have a translation
	 * @return true if translated string has been stored else false
	 */
	public boolean hasTranslatedValue(Data data) {
		Program p = data.getProgram();
		PropertyMapManager propertyMapManager = p.getUsrPropertyManager();
		StringPropertyMap translationMap =
			propertyMapManager.getStringPropertyMap(TRANSLATION_PROPERTY_MAP_NAME);
		boolean hasValue = false;
		if (translationMap != null) {
			hasValue = translationMap.hasProperty(data.getAddress());
		}
		if (!hasValue) {
			// check for deprecated settings-based value
			Data d = p.getListing().getDefinedDataAt(data.getAddress());
			hasValue = d != null ? d.hasProperty(DEPRECATED_TRANSLATED_VALUE_SETTING_NAME) : false;
		}
		return hasValue;
	}

	/**
	 * Get the translated string value which been set at the specified address.
	 * @param data defined string data which may have a translation
	 * @return translated string value or null
	 */
	public String getTranslatedValue(Data data) {
		Program p = data.getProgram();
		PropertyMapManager propertyMapManager = p.getUsrPropertyManager();
		StringPropertyMap translationMap =
			propertyMapManager.getStringPropertyMap(TRANSLATION_PROPERTY_MAP_NAME);
		String value = null;
		if (translationMap != null) {
			value = translationMap.getString(data.getAddress());
		}
		if (value == null) {
			// check for deprecated settings-based value
			Data d = p.getListing().getDefinedDataAt(data.getAddress());
			value = d != null ? d.getString(DEPRECATED_TRANSLATED_VALUE_SETTING_NAME) : null;
		}
		return value;
	}

	/**
	 * Set the translated string value at the specified address.
	 * @param data defined string data which may have a translation
	 * @param translatedValue translated string value or null to clear
	 */
	public void setTranslatedValue(Data data, String translatedValue) {
		Program p = data.getProgram();
		PropertyMapManager propertyMapManager = p.getUsrPropertyManager();
		StringPropertyMap translationMap =
			propertyMapManager.getStringPropertyMap(TRANSLATION_PROPERTY_MAP_NAME);
		if (translationMap == null) {
			try {
				translationMap =
					propertyMapManager.createStringPropertyMap(TRANSLATION_PROPERTY_MAP_NAME);
			}
			catch (DuplicateNameException e) {
				throw new RuntimeException(e);
			}
		}
		Data d = p.getListing().getDefinedDataAt(data.getAddress());
		if (d != null) {
			// clear deprecated settings-based value
			d.clearSetting(DEPRECATED_TRANSLATED_VALUE_SETTING_NAME);
		}
		if (translatedValue == null) {
			translationMap.remove(data.getAddress());
		}
		else {
			translationMap.add(data.getAddress(), translatedValue);
		}
	}

}
