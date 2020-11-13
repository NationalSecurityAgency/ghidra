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
	 * 'hidden' setting that stores the translated string value.
	 */
	private static final String TRANSLATED_VALUE_SETTING_NAME = "translation";

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

	public boolean hasTranslatedValue(Settings settings) {
		return settings.getString(TRANSLATED_VALUE_SETTING_NAME) != null;
	}

	public String getTranslatedValue(Settings settings) {
		return settings.getString(TRANSLATED_VALUE_SETTING_NAME);
	}

	public void setTranslatedValue(Settings settings, String translatedValue) {
		settings.setString(TRANSLATED_VALUE_SETTING_NAME, translatedValue);
	}

	@Override
	public void clear(Settings settings) {
		super.clear(settings);
		settings.clearSetting(TRANSLATED_VALUE_SETTING_NAME);
	}

	@Override
	public void copySetting(Settings srcSettings, Settings destSettings) {
		super.copySetting(srcSettings, destSettings);
		String translated = srcSettings.getString(TRANSLATED_VALUE_SETTING_NAME);
		if (translated == null) {
			destSettings.clearSetting(TRANSLATED_VALUE_SETTING_NAME);
		}
		else {
			destSettings.setString(TRANSLATED_VALUE_SETTING_NAME, translated);
		}
	}
}
