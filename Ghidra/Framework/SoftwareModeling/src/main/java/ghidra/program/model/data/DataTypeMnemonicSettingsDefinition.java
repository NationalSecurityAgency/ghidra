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

import ghidra.docking.settings.EnumSettingsDefinition;
import ghidra.docking.settings.Settings;

/**
 * The settings definition for the numeric display format
 */
public class DataTypeMnemonicSettingsDefinition implements EnumSettingsDefinition {

	public static final int DEFAULT = 0;
	public static final int ASSEMBLY = 1;
	public static final int CSPEC = 2;

	//NOTE: if these strings change, the XML needs to changed also...
	private static final String[] choices = { "default", "assembly", "C" };

	private static final String MNEMONIC = "mnemonic";

	public static final DataTypeMnemonicSettingsDefinition DEF =
		new DataTypeMnemonicSettingsDefinition();

	private DataTypeMnemonicSettingsDefinition() {
	}

	/**
	 * Returns the format based on the specified settings
	 * @param settings the instance settings.
	 * @return the format value (HEX, DECIMAL, BINARY, OCTAL, CHAR)
	 */
	public int getMnemonicStyle(Settings settings) {
		if (settings == null) {
			return ASSEMBLY;
		}
		Long value = settings.getLong(MNEMONIC);
		if (value == null) {
			return ASSEMBLY;
		}
		int style = (int) value.longValue();
		if ((style < 0) || (style > CSPEC)) {
			style = ASSEMBLY;
		}
		return style;
	}

	@Override
	public int getChoice(Settings settings) {
		return getMnemonicStyle(settings);
	}

	@Override
	public void setChoice(Settings settings, int value) {
		if (value < 0 || value > CSPEC) {
			settings.clearSetting(MNEMONIC);
		}
		else {
			settings.setLong(MNEMONIC, value);
		}
	}

	@Override
	public String[] getDisplayChoices(Settings settings) {
		return choices;
	}

	@Override
	public String getName() {
		return "Mnemonic-style";
	}

	@Override
	public String getDescription() {
		return "Selects the data-type mnemonic style";
	}

	@Override
	public String getDisplayChoice(int value, Settings settings) {
		return choices[value];
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(MNEMONIC);
	}

	@Override
	public void copySetting(Settings settings, Settings destSettings) {
		Long l = settings.getLong(MNEMONIC);
		if (l == null) {
			destSettings.clearSetting(MNEMONIC);
		}
		else {
			destSettings.setLong(MNEMONIC, l);
		}
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(MNEMONIC) != null;
	}

}
