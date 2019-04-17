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
package ghidra.docking.settings;

/**
 * SettingsDefinition to define the number of digits of precision to show. The value 
 * is rendered to thousandths, 3 digits of precision, by default.
 */
public class FloatingPointPrecisionSettingsDefinition implements EnumSettingsDefinition {

	private static final String PRECISION_DIGITS = "Precision digits";

	/**
	 * Default definition.
	 */
	public static final FloatingPointPrecisionSettingsDefinition DEF =
		new FloatingPointPrecisionSettingsDefinition();

	private static final String[] choices =
		{ "default", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10" };

	private static final int DEFAULT_PRECISION = 3;
	public static final int MAX_PRECISION = choices.length - 2; // ignore 'default' and '0'

	private FloatingPointPrecisionSettingsDefinition() {
	}

	public int getPrecision(Settings settings) {
		return getChoice(settings) - 1;
	}

	public void setPrecision(Settings settings, int digits) {
		setChoice(settings, digits + 1);
	}

	@Override
	public int getChoice(Settings settings) {
		Long value = (long) DEFAULT_PRECISION + 1;
		if (settings != null) {
			value = settings.getLong(PRECISION_DIGITS);
			if (value == null) {
				value = (long) DEFAULT_PRECISION + 1;
			}
		}
		return value.intValue();
	}

	@Override
	public void setChoice(Settings settings, int valueIndex) {

		if (valueIndex < 0) {
			settings.clearSetting(PRECISION_DIGITS);
		}
		else {

			if (valueIndex == 0) {
				valueIndex = DEFAULT_PRECISION + 1;
			}

			if (valueIndex > MAX_PRECISION + 1) {
				valueIndex = MAX_PRECISION + 1;
			}
			settings.setLong(PRECISION_DIGITS, valueIndex);
		}
	}

	@Override
	public String[] getDisplayChoices(Settings settings) {
		return choices;
	}

	@Override
	public String getName() {
		return PRECISION_DIGITS;
	}

	@Override
	public String getDescription() {
		return "Selects the number of digits of precision to display";
	}

	public int getChoice(String displayChoice, Settings settings) {
		for (int i = 0; i < choices.length; i++) {
			if (choices[i].equals(displayChoice)) {
				return i;
			}
		}
		return -1;
	}

	@Override
	public String getDisplayChoice(int value, Settings s1) {
		return choices[value];
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(PRECISION_DIGITS);
	}

	@Override
	public void copySetting(Settings settings, Settings destSettings) {
		Long l = settings.getLong(PRECISION_DIGITS);
		if (l == null) {
			destSettings.clearSetting(PRECISION_DIGITS);
		}
		else {
			destSettings.setLong(PRECISION_DIGITS, l);
		}
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(PRECISION_DIGITS) != null;
	}

}
