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
package ghidra.util.table.field;

import ghidra.docking.settings.EnumSettingsDefinition;
import ghidra.docking.settings.Settings;
import ghidra.program.model.address.AddressRange;

/**
 *  A class for selecting whether to use the min address or the max address of an 
 *  {@link AddressRange} for address range table columns
 */
public class AddressRangeEndpointSettingsDefinition implements EnumSettingsDefinition {

	private static final String ADDRESS_RANGE_ENDPOINT = "Address Range Endpoint";
	private static final String ENDPOINT = "Endpoint";
	public static final String BEGIN = "Begin";
	public static final String END = "End";
	private static final String[] CHOICES = { BEGIN, END };
	public static final int BEGIN_CHOICE_INDEX = 0;
	public static final int END_CHOICE_INDEX = 1;
	private static final int DEFAULT = 0;
	public static final AddressRangeEndpointSettingsDefinition DEF =
		new AddressRangeEndpointSettingsDefinition();

	private AddressRangeEndpointSettingsDefinition() {
		//singleton class
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(ADDRESS_RANGE_ENDPOINT) != null;
	}

	@Override
	public String getValueString(Settings settings) {
		return CHOICES[getChoice(settings)];
	}

	@Override
	public String getName() {
		return ENDPOINT;
	}

	@Override
	public String getStorageKey() {
		return ADDRESS_RANGE_ENDPOINT;
	}

	@Override
	public String getDescription() {
		return "Selects the base address";
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(ADDRESS_RANGE_ENDPOINT);

	}

	@Override
	public void copySetting(Settings srcSettings, Settings destSettings) {
		Long l = srcSettings.getLong(ADDRESS_RANGE_ENDPOINT);
		if (l == null) {
			destSettings.clearSetting(ADDRESS_RANGE_ENDPOINT);
		}
		else {
			destSettings.setLong(ADDRESS_RANGE_ENDPOINT, l);
		}

	}

	@Override
	public int getChoice(Settings settings) {
		if (settings == null) {
			return DEFAULT;
		}
		Long value = settings.getLong(ADDRESS_RANGE_ENDPOINT);
		if (value == null || value < 0 || value >= CHOICES.length) {
			return DEFAULT;
		}
		return value.intValue();
	}

	@Override
	public void setChoice(Settings settings, int value) {
		if (value < DEFAULT) {
			settings.clearSetting(ADDRESS_RANGE_ENDPOINT);
		}
		else {
			if (value > CHOICES.length) {
				value = CHOICES.length;
			}
			settings.setLong(ADDRESS_RANGE_ENDPOINT, value);
		}

	}

	@Override
	public String getDisplayChoice(int value, Settings settings) {
		return CHOICES[value];
	}

	@Override
	public String[] getDisplayChoices(Settings settings) {
		return CHOICES;
	}

}
