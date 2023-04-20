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

import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.StringSettingsDefinition;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.ProgramArchitecture;

public class AddressSpaceSettingsDefinition
		implements StringSettingsDefinition, TypeDefSettingsDefinition {

	private static final String ADDRESS_SPACE_SETTING_NAME = "addr_space_name";
	private static final String DESCRIPTION =
		"Identifies the referenced address space name (case-sensitive; ignored if no match)";
	private static final String DISPLAY_NAME = "Address Space";

	private static final String DEFAULT = null;

	public static final AddressSpaceSettingsDefinition DEF = new AddressSpaceSettingsDefinition();

	private AddressSpaceSettingsDefinition() {
	}

	@Override
	public String getValue(Settings settings) {
		if (settings == null) {
			return DEFAULT;
		}
		String value = settings.getString(ADDRESS_SPACE_SETTING_NAME);
		if (value == null) {
			return DEFAULT;
		}
		return value;
	}

	@Override
	public void setValue(Settings settings, String value) {
		if (StringUtils.isBlank(value)) {
			settings.clearSetting(ADDRESS_SPACE_SETTING_NAME);
		}
		else {
			settings.setString(ADDRESS_SPACE_SETTING_NAME, value);
		}
	}

	@Override
	public boolean hasValue(Settings settings) {
		return getValue(settings) != DEFAULT;
	}

	@Override
	public String getName() {
		return DISPLAY_NAME;
	}

	@Override
	public String getStorageKey() {
		return ADDRESS_SPACE_SETTING_NAME;
	}

	@Override
	public String getDescription() {
		return DESCRIPTION;
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(ADDRESS_SPACE_SETTING_NAME);
	}

	@Override
	public void copySetting(Settings srcSettings, Settings destSettings) {
		String value = srcSettings.getString(ADDRESS_SPACE_SETTING_NAME);
		if (value == null) {
			destSettings.clearSetting(ADDRESS_SPACE_SETTING_NAME);
		}
		else {
			destSettings.setString(ADDRESS_SPACE_SETTING_NAME, value);
		}
	}

	@Override
	public String getAttributeSpecification(Settings settings) {
		String spaceName = getValue(settings);
		if (!StringUtils.isBlank(spaceName)) {
			return "space(" + spaceName + ")";
		}
		return null;
	}

	@Override
	public String[] getSuggestedValues(Settings settings) {
		return settings.getSuggestedValues(this);
	}

	@Override
	public boolean supportsSuggestedValues() {
		return true;
	}

	@Override
	public boolean addPreferredValues(Object settingsOwner, Set<String> set) {
		if (settingsOwner instanceof DataTypeManager) {
			DataTypeManager dtm = (DataTypeManager) settingsOwner;
			ProgramArchitecture arch = dtm.getProgramArchitecture();
			if (arch != null) {
				for (AddressSpace space : arch.getAddressFactory().getAllAddressSpaces()) {
					if (space.isLoadedMemorySpace()) {
						set.add(space.getName());
					}
				}
			}
			return true;
		}
		return false;
	}

}
