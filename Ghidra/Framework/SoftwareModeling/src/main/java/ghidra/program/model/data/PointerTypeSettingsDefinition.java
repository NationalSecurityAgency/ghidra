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

import java.util.NoSuchElementException;

import ghidra.docking.settings.EnumSettingsDefinition;
import ghidra.docking.settings.Settings;

/**
 * The settings definition for the numeric display format
 */
public class PointerTypeSettingsDefinition
		implements EnumSettingsDefinition, TypeDefSettingsDefinition {

	private static final String POINTER_TYPE_SETTINGS_NAME = "ptr_type";
	private static final String DESCRIPTION =
		"Specifies the pointer type which affects interpretation of offset";
	private static final String DISPLAY_NAME = "Pointer Type";

	// Choices correspond to the enumerated PointerType values
	private static final String[] choices =
		{ "default", "image-base-relative", "relative", "file-offset" };

	public static final PointerTypeSettingsDefinition DEF = new PointerTypeSettingsDefinition(); // Format with HEX default

	private PointerTypeSettingsDefinition() {
	}

	/**
	 * Returns the format based on the specified settings
	 * @param settings the instance settings or null for default value.
	 * @return the {@link PointerType}.  {@link PointerType#DEFAULT} will be returned
	 * if no setting has been made.
	 */
	public PointerType getType(Settings settings) {
		if (settings == null) {
			return PointerType.DEFAULT;
		}
		Long value = settings.getLong(POINTER_TYPE_SETTINGS_NAME);
		if (value == null) {
			return PointerType.DEFAULT;
		}
		int type = (int) value.longValue();
		try {
			return PointerType.valueOf(type);
		}
		catch (NoSuchElementException e) {
			return PointerType.DEFAULT;
		}
	}

	@Override
	public int getChoice(Settings settings) {
		return getType(settings).value;
	}

	@Override
	public String getValueString(Settings settings) {
		return choices[getChoice(settings)];
	}

	@Override
	public void setChoice(Settings settings, int value) {
		try {
			setType(settings, PointerType.valueOf(value));
		}
		catch (NoSuchElementException e) {
			settings.clearSetting(POINTER_TYPE_SETTINGS_NAME);
		}
	}

	public void setType(Settings settings, PointerType type) {
		if (type == PointerType.DEFAULT) {
			settings.clearSetting(POINTER_TYPE_SETTINGS_NAME);
		}
		else {
			settings.setLong(POINTER_TYPE_SETTINGS_NAME, type.value);
		}
	}

	@Override
	public String[] getDisplayChoices(Settings settings) {
		return choices;
	}

	@Override
	public String getName() {
		return DISPLAY_NAME;
	}

	@Override
	public String getStorageKey() {
		return POINTER_TYPE_SETTINGS_NAME;
	}

	@Override
	public String getDescription() {
		return DESCRIPTION;
	}

	@Override
	public String getDisplayChoice(int value, Settings s1) {
		return choices[value];
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(POINTER_TYPE_SETTINGS_NAME);
	}

	@Override
	public void copySetting(Settings settings, Settings destSettings) {
		Long l = settings.getLong(POINTER_TYPE_SETTINGS_NAME);
		if (l == null) {
			destSettings.clearSetting(POINTER_TYPE_SETTINGS_NAME);
		}
		else {
			destSettings.setLong(POINTER_TYPE_SETTINGS_NAME, l);
		}
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(POINTER_TYPE_SETTINGS_NAME) != null;
	}

	public String getDisplayChoice(Settings settings) {
		return choices[getChoice(settings)];
	}

	/**
	 * Sets the settings object to the enum value indicating the specified choice as a string.
	 * @param settings the settings to store the value.
	 * @param choice enum string representing a choice in the enum.
	 */
	public void setDisplayChoice(Settings settings, String choice) {
		for (int i = 0; i < choices.length; i++) {
			if (choices[i].equals(choice)) {
				setChoice(settings, i);
				break;
			}
		}
	}

	@Override
	public String getAttributeSpecification(Settings settings) {
		int choice = getChoice(settings);
		if (choice != 0) {
			return choices[choice];
		}
		return null;
	}

}
