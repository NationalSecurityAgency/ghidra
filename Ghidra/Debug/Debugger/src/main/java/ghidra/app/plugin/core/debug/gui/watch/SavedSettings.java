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
package ghidra.app.plugin.core.debug.gui.watch;

import ghidra.docking.settings.*;
import ghidra.framework.options.SaveState;
import ghidra.program.model.data.TypeDefSettingsDefinition;

public class SavedSettings {
	private final Settings settings;
	private SaveState state;

	public SavedSettings(Settings settings) {
		this.settings = settings;
		setState(state);
	}

	public void setState(SaveState state) {
		if (state == null) {
			state = new SaveState("Settings");
		}
		this.state = state;
	}

	public SaveState getState() {
		return state;
	}

	public void write(SettingsDefinition[] definitions, Settings defaultSettings) {
		for (SettingsDefinition sd : definitions) {
			if (sd.hasSameValue(settings, defaultSettings)) {
				continue;
			}
			if (sd instanceof BooleanSettingsDefinition bsd) {
				state.putBoolean(sd.getStorageKey(), bsd.getValue(settings));
			}
			else if (sd instanceof EnumSettingsDefinition esd) {
				state.putInt(sd.getStorageKey(), esd.getChoice(settings));
			}
			else if (sd instanceof NumberSettingsDefinition nsd) {
				state.putLong(sd.getStorageKey(), nsd.getValue(settings));
			}
			else if (sd instanceof StringSettingsDefinition ssd) {
				state.putString(sd.getStorageKey(), ssd.getValue(settings));
			}
			else if (sd instanceof TypeDefSettingsDefinition tdsd) {
				// Toss this on the floor
			}
			else {
				throw new AssertionError();
			}
		}
	}

	public void read(SettingsDefinition[] definitions, Settings defaultSettings) {
		for (SettingsDefinition sd : definitions) {
			if (!state.hasValue(sd.getStorageKey())) {
				continue;
			}
			if (sd instanceof BooleanSettingsDefinition bsd) {
				bsd.setValue(settings, state.getBoolean(sd.getStorageKey(), false));
			}
			else if (sd instanceof EnumSettingsDefinition esd) {
				esd.setChoice(settings, state.getInt(sd.getStorageKey(), 0));
			}
			else if (sd instanceof NumberSettingsDefinition nsd) {
				nsd.setValue(settings, state.getLong(sd.getStorageKey(), 0));
			}
			else if (sd instanceof StringSettingsDefinition ssd) {
				ssd.setValue(settings, state.getString(sd.getStorageKey(), null));
			}
			else if (sd instanceof TypeDefSettingsDefinition tdsd) {
				// Toss this on the floor
			}
			else {
				throw new AssertionError();
			}
		}
	}
}
