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
package ghidra.program.model.data.ISF;

import java.util.ArrayList;
import java.util.List;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ISF.AbstractIsfWriter.Exclude;

public abstract class AbstractIsfObject implements IsfObject {

	@Exclude
	public String name;
	@Exclude
	public String location;
	@Exclude
	public List<IsfSetting> settings;

	public AbstractIsfObject(DataType dt) {
		if (dt != null) {
			name = dt.getName();
			location = dt.getCategoryPath().getPath();
			Settings defaultSettings = dt.getDefaultSettings();
			processSettings(dt, defaultSettings);
		}
	}

	protected void processSettings(DataType dt, Settings defaultSettings) {
		SettingsDefinition[] settingsDefinitions = dt.getSettingsDefinitions();
		for (SettingsDefinition def : settingsDefinitions) {
			if (def.hasValue(defaultSettings)) {
				settings = new ArrayList<>();
				String[] names = defaultSettings.getNames();
				for (String n : names) {
					Object value = defaultSettings.getValue(n);
					if (value != null) {
						IsfSetting setting = new IsfSetting(n, value);
						settings.add(setting);
					}
				}
			}
		}
	}
}
