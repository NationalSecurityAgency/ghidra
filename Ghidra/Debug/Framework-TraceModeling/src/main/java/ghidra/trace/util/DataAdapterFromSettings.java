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
package ghidra.trace.util;

import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.listing.Data;

public interface DataAdapterFromSettings extends Data {

	default <T extends SettingsDefinition> T getSettingsDefinition(
			Class<T> settingsDefinitionClass) {
		DataType dt = getBaseDataType();
		for (SettingsDefinition def : dt.getSettingsDefinitions()) {
			if (settingsDefinitionClass.isAssignableFrom(def.getClass())) {
				return settingsDefinitionClass.cast(def);
			}
		}
		return null;
	}

	default boolean hasMutability(int mutabilityType) {
		MutabilitySettingsDefinition def =
			getSettingsDefinition(MutabilitySettingsDefinition.class);
		if (def != null) {
			return def.getChoice(this) == mutabilityType;
		}
		return false;
	}

	@Override
	default boolean isConstant() {
		return hasMutability(MutabilitySettingsDefinition.CONSTANT);
	}

	@Override
	default boolean isVolatile() {
		return hasMutability(MutabilitySettingsDefinition.VOLATILE);
	}
}
