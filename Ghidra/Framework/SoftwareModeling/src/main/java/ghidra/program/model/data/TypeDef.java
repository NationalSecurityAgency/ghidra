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

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;

/**
 * The typedef interface
 */
public interface TypeDef extends DataType {

	/**
	 * Returns the dataType that this typedef is based on. This could be
	 * another typedef
	 */
	public DataType getDataType();

	/**
	 * Returns the non-typedef dataType that this typedef is based on, following
	 * chains of typedefs as necessary.
	 */
	public DataType getBaseDataType();

	/**
	 * Determine if this is a Pointer-TypeDef
	 * @return true if base datatype is a pointer
	 */
	public default boolean isPointer() {
		return (getBaseDataType() instanceof Pointer);
	}

	/**
	 * Compare the settings of two datatypes which correspond to a
	 * {@link TypeDefSettingsDefinition}. 
	 * <p>
	 * NOTE: It is required that both datatypes present their settings
	 * definitions in the same order (see {@link DataType#getSettingsDefinitions})
	 * to be considered the same.
	 * @param dt other typedef to compare with
	 * @return true if both datatypes have the same settings defined 
	 * which correspond to {@link TypeDefSettingsDefinition} and have the 
	 * same values, else false. 
	 */
	public default boolean hasSameTypeDefSettings(TypeDef dt) {
		SettingsDefinition[] defs1 = getSettingsDefinitions();
		SettingsDefinition[] defs2 = dt.getSettingsDefinitions();
		if (defs1.length != defs2.length) {
			return false;
		}

		Settings settings1 = getDefaultSettings();
		Settings settings2 = dt.getDefaultSettings();

		for (int i = 0; i < defs1.length; i++) {
			SettingsDefinition def = defs1[i];
			if (!defs2[i].getClass().equals(def.getClass())) {
				return false;
			}
			if (def instanceof TypeDefSettingsDefinition) {
				if (!def.hasSameValue(settings1, settings2)) {
					return false;
				}
			}
		}
		return true;
	}
}
