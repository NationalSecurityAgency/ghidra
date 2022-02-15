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
 * <code>TypeDefSettingsDefinition</code> specifies a {@link SettingsDefinition} whose
 * use as a {@link TypeDef} setting will be available for use within a non-Program 
 * DataType archive.  Such settings will be considered for DataType equivalence checks and
 * preserved during DataType cloning and resolve processing.  As such, these settings
 * are only currently supported as a default-setting on a {@link TypeDef}
 * (see {@link DataType#getDefaultSettings()}) and do not support component-specific 
 * or data-instance use.
 * 
 * NOTE: Full support for this type of setting has only been fully implemented for TypeDef
 * in support. There may be quite a few obstacles to overcome when introducing such 
 * settings to a different datatype.
 */
public interface TypeDefSettingsDefinition extends SettingsDefinition {

	/**
	 * Get the {@link TypeDef} attribute specification for this setting and its
	 * current value.
	 * @param settings typedef settings
	 * @return attribute specification or null if not currently set.
	 */
	String getAttributeSpecification(Settings settings);

}
