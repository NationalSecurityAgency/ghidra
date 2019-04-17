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

public interface DataTypeWithCharset extends DataType {

	/**
	 * Get the character set for a specific data type and settings
	 * @param settings data instance settings
	 * @return Charset for this datatype and settings
	 */
	public default String getCharsetName(Settings settings) {
		return StringDataInstance.DEFAULT_CHARSET_NAME;
	}

}
