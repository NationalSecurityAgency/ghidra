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
package ghidra.app.plugin.core.debug.register;

import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;

public interface DynamicRegisterChangeListener {
	void updateRegisterValue(RegisterValue registerValue);

	void updateRegisterDataType(Register register, DataType dataType);
}
