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
package ghidra.program.model.listing;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;

public interface DefaultProgramContext {

	/**
	 * Associates a default value with the given register over the given range.
	 * @param registerValue the register for which to associate a default value.
	 * @param start the start address.
	 * @param end the end address (inclusive)
	 */
	public void setDefaultValue(RegisterValue registerValue, Address start, Address end);

	/**
	 * Returns the default value of a register at a given address.
	 * @param register the register for which to get a default value.
	 * @param address the address at which to get a default value.
	 * @return the default value of the register at the given address or null if no default value
	 * has been assigned.
	 */
	public RegisterValue getDefaultValue(Register register, Address address);

}
