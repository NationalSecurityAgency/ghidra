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
package ghidra.dbg.sctl.protocol.common;

import java.util.*;

import ghidra.comm.packet.Packet;

/**
 * A base type for contexts
 * 
 * This is a dialect-defined format.
 * 
 * The default implementation assumes each register is stored in a field named after that register.
 */
public abstract class AbstractSctlContext extends Packet {
	/**
	 * Convert this context to a register-value map as used in the Debugging API.
	 * 
	 * @return the map
	 */
	public abstract Map<String, byte[]> toMap();

	/**
	 * List the registers represented within this context
	 * 
	 * @return the set of register names
	 */
	public abstract Set<String> getRegisterNames();

	/**
	 * Set the selected registers
	 * 
	 * If the context has already been loaded with data, i.e., parsed from the channel, then this
	 * may re-parse the individual registers.
	 * 
	 * @param regdefs the list of selected register definitions
	 */
	public abstract void setSelectedRegisters(List<SctlRegisterDefinition> regdefs);

	/**
	 * Update the fields from a register-value map as used in the Debugging API.
	 * 
	 * @param values the map
	 */
	public abstract void updateFromMap(Map<String, byte[]> values);

	/**
	 * Update a field by name using bytes in big-endian order
	 * 
	 * @param name the register name
	 * @param value the register value
	 */
	public abstract void update(String name, byte[] value);
}
