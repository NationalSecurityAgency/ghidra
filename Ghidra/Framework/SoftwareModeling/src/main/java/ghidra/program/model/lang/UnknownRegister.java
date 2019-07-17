/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.lang;

import ghidra.program.model.address.Address;

/**
 * <code>UnknownRegister</code> is used when a register is requested in the register space
 * for an undefined location.
 */
public class UnknownRegister extends Register {

	public UnknownRegister(String name, String description, Address address, int numBytes,
			boolean bigEndian, int typeFlags) {
		super(name, description, address, numBytes, bigEndian, typeFlags);
		// TODO Auto-generated constructor stub
	}

}
