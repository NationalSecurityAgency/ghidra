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
package ghidra.program.model.lang;

import ghidra.program.model.address.Address;

public interface DisassemblerContext extends ProcessorContext {

	/**
	 * Combines <code>value</code> with any previously saved future
	 * register value at <code>address</code> or any value stored in the program if there is no
	 * previously saved future value.  Use this method when multiple flows to the same address
	 * don't matter or the flowing from address is unknown.
	 * <br>
	 * When <code>value</code> has conflicting bits with the previously
	 * saved value, <code>value</code> will take precedence.
	 * <br> 
	 * If the register value is the value for the 
	 * processor context register and a previously saved
	 * value does not exist, the user saved values in the 
	 * stored context of the program will be used as existing
	 * value.
	 * 
	 * @param address  the address to store the register value
	 * @param value    the register value to store at the address
	 */
	public void setFutureRegisterValue(Address address, RegisterValue value);

	/**
	 * Combines <code>value</code> with any previously saved future
	 * register value at <code>fromAddr/toAddr</code> or any value stored in the program if there is no
	 * previously saved future value.
	 * <br>
	 * When <code>value</code> has conflicting bits with the previously
	 * saved value, <code>value</code> will take precedence.
	 * <br> 
	 * If the register value is the value for the 
	 * processor context register and a previously saved
	 * value does not exist, the user saved values in the 
	 * stored context of the program will be used as existing
	 * value.
	 * 
	 * @param fromAddr the address this value if flowing from
	 * @param toAddr   the address to store the register value
	 * @param value    the register value to store at the address
	 */
	public void setFutureRegisterValue(Address fromAddr, Address toAddr, RegisterValue value);
}
