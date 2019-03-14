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

import ghidra.program.model.listing.ContextChangeException;

import java.math.BigInteger;

/**
 * Defines the interface for an object containing the state
 * of all processor registers relative to a specific address.
 */
public interface ProcessorContext extends ProcessorContextView {

	/**
	 * Sets the value for a Register.
	 * @param register the register to have its value set
	 * @param value the value for the register (null is not permitted).
	 * @throws ContextChangeException an illegal attempt to change context was made
	 */
	public void setValue(Register register, BigInteger value) throws ContextChangeException;

	/**
	 * Sets the specified register value within this context.
	 * @param value register value
	 * @throws ContextChangeException an illegal attempt to change context was made
	 */
	public void setRegisterValue(RegisterValue value) throws ContextChangeException;

	/**
	 * Clears the register within this context.
	 * @param register register to be cleared.
	 * @throws ContextChangeException an illegal attempt to change context was made
	 */
	public void clearRegister(Register register) throws ContextChangeException;

}
