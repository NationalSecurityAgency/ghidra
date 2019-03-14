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
package ghidra.app.plugin.exceptionhandlers.gcc.sections;

import ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.Cie;
import ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.ExceptionHandlerFrameException;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;

/** 
 * Provides GCC exception handling model classes the means to obtain a Common Information Entry
 * (CIE) object for a given address.
 */
public interface CieSource {

	/**
	 * For the provided address, return a Common Information Entry (CIE)
	 * @param currAddress the address with the CIE
	 * @return the Cie at <code>currAddress</code>
	 * @throws MemoryAccessException if memory for the CIE couldn't be read
	 * @throws ExceptionHandlerFrameException if a problem was encountered
	 */
	public Cie getCie(Address currAddress)
			throws MemoryAccessException, ExceptionHandlerFrameException;
}
