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
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * <code>InstructionContext</code> is utilized by a shared instruction prototype to
 * access all relevant instruction data and context-register storage needed during 
 * instruction parse and semantic pcode generation. 
 */
public interface InstructionContext {

	/**
	 * Get the instruction address that this context corresponds to.
	 * @return instruction address
	 */
	public Address getAddress();

	/**
	 * Get the read-only processor context containing the context-register state
	 * state at the corresponding instruction.  This is primarily used during the 
	 * parse phase to provide the initial context-register state.
	 * @return the read-only processor context
	 */
	public ProcessorContextView getProcessorContext();

	/**
	 * Get the read-only memory buffer containing the instruction bytes.  Its position will
	 * correspond to the instruction address.
	 * @return instruction memory buffer
	 */
	public MemBuffer getMemBuffer();

	/**
	 * Get the instruction parser context for the instruction which corresponds to this 
	 * context object.
	 * @return the instruction parser context for the instruction which corresponds to this 
	 * context object.
	 * @throws MemoryAccessException if memory error occurred while resolving instruction
	 * details. 
	 */
	public ParserContext getParserContext() throws MemoryAccessException;

	/**
	 * Get the instruction parser context which corresponds to the specified instruction
	 * address.  This may be obtained via either caching or by parsing the instruction
	 * at the specified address.  The returned ParserContext may be cast to the prototype's
	 * implementation without checking.  This method will throw an UnknownContextException
	 * if a compatible ParserContext is not found at the specified address. 
	 * @return the instruction parser context at the specified instruction address
	 * @throws UnknownContextException if the instruction at the specified address
	 * was not previously parsed or attempting to instantiate context resulted in an
	 * exception. 
	 * @throws MemoryAccessException if memory error occurred while resolving instruction
	 * details.
	 */
	public ParserContext getParserContext(Address instructionAddress)
			throws UnknownContextException, MemoryAccessException;

}
