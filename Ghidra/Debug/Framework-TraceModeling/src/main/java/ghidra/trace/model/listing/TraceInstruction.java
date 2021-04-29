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
package ghidra.trace.model.listing;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public interface TraceInstruction extends TraceCodeUnit, Instruction {
	/**
	 * {@inheritDoc}
	 * 
	 * If the instruction is of a guest language, the returned address is mapped into the trace's
	 * base address space
	 */
	@Override
	Address getDefaultFallThrough();

	/**
	 * Get the default fall-through as viewed in the instruction's native address space
	 * 
	 * @return the default fall-through
	 */
	Address getGuestDefaultFallThrough();

	/**
	 * {@inheritDoc}
	 * 
	 * If the instruction is of a guest language, the returned addresses are mapped into the trace's
	 * base address space
	 */
	@Override
	Address[] getDefaultFlows();

	/**
	 * Get the default flows as viewed in the instruction's native address space
	 * 
	 * @return the default flows
	 */
	Address[] getGuestDefaultFlows();

	/**
	 * {@inheritDoc}
	 * 
	 * Note that it is possible instructions are staggered vertically, in which case, multiple
	 * instructions may immediately follow this in terms of the address. The rule to resolve this
	 * ambiguity is that we only consider instructions containing the starting snap of this
	 * instruction.
	 */
	@Override
	TraceInstruction getNext();

	/**
	 * {@inheritDoc}
	 * 
	 * Note that it is possible instructions are staggered vertically, in which case, multiple
	 * instruction may immediately precede this in terms of the address. The rule to resolve this
	 * ambiguity is that we only consider instructions containing the start snap of this
	 * instruction.
	 */
	@Override
	TraceInstruction getPrevious();
}
