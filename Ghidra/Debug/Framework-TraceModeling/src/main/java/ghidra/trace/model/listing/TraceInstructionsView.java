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

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.model.guest.TraceGuestPlatform;

public interface TraceInstructionsView extends TraceBaseDefinedUnitsView<TraceInstruction> {
	/**
	 * Create an instruction
	 * 
	 * @param lifespan the lifespan for the instruction unit
	 * @param address the starting address of the instruction
	 * @param platform the optional guest platform, null for the host
	 * @param prototype the instruction prototype
	 * @param context the input disassembly context for the instruction
	 * @return the new instruction
	 * @throws CodeUnitInsertionException if the instruction cannot be created
	 */
	TraceInstruction create(Range<Long> lifespan, Address address, TraceGuestPlatform platform,
			InstructionPrototype prototype, ProcessorContextView context)
			throws CodeUnitInsertionException;

	/**
	 * Create several instructions
	 * 
	 * <p>
	 * <b>NOTE:</b> This does not throw {@link CodeUnitInsertionException}. Conflicts are instead
	 * recorded in the {@code instructionSet}.
	 * 
	 * @param lifespan the lifespan for all instruction units
	 * @param platform the optional guest platform, null for the host
	 * @param instructionSet the set of instructions to add
	 * @param overwrite true to replace conflicting instructions
	 * @return the (host) address set of instructions actually added
	 */
	AddressSetView addInstructionSet(Range<Long> lifespan, TraceGuestPlatform platform,
			InstructionSet instructionSet, boolean overwrite);
}
