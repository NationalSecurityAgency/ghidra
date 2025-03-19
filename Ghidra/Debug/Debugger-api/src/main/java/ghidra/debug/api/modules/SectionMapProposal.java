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
package ghidra.debug.api.modules;

import ghidra.debug.api.modules.SectionMapProposal.SectionMapEntry;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;

/**
 * A proposed map of sections to program memory blocks
 */
public interface SectionMapProposal
		extends MapProposal<TraceSection, MemoryBlock, SectionMapEntry> {

	interface SectionMapEntry extends MapEntry<TraceSection, MemoryBlock> {

		/**
		 * Get the section
		 * 
		 * @return the section
		 */
		TraceSection getSection();

		/**
		 * Get the section name (may depend on the snap)
		 * 
		 * @return the name
		 */
		String getSectionName();

		/**
		 * Get the start address of the section (may depend on the snap)
		 * 
		 * @return the start address
		 */
		Address getSectionStart();

		/**
		 * Get the module containing the section
		 * 
		 * @return the module
		 */
		TraceModule getModule();

		/**
		 * Get the name of the module containing the section (may depend on snap)
		 * 
		 * @return the name
		 */
		String getModuleName();

		/**
		 * Get the matched memory block
		 * 
		 * @return the block
		 */
		MemoryBlock getBlock();

		/**
		 * Set the matched memory block
		 * 
		 * @param program the program containing the block
		 * @param block the block
		 */
		void setBlock(Program program, MemoryBlock block);
	}

	/**
	 * Get the trace module of this proposal
	 * 
	 * @return the module
	 */
	TraceModule getModule();

	/**
	 * Get the corresponding program image of this proposal
	 * 
	 * @return the program
	 */
	@Override
	Program getProgram();
}
