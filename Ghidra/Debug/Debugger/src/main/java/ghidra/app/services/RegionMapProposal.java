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
package ghidra.app.services;

import ghidra.app.services.RegionMapProposal.RegionMapEntry;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.model.memory.TraceMemoryRegion;

/**
 * A proposed map of regions to program memory blocks
 */
public interface RegionMapProposal
		extends MapProposal<TraceMemoryRegion, MemoryBlock, RegionMapEntry> {

	interface RegionMapEntry extends MapEntry<TraceMemoryRegion, MemoryBlock> {
		/**
		 * Get the region
		 * 
		 * @return the region
		 */
		TraceMemoryRegion getRegion();

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
}
