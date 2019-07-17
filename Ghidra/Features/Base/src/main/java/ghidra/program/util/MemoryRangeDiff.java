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
package ghidra.program.util;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.mem.Memory;

/**
 * <CODE>MemoryBlockDiff</CODE> determines the types of differences between two memory blocks.
 */
public class MemoryRangeDiff extends MemoryBlockDiff {
	
	Memory memory1;
	Memory memory2;
	AddressRange range;
	
	/**
	 * Constructor. <CODE>MemoryRangeDiff</CODE> determines the types of differences 
	 * between two memory blocks.
	 * @param memory1 the first program's memory
	 * @param memory2 the second program's memory
	 * @param range the address range where the two programs differ
	 */
	public MemoryRangeDiff(Memory memory1, Memory memory2, AddressRange range) {
		super(memory1.getBlock(range.getMinAddress()), memory2.getBlock(range.getMinAddress()));
		this.memory1 = memory1;
		this.memory2 = memory2;
		this.range = range;
	}

	Memory getMemory1() {
		return memory1;
	}
	
	Memory getMemory2() {
		return memory2;
	}
	
	AddressRange getAddressRange() {
		return range;
	}
}
