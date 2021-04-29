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
package ghidra.trace.database.program;

import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.database.memory.DBTraceMemoryRegisterSpace;

public class DBTraceProgramViewRegisterMemory extends AbstractDBTraceProgramViewMemory {
	protected final DBTraceMemoryRegisterSpace space;
	protected final DBTraceProgramViewRegisterMemoryBlock block;

	public DBTraceProgramViewRegisterMemory(DBTraceProgramView program,
			DBTraceMemoryRegisterSpace space) {
		super(program);
		this.space = space;
		this.block = new DBTraceProgramViewRegisterMemoryBlock(program, space);
		this.addressSet =
			new AddressSet(new AddressRangeImpl(space.getAddressSpace().getMinAddress(),
				space.getAddressSpace().getMaxAddress()));
	}

	@Override
	protected void recomputeAddressSet() {
		// AddressSet is always full space
	}

	@Override
	public MemoryBlock getBlock(Address addr) {
		if (addr.getAddressSpace().isRegisterSpace()) {
			return block;
		}
		return null;
	}

	@Override
	public MemoryBlock getBlock(String blockName) {
		if (DBTraceProgramViewRegisterMemoryBlock.REGS_BLOCK_NAME.equals(blockName)) {
			return block;
		}
		return null;
	}

	@Override
	public MemoryBlock[] getBlocks() {
		// NOTE: Don't cache, to avoid external mutation.
		return new MemoryBlock[] { block };
	}
}
