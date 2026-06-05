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
package ghidra.features.base.replace.items;

import ghidra.features.base.quickfix.QuickFixStatus;
import ghidra.features.base.replace.RenameQuickFix;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.MemoryBlockStartFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
 * QuickFix for renaming memory blocks.
 */
public class RenameMemoryBlockQuickFix extends RenameQuickFix {

	private MemoryBlock block;

	/**
	 * Constructor
	 * @param program the program containing the memory block to be renamed
	 * @param block the memory block to be renamed
	 * @param newName the new name for the memory block
	 */
	public RenameMemoryBlockQuickFix(Program program, MemoryBlock block, String newName) {
		super(program, block.getName(), newName);
		this.block = block;
	}

	@Override
	public String getItemType() {
		return "Memory Block";
	}

	@Override
	public String doGetCurrent() {
		return block.getName();
	}

	@Override
	public void execute() {
		try {
			block.setName(replacement);
		}
		catch (Exception e) {
			setStatus(QuickFixStatus.ERROR, "Rename Failed! " + e);
		}
	}

	@Override
	public Address getAddress() {
		return block.getStart();
	}

	@Override
	public String getPath() {
		return null;
	}

	@Override
	public ProgramLocation getProgramLocation() {
		return new MemoryBlockStartFieldLocation(program, getAddress(), null, 0, 0, null, 0);
	}

}
