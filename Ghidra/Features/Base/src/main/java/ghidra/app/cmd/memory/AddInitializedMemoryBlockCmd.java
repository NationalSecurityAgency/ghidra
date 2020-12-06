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
package ghidra.app.cmd.memory;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.*;
import ghidra.util.exception.CancelledException;

/**
 * Command for adding a new memory block initialized with a specific byte.
 */
public class AddInitializedMemoryBlockCmd extends AbstractAddMemoryBlockCmd {

	private final byte initialValue;

	/**
	 * Create a new AddFileBytesMemoryBlockCmd
	 * @param name the name for the new memory block.
	 * @param comment the comment for the block
	 * @param source indicates what is creating the block
	 * @param start the start address for the the block
	 * @param length the length of the new block
	 * @param read sets the block's read permission flag
	 * @param write sets the block's write permission flag
	 * @param execute sets the block's execute permission flag
	 * @param isVolatile sets the block's volatile flag
	 * @param initialValue the bytes value to use throught the new block.
	 * @param isOverlay if true, the block will be created in a new overlay address space.
	 */
	public AddInitializedMemoryBlockCmd(String name, String comment, String source, Address start,
			long length, boolean read, boolean write, boolean execute, boolean isVolatile,
			byte initialValue, boolean isOverlay) {
		super(name, comment, source, start, length, read, write, execute, isVolatile, isOverlay);

		this.initialValue = initialValue;
	}

	@Override
	protected MemoryBlock createMemoryBlock(Memory memory)
			throws LockException, MemoryConflictException, AddressOverflowException,
			CancelledException {
		return memory.createInitializedBlock(name, start, length, initialValue, null, isOverlay);
	}

}
