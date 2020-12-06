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
import ghidra.program.database.mem.ByteMappingScheme;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.*;

/**
 * Command for adding byte-mapped memory blocks
 */
public class AddByteMappedMemoryBlockCmd extends AbstractAddMemoryBlockCmd {

	private final Address mappedAddress;
	private final ByteMappingScheme byteMappingScheme;

	/**
	 * Create a new AddByteMappedMemoryBlockCmd with a specified byte mapping scheme.
	 * Byte mapping scheme is specified by two values schemeDestByteCount and schemeSrcByteCount which
	 * may be viewed as a ratio of number of destination bytes to number of mapped source bytes. 
	 * When the destination consumes bytes from the mapped source it consume schemeDestByteCount bytes then 
	 * skips (schemeSrcByteCount - schemeDestByteCount) bytes before repeating the mapping sequence over 
	 * the extent of the destination block.  The block start address and source mappedAddress must
	 * be chosen carefully as they relate to the mapping scheme when it is anything other than 1:1.
	 * @param name the name for the new memory block.
	 * @param comment the comment for the block
	 * @param source indicates what is creating the block
	 * @param start the start address for the the block
	 * @param length the length of the new block
	 * @param read sets the block's read permission flag
	 * @param write sets the block's write permission flag
	 * @param execute sets the block's execute permission flag
	 * @param isVolatile sets the block's volatile flag
	 * @param mappedAddress the address in memory that will serve as the bytes source for the block
	 * @param byteMappingScheme byte mapping scheme (may be null for 1:1 mapping)
	 * @param isOverlay if true, the block will be created in a new overlay address space.
	 */
	public AddByteMappedMemoryBlockCmd(String name, String comment, String source, Address start,
			long length, boolean read, boolean write, boolean execute, boolean isVolatile,
			Address mappedAddress, ByteMappingScheme byteMappingScheme, boolean isOverlay) {
		super(name, comment, source, start, length, read, write, execute, isVolatile, isOverlay);
		this.mappedAddress = mappedAddress;
		this.byteMappingScheme = byteMappingScheme;
	}

	/**
	 * Create a new AddByteMappedMemoryBlockCmd with 1:1 byte mapping scheme
	 * @param name the name for the new memory block.
	 * @param comment the comment for the block
	 * @param source indicates what is creating the block
	 * @param start the start address for the the block
	 * @param length the length of the new block
	 * @param read sets the block's read permission flag
	 * @param write sets the block's write permission flag
	 * @param execute sets the block's execute permission flag
	 * @param isVolatile sets the block's volatile flag
	 * @param mappedAddress the address in memory that will serve as the bytes source for the block
	 * @param isOverlay if true, the block will be created in a new overlay address space.
	 */
	public AddByteMappedMemoryBlockCmd(String name, String comment, String source, Address start,
			long length, boolean read, boolean write, boolean execute, boolean isVolatile,
			Address mappedAddress, boolean isOverlay) {
		this(name, comment, source, start, length, read, write, execute, isVolatile, mappedAddress,
			null, isOverlay);
	}

	@Override
	protected MemoryBlock createMemoryBlock(Memory memory)
			throws LockException, MemoryConflictException, AddressOverflowException,
			IllegalArgumentException {
		return memory.createByteMappedBlock(name, start, mappedAddress, length,
			byteMappingScheme,
			isOverlay);
	}

}
