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

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.RollbackException;

/**
 *
 * Command to add a memory block.
 * 
 * 
 */
public class AddMemoryBlockCmd implements Command {

	private String name;
	private String comment;
	private String source;
	private Address start;
	private int length;
	private boolean read;
	private boolean write;
	private boolean execute;
	private boolean isVolatile;
	private byte initialValue;
	private MemoryBlockType blockType;
	private Address baseAddr;
	private Program program;
	private String message;
	private boolean isInitialized;

	/**
	 * 
	 * Construct a new AddMemoryBlockCmd
	 * @param name block name
	 * @param comment block comments
	 * @param source block source
	 * @param start starting address of the block
	 * @param length block length
	 * @param read read permissions
	 * @param write write permissions
	 * @param execute execute permissions
	 * @param isVolatile volatile setting
	 * @param initialValue initial byte value
	 * @param blockType type of block to add: MemoryBlockType.DEFAULT, 
	 * MemoryBlockType.OVERLAY, or MemoryBlockType.BIT_MAPPED or MemoryBlockType.BYTE_MAPPED
	 * @param baseAddr base address for the source address if the block type
	 * is TYPE_BIT_MAPPED or TYPE_BYTE_MAPPED; otherwise, null
	 */
	public AddMemoryBlockCmd(String name, String comment, String source, Address start, int length,
			boolean read, boolean write, boolean execute, boolean isVolatile, byte initialValue,
			MemoryBlockType blockType, Address baseAddr, boolean isInitialized) {
		this.name = name;
		this.comment = comment;
		this.source = source;
		this.start = start;
		this.length = length;
		this.read = read;
		this.write = write;
		this.execute = execute;
		this.isVolatile = isVolatile;
		this.initialValue = initialValue;
		this.blockType = blockType;
		this.baseAddr = baseAddr;
		this.isInitialized = isInitialized;

	}

	/**
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		program = (Program) obj;
		try {
			Memory memory = program.getMemory();
			MemoryBlock block = null;
			if (isInitialized) {
				block = memory.createInitializedBlock(name, start, length, initialValue, null,
					(blockType == MemoryBlockType.OVERLAY));
			}
			else if (blockType == MemoryBlockType.DEFAULT || blockType == MemoryBlockType.OVERLAY) {
				block = memory.createUninitializedBlock(name, start, length,
					(blockType == MemoryBlockType.OVERLAY));
			}
			else if (blockType == MemoryBlockType.BIT_MAPPED) {
				block = memory.createBitMappedBlock(name, start, baseAddr, length);
			}
			else {
				block = memory.createByteMappedBlock(name, start, baseAddr, length);
			}
			block.setComment(comment);
			block.setRead(read);
			block.setWrite(write);
			block.setExecute(execute);
			block.setVolatile(isVolatile);
			block.setSourceName(source);
			renameFragment(block.getStart());
			return true;
		}
		catch (IllegalArgumentException e) {
			message = e.getMessage();
		}
		catch (AddressOverflowException e) {
			message = e.getMessage();
		}
		catch (MemoryConflictException e) {
			message = e.getMessage();
		}
		catch (OutOfMemoryError e) {
			message = "Not enough memory to create block";
		}
		catch (DuplicateNameException e) {
			message = "Duplicate Name: " + e.getMessage();
		}
		catch (IllegalStateException e) {
			message = e.getMessage();
		}
		catch (Throwable t) {
			message = "Create block failed";
			Msg.showError(this, null, "Create Block Failed", t.getMessage(), t);
		}
		throw new RollbackException(message);
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Add Memory Block";
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return message;
	}

	private void renameFragment(Address blockStartAddr) {
		Listing listing = program.getListing();
		String[] treeNames = listing.getTreeNames();
		for (int i = 0; i < treeNames.length; i++) {
			try {
				ProgramFragment frag = listing.getFragment(treeNames[i], blockStartAddr);
				frag.setName(name);
			}
			catch (DuplicateNameException exc) {
			}
		}
	}
}
