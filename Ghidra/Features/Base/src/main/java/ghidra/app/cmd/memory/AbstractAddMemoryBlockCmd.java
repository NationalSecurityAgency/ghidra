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
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;

/**
 * Base command class for adding memory blocks.
 */
abstract class AbstractAddMemoryBlockCmd implements Command {
	protected String message;
	protected final String name;
	protected final String comment;
	protected final String source;
	protected final Address start;
	protected final long length;

	protected final boolean read;
	protected final boolean write;
	protected final boolean execute;
	protected final boolean isVolatile;
	protected final boolean isOverlay;

	AbstractAddMemoryBlockCmd(String name, String comment, String source, Address start,
			long length, boolean read, boolean write, boolean execute, boolean isVolatile,
			boolean isOverlay) {
		this.name = name;
		this.comment = comment;
		this.source = source;
		this.start = start;
		this.length = length;
		this.read = read;
		this.write = write;
		this.execute = execute;
		this.isVolatile = isVolatile;
		this.isOverlay = isOverlay;
	}

	@Override
	public String getStatusMsg() {
		return message;
	}

	@Override
	public String getName() {
		return "Add Memory Block";
	}

	protected abstract MemoryBlock createMemoryBlock(Memory memory)
			throws LockException, MemoryConflictException, AddressOverflowException,
			CancelledException;

	@Override
	public boolean applyTo(DomainObject obj) {
		Program program = (Program) obj;
		try {
			Memory memory = program.getMemory();
			MemoryBlock block = createMemoryBlock(memory);
			block.setComment(comment);
			block.setRead(read);
			block.setWrite(write);
			block.setExecute(execute);
			block.setVolatile(isVolatile);
			block.setSourceName(source);
			renameFragment(program, block.getStart());
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
		catch (IllegalStateException e) {
			message = e.getMessage();
		}
		catch (Throwable t) {
			message = "Create block failed";
			Msg.showError(this, null, "Create Block Failed", t.getMessage(), t);
		}
		throw new RollbackException(message);
	}

	private void renameFragment(Program program, Address blockStartAddr) {
		Listing listing = program.getListing();
		String[] treeNames = listing.getTreeNames();
		for (String treeName : treeNames) {
			ProgramFragment frag = listing.getFragment(treeName, blockStartAddr);
			renameFragment(frag, name);
		}
	}

	private void renameFragment(ProgramFragment fragment, String fragmentName) {
		String newName = fragmentName;
		int count = 1;
		while (!doRenameFragment(fragment, newName)) {
			newName = fragmentName + "_" + count;
			count++;
		}
	}

	private boolean doRenameFragment(ProgramFragment fragment, String fragmentName) {
		try {
			fragment.setName(fragmentName);
			return true;
		}
		catch (DuplicateNameException e) {
			return false;
		}
	}
}
