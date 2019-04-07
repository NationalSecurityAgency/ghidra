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
package ghidra.app.plugin.core.memory;

import javax.swing.event.ChangeListener;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Base class for a model that expands a memory block.
 */
abstract class ExpandBlockModel implements DomainObjectListener {

	protected PluginTool tool;
	protected Program program;
	protected Address startAddr;
	protected Address endAddr;
	protected Address blockStart;
	protected long length;
	protected MemoryBlock block;
	protected String message;

	protected ChangeListener listener;

	ExpandBlockModel(PluginTool tool, Program program) {
		this.tool = tool;
		this.program = program;
		program.addListener(this);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (!ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			return;
		}

		if (blockStart == null) {
			return; // not yet initialized
		}

		MemoryBlock updatedBlock = program.getMemory().getBlock(blockStart);
		initialize(updatedBlock);
	}

	/**
	 * Initialize this model using the given block.
	 * @param newBlock block that will be expanded
	 */
	void initialize(MemoryBlock newBlock) {
		this.block = newBlock;
		length = newBlock.getSize();
		startAddr = newBlock.getStart();
		endAddr = newBlock.getEnd();
		blockStart = startAddr;
		message = "";
		listener.stateChanged(null);
	}

	void setChangeListener(ChangeListener listener) {
		this.listener = listener;
	}

	String getMessage() {
		return message;
	}

	Address getStartAddress() {
		return startAddr;
	}

	Address getEndAddress() {
		return endAddr;
	}

	long getLength() {
		return length;
	}

	abstract void setStartAddress(Address addr);

	abstract void setEndAddress(Address addr);

	abstract void setLength(long length);

	/**
	 * Expand the block.
	 * @return true if the block was successfully expanded.
	 */
	abstract boolean execute();

	/**
	 * Expand the given block; creates a new block at startAddr of
	 * length, then joins the two blocks.
	 */
	protected boolean expandBlock() {

		ExpandBlockCmd cmd = new ExpandBlockCmd(block);
		if (!tool.execute(cmd, program)) {
			message = cmd.getStatusMsg();
			tool.setStatusInfo(message);
			return false;
		}
		return true;
	}

	/**
	 * Return true if the length greater than the current block size.
	 */
	boolean isValidLength() {

		long blockSize = block.getSize();
		if (length <= blockSize) {
			message = "Block size must be greater than " + Long.toHexString(blockSize);
			return false;
		}
		else if (length < 0 || length > Integer.MAX_VALUE) {
			message = "Expanded block is too large";
			return false;
		}
		return true;
	}

	/**
	 * Clear resources.
	 */
	void dispose() {
		tool = null;
		program.removeListener(this);
		program = null;
	}

	private class ExpandBlockCmd implements Command {
		private String msg;
		private MemoryBlock expandBlock;

		ExpandBlockCmd(MemoryBlock block) {
			this.expandBlock = block;
		}

		@Override
		public boolean applyTo(DomainObject obj) {
			Program prog = (Program) obj;
			Memory memory = prog.getMemory();
			try {
				MemoryBlock newBlock = memory.createBlock(expandBlock,
					expandBlock.getName() + ".exp", startAddr, length);
				MemoryBlock b = memory.join(expandBlock, newBlock);
				if (!b.getName().endsWith(".exp")) {
					b.setName(b.getName() + ".exp");
				}
				return true;
			}
			catch (Exception e) {
				msg = e.getMessage();
				if (msg == null) {
					msg = "Error expanding block: " + e;
				}
			}
			return false;
		}

		@Override
		public String getName() {
			return "Expand Block";
		}

		@Override
		public String getStatusMsg() {
			return msg;
		}
	}
}
