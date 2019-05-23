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

import ghidra.app.cmd.memory.MoveBlockListener;
import ghidra.app.cmd.memory.MoveBlockTask;
import ghidra.framework.model.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Model for moving a memory block; this class does validation of the new start
 * and end address for the block, and starts the task to do the move.
 * 
 * 
 */
class MoveBlockModel implements DomainObjectListener {

	private Program program;
	private MemoryBlock block;
	private Address blockStart;
	private Address newStartAddr;
	private Address newEndAddr;
	private MoveBlockListener listener;
	private String message;

//    private static final String PROGRESS_DIALOG_TITLE = "Moving Memory";
//    private static final String INIT_PROGRESS_MSG = "Moving Memory...";

	/**
	 * Constructor
	 * 
	 */
	MoveBlockModel(Program program) {
		this.program = program;
		message = "";
		program.addListener(this);
	}

	/**
	 * @see ghidra.framework.model.DomainObjectListener#domainObjectChanged(ghidra.framework.model.DomainObjectChangedEvent)
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			block = program.getMemory().getBlock(blockStart);
		}
	}

	/**
	 * Set up this model.
	 * 
	 * @param blockToInitialize block to move
	 */
	void initialize(MemoryBlock blockToInitialize) {
		this.block = blockToInitialize;
		newStartAddr = blockToInitialize.getStart();
		blockStart = newStartAddr;
		newEndAddr = blockToInitialize.getEnd();
		listener.stateChanged();
	}

	/**
	 * Set the listener that will be notified when changes are made and when the
	 * block move is completed.
	 */
	void setMoveBlockListener(MoveBlockListener listener) {
		this.listener = listener;
	}

	/**
	 * Get the name of the block.
	 */
	String getName() {
		return block.getName();
	}

	/**
	 * Get the start address of the block.
	 */
	Address getStartAddress() {
		return block.getStart();
	}

	/**
	 * Get the end address of the block.
	 */
	Address getEndAddress() {
		return block.getEnd();
	}

	/**
	 * Get the formatted string for the block length; shown in decimal and hex in
	 * parens.
	 */
	String getLengthString() {
		long length = block.getSize();
		return length + "  (0x" + Long.toHexString(length) + ")";
	}

	/**
	 * Get the new start address for the block.
	 */
	Address getNewStartAddress() {
		return newStartAddr;
	}

	/**
	 * Get the new end address for the block.
	 */
	Address getNewEndAddress() {
		return newEndAddr;
	}

	/**
	 * Get the current message.
	 * 
	 * @return empty string if there are no errors to report
	 */
	String getMessage() {
		return message;
	}

	/**
	 * Set the new start address for the block.
	 */
	void setNewStartAddress(Address newStart) {

		message = "";
		newStartAddr = newStart;

		newEndAddr = getEndAddress(newStart);
		if (newStart.equals(block.getStart())) {
			message = "Block is already at " + newStart;
		}
		else if (newEndAddr == null) {
			message = "Start Address is too big";
		}
		listener.stateChanged();
	}

	/**
	 * Set the new end address for the block.
	 */
	void setNewEndAddress(Address newEnd) {
		message = "";
		newEndAddr = newEnd;
		newStartAddr = getStartAddress(newEnd);
		if (newStartAddr == null) {
			message = "End Address is too small";
		}
		listener.stateChanged();
	}

	/**
	 * Create the task that will move the block
	 * 
	 * @return the new task
	 */
	MoveBlockTask makeTask() {
		return new MoveBlockTask(program, block.getStart(), newStartAddr, listener);
	}

	/**
	 * Clear resources.
	 */
	void dispose() {
		program.removeListener(this);
		program = null;
	}

	AddressFactory getAddressFactory() {
		return program.getAddressFactory();
	}

	private Address getEndAddress(Address start) {
		try {
			return start.addNoWrap(block.getSize() - 1);
		}
		catch (AddressOverflowException e) {
		}
		return null;
	}

	private Address getStartAddress(Address end) {
		try {
			return end.subtractNoWrap(block.getSize() - 1);
		}
		catch (AddressOverflowException e) {
		}
		return null;
	}
}
