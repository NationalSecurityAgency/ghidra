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

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Command that runs in the background to delete a memory block, as 
 * the delete may be a time consuming operation.
 */
public class DeleteBlockCmd extends BackgroundCommand {
	private Address[] blockAddresses;
	private DeleteBlockListener listener;
	private boolean status;

	/**
	 * Creates a background command for deleting memory blocks. Each address in
	 * the array of block addresses indicates that the block containing that
	 * address should be removed.
	 * After the command has completed, getStatus() can be called to check the success.
	 * If unsuccessful, getStatusMsg() can be called to get a message 
	 * indicating why the command failed.
	 * @param blockAddresses addresses indicating each block to be removed.
	 * @param listener listener that will be notified when the delete block has completed.
	 */
	public DeleteBlockCmd(Address[] blockAddresses, DeleteBlockListener listener) {
		super("Delete Memory Block", false, true, true);
		this.blockAddresses = blockAddresses;
		this.listener = listener;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		Program program = (Program) obj;
		Memory mem = program.getMemory();

		if (!program.hasExclusiveAccess()) {
			setStatusMsg("Exclusive access required");
			return false;
		}

		monitor.initialize(blockAddresses.length);
		for (Address blockAddresse : blockAddresses) {
			if (monitor.isCancelled()) {
				break;
			}

			MemoryBlock block = mem.getBlock(blockAddresse);
			monitor.setMessage("Deleting block '" + block.getName() + "'...");

			try {
				mem.removeBlock(block, monitor);
			}
			catch (LockException e) {
				Msg.debug(this,
					"Unable to delete block--do not have lock: '" + block.getName() + "'", e);
			}
			monitor.initialize(block.getSize());
		}
		status = true;
		return status;
	}

	/**
	 * Return whether the delete block was successful.
	 * @return true if the block was deleted
	 */
	public boolean getStatus() {
		return status;
	}

	/**
	 * @see ghidra.framework.cmd.BackgroundCommand#taskCompleted()
	 */
	@Override
	public void taskCompleted() {
		listener.deleteBlockCompleted(this);
	}

}
