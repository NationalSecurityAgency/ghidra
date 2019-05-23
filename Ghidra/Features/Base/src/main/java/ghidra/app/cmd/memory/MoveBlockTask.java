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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.util.ProgramTask;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;
import ghidra.util.exception.RollbackException;
import ghidra.util.task.TaskMonitor;

/**
 * Command that runs in the background to move a memory block, as the move may
 * be a time consuming operation.
 */
public class MoveBlockTask extends ProgramTask {
	private Address currentStart;
	private Address newStart;
	private MoveBlockListener listener;
	private boolean cancelled;
	private String statusMessage;
	private boolean success;

	/**
	 * Creates a background command for moving memory blocks. The memory block
	 * is moved from its current start address to its new start address. After
	 * the command has completed, getStatus() can be called to check the
	 * success. If unsuccessful, getStatusMsg() can be called to get a message
	 * indicating why the command failed.
	 * 
	 * @param program the program whose memory map is being modified
	 * @param currentStart the start address of the block before the move.
	 * @param newStart the start address of the block after the move.
	 * @param listener listener that will be notified when the move block has
	 *            completed.
	 */
	public MoveBlockTask(Program program, Address currentStart, Address newStart,
			MoveBlockListener listener) {
		super(program, "Move Block", true, false, true);
		this.currentStart = currentStart;
		this.newStart = newStart;
		this.listener = listener;
	}

	@Override
	protected void doRun(TaskMonitor monitor) {

		Memory mem = program.getMemory();
		MemoryBlock block = mem.getBlock(currentStart);
		monitor.setMessage("Moving Memory Block ...");
		statusMessage = "";
		Throwable cause = null;
		try {
			mem.moveBlock(block, newStart, monitor);
			if (monitor.isCancelled()) {
				cancelled = true;
			}
			else {
				success = true;
				listener.moveBlockCompleted(this);
				return;
			}
		}
		catch (OutOfMemoryError e) {
			statusMessage = "Insufficient memory to complete operation";
			cause = e;
		}
		catch (NotFoundException e) {
			statusMessage = "Memory block not found";
			cause = e;
		}
		catch (MemoryConflictException | MemoryBlockException | IllegalArgumentException e) {
			statusMessage = e.getMessage();
			cause = e;
		}
		catch (Throwable t) {
			Msg.error(this, "Unexpected Exception: " + t.getMessage(), t);
			statusMessage = t.getMessage();
			if (statusMessage == null) {
				statusMessage = t.toString();
			}
			cause = t;
		}

		listener.moveBlockCompleted(this);
		throw new RollbackException(statusMessage, cause);
	}

	public boolean isCancelled() {
		return cancelled;
	}

	public boolean wasSuccessful() {
		return success;
	}

	public String getStatusMessage() {
		return statusMessage;
	}
}
