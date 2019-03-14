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
	private boolean wasCancelled;
	private boolean status;

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
		// TODO Auto-generated method stub

		Memory mem = program.getMemory();
		MemoryBlock block = mem.getBlock(currentStart);
		monitor.setMessage("Moving Memory Block ...");
		String msg = "";
		Throwable cause = null;
		try {
			mem.moveBlock(block, newStart, monitor);
			if (monitor.isCancelled()) {
				wasCancelled = true;
			}
			else {
				status = true;
				listener.moveBlockCompleted(this);
				return;
			}
		}
		catch (OutOfMemoryError e) {
			monitor.setMessage(msg = "Insufficient memory to complete operation");
			cause = e;
		}
		catch (NotFoundException exc) {
			monitor.setMessage(msg = "Memory block not found");
			cause = exc;
		}
		catch (MemoryConflictException exc) {
			monitor.setMessage(msg = exc.getMessage());
			cause = exc;
		}
		catch (MemoryBlockException exc) {
			monitor.setMessage(msg = exc.getMessage());
			cause = exc;
		}
		catch (IllegalArgumentException e) {
			monitor.setMessage(msg = e.getMessage());
			cause = e;
		}
		catch (Throwable t) {
			Msg.error(this, "Unexpected Exception: " + t.getMessage(), t);
			msg = t.getMessage();
			if (msg == null) {
				msg = t.toString();
			}
			monitor.setMessage(msg);
			cause = t;
		}
		listener.moveBlockCompleted(this);
		throw new RollbackException(msg, cause);
	}

	/**
	 * Return true if the user cancelled the move command.
	 */
	public boolean isCancelled() {
		return wasCancelled;
	}

	/**
	 * Return whether the block was successfully moved.
	 * 
	 * @return true if the block was moved
	 */
	public boolean getStatus() {
		return status;
	}
}
