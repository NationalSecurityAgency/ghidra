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
package agent.gdb.manager.impl.cmd;

import java.util.Collection;

import agent.gdb.manager.*;
import agent.gdb.manager.reason.GdbReason;

/**
 * A record of a state change in GDB
 */
public class GdbStateChangeRecord {
	private GdbInferior inferior;
	private GdbThread eventThread;
	private Collection<GdbThread> affectedThreads;
	private GdbState state;
	private GdbCause cause;
	private GdbReason reason;

	/**
	 * Construct a new record
	 * 
	 * @param inferior the inferior affected by this changed
	 * @param affectedThreads the threads affected by this change (includes only those from this
	 *            inferior)
	 * @param state the new state of the inferior and threads
	 * @param eventThread the thread causing the change (may not be from this inferior)
	 * @param cause the user-driven cause of this change, e.g., a command
	 * @param reason the target-driven reason for this change, e.g., an event
	 */
	public GdbStateChangeRecord(GdbInferior inferior, Collection<GdbThread> affectedThreads,
			GdbState state, GdbThread eventThread, GdbCause cause, GdbReason reason) {
		this.inferior = inferior;
		this.affectedThreads = affectedThreads;
		this.state = state;
		this.eventThread = eventThread;
		this.cause = cause;
		this.reason = reason;
	}

	/**
	 * Get the inferior affected by this change
	 * 
	 * @return the inferior
	 */
	public GdbInferior getInferior() {
		return inferior;
	}

	/**
	 * Get the thread causing this change
	 * 
	 * @return the event thread
	 */
	public GdbThread getEventThread() {
		return eventThread;
	}

	/**
	 * Get the threads affected by this change
	 * 
	 * @return the threads
	 */
	public Collection<GdbThread> getAffectedThreads() {
		return affectedThreads;
	}

	/**
	 * Get the new state of the affected items
	 * 
	 * @return the new state
	 */
	public GdbState getState() {
		return state;
	}

	/**
	 * Get the user-driven cause of the change
	 * 
	 * @return the cause
	 */
	public GdbCause getCause() {
		return cause;
	}

	/**
	 * Get the target-driven reason for this change
	 * 
	 * @return the reason
	 */
	public GdbReason getReason() {
		return reason;
	}
}
