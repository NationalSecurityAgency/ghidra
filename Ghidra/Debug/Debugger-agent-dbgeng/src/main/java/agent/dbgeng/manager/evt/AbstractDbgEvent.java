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
package agent.dbgeng.manager.evt;

import agent.dbgeng.dbgeng.DebugClient.DebugStatus;
import agent.dbgeng.manager.*;
import agent.dbgeng.manager.DbgCause.Causes;
import agent.dbgeng.manager.cmd.DbgPendingCommand;

/**
 * A base class for Dbg events
 *
 * @param <T> the type of information detailing the event
 */
public abstract class AbstractDbgEvent<T> implements DbgEvent<T> {
	private final T info;
	protected DbgCause cause = Causes.UNCLAIMED;
	protected boolean stolen = false;
	protected DebugStatus status = DebugStatus.NO_CHANGE;

	/**
	 * Construct a new event with the given information
	 * 
	 * @param info the information
	 */
	protected AbstractDbgEvent(T info) {
		this.info = info;
	}

	@Override
	public T getInfo() {
		return info;
	}

	@Override
	public void claim(DbgPendingCommand<?> cmd) {
		if (cause != Causes.UNCLAIMED) {
			throw new IllegalStateException("Event is already claimed by " + cause);
		}
		cause = cmd;
	}

	@Override
	public DbgCause getCause() {
		return cause;
	}

	public DbgReason getReason() {
		return DbgReason.getReason(null);
	}

	@Override
	public void steal() {
		stolen = true;
	}

	@Override
	public boolean isStolen() {
		return stolen;
	}

	@Override
	public String toString() {
		return "<" + getClass().getSimpleName() + " " + info + " >";
	}

	@Override
	public DbgState newState() {
		return null;
	}

}
