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

import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.DbgState;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.impl.DbgStackFrameImpl;
import agent.dbgeng.manager.impl.DbgThreadImpl;

/**
 * The event corresponding with "{@code =thread-selected}"
 */
public class DbgThreadSelectedEvent extends AbstractDbgEvent<DebugThreadId> {
	private final DebugThreadId id;
	private DbgState state;
	private DbgThread thread;
	private DbgStackFrameImpl frame;

	/**
	 * The selected thread ID must be specified by dbgeng.
	 * 
	 * @param frame
	 * @param id dbgeng-provided id
	 */
	public DbgThreadSelectedEvent(DbgState state, DbgThread thread, DbgStackFrameImpl frame) {
		super(thread.getId());
		this.id = thread.getId();
		this.state = state;
		this.thread = thread;
		this.frame = frame;
	}

	/**
	 * Get the selected thread ID
	 * 
	 * @return the thread ID
	 */
	public DebugThreadId getThreadId() {
		return id;
	}

	public DbgState getState() {
		return state;
	}

	public DbgThreadImpl getThread() {
		return (DbgThreadImpl) thread;
	}

	public DbgStackFrameImpl getFrame() {
		return frame;
	}

}
