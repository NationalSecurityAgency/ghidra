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
package agent.dbgeng.manager.cmd;

import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.dbgeng.DebugSystemObjects;
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.DbgCommand;
import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.DbgState;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.evt.DbgCommandDoneEvent;
import agent.dbgeng.manager.impl.DbgManagerImpl;

/**
 * A base class for interacting with specific Dbg commands
 *
 * @param <T> the type of object "returned" by the command
 */
public abstract class AbstractDbgCommand<T> implements DbgCommand<T> {
	protected final DbgManagerImpl manager;
	DbgProcess previousProcess;
	Long previousProcessOffset;
	DebugProcessId previousProcessId;
	DbgThread previousThread;
	Long previousThreadOffset;
	DebugThreadId previousThreadId;

	/**
	 * Construct a new command to be executed by the given manager
	 * 
	 * @param manager the manager to execute the command
	 */
	protected AbstractDbgCommand(DbgManagerImpl manager) {
		this.manager = manager;
	}

	@Override
	public boolean validInState(DbgState state) {
		return true; // With dual interpreters, shouldn't have to worry.
	}

	@Override
	public boolean handle(DbgEvent<?> evt, DbgPendingCommand<?> pending) {
		if (evt instanceof DbgCommandDoneEvent) {
			if (pending.getCommand().equals(((DbgCommandDoneEvent) evt).getCmd())) {
				return true;
			}
		}
		return false;
	}

	@Override
	public T complete(DbgPendingCommand<?> pending) {
		return null;
	}

	@Override
	public void invoke() {
		// Nothing
	}
	
	public void setProcess(DbgProcess process) {
		DebugSystemObjects so = manager.getSystemObjects();
		previousProcess = process;
		if (manager.isKernelMode() && !process.getId().isSystem()) {
			previousProcessOffset = so.getCurrentProcessDataOffset();
			so.setImplicitProcessDataOffset(process.getOffset());		
		}
		else {
			previousProcessId = so.getCurrentProcessId();
			so.setCurrentProcessId(process.getId());	
		}
	}
	
	
	public void resetProcess() {
		DebugSystemObjects so = manager.getSystemObjects();
		if (manager.isKernelMode() && !previousProcess.getId().isSystem()) {
			so.setImplicitProcessDataOffset(previousProcessOffset);
		}
		else {
			so.setCurrentProcessId(previousProcessId);	
		}
	}	
	
	public void setThread(DbgThread thread) {
		DebugSystemObjects so = manager.getSystemObjects();
		previousThread = thread;
		if (manager.isKernelMode() && !thread.getId().isSystem()) {
			previousThreadOffset = so.getCurrentThreadDataOffset();
			so.setImplicitThreadDataOffset(thread.getOffset());		
		}
		else {
			previousThreadId = so.getCurrentThreadId();
			so.setCurrentThreadId(thread.getId());	
		}
	}
	
	
	public void resetThread() {
		DebugSystemObjects so = manager.getSystemObjects();
		if (manager.isKernelMode() && !previousThread.getId().isSystem()) {
			so.setImplicitThreadDataOffset(previousThreadOffset);
		}
		else {
			so.setCurrentThreadId((DebugThreadId) previousThreadId);	
		}
	}
}
