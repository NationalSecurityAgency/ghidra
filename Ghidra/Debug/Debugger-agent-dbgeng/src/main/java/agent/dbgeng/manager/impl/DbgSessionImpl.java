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
package agent.dbgeng.manager.impl;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.dbgeng.DebugSessionId;
import agent.dbgeng.manager.*;
import agent.dbgeng.manager.cmd.DbgListProcessesCommand;

public class DbgSessionImpl implements DbgSession {

	private final Map<DebugProcessId, DbgProcessImpl> processes = new LinkedHashMap<>();
	private final Map<DebugProcessId, DbgProcess> unmodifiableProcesses =
		Collections.unmodifiableMap(processes);

	private DbgManagerImpl manager;
	private DebugSessionId id;
	private Long exitCode;

	/**
	 * Construct a new session
	 * 
	 * @param manager the manager creating the session
	 * @param id the dbgeng-assigned session ID
	 */
	public DbgSessionImpl(DbgManagerImpl manager, DebugSessionId id) {
		this.manager = manager;
		this.id = id;
	}

	public DbgSessionImpl(DbgManagerImpl manager) {
		this.manager = manager;
	}

	@Override
	public String toString() {
		return "<DbgSession id=" + id + ",exitCode=" + exitCode + ">";
	}

	@Override
	public DebugSessionId getId() {
		return id;
	}

	public void setId(DebugSessionId id) {
		this.id = id;
	}

	/**
	 * Set the exit code
	 * 
	 * @param exitCode the exit code (status or signal)
	 */
	public void setExitCode(Long exitCode) {
		this.exitCode = exitCode;
	}

	@Override
	public Long getExitCode() {
		return exitCode;
	}

	/**
	 * Add this process to the manager's list of processes, because of a given cause
	 * 
	 * @param cause the cause of the new inferior
	 */
	public void add() {
		manager.sessions.put(id, this);
		manager.getEventListeners().fire.sessionAdded(this, DbgCause.Causes.UNCLAIMED);
		//manager.addSession(this, cause);
	}

	/**
	 * Remove this process from the manager's list of processes, because of a given cause
	 * 
	 * @param cause the cause of removal
	 */
	public void remove(DbgCause cause) {
		manager.removeSession(id, cause);
	}

	/**
	 * Use {@link DbgSessionImpl#add()} instead
	 * 
	 * @param process the process to add
	 */
	public void addProcess(DbgProcessImpl process) {
		DbgProcessImpl exists = processes.get(process.getId());
		if (exists != null) {
			throw new IllegalArgumentException("There is already process " + exists);
		}
		processes.put(process.getId(), process);

	}

	@Override
	public DbgProcessImpl getProcess(DebugProcessId tid) {
		DbgProcessImpl result = processes.get(tid);
		if (result == null) {
			throw new IllegalArgumentException("There is no thread with id " + tid);
		}
		return result;
	}

	/**
	 * Use {@link DbgProcessImpl#remove()} instead
	 * 
	 * @param pid the ID of the thread to remove
	 */
	public void removeProcess(DebugProcessId pid) {
		if (processes.remove(pid) == null) {
			throw new IllegalArgumentException("There is no process with id " + pid);
		}
	}

	@Override
	public Map<DebugProcessId, DbgProcess> getKnownProcesses() {
		return unmodifiableProcesses;
	}

	public Map<DebugProcessId, DbgProcessImpl> getKnownProcessImpl() {
		return processes;
	}

	@Override
	public CompletableFuture<Map<DebugProcessId, DbgProcess>> listProcesses() {
		return manager.execute(new DbgListProcessesCommand(manager));
	}

	protected void processCreated(DbgProcessImpl process) {
		processes.put(process.getId(), process);
	}

	public void processExited(DebugProcessId id) {
		processes.remove(id);
	}
}
