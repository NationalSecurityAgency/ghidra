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
package ghidra.dbg.sctl.client;

import java.util.*;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;

public class SctlTargetProcessContainer
		extends DefaultTargetObject<SctlTargetProcess, SctlTargetSession> {

	protected final SctlClient client;

	// ID proc by CTLID of its main thread, because PID is not always known
	private final Map<Long, SctlTargetProcess> procsByCtlid = new LinkedHashMap<>();
	private final Map<Long, SctlTargetProcess> procsByPid = new LinkedHashMap<>();

	// Manage the global lists here, but dole them out by proc
	private final Map<Long, SctlTargetThread> threadsByCtlid = new LinkedHashMap<>();
	private final Map<Long, SctlTargetModule> modulesByNsid = new LinkedHashMap<>();

	public SctlTargetProcessContainer(SctlTargetSession session) {
		super(session.client, session, "Processes", "ProcessContainer");
		this.client = session.client;
	}

	/**
	 * Create a process
	 * 
	 * This is preferred to calling
	 * {@link SctlTargetProcess#SctlTargetProcess(SctlClient, long, long)} directly, since this will
	 * add the process to the client container.
	 * 
	 * @param ctlid the CTLID of the primary thread
	 * @param pid the PID
	 * @return the new process proxy
	 */
	protected SctlTargetProcess create(long ctlid, Long pid, String platform) {
		SctlTargetProcess proc = new SctlTargetProcess(this, ctlid, pid, platform);
		procsByCtlid.put(ctlid, proc);
		changeElements(List.of(), List.of(proc), "Created");
		if (pid == null) {
			return proc;
		}
		notifyProcPid(proc, pid);
		return proc;
	}

	protected synchronized SctlTargetProcess getByCtlid(long ctlid) {
		return procsByCtlid.get(ctlid);
	}

	protected synchronized SctlTargetProcess require(long ctlid) {
		SctlTargetProcess proc = procsByCtlid.get(ctlid);
		if (proc == null) {
			throw new NoSuchElementException("No such process: primary ctlid=" + ctlid);
		}
		return proc;
	}

	protected synchronized void notifyProcPid(SctlTargetProcess proc, long pid) {
		SctlTargetProcess collision = procsByPid.put(pid, proc);
		if (collision != null && collision != proc) {
			throw new AssertionError("Process " + pid + " is already known");
		}
	}

	protected synchronized SctlTargetProcess getByPid(long pid) {
		return procsByPid.get(pid);
	}

	/**
	 * Destroy a process
	 * 
	 * This does not generate any SCTL command.
	 * 
	 * @param ctlid the CTLID of the primary thread
	 */
	protected SctlTargetProcess destroy(long ctlid, String reason) {
		SctlTargetProcess proc;
		synchronized (this) {
			proc = procsByCtlid.remove(ctlid);
		}
		if (proc == null) {
			throw new AssertionError("No such process: ctlid=" + ctlid);
		}
		Long pid = proc.getPid();
		if (pid != null) {
			synchronized (this) {
				proc = procsByPid.remove(pid);
			}
			if (proc == null) {
				throw new AssertionError("procByPid out of sync with procsByCtlid");
			}
		}
		changeElements(List.of(proc.getIndex()), List.of(), reason);
		return proc;
	}

	protected synchronized void putThread(long ctlid, SctlTargetThread thread) {
		threadsByCtlid.put(ctlid, thread);
	}

	protected synchronized SctlTargetThread requireThread(long ctlid) {
		SctlTargetThread thread = threadsByCtlid.get(ctlid);
		if (thread == null) {
			throw new NoSuchElementException("No such thread: ctlid=" + ctlid);
		}
		return thread;
	}

	protected void setThreadState(long ctlid, TargetExecutionState state) {
		SctlTargetThread thread = requireThread(ctlid);
		thread.setState(state);
	}

	protected synchronized SctlTargetThread removeThread(long ctlid) {
		return threadsByCtlid.remove(ctlid);
	}

	/**
	 * Destroy a thread, invoking listeners
	 * 
	 * @param ctlid the CTLID of the thread
	 */
	protected void destroyThread(long ctlid, String reason) {
		SctlTargetThread thread = requireThread(ctlid);
		thread.process.destroyThread(ctlid, reason);
	}

	protected synchronized void putModule(long nsid, SctlTargetModule module) {
		modulesByNsid.put(nsid, module);
	}

	protected synchronized SctlTargetModule getModule(long nsid) {
		return modulesByNsid.get(nsid);
	}

	protected synchronized void removeAllModules(Map<Long, SctlTargetModule> modules) {
		modulesByNsid.keySet().removeAll(modules.keySet());
	}
}
