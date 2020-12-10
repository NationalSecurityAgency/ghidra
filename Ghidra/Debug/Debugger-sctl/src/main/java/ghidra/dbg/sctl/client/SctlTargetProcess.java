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

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncLazyValue;
import ghidra.comm.util.BitmaskSet;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.*;
import ghidra.dbg.util.PathUtils;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.util.Msg;

/**
 * A target process on the SCTL server
 */
public class SctlTargetProcess extends DefaultTargetObject<TargetObject, SctlTargetProcessContainer>
		implements TargetProcess<SctlTargetProcess>, TargetAggregate,
		TargetExecutionStateful<SctlTargetProcess> {
	//protected static int READ_COALESCE_DELAY_MS = 100;
	//protected static int READ_PAGE_SIZE = 4096; // TODO: Make this configurable

	protected static final String PID_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "pid";
	protected static final String PLATFORM_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "platform";

	protected static String keyProcess(long ctlid) {
		return PathUtils.makeKey(indexProcess(ctlid));
	}

	protected static String indexProcess(long ctlid) {
		return PathUtils.makeIndex(ctlid);
	}

	protected final SctlClient client;

	protected final long primaryCtlid; // CTLID of "primary" thread

	protected final AsyncLazyValue<Void> lazyStat = new AsyncLazyValue<>(this::doStat);
	protected Long pid;
	protected final String platform;

	protected final SctlTargetThreadContainer threads;
	protected final SctlTargetModuleContainer modules;
	protected final SctlTargetMemory memory;

	/**
	 * Construct a process
	 * 
	 * SCTL does not have a distinct process object, so this is not technically a proxy object. It
	 * is simply a container to help track threads and properly implement Ghidra's debugging model.
	 * 
	 * @see SctlClient#createProcess(long, long)
	 * @param client the client controlling the process
	 * @param primaryCtlid any CTLID, preferably the first observed, belonging to the process
	 * @param pid the PID, if known, of the process, or -1
	 */
	protected SctlTargetProcess(SctlTargetProcessContainer processes, long primaryCtlid, Long pid,
			String platform) {
		super(processes.client, processes, keyProcess(primaryCtlid), "ProcessCTL");
		this.client = processes.client;
		this.primaryCtlid = primaryCtlid;
		this.pid = pid;
		this.platform = platform;

		this.memory = new SctlTargetMemory(this);
		this.modules = new SctlTargetModuleContainer(this);
		this.threads = new SctlTargetThreadContainer(this);

		changeAttributes(List.of(), Map.of( //
			PLATFORM_ATTRIBUTE_NAME, platform, // TODO: Use an environment object?
			memory.getName(), memory, //
			modules.getName(), modules, //
			threads.getName(), threads //
		), "Initialized");
		if (pid != null) {
			changeAttributes(List.of(), Map.of( //
				PID_ATTRIBUTE_NAME, pid //
			), "Fetched");
		}
		invalidateStat();
	}

	@Override
	public String getName() {
		return "Process CTL " + primaryCtlid;
	}

	@Override
	public SctlClient getModel() {
		return client;
	}

	/**
	 * Create a thread proxy
	 * 
	 * This is preferred to calling
	 * {@link SctlTargetThread#SctlTargetThread(SctlTargetProcess, long, TargetThreadDisposition)}
	 * directly, since this will add the thread to the process's and client's containers.
	 * 
	 * @param ctlid the SCTL-assigned CTLID "control ID"
	 * @param reason an explanation of the thread's existence
	 * @return the new thread
	 */
	protected SctlTargetThread createThread(long ctlid, String reason) {
		SctlTargetThread newThread = new SctlTargetThread(threads, this, ctlid);
		threads.put(ctlid, newThread, reason);
		return newThread;
	}

	protected void checkValid() {
		if (!valid) {
			throw new IllegalStateException(
				"This process handle is no longer valid, i.e., the process has been destroyed.");
		}
	}

	/**
	 * Create a memory region
	 * 
	 * This is preferred to calling
	 * {@link SctlMemoryRegion#SctlMemoryRegion(SctlTargetProcess, String, Address, long, BitmaskSet)}
	 * directly, since this will add the region to the process's container.
	 * 
	 * @param file the name of the file defining the region
	 * @param addr the starting address (VMA) of the region
	 * @param len the length, in bytes, of the region
	 * @param flags the permission flags of the region from the protocol message
	 * @return the new region
	 * @throws AddressOverflowException if the region exceeds the bounds of the memory space
	 */
	@Internal
	public SctlTargetMemoryRegion createMemoryRegion(String file, long addr, long len,
			BitmaskSet<SctlMemoryProtection> flags) throws AddressOverflowException {
		Address start = client.addrMapper.mapOffsetToAddress(addr);
		SctlTargetMemoryRegion region = new SctlTargetMemoryRegion(memory, file, start, len, flags);
		memory.addRegion(region);
		return region;
	}

	protected void setThreadState(SctlTargetThread thread, TargetExecutionState state) {
		if (state == TargetExecutionState.RUNNING) {
			memory.invalidateMemoryCaches();
		}
		if (thread.getExecutionState() == TargetExecutionState.RUNNING) {
			if (state != TargetExecutionState.RUNNING) {
				// Forget what to do here....
			}
		}
		thread.setExecutionStateInternal(state);
		TargetExecutionState procState =
			isAnyThreadRunning() ? TargetExecutionState.RUNNING : TargetExecutionState.STOPPED;
		changeAttributes(List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, procState //
		), "State changed");
		listeners.fire(TargetExecutionStateListener.class).executionStateChanged(this, procState);
	}

	protected boolean isAnyThreadRunning() {
		for (SctlTargetThread thread : threads.getCachedElements().values()) {
			if (thread.isRunning()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Destroy a thread, invoking listeners
	 * 
	 * @param ctlid the CTLID of the thread
	 */
	protected void destroyThread(long ctlid, String reason) {
		SctlTargetThread removed = threads.removeByCtlid(ctlid, reason);
		if (removed == null) {
			return;
		}
		if (threads.getCachedElements().isEmpty()) {
			parent.destroy(primaryCtlid, reason);
		}
	}

	/**
	 * Clear and re-request stat
	 */
	protected void invalidateStat() {
		lazyStat.forget();
		modules.clear();
		memory.clearRegions();
		lazyStat.request().exceptionally(e -> {
			Msg.error(this, "Could not stat", e);
			return null;
		});
	}

	/**
	 * Set the PID of this process
	 * 
	 * Unfortunately, SCTL's {@code Rlaunch} does not provide the PID of the newly-launched process.
	 * However, it can be retrieved via a {@code Tstat}. Thus overall, the PID an come from multiple
	 * places. The client does not actively seek a PID, but will store it opportunistically. When a
	 * process is created via {@code Tattach}, the PID is immediately known from the command and
	 * stored. In other circumstances, the PID is stored if/when {@code Rstat} is observed. A call
	 * to {@link #getPid()} will send a {@code Tstat} if the PID is not already known.
	 * 
	 * Due to code organization, this method must be public, which is not ideal. Ghidra's
	 * {@link TargetProcess} does not include this method, so it cannot be accessed without a cast,
	 * but it can be accessed without reflection.
	 * 
	 * Implementation note: The official sctl process control server tends to use the PID as the
	 * CTLID; however, that appears to be an implementation decision on their part as nothing in the
	 * specification requires it. Also, a second thread in the same process has a CTLID different
	 * than the PID. Granted, its PID would be the same as its spawning thread.
	 * 
	 * @param pid the PID
	 */
	@Internal
	public void setPid(long pid) {
		this.pid = pid;
		parent.notifyProcPid(this, pid);
		changeAttributes(List.of(), Map.of( //
			PID_ATTRIBUTE_NAME, pid, //
			DISPLAY_ATTRIBUTE_NAME, getDisplay() //
		), "Fetched");
	}

	protected CompletableFuture<Void> doStat() {
		// NOTE: Client populates fields on completion
		return client.stat(primaryCtlid);
	}

	public Long getPid() {
		return pid;
	}

	public String getPlatform() {
		return platform;
	}

	// TODO: Ensure someone calls stat

	@Override
	public String toString() {
		if (!valid) {
			return "<SCTL process (INVALID)>";
		}
		return "<SCTL process ctlid=" + primaryCtlid + ", pid=" + pid + ">";
	}

	@Override
	public synchronized String getDisplay() {
		if (!valid) {
			return "Process INVALID";
		}
		String exec = modules.getExecutablePath();
		if (exec == null) {
			return "Process " + pid;
		}
		return "Process " + pid + " " + exec;
	}
}
