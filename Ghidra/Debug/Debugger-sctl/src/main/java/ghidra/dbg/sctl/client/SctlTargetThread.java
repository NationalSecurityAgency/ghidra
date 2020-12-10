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
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.sctl.protocol.consts.Mkind;
import ghidra.dbg.target.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

/**
 * A target thread on the SCTL server
 */
public class SctlTargetThread extends DefaultTargetObject<TargetObject, SctlTargetThreadContainer>
		implements TargetThread<SctlTargetThread>, TargetDetachable<SctlTargetThread>,
		TargetExecutionStateful<SctlTargetThread>, TargetInterruptible<SctlTargetThread>,
		TargetKillable<SctlTargetThread>, TargetResumable<SctlTargetThread>,
		TargetSteppable<SctlTargetThread> {
	private static final String EXIT_STATUS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "exit_status";

	protected static String keyThread(long ctlid) {
		return PathUtils.makeKey(indexThread(ctlid));
	}

	protected static String indexThread(long ctlid) {
		return PathUtils.makeIndex(ctlid);
	}

	protected final SctlClient client;

	protected final SctlTargetProcess process;
	protected final long ctlid;

	private TargetExecutionState state = TargetExecutionState.STOPPED;

	protected final SctlTargetBreakpointContainer breakpoints;
	protected final SctlTargetRegisters registers;

	/**
	 * Construct a thread proxy
	 * 
	 * @see SctlTargetProcess#createThread(long, TargetThreadDisposition)
	 * @param process the process owning the thread
	 * @param ctlid the SCTL-assigned CTLID "control ID"
	 * @param disposition an explanation of the thread's existence
	 */
	SctlTargetThread(SctlTargetThreadContainer threads, SctlTargetProcess process, long ctlid) {
		super(threads.client, threads, keyThread(ctlid), "Thread");
		this.client = threads.client;
		this.process = process;
		this.ctlid = ctlid;

		this.breakpoints = new SctlTargetBreakpointContainer(this);
		this.registers = new SctlTargetRegisters(this);

		changeAttributes(List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, state, //
			breakpoints.getName(), breakpoints, //
			registers.getName(), registers //
		), "Initialized");
	}

	protected void checkValid() {
		if (!valid) {
			throw new IllegalStateException(
				"This thread handle is no longer valid, i.e., the thread has been destroyed.");
		}
	}

	@Override
	public TargetExecutionState getExecutionState() {
		return state;
	}

	/**
	 * Change the thread's state, invoking thread and/or process listeners
	 * 
	 * @param state the new state
	 */
	protected void setState(TargetExecutionState state) {
		process.setThreadState(this, state);
	}

	protected boolean isRunning() {
		return state == TargetExecutionState.RUNNING;
	}

	/**
	 * Create a breakpoint proxy
	 * 
	 * This does not generate a {@link Mkind#Tsettrap} command. This only creates the proxy and
	 * stores it in the thread's container.
	 * 
	 * This is preferred to calling
	 * {@link SctlBreakpoint#SctlBreakpoint(SctlTargetThread, long, long)} directly, since this will
	 * add the breakpoint to the thread's container.
	 * 
	 * @param trpid the SCTL-assigned TRPID "trap ID"
	 * @param addr the address of the trap
	 * @return the new breakpoint
	 */
	protected SctlTargetBreakpoint createBreakpoint(long trpid, long addr) {
		SctlTargetBreakpoint bpt = new SctlTargetBreakpoint(breakpoints, this, trpid, addr);
		breakpoints.put(trpid, bpt);
		return bpt;
	}

	/**
	 * Destroy a breakpoint proxy
	 * 
	 * This simply removes the specified proxy from the thread's container and sets the breakpoint's
	 * state to cleared. This does not generate a {@code Tclrtrap} command. It is merely a tracking
	 * mechanism.
	 * 
	 * @param trpid the SCTL-assigned TRPID "trap ID"
	 * @return the removed breakpoint
	 */
	protected SctlTargetBreakpoint destroyBreakpoint(long trpid) {
		SctlTargetBreakpoint bkpt = breakpoints.removeByTrpid(trpid);
		if (bkpt == null) {
			Msg.warn(this, "No such SCTL trap: " + trpid);
			return null;
		}
		bkpt.cleared = true;
		return bkpt;
	}

	/**
	 * Copy all breakpoints from a given thread's container into this one's container
	 * 
	 * @param src the thread whose breakpoints to copy
	 */
	protected void copyBreakpointsFrom(SctlTargetThread src) {
		Map<Long, SctlTargetBreakpoint> copied = new LinkedHashMap<>();
		synchronized (src.breakpoints) {
			for (SctlTargetBreakpoint b : src.breakpoints.getAll()) {
				SctlTargetBreakpoint c = new SctlTargetBreakpoint(b, breakpoints);
				copied.put(c.trpid, c);
			}
		}
		breakpoints.putAll(copied);
	}

	protected void setExecutionStateInternal(TargetExecutionState state) {
		this.state = state;
		if (state == TargetExecutionState.STOPPED) {
			registers.invalidateCtx();
		}
		changeAttributes(List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, state //
		), "State changed");
		listeners.fire(TargetExecutionStateListener.class).executionStateChanged(this, state);
	}

	@Override
	public CompletableFuture<Void> resume() {
		checkValid();
		return process.client.resume(ctlid);
	}

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		if (kind != TargetStepKind.INTO) {
			throw new UnsupportedOperationException("step kind = " + kind);
		}
		checkValid();
		return process.client.step(ctlid);
	}

	// SCTL-only
	/**
	 * Snapshot a thread
	 * 
	 * Creates an exact copy of this thread in a new process. It is unclear what happens if there
	 * are other threads in the source process. See {@code Tsnap} in the SCTL documentation.
	 * 
	 * @return a proxy to the new copy
	 */
	public CompletableFuture<SctlTargetThread> snap() {
		checkValid();
		return process.client.snap(ctlid);
	}

	@Override
	public CompletableFuture<Void> interrupt() {
		checkValid();
		return process.client.interrupt(ctlid);
	}

	protected CompletableFuture<SctlTargetBreakpoint> setBreakpoint(Address address) {
		checkValid();
		return process.client.setTrap(ctlid, address, 1, false, false, false);
	}

	@Override
	public CompletableFuture<Void> detach() {
		checkValid();
		return process.client.detachThread(ctlid);
	}

	@Override
	public CompletableFuture<Void> kill() {
		checkValid();
		return process.client.killThread(ctlid);
	}

	// SCTL-only
	/**
	 * Select which events cause a thread to stop
	 * 
	 * This allows trapping on events other than breakpoints. See {@code Ttrace} in the SCTL
	 * documentation.
	 * 
	 * @param mode indicates whether to enable or disable the given events
	 * @param events the events to enable or disable
	 * @return a future which completes when the request is confirmed
	 */
	public CompletableFuture<Void> traceEvents(SctlTrace.Mode mode, Set<SctlTrace.Event> events) {
		checkValid();
		return process.client.traceEvents(ctlid, mode, events);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("<SCTL thread ");
		if (!valid) {
			sb.append("(INVALID) ");
		}
		sb.append("ctlid=");
		sb.append(ctlid);
		sb.append(", pid=");
		sb.append(process.getPid());
		sb.append(", state=");
		sb.append(state);
		sb.append(">");
		return sb.toString();
	}

	@Override
	public String getDisplay() {
		if (!valid) {
			return "Thread INVALID CTL";
		}
		return "Thread CTL " + ctlid + " (" + state + ")";
	}

	/**
	 * Destroy this thread
	 */
	protected void destroy(String reason) {
		process.destroyThread(ctlid, reason);
	}

	protected void setExitStatusCode(long status) {
		// NOTE: I hope the user has a listener. Otherwise, it's gone in an instant.
		changeAttributes(List.of(), Map.of( //
			EXIT_STATUS_ATTRIBUTE_NAME, status //
		), "Exited");
	}
}
