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

import static ghidra.async.AsyncUtils.loop;
import static ghidra.async.AsyncUtils.sequence;
import static ghidra.lifecycle.Unfinished.TODO;

import java.io.EOFException;
import java.io.InvalidObjectException;
import java.nio.channels.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.StringUtils;

import com.google.common.cache.RemovalNotification;

import ghidra.async.*;
import ghidra.comm.packet.AsynchronousPacketChannel;
import ghidra.comm.packet.AsynchronousPacketDebugChannel;
import ghidra.dbg.DebuggerModelClosedReason;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.sctl.client.depr.DebuggerAddressMapper;
import ghidra.dbg.sctl.client.depr.DefaultDebuggerAddressMapper;
import ghidra.dbg.sctl.client.err.*;
import ghidra.dbg.sctl.dialect.SctlDialect;
import ghidra.dbg.sctl.err.SctlError;
import ghidra.dbg.sctl.protocol.*;
import ghidra.dbg.sctl.protocol.common.*;
import ghidra.dbg.sctl.protocol.common.notify.*;
import ghidra.dbg.sctl.protocol.common.notify.AbstractSctlListsLibrariesEventNotification.PathBase;
import ghidra.dbg.sctl.protocol.common.reply.*;
import ghidra.dbg.sctl.protocol.common.request.*;
import ghidra.dbg.sctl.protocol.v2012base.Sctl2012SnapNotification;
import ghidra.dbg.sctl.protocol.v2012ext.SctlExecuteReply;
import ghidra.dbg.sctl.protocol.v2012ext.SctlExecuteRequest;
import ghidra.dbg.sctl.protocol.v2012ext.x86.linux.Sctl2012ExtLinuxX86Dialect;
import ghidra.dbg.sctl.protocol.v2018base.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetObject.TargetObjectListener;
import ghidra.dbg.target.TargetSymbol;
import ghidra.dbg.util.PathUtils;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;

/**
 * A debugger client implementation that communicates with an external debugger via SCTL-bus
 * 
 * SCTL-bus, created by the GHIDRA team, is an extension to SCTL. The SCTL protocol is specified for
 * Cinquecento. Details are available at their website
 * <a href="http://cqctworld.org">cqctworld.org</a>. Details for the SCTL-bus extension are
 * available within {@link Sctl2012ExtLinuxX86Dialect}. It is backward compatible with standard
 * SCTL, so this client can control the sctl process control server for Linux out-of-box.
 * 
 * This fully implements the Ghidra debugging API with some notable limitations, including but
 * certainly not limited to the following:
 * 
 * 1) The step command is not properly confirmed. The SCTL protocol's {@code Tstep} command requires
 * the step to complete before the {@code Rstep} response is given. Thus, it is difficult to tell if
 * the command was dropped, or if the step is taking a long time. This can happen if, e.g., the
 * stepped instruction is a system call. As a result, the step instruction may time out, even though
 * the target thread has entered the {@link TargetExecutionState#RUNNING} state. A better model is
 * exemplified by GDB, which may provide a model for extending SCTL further. The step should
 * complete as soon as the target is running. When the step completes, a stop notification should be
 * sent indicating "step completed" as the reason. This is a minor issue, though. As a workaround,
 * this implementation assumes the thread is {@link TargetExecutionState#RUNNING} immediately after
 * {@code Tstep} is sent. Once the result is returned (whether successful, erroneous, or timed out),
 * the thread re-enters the {@link TargetExecutionState#STOPPED} state. In most circumstances, this
 * workaround is unnoticeable. When it does time out, it is usually because the remote thread is
 * actually running. When it times out, the client will go out of sync. However, when the step
 * completes on the remote side, it will generate a notification. The reason may not make sense, but
 * at least the client and server will be back in sync.
 * 
 * 2) It may not be possible to attach to a multi-threaded process. SCTL's {@code Tattach} request
 * accepts only a PID, not a thread ID, but it {@code Rattach} response only gives a single CTLID,
 * which corresponds to a single thread. Thus, it's impossible to attach to a multi-threaded process
 * without a workaround. For the standard sctl server, there is no workaround. In fact, the server
 * behaves oddly and may crash in these circumstances. A workaround if SCTL-bus is used is for the
 * server to synthesize additional {@code Tattach} requests for the same PID, providing a unique
 * CTLID in the {@code Rattach} for each thread. This may seem odd, though, since the repeated
 * requests all look identical, but it works well.
 * 
 * 3) Ghidra does not (yet) support or understand the snapshot command. This is one of the hallmarks
 * of SCTL, but this feature is not necessary to synchronize the GUI with the debugger's CLI. This
 * client implementation does, however, correctly interpret snapshot requests, replies, and
 * notifications sent by other clients on the SCTL-bus. It will create a copy of the target, as
 * specified by SCTL, but it will be presented to Ghidra as a fork event. Use of this feature would
 * require a SCTL-bus to standard SCTL proxy, or a bus-aware process control server that implements
 * snapshots.
 * 
 * 4) SCTL only transfers a fixed set of x86 registers. It currently provides no mechanism to
 * request other arbitrary registers. As a result, this client only supports x86 architectures
 * (including x86_64), and only those specific registers may be read or written. Future versions
 * will likely introduce a more generic "dialect" of SCTL, permitting the client to control targets
 * of any architecture and access all known registers. The protocol is also currently limited to
 * registers of at most 64 bits.
 * 
 * 5) SCTL only allows reading and writing bytes to a single memory. Granted, there is a lot of
 * flexibility in mapping addresses to a single spaces, esp. with 64 address bits, but this can lead
 * to confusion if the client and server do not agree on the mapping scheme. Currently, this is not
 * an issue, since x86 supports only one memory. As new architectures are added, this design
 * limitation must be addressed. Notably, the {@code Tread} request has an {@code fd[8]} field,
 * which might be used to encode alternative address spaces.
 * 
 * 6) SCTL allows the client to request any arbitrary type known to a given namespace. The Ghidra
 * {@link LegacyDebuggerClient} API does not support this. A type can only be retrieved via a
 * {@link TargetSymbol} object or by requesting all types. Thus, a type that is never used cannot be
 * retrieved singly.
 * 
 * 7) This client introduces two assumptions to Ghidra's debugging model. Threads belonging to the
 * same process share the same memory and namespaces. Suppose a process contains threads A and B. If
 * A loads a new library, that same library is assumed to be available in B. If memory is read from
 * A, it is stored in a cache shared with B. This assumption should be true for processes on x86
 * Linux. When other systems are supported, these assumptions may need to be re-addressed.
 * 
 * 8) SCTL provides a means of transferring data types and their definitions, if available, from the
 * target. It even provides descriptions of the base C data types. Currently, those base
 * descriptions are ignored in favor of what is defined by Ghidra's language modules. Furthermore,
 * bit fields are not yet supported by Ghidra, yet SCTL can describe them, so they are simply not
 * converted.
 */
public class SctlClient extends AbstractDebuggerObjectModel {
	private static final int MAX_OUTSTANDING_REQUESTS = 1000;
	private static final int REQUEST_TIMEOUT_MILLIS = Integer.MAX_VALUE; // TODO: Consider no timeout

	private enum ConnectionState {
		INITIAL(false, false),
		CONNECTING(true, false),
		CONNECTED(true, false),
		DISCONNECTED(false, true);

		final boolean isOpen;
		final boolean isTerminate;

		ConnectionState(boolean isOpen, boolean isTerminate) {
			this.isOpen = isOpen;
			this.isTerminate = isTerminate;
		}
	}

	protected class SctlPairingCache extends AsyncPairingCache<Integer, SctlPacket> {
		public SctlPairingCache() {
			super(4, REQUEST_TIMEOUT_MILLIS, MAX_OUTSTANDING_REQUESTS);
		}

		@Override
		protected void resultRemoved(RemovalNotification<Integer, SctlPacket> rn) {
			if (rn.wasEvicted()) {
				Msg.error(this,
					"Received SCTL reply for unmatched tag: " + rn.getKey());
			}
		}

		@Override
		protected void promiseRemoved(
				RemovalNotification<Integer, CompletableFuture<SctlPacket>> rn) {
			if (rn.wasEvicted()) {
				String message =
					"Command with tag " + rn.getKey() + " evicted because " + rn.getCause();
				Msg.error(this, message);
				// This thread may hold a lock. Offload completion to avoid deadlocks.
				AsyncUtils.FRAMEWORK_EXECUTOR.execute(
					() -> rn.getValue().completeExceptionally(new TimeoutException(message)));
			}
		}
	}

	private Collection<SctlDialect> restrictedDialects = SctlVersionInfo.KNOWN_DIALECTS;

	private ConnectionState connectionState = ConnectionState.INITIAL;
	private final String description;
	private final AsynchronousPacketChannel<AbstractSelSctlPacket, AbstractSelSctlPacket> packetChannel;
	private final SctlMarshaller marshaller = new SctlMarshaller();

	private SctlDialect activeDialect = SctlDialect.NULL_DIALECT;

	private int idOnBus = 0;
	private int nextTag = 0;

	// TODO: These are meant to be per-object, not global
	protected final ListenerSet<TargetObjectListener> listenersObject =
		new ListenerSet<>(TargetObjectListener.class);

	protected final SctlTargetSession session;

	private final SctlPairingCache packetMatcher = new SctlPairingCache();

	@Internal
	public final DebuggerAddressMapper addrMapper;

	/**
	 * Construct a new client on the given channel with the given address mapper
	 * 
	 * SCTL is usually carried over TCP/IP. More than likely, {@code channel} should be an instance
	 * of {@link AsynchronousSocketChannel} that is already connected to the server. Though the TCP
	 * connection should already be established, no other messages should be sent before the channel
	 * is given to the client. The client will perform the SCTL version negotiation upon calling
	 * {@link #connect()}. To close the SCTL connection, simply close the channel. By
	 * {@link LegacyDebuggerClient} convention, {@link #disconnect()} should be called before
	 * closing the channel.
	 * 
	 * @param channel a channel connected to the process control server
	 * @param addrMapper a mapper of Ghidra addresses to debugger addresses
	 */
	public SctlClient(String description, AsynchronousByteChannel channel,
			DebuggerAddressMapper addrMapper) {
		this.description = description;
		this.packetChannel = new AsynchronousPacketDebugChannel<>(channel, marshaller);
		marshaller.setPacketFactory(activeDialect.getPacketFactory());
		this.addrMapper = addrMapper;
		this.session = new SctlTargetSession(this);
	}

	/**
	 * Construct a new client on the given channel with the default address mapper
	 * 
	 * @see #SctlClient(AsynchronousByteChannel, DebuggerAddressMapper)
	 * @param channel a channel connected to the process control server
	 */
	public SctlClient(String description, AsynchronousByteChannel channel) {
		this(description, channel, DefaultDebuggerAddressMapper.INSTANCE);
	}

	public SctlClient setDialects(SctlDialect... dialects) {
		return this.setDialects(Arrays.asList(dialects));
	}

	public SctlClient setDialects(Collection<SctlDialect> dialects) {
		this.restrictedDialects = dialects;
		return this;
	}

	/**
	 * Change the client's SCTL-bus ID
	 * 
	 * This concept is an extension to SCTL. When multiple clients are issuing commands, the bus ID
	 * allows each client to identify the other clients. This does not often need to be changed.
	 * Future versions may incorporate a mechanism for changing this automatically to avoid ID
	 * conflicts among multiple clients.
	 * 
	 * @param idOnBus the new ID
	 */
	public void setIdOnBus(int idOnBus) {
		this.idOnBus = idOnBus;
	}

	/**
	 * Get the client's SCTL-bus ID
	 * 
	 * @see #setIdOnBus(int)
	 * @return the current bus ID
	 */
	public int getIdOnBus() {
		return idOnBus;
	}

	@Override
	public boolean isAlive() {
		return connectionState == ConnectionState.CONNECTED;
	}

	protected void checkOpen() {
		if (!connectionState.isOpen) {
			throw new SctlError("Connection is not open");
		}
	}

	protected void fireConnectionEstablished() {
		connectionState = ConnectionState.CONNECTED;
		listeners.fire.modelOpened();
	}

	protected void fireConnectionClosed(DebuggerModelClosedReason reason) {
		connectionState = ConnectionState.DISCONNECTED;
		packetMatcher.flush(new SctlError("Client disconnected while waiting for reply"));
		listeners.fire.modelClosed(reason);
	}

	protected <T> T reportOthersErrors(Throwable exc) {
		Msg.info(this, "Ignoring an error caused by another controller: " + exc);
		return null;
	}

	/**
	 * Handle a request sent by another client
	 * 
	 * This just prepares the client to receive the server's response and process both as if this
	 * client sent the original request.
	 * 
	 * @param tag the tag of the request
	 * @param sel the request
	 */
	private void processBusRequest(int tag, AbstractSctlRequest sel) {
		//Msg.debug(this, "Bus: " + sel);
		if (!activeDialect.isBusSupported()) {
			Msg.error(this,
				"This SCTL channel is not a bus. Nevertheless, the controller received a request.");
			return;
		}

		int id = (tag >> 24) & 0x0ff;
		if (id == idOnBus) {
			Msg.warn(this,
				"There appears to be another controller with my id (" + id + ") on this bus");
		}
		//Msg.info(this, "Controller " + id + " sent: " + sel);
		final CompletableFuture<?> future;
		if (sel instanceof SctlVersionRequest) {
			future = processBusConnect(tag, (SctlVersionRequest) sel);
		}
		else if (sel instanceof SctlPingRequest) {
			future = processBusPing(tag, (SctlPingRequest) sel);
		}
		else if (sel instanceof SctlExecuteRequest) {
			future = processBusExecute(tag, (SctlExecuteRequest) sel);
		}
		else if (sel instanceof SctlProcessListRequest) {
			future = processBusListAttachable(tag, (SctlProcessListRequest) sel);
		}
		else if (sel instanceof SctlStatusRequest) {
			future = processBusStat(tag, (SctlStatusRequest) sel);
		}
		else if (sel instanceof SctlAttachRequest) {
			future = processBusAttach(tag, (SctlAttachRequest) sel);
		}
		else if (sel instanceof SctlLaunchRequest) {
			future = processBusLaunch(tag, (SctlLaunchRequest) sel);
		}
		else if (sel instanceof SctlContinueRequest) {
			future = processBusResume(tag, (SctlContinueRequest) sel);
		}
		else if (sel instanceof SctlStepRequest) {
			future = processBusStep(tag, (SctlStepRequest) sel);
		}
		else if (sel instanceof SctlSnapshotRequest) {
			future = processBusSnap(tag, (SctlSnapshotRequest) sel);
		}
		else if (sel instanceof SctlStopRequest) {
			future = processBusInterrupt(tag, (SctlStopRequest) sel);
		}
		else if (sel instanceof SctlReadRequest) {
			future = processBusReadMemory(tag, (SctlReadRequest) sel);
		}
		else if (sel instanceof SctlWriteRequest) {
			future = processBusWriteMemory(tag, (SctlWriteRequest) sel);
		}
		else if (sel instanceof SctlGetContextRequest) {
			future = processBusGetContext(tag, (SctlGetContextRequest) sel);
		}
		else if (sel instanceof SctlSetContextRequest) {
			future = processBusSetContext(tag, (SctlSetContextRequest) sel);
		}
		else if (sel instanceof SctlEnumerateContextRequest) {
			future = processBusEnumerateContext(tag, (SctlEnumerateContextRequest) sel);
		}
		else if (sel instanceof SctlChooseContextRequest) {
			future = processBusChooseContext(tag, (SctlChooseContextRequest) sel);
		}
		else if (sel instanceof SctlSetTrapRequest) {
			future = processBusSetTrap(id, tag, (SctlSetTrapRequest) sel);
		}
		else if (sel instanceof SctlClearTrapRequest) {
			future = processBusClearTrap(tag, (SctlClearTrapRequest) sel);
		}
		else if (sel instanceof SctlDetachRequest) {
			future = processBusDetachThread(tag, (SctlDetachRequest) sel);
		}
		else if (sel instanceof SctlKillRequest) {
			future = processBusKillThread(tag, (SctlKillRequest) sel);
		}
		else if (sel instanceof SctlTraceRequest) {
			future = processBusTraceEvents(tag, (SctlTraceRequest) sel);
		}
		else if (sel instanceof SctlLookupSymbolRequest) {
			SctlLookupSymbolRequest looksym = (SctlLookupSymbolRequest) sel;
			SctlTargetModule ns = session.processes.getModule(looksym.nsid);
			if (ns == null) {
				future = processUnknownNSID(id, tag, looksym.nsid, sel);
			}
			else {
				future = ns.symbols.processBusGetSymbol(tag, looksym);
			}
		}
		else if (sel instanceof SctlEnumerateSymbolsRequest) {
			SctlEnumerateSymbolsRequest enumsym = (SctlEnumerateSymbolsRequest) sel;
			SctlTargetModule ns = session.processes.getModule(enumsym.nsid);
			if (ns == null) {
				future = processUnknownNSID(id, tag, enumsym.nsid, sel);
			}
			else {
				future = ns.symbols.processBusGetAllSymbols(tag, enumsym);
			}
		}
		else if (sel instanceof SctlLookupTypeRequest) {
			SctlLookupTypeRequest looktype = (SctlLookupTypeRequest) sel;
			SctlTargetModule ns = session.processes.getModule(looktype.nsid);
			if (ns == null) {
				future = processUnknownNSID(id, tag, looktype.nsid, sel);
			}
			else {
				future = ns.types.processBusGetTypeDef(tag, looktype);
			}
		}
		else if (sel instanceof SctlEnumerateSymbolsRequest) {
			SctlEnumerateTypesRequest enumtype = (SctlEnumerateTypesRequest) sel;
			SctlTargetModule ns = session.processes.getModule(enumtype.nsid);
			if (ns == null) {
				future = processUnknownNSID(id, tag, enumtype.nsid, sel);
			}
			else {
				future = ns.types.processBusGetAllTypeDefs(tag, enumtype);
			}
		}
		else if (sel instanceof SctlFocusRequest) {
			future = processBusFocusThread(tag, (SctlFocusRequest) sel);
		}
		else if (sel instanceof SctlGetAttributesRequest) {
			future = processBusGetAttributes(tag, (SctlGetAttributesRequest) sel);
		}
		else if (sel instanceof SctlGetElementsRequest) {
			future = processBusGetElements(tag, (SctlGetElementsRequest) sel);
		}
		else {
			future = processBusUnknown(id, tag, sel);
		}
		future.exceptionally(this::reportOthersErrors);
	}

	private void processEventNotifyListsLibraries(long ctlid, TargetExecutionState state,
			AbstractSctlListsLibrariesEventNotification lists) {

		// Use module names to decide whether or not to invalidate our stat
		List<String> moduleNames = new ArrayList<>();
		for (PathBase lib : lists.libs) {
			moduleNames.add(lib.path.str);
		}

		SctlTargetThread thread = session.processes.requireThread(ctlid);
		try {
			thread.registers.updateContextIfPresent(lists.getCtx());

			// NOTE: no nsids are provided with the lib paths, so just re-stat
			if (!thread.process.modules.getCachedElements().keySet().containsAll(moduleNames)) {
				thread.process.invalidateStat();
			}
		}
		finally {
			thread.setState(state);
		}
	}

	private void processEventNotifyForkClone(long ctlid, TargetExecutionState state,
			AbstractSctlForkCloneNotification fc, String reason) {
		SctlTargetThread thread = session.processes.requireThread(ctlid);
		try {
			thread.registers.updateContextIfPresent(fc.getCtx());

			SctlTargetProcess spwnProc;
			if (fc instanceof AbstractSctlForkNotification) {
				AbstractSctlForkNotification forked = (AbstractSctlForkNotification) fc;
				Long pid = forked.supportsProcessID() ? forked.getProcessID() : null;
				spwnProc = session.processes.create(forked.spwnid, pid, thread.process.platform);
			}
			else {
				spwnProc = thread.process;
			}
			SctlTargetThread spwnThread = spwnProc.createThread(fc.spwnid, reason);
			spwnThread.registers.updateContextIfPresent(fc.spwnctx);
			spwnThread.copyBreakpointsFrom(thread);
			// NOTE: Adding a breakpoint action post-clone/-fork, applies only to one thread
		}
		finally {
			thread.setState(state);
		}
	}

	private void processEventNotifyTrap(long ctlid, TargetExecutionState state,
			SctlTrapNotification trapped) {
		SctlTargetThread thread = session.processes.requireThread(ctlid);
		try {
			thread.registers.updateContextIfPresent(trapped.getCtx());

			SctlTargetBreakpoint bpt = thread.breakpoints.getByTrpid(trapped.trpid);
			if (bpt == null) {
				throw new NoSuchElementException("Trap " + trapped.trpid + " is not known");
			}
			bpt.hit();
		}
		finally {
			thread.setState(state);
		}
	}

	private void processEventNotifySnap(long ctlid, TargetExecutionState state,
			AbstractSctlSnapNotification snapped) {
		SctlTargetThread thread = session.processes.requireThread(ctlid);
		try {
			thread.registers.updateContextIfPresent(snapped.getCtx());
			Long pid = snapped.supportsProcessID() ? snapped.getProcessID() : null;

			// Create a handle for the new process and thread
			SctlTargetProcess snapProc =
				session.processes.create(snapped.spwnid, pid, thread.process.platform);
			SctlTargetThread snapThread = snapProc.createThread(snapped.spwnid, "Snapshotted");
			// The two should have the same context, so no spwnctx
			snapThread.registers.updateContextIfPresent(snapped.getCtx());

			// Snap events happen because of "snap points"
			SctlTargetBreakpoint bpt = thread.breakpoints.getByTrpid(snapped.trpid);
			if (bpt == null) {
				throw new NoSuchElementException("Trap " + snapped.trpid + " is not known");
			}
			bpt.hit();
		}
		finally {
			thread.setState(state);
		}
	}

	private void processEventNotifyExit(long ctlid, TargetExecutionState state,
			SctlExitNotification exit) {
		SctlTargetThread thread = session.processes.requireThread(ctlid);
		try {
			thread.registers.updateContextIfPresent(exit.getCtx());

			thread.setExitStatusCode(exit.status);
			thread.destroy("Exited");
		}
		finally {
			thread.setState(state);
		}
	}

	private void processEventNotifyExec(long ctlid, TargetExecutionState state,
			SctlExecNotification exec) {
		SctlTargetThread thread = session.processes.requireThread(ctlid);
		try {
			thread.registers.updateContextIfPresent(exec.getCtx());

			// Destroy all but the calling thread, according to execve man page
			// NOTE: Sctl assumes the client knows that exec destroys all other threads
			thread.process.threads.removeOthers(thread, "Other execed");
			thread.process.invalidateStat(); // my best guess based on what exec does
			thread.breakpoints.clear(); // From the SCTL manual
		}
		finally {
			thread.setState(state);
		}
	}

	private void processEventNotifySignal(long ctlid, TargetExecutionState state,
			SctlSignalNotification signal) {
		SctlTargetThread thread = session.processes.requireThread(ctlid);
		try {
			thread.registers.updateContextIfPresent(signal.getCtx());
		}
		finally {
			thread.setState(state);
		}
	}

	private void processEventNotifySyscall(long ctlid, TargetExecutionState state,
			SctlSyscallNotification syscall) {
		SctlTargetThread thread = session.processes.requireThread(ctlid);
		try {
			thread.registers.updateContextIfPresent(syscall.getCtx());
		}
		finally {
			thread.setState(state);
		}
	}

	private void processEventNotify(SctlEventNotify sel) {
		//Msg.debug(this, "Event: " + sel);

		Set<AbstractSctlEventNotification> events = sel.getAllEvents();
		if (events.size() > 1) {
			Msg.warn(this, "More than one event in a notification....: " + events);
		}
		AbstractSctlEventNotification details = events.iterator().next();
		TargetExecutionState state = activeDialect.stateAfterEvent(sel.flags);
		if (details instanceof AbstractSctlListsLibrariesEventNotification) {
			processEventNotifyListsLibraries(sel.ctlid, state,
				(AbstractSctlListsLibrariesEventNotification) details);
		}
		else if (details instanceof AbstractSctlForkNotification) {
			processEventNotifyForkClone(sel.ctlid, state,
				(AbstractSctlForkNotification) details, "Forked");
		}
		else if (details instanceof SctlCloneNotification) {
			processEventNotifyForkClone(sel.ctlid, state,
				(SctlCloneNotification) details, "Cloned");
		}
		else if (details instanceof SctlTrapNotification) {
			processEventNotifyTrap(sel.ctlid, state, (SctlTrapNotification) details);
		}
		else if (details instanceof Sctl2012SnapNotification) {
			processEventNotifySnap(sel.ctlid, state, (Sctl2012SnapNotification) details);
		}
		else if (details instanceof SctlExitNotification) {
			processEventNotifyExit(sel.ctlid, state, (SctlExitNotification) details);
		}
		else if (details instanceof SctlExecNotification) {
			processEventNotifyExec(sel.ctlid, state, (SctlExecNotification) details);
		}
		else if (details instanceof SctlSignalNotification) {
			processEventNotifySignal(sel.ctlid, state, (SctlSignalNotification) details);
		}
		else if (details instanceof SctlSyscallNotification) {
			processEventNotifySyscall(sel.ctlid, state, (SctlSyscallNotification) details);
		}
		else {
			throw new IllegalArgumentException("details of type " + details.getClass().toString());
		}
	}

	/**
	 * Generate the next tag
	 * 
	 * This always generates a tag in the SCTL-bus form. Even in non-bus dialects. Since the server
	 * need only echo the same tag in the reply, this should be backward compatible.
	 * 
	 * @return the next tag
	 */
	@SctlExtension("This generates bus tags, but they are compatible with non-bus tags")
	private synchronized int tag() {
		int result = nextTag;
		nextTag++;
		// This scheme should not cause a problem for non-bus implementations
		// TODO: Should I just incorporate this directly into the packet structure?
		nextTag &= 0x00ffffff;
		return result | (idOnBus << 24);
	}

	/**
	 * Performs generic checks on a SCTL reply
	 * 
	 * Namely, this checks if the reply is an {@code Rerror}. If it is, it copies the message and
	 * throws a {@link SctlError}. Then, it checks if the reply is of the expected type. If not, it
	 * throws a {@link SctlIncorrectReply}. Otherwise, it returns the reply cast to the expected
	 * type.
	 * 
	 * @param cmd the command whose tag matches that of the reply
	 * @param pktType the expected type of the reply
	 * @param reply the reply actually received
	 * @return the reply cast to the expected type
	 * @throws SctlError if the reply is an {@code Rerror}
	 * @throws SctlIncorrectReply if the reply is not of the expected type
	 */
	protected static <R extends SctlPacket> R checkReply(SctlPacket cmd, Class<R> pktType,
			SctlPacket reply) {
		if (reply instanceof SctlErrorReply) {
			throw new SctlError((SctlErrorReply) reply);
		}
		if (pktType.isAssignableFrom(reply.getClass())) {
			return pktType.cast(reply);
		}
		throw new SctlIncorrectReply(cmd, reply);
	}

	/*
	 * Methods for Tversion
	 */

	public CompletableFuture<Void> connect() {
		SctlVersionRequest req = SctlVersionInfo.makeRequest(restrictedDialects);
		return sequence(TypeSpec.VOID).then((seq) -> {
			if (connectionState != ConnectionState.INITIAL) {
				throw new SctlError("Client has already connected");
			}
			Msg.trace(this, "Connecting");

			connectionState = ConnectionState.CONNECTING;
			CompletableFuture<SctlPacket> cmd = sendCommand(req);
			cmd.handle(seq::next);
			// receive loop is not yet running, so receive exactly the version reply in parallel
			packetChannel.read(AbstractSelSctlPacket.class).thenAccept((pkt) -> {
				packetMatcher.fulfill(pkt.tag, pkt.sel);
			});
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			SctlVersionReply version = finishConnect(req, reply);
			// This doesn't go in finishConnect, because a bus connect is not our connect
			SctlDialect dialect = SctlVersionInfo.agreeDialect(version.version);
			synchronized (this) {
				activeDialect = dialect;
				marshaller.setPacketFactory(dialect.getPacketFactory());
			}
			receiveLoop(); // in parallel. Performs command callbacks
			fireConnectionEstablished();
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusConnect(int tag, SctlVersionRequest req) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishConnect(req, reply);
			seq.exit();
		}).finish();
	}

	private SctlVersionReply finishConnect(SctlVersionRequest req, SctlPacket reply) {
		return checkReply(req, SctlVersionReply.class, reply);
	}

	/*
	 * Misc message-handling
	 */

	private void receiveLoop() {
		loop(TypeSpec.VOID, (loop) -> {
			if (connectionState.isTerminate) {
				loop.exit();
				return;
			}
			//Msg.trace(this, "Queueing receive");
			packetChannel.read(AbstractSelSctlPacket.class).handle(loop::consume);
		}, TypeSpec.cls(AbstractSelSctlPacket.class), (rcvd, loop) -> {
			loop.repeat(); // Don't get hung up servicing listeners before processing next packet
			//Msg.debug(this, "Received: " + rcvd);

			if (rcvd.sel instanceof SctlEventNotify) {
				processEventNotify((SctlEventNotify) rcvd.sel);
			}
			else if (rcvd.sel instanceof AbstractSctlRequest) {
				processBusRequest(rcvd.tag, (AbstractSctlRequest) rcvd.sel);
			}
			else {
				packetMatcher.fulfill(rcvd.tag, rcvd.sel);
			}
		}).exceptionally((exc) -> {
			if (exc instanceof CompletionException) {
				exc = exc.getCause();
			}
			if (exc instanceof NotYetConnectedException) {
				throw new AssertionError("INTERNAL: Connect first, please", exc);
			}
			else if (exc instanceof EOFException) {
				Msg.error(this, "Server closed connection");
				fireConnectionClosed(DebuggerModelClosedReason.abnormal(exc));
			}
			else if (exc instanceof ClosedChannelException) {
				Msg.info(this, "Client closed connection");
				connectionState = ConnectionState.DISCONNECTED;
			}
			else if (exc instanceof CancelledKeyException) {
				Msg.info(this, "Terminating receive loop: Connection closed.");
				connectionState = ConnectionState.DISCONNECTED;
			}
			else {
				Msg.error(this, "Receive failed for an unknown reason", exc);
				fireConnectionClosed(DebuggerModelClosedReason.abnormal(exc));
			}
			return null;
		});
	}

	@Override
	public CompletableFuture<Void> close() {
		connectionState = ConnectionState.DISCONNECTED;
		fireConnectionClosed(DebuggerModelClosedReason.normal());
		// No close notifications to send, and I'm not responsible to close the channel
		return AsyncUtils.NIL;
	}

	/**
	 * Send the given command and wait on its reply
	 * 
	 * The method follows the asynchronous pattern: It immediately returns a future that will
	 * complete at a later time. It completes with the corresponding reply received from the server.
	 * This is accomplished using an {@link AsyncPairingCache} on the tag. A tag is assigned
	 * automatically, and the cache matches it to that of the received reply. If the reply is not
	 * received within a given timeout, the returned future is completed exceptionally. Multiple
	 * commands may be sent before any reply is received.
	 * 
	 * @param cmd the command to send
	 * @return a future that completes with the corresponding reply
	 */
	protected CompletableFuture<SctlPacket> sendCommand(SctlPacket cmd) {
		AbstractSelSctlPacket pkt = activeDialect.createSel(tag(), cmd);
		//Msg.debug(this, "Sending: " + pkt);
		checkOpen();
		return packetChannel.write(pkt).thenCompose(__ -> {
			//Msg.trace(this, "Sent tag " + pkt.tag);
			checkOpen();
			return packetMatcher.waitOn(pkt.tag);
		});
	}

	/**
	 * Wait for a reply to a command that is not sent by this client
	 * 
	 * This method is used for bus commands. It can also be used in circumstances where the command
	 * is sent by some means other than {@link #sendCommand(SctlPacket)}. It does the same thing
	 * without sending any command. It returns a future which completes with the reply having the
	 * given tag.
	 * 
	 * @param tag the tag from the command
	 * @return a future that completes with the corresponding reply
	 */
	protected CompletableFuture<SctlPacket> recvTag(int tag) {
		return sequence(TypeSpec.cls(SctlPacket.class)).then(seq -> {
			checkOpen();
			packetMatcher.waitOn(tag).handle(seq::exit);
		}).finish();
	}

	/*
	 * Methods for Tping
	 */

	@Override
	public CompletableFuture<Void> ping(String content) {
		SctlPingRequest req = new SctlPingRequest(content);
		return sequence(TypeSpec.VOID).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishPing(req, reply);
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusPing(int tag, SctlPingRequest req) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishPing(req, reply);
			seq.exit();
		}).finish();
	}

	protected void finishPing(SctlPingRequest req, SctlPacket reply) {
		SctlPingReply pinged = checkReply(req, SctlPingReply.class, reply);
		int expected = req.bytes.length;
		if (pinged.cnt != expected) {
			throw new SctlIncorrectPingResponse(req.bytes, expected, (int) pinged.cnt);
		}
	}

	/*
	 * Methods for Texec
	 * 
	 * NOTE: This command is not actually part of the SCTL specification.
	 */

	@SctlExtension("requests execution of a CLI command")
	protected CompletableFuture<String> executeCapture(String cmd) {
		SctlExecuteRequest req = new SctlExecuteRequest(cmd);
		return sequence(TypeSpec.STRING).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishExecute(req, reply));
		}).finish();
	}

	private CompletableFuture<String> processBusExecute(int tag, SctlExecuteRequest req) {
		return sequence(TypeSpec.STRING).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishExecute(req, reply));
		}).finish();
	}

	protected String finishExecute(SctlExecuteRequest req, SctlPacket reply) {
		SctlExecuteReply executed = SctlClient.checkReply(req, SctlExecuteReply.class, reply);
		return executed.out.str;
	}

	/*
	 * Methods for Tps
	 */
	protected CompletableFuture<List<SctlTargetAttachable>> listAttachable() {
		SctlProcessListRequest req = new SctlProcessListRequest();
		return sequence(TypeSpec.cls(SctlTargetAttachable.class).list()).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishListAttachable(req, reply));
		}).finish();
	}

	protected List<SctlTargetAttachable> finishListAttachable(SctlProcessListRequest req,
			SctlPacket reply) {
		SctlProcessListReply procs = SctlClient.checkReply(req, SctlProcessListReply.class, reply);
		return readProcessList(procs);
	}

	private CompletableFuture<List<SctlTargetAttachable>> processBusListAttachable(int tag,
			SctlProcessListRequest req) {
		return sequence(TypeSpec.cls(SctlTargetAttachable.class).list()).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishListAttachable(req, reply));
		}).finish();
	}

	protected List<SctlTargetAttachable> readProcessList(SctlProcessListReply reply) {
		List<? extends AbstractSctlProcessEntry> procList = reply.pslist.getProcesses();
		List<SctlTargetAttachable> result = new ArrayList<>(procList.size());
		for (AbstractSctlProcessEntry procEnt : procList) {
			result.add(new SctlTargetAttachable(session.attachable, procEnt.getProcessID(),
				procEnt.getCommand()));
		}
		session.attachable.changeElements(List.of(), result, "Retreived process list");
		return result;
	}

	/*
	 * Methods for Tstat
	 */

	// Doesn't return anything, rather updates internal info
	protected CompletableFuture<Void> stat(long ctlid) {
		SctlStatusRequest req = new SctlStatusRequest(ctlid);
		return sequence(TypeSpec.VOID).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishStat(req, reply);
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusStat(int tag, SctlStatusRequest req) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishStat(req, reply);
			seq.exit();
		}).finish();
	}

	protected void finishStat(SctlStatusRequest req, SctlPacket reply) {
		SctlStatusReply stats = checkReply(req, SctlStatusReply.class, reply);
		//Msg.info(this, stats);
		synchronized (this) {
			SctlTargetProcess proc = session.processes.getByCtlid(req.ctlid);
			if (proc == null) {
				Msg.warn(this, "Process removed before stat reply: ctlid=" + req.ctlid);
				return;
			}
			populateStat(proc, stats.status);
		}
	}

	protected void populateStat(SctlTargetProcess proc, AbstractSctlStatus status) {
		if (status.supportsProcessID()) {
			proc.setPid(status.getProcessID());
		}

		for (AbstractSctlRegion region : status.getRegions()) {
			try {
				proc.createMemoryRegion(region.getName(), region.getAddress(), region.getLength(),
					region.getProtections());
			}
			catch (AddressOverflowException e) {
				Msg.error(this, "Invalid region in SCTL response: " + region.getName() + ": " + e);
			}
		}

		for (AbstractSctlBinary bin : status.getBinaries()) {
			Address base = null;
			if (bin.supportsBase()) {
				base = addrMapper.mapOffsetToAddress(bin.getBase());
			}
			SctlTargetModule mod =
				proc.modules.create(bin.getNamespaceID(), bin.getPath(), base, bin.isExecutable());
			if (bin.supportsSections()) {
				for (AbstractSctlSection s : bin.getSections()) {
					Address start = addrMapper.mapOffsetToAddress(s.getAddress());
					mod.addSection(s.getName(), start, s.getLength());
				}
				mod.updateRange();
			}
		}
	}

	/*
	 * Methods for Tattach
	 */

	protected CompletableFuture<SctlTargetThread> attach(long pid) {
		SctlAttachRequest req = new SctlAttachRequest(pid);
		return sequence(TypeSpec.cls(SctlTargetThread.class)).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishAttach(req, reply));
		}).finish();
	}

	private CompletableFuture<SctlTargetThread> processBusAttach(int tag, SctlAttachRequest req) {
		return sequence(TypeSpec.cls(SctlTargetThread.class)).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishAttach(req, reply));
		}).finish();
	}

	protected SctlTargetThread finishAttach(SctlAttachRequest req, SctlPacket reply) {
		AbstractSctlAttachReply attached = checkReply(req, AbstractSctlAttachReply.class, reply);
		SctlTargetProcess proc = session.processes.getByPid(req.pid);
		if (proc == null) {
			String platform = attached.supportsPlatform() ? attached.getPlatform()
					: activeDialect.getSolePlatform();
			proc = session.processes.create(attached.ctlid, req.pid, platform);
		}
		SctlTargetThread newThread = proc.createThread(attached.ctlid, "Attached");
		newThread.registers.updateContextIfPresent(attached.ctx);
		return newThread;
	}

	/*
	 * Methods for Tlaunch
	 */

	protected CompletableFuture<SctlTargetThread> launch(List<String> args) {
		SctlLaunchRequest req = new SctlLaunchRequest(args);
		return sequence(TypeSpec.cls(SctlTargetThread.class)).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishLaunch(req, reply));
		}).finish();
	}

	private CompletableFuture<SctlTargetThread> processBusLaunch(int tag, SctlLaunchRequest req) {
		return sequence(TypeSpec.cls(SctlTargetThread.class)).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishLaunch(req, reply));
		}).finish();
	}

	protected SctlTargetThread finishLaunch(SctlLaunchRequest req, SctlPacket reply) {
		AbstractSctlLaunchReply launched = checkReply(req, AbstractSctlLaunchReply.class, reply);
		long ctlid = launched.ctlid;
		Long pid = launched.supportsProcessID() ? launched.getProcessID() : null;
		String platform = launched.supportsPlatform() ? launched.getPlatform()
				: activeDialect.getSolePlatform();
		SctlTargetProcess newProc = session.processes.create(ctlid, pid, platform);
		SctlTargetThread newThread = newProc.createThread(ctlid, "Launched");
		newThread.registers.updateContextIfPresent(launched.ctx);
		return newThread;
	}

	/*
	 * Methods for Tcont
	 */

	protected CompletableFuture<Void> resume(long ctlid) {
		SctlContinueRequest req = new SctlContinueRequest(ctlid);
		return sequence(TypeSpec.VOID).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishResume(req, reply);
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusResume(int tag, SctlContinueRequest req) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishResume(req, reply);
			seq.exit();
		}).finish();
	}

	protected void finishResume(SctlContinueRequest req, SctlPacket reply) {
		checkReply(req, SctlContinueReply.class, reply);
		session.processes.requireThread(req.ctlid).setState(TargetExecutionState.RUNNING);
	}

	/*
	 * Methods for Tstep
	 */

	CompletableFuture<Void> step(long ctlid) {
		SctlStepRequest req = new SctlStepRequest(ctlid);
		return sequence(TypeSpec.VOID).then((seq) -> {
			sendCommand(req).handle(seq::next);
			// Assume it's running at this point, but I don't really know
			session.processes.requireThread(ctlid).setState(TargetExecutionState.RUNNING);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishStep(req, reply);
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusStep(int tag, SctlStepRequest req) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			// Assume it's running at this point, but I don't really know
			session.processes.requireThread(req.ctlid).setState(TargetExecutionState.RUNNING);
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishStep(req, reply);
			seq.exit();
		}).finish();
	}

	protected void finishStep(SctlStepRequest req, SctlPacket reply) {
		SctlTargetThread thread = session.processes.requireThread(req.ctlid);
		try {
			SctlStepReply stepped = checkReply(req, SctlStepReply.class, reply);
			thread.registers.updateContextIfPresent(stepped.ctx);
		}
		finally {
			// Assume we're stopped whether or not there's an error
			thread.setState(TargetExecutionState.STOPPED);
		}
	}

	/*
	 * Methods for Tsnap
	 */

	protected CompletableFuture<SctlTargetThread> snap(long ctlid) {
		SctlSnapshotRequest req = new SctlSnapshotRequest(ctlid);
		return sequence(TypeSpec.cls(SctlTargetThread.class)).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishSnap(req, reply));
		}).finish();
	}

	private CompletableFuture<SctlTargetThread> processBusSnap(int tag,
			SctlSnapshotRequest req) {
		return sequence(TypeSpec.cls(SctlTargetThread.class)).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishSnap(req, reply));
		}).finish();
	}

	protected SctlTargetThread finishSnap(SctlSnapshotRequest req, SctlPacket reply) {
		AbstractSctlSnapshotReply snapped = checkReply(req, AbstractSctlSnapshotReply.class, reply);
		SctlTargetThread origThread = session.processes.requireThread(req.ctlid);
		// snap is implemented via fork, so a new process!
		Long pid = snapped.supportsProcessID() ? snapped.getProcessID() : null;
		SctlTargetProcess newProc =
			session.processes.create(snapped.spwnid, pid, origThread.process.platform);
		SctlTargetThread newThread = newProc.createThread(snapped.spwnid, "Snapshotted");
		newThread.registers.updateContextIfPresent(snapped.ctx);
		return newThread;
	}

	/*
	 * Methods for Tstop
	 */

	protected CompletableFuture<Void> interrupt(long ctlid) {
		SctlStopRequest req = new SctlStopRequest(ctlid);
		return sequence(TypeSpec.VOID).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishInterrupt(req, reply);
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusInterrupt(int tag, SctlStopRequest req) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishInterrupt(req, reply);
			seq.exit();
		}).finish();
	}

	protected void finishInterrupt(SctlStopRequest req, SctlPacket reply) {
		checkReply(req, SctlStopReply.class, reply);
		session.processes.requireThread(req.ctlid).setState(TargetExecutionState.STOPPED);
	}

	/*
	 * Methods for Tread
	 */

	protected CompletableFuture<byte[]> readMemory(long ctlid, long addr, int len) {
		SctlReadRequest req = new SctlReadRequest(ctlid, -1, addr, len);
		return sequence(TypeSpec.BYTE_ARRAY).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishReadMemory(req, reply));
		}).finish();
	}

	private CompletableFuture<byte[]> processBusReadMemory(int tag, SctlReadRequest req) {
		return sequence(TypeSpec.BYTE_ARRAY).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			byte[] data = finishReadMemory(req, reply);
			SctlTargetThread thread = session.processes.requireThread(req.ctlid);
			thread.process.memory.notifyUpdate(req.offset, data);
			seq.exit(data);
		}).finish();
	}

	protected byte[] finishReadMemory(SctlReadRequest req, SctlPacket reply) {
		SctlReadReply read = checkReply(req, SctlReadReply.class, reply);
		return read.bytes;
	}

	/*
	 * Methods for Twrite
	 */

	protected CompletableFuture<Void> writeMemory(long ctlid, long addr, byte[] data) {
		SctlWriteRequest req = new SctlWriteRequest(ctlid, -1, addr, data);
		return sequence(TypeSpec.VOID).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishWriteMemory(req, reply);
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusWriteMemory(int tag, SctlWriteRequest req) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishWriteMemory(req, reply);
			SctlTargetThread thread = session.processes.requireThread(req.ctlid);
			thread.process.memory.notifyUpdate(req.offset, req.bytes);
			seq.exit();
		}).finish();
	}

	protected void finishWriteMemory(SctlWriteRequest req, SctlPacket reply) {
		SctlWriteReply written = checkReply(req, SctlWriteReply.class, reply);
		if (req.bytes.length != written.cnt) {
			throw new SctlPartialWriteException(req.bytes, (int) written.cnt);
		}
	}

	/*
	 * Methods for Tgetctx
	 * 
	 * Actually, these use the context sent by the last notification message
	 */

	private Map<String, byte[]> checkCtxAvail(SctlTargetThread thread) {
		if (!thread.registers.hasContextSinceStop() ||
			thread.getExecutionState() != TargetExecutionState.STOPPED) {
			throw new IllegalStateException("Thread is not stopped, or has no valid context");
		}
		return thread.registers.getContext();
	}

	protected CompletableFuture<Map<String, byte[]>> getContext(long ctlid) {
		SctlGetContextRequest req = new SctlGetContextRequest(ctlid);
		SctlTargetThread thread = session.processes.requireThread(ctlid);
		return sequence(TypeSpec.map(String.class, byte[].class)).then(seq -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishGetContext(req, reply);
			seq.exit(thread.registers.getContext());
		}).finish();
	}

	private CompletableFuture<Void> processBusGetContext(int tag, SctlGetContextRequest req) {
		return sequence(TypeSpec.VOID).then(seq -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishGetContext(req, reply);
			seq.exit();
		}).finish();
	}

	protected void finishGetContext(SctlGetContextRequest req, SctlPacket reply) {
		SctlGetContextReply get = checkReply(req, SctlGetContextReply.class, reply);
		SctlTargetThread thread = session.processes.requireThread(req.ctlid);
		thread.registers.updateContextIfPresent(get.ctx);
	}

	protected void checkRegisterSelectionSupported() {
		if (!activeDialect.isRegisterSelectionSupported()) {
			throw new IllegalStateException(
				activeDialect.getFullVersion() + " does not support register selection");
		}
	}

	protected CompletableFuture<Map<String, SctlRegisterDefinition>> enumerateContext(long ctlid) {
		checkRegisterSelectionSupported();
		SctlEnumerateContextRequest req = new SctlEnumerateContextRequest(ctlid);
		return sequence(TypeSpec.map(String.class, SctlRegisterDefinition.class)).then(seq -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishEnumerateContext(req, reply));
		}).finish();
	}

	private CompletableFuture<Void> processBusEnumerateContext(int tag,
			SctlEnumerateContextRequest req) {
		checkRegisterSelectionSupported(); // If not, we might be in deep deep doo doo
		// The server ought to also reject it, so we'll log it and pretend it didn't happen.
		SctlTargetThread thread = session.processes.requireThread(req.ctlid);
		return sequence(thread.registers.lazyRegDefs.provide()).then(seq -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishEnumerateContext(req, reply));
		}).finish().thenApply(t -> null);
	}

	protected Map<String, SctlRegisterDefinition> finishEnumerateContext(
			SctlEnumerateContextRequest req, SctlPacket reply) {
		SctlEnumerateContextReply enumed = checkReply(req, SctlEnumerateContextReply.class, reply);
		Map<String, SctlRegisterDefinition> result = new LinkedHashMap<>();
		for (SctlRegisterDefinition def : enumed.regdefs) {
			result.put(def.name.str, def);
		}
		return result;
	}

	protected synchronized CompletableFuture<Void> chooseContext(long ctlid,
			Set<SctlTargetRegisterDescription> descs) {
		checkRegisterSelectionSupported();
		SctlTargetThread thread = session.processes.requireThread(ctlid);
		SctlChooseContextRequest req = new SctlChooseContextRequest(ctlid);
		List<SctlRegisterDefinition> selDefs = new ArrayList<>();
		return sequence(TypeSpec.VOID).then(seq -> {
			thread.registers.lazyRegDefs.request().handle(seq::next);
		}, TypeSpec.map(String.class, SctlRegisterDefinition.class)).then((defs, seq) -> {
			for (SctlTargetRegisterDescription trd : descs) {
				String name = trd.getName();
				SctlRegisterDefinition d = defs.get(name);
				if (d == null) {
					throw new IllegalArgumentException("No register with name " + name);
				}
				req.regids.add(d.regid);
				selDefs.add(d);
			}
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishChooseContext(req, reply, selDefs, descs, null, null);
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusChooseContext(int tag, SctlChooseContextRequest req) {
		checkRegisterSelectionSupported(); // If not, we might be in deep deep doo doo
		// The server ought to also reject it, so we'll log it and pretend it didn't happen.
		AtomicReference<SctlPacket> recvd = new AtomicReference<>();
		AtomicReference<Map<Long, SctlRegisterDefinition>> defsById = new AtomicReference<>();
		AtomicReference<Map<String, SctlTargetRegisterDescription>> descsByName =
			new AtomicReference<>();
		SctlTargetThread thread = session.processes.requireThread(req.ctlid);
		return sequence(TypeSpec.VOID).then(seq -> {
			AsyncFence fence = new AsyncFence();
			fence.include(recvTag(tag).thenAccept(recvd::set));
			fence.include(thread.registers.lazyRegDefsById.request().thenAccept(defsById::set));
			fence.include(thread.registers.lazyRegDescs.request().thenAccept(descsByName::set));
			fence.ready().handle(seq::next);
		}).then(seq -> {
			finishChooseContext(req, recvd.get(), null, null, defsById.get(), descsByName.get());
			seq.exit();
		}).finish();
	}

	void finishChooseContext(SctlChooseContextRequest req, SctlPacket reply,
			List<SctlRegisterDefinition> selDefs, Set<SctlTargetRegisterDescription> descs,
			Map<Long, SctlRegisterDefinition> defsById,
			Map<String, SctlTargetRegisterDescription> descsByName) {
		SctlChooseContextReply choose = checkReply(req, SctlChooseContextReply.class, reply);
		if (selDefs == null) {
			selDefs = new ArrayList<>();
			descs = new LinkedHashSet<>();
			for (long id : req.regids) {
				SctlRegisterDefinition def = defsById.get(id);
				if (def == null) {
					throw new AssertionError("Bus client chose a non-existent register id");
				}
				selDefs.add(def);
				SctlTargetRegisterDescription trd = descsByName.get(def.name.str);
				if (trd == null) {
					throw new AssertionError(); // INTERNAL consistency check
				}
				descs.add(trd);
			}
		}
		SctlTargetThread thread = session.processes.requireThread(req.ctlid);
		thread.registers.setSelectedRegisters(selDefs);
		thread.registers.updateContextIfPresent(choose.ctx);
	}

	protected CompletableFuture<Map<String, byte[]>> readRegisters(long ctlid) {
		SctlTargetThread thread = session.processes.requireThread(ctlid);
		if (thread.getExecutionState() == TargetExecutionState.RUNNING) {
			return CompletableFuture.failedFuture(new IllegalStateException("Thread is running"));
		}
		if (thread.registers.hasContextSinceStop()) {
			return CompletableFuture.completedFuture(thread.registers.getContext());
		}
		return getContext(ctlid);
	}

	protected CompletableFuture<byte[]> readSingleRegister(long ctlid, String regname) {
		return sequence(TypeSpec.BYTE_ARRAY).then(seq -> {
			readRegisters(ctlid).handle(seq::next);
		}, TypeSpec.map(String.class, byte[].class)).then((regs, seq) -> {
			byte[] val = regs.get(regname);
			if (val == null) {
				throw new IllegalArgumentException(
					"Register " + regname + " is not in the context");
			}
			seq.exit(val);
		}).finish();
	}

	/*
	 * Methods for Tsetctx
	 */

	protected CompletableFuture<Void> setContext(long ctlid, AbstractSctlContext ctx) {
		SctlSetContextRequest req = new SctlSetContextRequest(ctlid, ctx);
		return sequence(TypeSpec.VOID).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishSetContext(req, reply);
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusSetContext(int tag, SctlSetContextRequest req) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishSetContext(req, reply);
			seq.exit();
		}).finish();
	}

	protected void finishSetContext(SctlSetContextRequest req, SctlPacket reply) {
		checkReply(req, SctlSetContextReply.class, reply);
		session.processes.requireThread(req.ctlid).registers.updateContextIfPresent(req.ctx);
	}

	protected CompletableFuture<Void> writeRegisters(long ctlid, Map<String, byte[]> vals) {
		try {
			SctlTargetThread thread = session.processes.requireThread(ctlid);
			AbstractSctlContext ctx = activeDialect.create(AbstractSctlContext.class);
			ctx.setSelectedRegisters(thread.registers.getSelectedRegisters());

			if (!vals.keySet().containsAll(ctx.getRegisterNames())) {
				ctx.updateFromMap(checkCtxAvail(thread));
			}
			ctx.updateFromMap(vals);
			return setContext(ctlid, ctx);
		}
		catch (Exception e) {
			return CompletableFuture.failedFuture(e);
		}
	}

	synchronized CompletableFuture<Void> writeSingleRegister(long ctlid, String regname,
			byte[] data) {
		try {
			SctlTargetThread thread = session.processes.requireThread(ctlid);
			AbstractSctlContext ctx = activeDialect.create(AbstractSctlContext.class);
			ctx.setSelectedRegisters(thread.registers.getSelectedRegisters());

			ctx.updateFromMap(checkCtxAvail(thread));
			ctx.update(regname, data);
			return setContext(ctlid, ctx);
		}
		catch (Exception e) {
			return CompletableFuture.failedFuture(e);
		}
	}

	/*
	 * Methods for Tsettrap
	 */

	protected CompletableFuture<SctlTargetBreakpoint> setTrap(long ctlid, Address address,
			long length, boolean read, boolean write, boolean execute) {
		AbstractSctlTrapSpec spec = activeDialect.create(AbstractSctlTrapSpec.class);
		long offset = addrMapper.mapAddressToOffset(address);
		spec.setActionStop();
		spec.setAddress(offset);
		spec.setLength(length);
		spec.setHardware(read, write, execute);
		SctlSetTrapRequest req = new SctlSetTrapRequest(ctlid, spec);
		return sequence(TypeSpec.cls(SctlTargetBreakpoint.class)).then(seq -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishSetTrap(req, reply));
		}).finish();
	}

	private CompletableFuture<SctlTargetBreakpoint> processBusSetTrap(int id, int tag,
			SctlSetTrapRequest req) {
		return sequence(TypeSpec.cls(SctlTargetBreakpoint.class)).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			SctlTargetBreakpoint bpt = finishSetTrap(req, reply);
			seq.exit(bpt);
		}).finish();
	}

	protected SctlTargetBreakpoint finishSetTrap(SctlSetTrapRequest req, SctlPacket reply) {
		SctlSetTrapReply set = checkReply(req, SctlSetTrapReply.class, reply);
		SctlTargetThread thread = session.processes.requireThread(req.ctlid);
		SctlTargetBreakpoint bpt = thread.createBreakpoint(set.trpid, req.spec.getAddress());
		return bpt;
	}

	/*
	 * Methods for Tclrtrap
	 */

	protected CompletableFuture<Void> clearTrap(long ctlid, long trpid) {
		SctlClearTrapRequest req = new SctlClearTrapRequest(ctlid, trpid);
		return sequence(TypeSpec.VOID).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishClearTrap(req, reply);
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusClearTrap(int tag, SctlClearTrapRequest req) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishClearTrap(req, reply);
			seq.exit();
		}).finish();
	}

	protected void finishClearTrap(SctlClearTrapRequest req, SctlPacket reply) {
		checkReply(req, SctlClearTrapReply.class, reply);
		session.processes.requireThread(req.ctlid).destroyBreakpoint(req.trpid);
	}

	/*
	 * Methods for Tdetach
	 */

	protected CompletableFuture<Void> detachThread(long ctlid) {
		SctlDetachRequest req = new SctlDetachRequest(ctlid);
		return sequence(TypeSpec.VOID).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishDetach(req, reply);
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusDetachThread(int tag, SctlDetachRequest req) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishDetach(req, reply);
			seq.exit();
		}).finish();
	}

	protected void finishDetach(SctlDetachRequest req, SctlPacket reply) {
		checkReply(req, SctlDetachReply.class, reply);
		session.processes.destroyThread(req.ctlid, "Detached");
	}

	/*
	 * Methods for Tkill
	 */

	protected CompletableFuture<Void> killThread(long ctlid) {
		SctlKillRequest req = new SctlKillRequest(ctlid);
		return sequence(TypeSpec.VOID).then((seq) -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishKill(req, reply);
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusKillThread(int tag, SctlKillRequest req) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishKill(req, reply);
			seq.exit();
		}).finish();
	}

	protected void finishKill(SctlKillRequest req, SctlPacket reply) {
		checkReply(req, SctlKillReply.class, reply);
		session.processes.destroyThread(req.ctlid, "Killed");
	}

	@SctlExtension("Cause the debugger to select a given thread")
	protected CompletableFuture<Void> focusThread(long ctlid) {
		SctlFocusRequest req = new SctlFocusRequest(ctlid);
		return sequence(TypeSpec.VOID).then(seq -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishFocus(req, reply);
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusFocusThread(int tag, SctlFocusRequest req) {
		return sequence(TypeSpec.VOID).then(seq -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishFocus(req, reply);
			seq.exit();
		}).finish();
	}

	protected void finishFocus(SctlFocusRequest req, SctlPacket reply) {
		checkReply(req, SctlFocusReply.class, reply);
		SctlTargetThread thread = session.processes.requireThread(req.ctlid);
		session.fireFocused(thread);
	}

	/**
	 * The given path must be relative to the "Objects" sub-tree
	 * 
	 * @param path the path, relative to ["Objects"]
	 * @return the attributes of the object at the given path
	 */
	protected CompletableFuture<Map<String, TargetObject>> getAttributes(List<String> path) {
		String joinedPath = StringUtils.join(path, SctlTargetObject.PATH_SEPARATOR_STRING);
		SctlGetAttributesRequest req = new SctlGetAttributesRequest(joinedPath);
		return sequence(TypeSpec.map(String.class, TargetObject.class)).then(seq -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishGetAttributes(req, reply));
		}).finish();
	}

	private CompletableFuture<Void> processBusGetAttributes(int tag,
			SctlGetAttributesRequest req) {
		return sequence(TypeSpec.VOID).then(seq -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishGetAttributes(req, reply);
			seq.exit(null, null);
		}).finish();
	}

	protected Map<String, TargetObject> finishGetAttributes(SctlGetAttributesRequest req,
			SctlPacket reply) {
		SctlGetAttributesReply attr = checkReply(req, SctlGetAttributesReply.class, reply);
		Map<String, TargetObject> map = new LinkedHashMap<String, TargetObject>();
		for (AbstractSctlObjectEntry obj : attr.attributes) {
			String joinedPath = obj.getPath().str;
			List<String> path = new ArrayList<>();
			path.addAll(session.objects.getPath());
			path.addAll(List.of(joinedPath.split(SctlTargetObject.PATH_SEPARATOR_REGEX)));
			SctlTargetObject tobj;
			try {
				tobj = session.objects.create(obj.getKey().str, path, obj.getKind().str,
					obj.getValue().str, obj.getType().str);
			}
			catch (InvalidObjectException e) {
				Msg.error(this, e);
				return map;
			}
			map.put(obj.getKey().str, tobj);
		}
		session.objects.notifyAttributes(req.path.str, map);
		return map;
	}

	protected CompletableFuture<Map<String, TargetObject>> getElements(List<String> path) {
		String joinedPath = StringUtils.join(path, SctlTargetObject.PATH_SEPARATOR_STRING);
		SctlGetElementsRequest req = new SctlGetElementsRequest(joinedPath);
		return sequence(TypeSpec.map(String.class, TargetObject.class)).then(seq -> {
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishGetElements(req, reply));
		}).finish();
	}

	private CompletableFuture<Void> processBusGetElements(int tag, SctlGetElementsRequest req) {
		return sequence(TypeSpec.VOID).then(seq -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishGetElements(req, reply);
			seq.exit(null, null);
		}).finish();
	}

	protected Map<String, TargetObject> finishGetElements(SctlGetElementsRequest req,
			SctlPacket reply) {
		SctlGetElementsReply result = checkReply(req, SctlGetElementsReply.class, reply);
		Map<String, TargetObject> map = new LinkedHashMap<>();
		for (AbstractSctlObjectEntry obj : result.elements) {
			String joinedPath = obj.getPath().str;
			List<String> path = new ArrayList<>();
			for (String str : joinedPath.split(SctlTargetObject.PATH_SEPARATOR_REGEX)) {
				path.add(str);
			}
			SctlTargetObject tobj;
			try {
				tobj = session.objects.create(obj.getKey().str, path, obj.getKind().str,
					obj.getValue().str, obj.getType().str);
			}
			catch (InvalidObjectException e) {
				Msg.error(this, e);
				return map;
			}
			map.put(tobj.getName(), tobj);
		}
		session.objects.notifyElements(req.path.str, map);
		return map;
	}

	/*
	 * Methods for Ttrace
	 */

	CompletableFuture<Void> traceEvents(long ctlid, SctlTrace.Mode mode,
			Set<SctlTrace.Event> events) {
		SctlTraceRequest req = new SctlTraceRequest(ctlid, SctlTrace.toFlags(mode, events));
		return sequence(TypeSpec.VOID).then((seq) -> {
			//Msg.debug(this, "TraceRequest: " + req);
			sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishTraceEvents(req, reply);
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusTraceEvents(int tag, SctlTraceRequest req) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			finishTraceEvents(req, reply);
			seq.exit();
		}).finish();
	}

	private void finishTraceEvents(SctlTraceRequest req, SctlPacket reply) {
		checkReply(req, SctlTraceReply.class, reply);
	}

	/*
	 * Methods for handling errors apparently generated by other clients on the bus
	 */

	private CompletableFuture<Void> processUnknownNSID(int id, int tag, long nsid, SctlPacket req) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			Msg.warn(this, "Client " + id + " is talking about nsid " + nsid +
				", which is unknown to this client: \n  --(" + tag + ")-> " + req);
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			Msg.warn(this, "  <-(" + tag + ")-- " + reply);
			seq.exit();
		}).finish();
	}

	private CompletableFuture<Void> processBusUnknown(int id, int tag, SctlPacket req) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			Msg.warn(this, "Do not know how to process command from controller " + id +
				":\n  --(" + tag + ")-> " + req);
			recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			Msg.warn(this, "  <-(" + tag + ")-- " + reply);
			seq.exit();
		}).finish();
	}

	/*
	 * Misc
	 */

	@Override
	public String toString() {
		String status = connectionState.name().toLowerCase();
		return "<SctlClient desc=" + description + ",dialect=" + activeDialect.getClass() +
			",status=" + status + ">";
	}

	@Override
	public String getBrief() {
		String diaStr = activeDialect.getSysVersion();
		String status = connectionState.name().toLowerCase();
		return description + " via SCTL " + diaStr + " (" + status + ")";
	}

	@Override
	public CompletableFuture<? extends TargetObject> fetchModelRoot() {
		return CompletableFuture.completedFuture(session);
	}

	@Override
	public CompletableFuture<? extends TargetObject> fetchModelObject(List<String> path) {
		if (PathUtils.isAncestor(session.objects.getPath(), path)) {
			List<String> sub = path.subList(session.objects.getPath().size(), path.size());
			return session.objects.fetchSuccessor(sub);
		}
		return super.fetchModelObject(path);
	}

	@Override
	public AddressFactory getAddressFactory() {
		return addrMapper.getAddressFactory();
	}

	@Override
	public void invalidateAllLocalCaches() {
		TODO();
	}
}
