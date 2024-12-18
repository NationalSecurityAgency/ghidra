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
package ghidra.debug.api.control;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import javax.swing.Icon;

import db.Transaction;
import generic.theme.GIcon;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.async.AsyncUtils;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryOperations;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.program.TraceVariableSnapProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.PatchStep;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The control / state editing modes
 */
public enum ControlMode {
	/**
	 * Control actions, breakpoint commands are directed to the target, but state edits are
	 * rejected.
	 */
	RO_TARGET("Control Target w/ Edits Disabled", new GIcon(
		"icon.debugger.control.mode.ro.target")) {
		@Override
		public boolean isTarget() {
			return true;
		}

		@Override
		public boolean followsPresent() {
			return true;
		}

		@Override
		public boolean canEdit(DebuggerCoordinates coordinates) {
			return false;
		}

		@Override
		public boolean isVariableEditable(DebuggerCoordinates coordinates, Address address,
				int length) {
			return false;
		}

		@Override
		public CompletableFuture<Void> setVariable(PluginTool tool,
				DebuggerCoordinates coordinates, Address address, byte[] data) {
			return CompletableFuture.failedFuture(new MemoryAccessException("Read-only mode"));
		}

		@Override
		public boolean useEmulatedBreakpoints() {
			return false;
		}

		@Override
		public boolean isSelectable(DebuggerCoordinates coordinates) {
			return coordinates.isAlive();
		}

		@Override
		public ControlMode getAlternative(DebuggerCoordinates coordinates) {
			return RW_EMULATOR;
		}
	},
	/**
	 * Control actions, breakpoint commands, and state edits are all directed to the target.
	 */
	RW_TARGET("Control Target", new GIcon("icon.debugger.control.mode.rw.target")) {
		@Override
		public boolean isTarget() {
			return true;
		}

		@Override
		public boolean followsPresent() {
			return true;
		}

		@Override
		public boolean canEdit(DebuggerCoordinates coordinates) {
			return coordinates.isAliveAndPresent();
		}

		@Override
		public boolean isVariableEditable(DebuggerCoordinates coordinates, Address address,
				int length) {
			if (!coordinates.isAliveAndPresent()) {
				return false;
			}
			Target target = coordinates.getTarget();
			return target.isVariableExists(platformFor(coordinates, address),
				coordinates.getThread(), coordinates.getFrame(), address, length);
		}

		@Override
		public CompletableFuture<Void> setVariable(PluginTool tool,
				DebuggerCoordinates coordinates, Address address, byte[] data) {
			Target target = coordinates.getTarget();
			if (target == null) {
				return CompletableFuture
						.failedFuture(new MemoryAccessException("Trace has no live target"));
			}
			if (!coordinates.isAliveAndPresent()) {
				return CompletableFuture
						.failedFuture(new MemoryAccessException("View is not the present"));
			}
			return target.writeVariableAsync(platformFor(coordinates, address),
				coordinates.getThread(), coordinates.getFrame(), address, data);
		}

		@Override
		public boolean useEmulatedBreakpoints() {
			return false;
		}

		@Override
		public boolean isSelectable(DebuggerCoordinates coordinates) {
			return coordinates.isAlive();
		}

		@Override
		public ControlMode getAlternative(DebuggerCoordinates coordinates) {
			return RW_EMULATOR;
		}
	},
	/**
	 * Control actions activate trace snapshots, breakpoint commands are directed to the emulator,
	 * and state edits are rejected.
	 */
	RO_TRACE("Control Trace w/ Edits Disabled", new GIcon("icon.debugger.control.mode.ro.trace")) {
		@Override
		public boolean isTarget() {
			return false;
		}

		@Override
		public boolean followsPresent() {
			return false;
		}

		@Override
		public boolean canEdit(DebuggerCoordinates coordinates) {
			return false;
		}

		@Override
		public boolean isVariableEditable(DebuggerCoordinates coordinates, Address address,
				int length) {
			return false;
		}

		@Override
		public CompletableFuture<Void> setVariable(PluginTool tool,
				DebuggerCoordinates coordinates, Address address, byte[] data) {
			return CompletableFuture.failedFuture(new MemoryAccessException("Read-only mode"));
		}

		@Override
		public boolean useEmulatedBreakpoints() {
			return true;
		}
	},
	/**
	 * Control actions activate trace snapshots, breakpoint commands are directed to the emulator,
	 * and state edits modify the current trace snapshot.
	 */
	RW_TRACE("Control Trace", new GIcon("icon.debugger.control.mode.rw.trace")) {
		@Override
		public boolean isTarget() {
			return false;
		}

		@Override
		public boolean followsPresent() {
			return false;
		}

		@Override
		public boolean canEdit(DebuggerCoordinates coordinates) {
			return coordinates.getTrace() != null;
		}

		@Override
		public boolean isVariableEditable(DebuggerCoordinates coordinates, Address address,
				int length) {
			return address.isMemoryAddress() || coordinates.getThread() != null;
		}

		@Override
		public CompletableFuture<Void> setVariable(PluginTool tool,
				DebuggerCoordinates coordinates, Address guestAddress, byte[] data) {
			Trace trace = coordinates.getTrace();
			TracePlatform platform = platformFor(coordinates, guestAddress);
			long snap = coordinates.getViewSnap();
			Address hostAddress = platform.mapGuestToHost(guestAddress);
			if (hostAddress == null) {
				throw new IllegalArgumentException(
					"Guest address " + guestAddress + " is not mapped");
			}
			TraceMemoryOperations memOrRegs;
			Address overlayAddress;
			try (Transaction tx = trace.openTransaction("Edit Variable")) {
				if (hostAddress.isRegisterAddress()) {
					TraceThread thread = coordinates.getThread();
					if (thread == null) {
						throw new IllegalArgumentException("Register edits require a thread.");
					}
					TraceMemorySpace regs = trace.getMemoryManager()
							.getMemoryRegisterSpace(thread, coordinates.getFrame(),
								true);
					memOrRegs = regs;
					overlayAddress = regs.getAddressSpace().getOverlayAddress(hostAddress);
				}
				else {
					memOrRegs = trace.getMemoryManager();
					overlayAddress = hostAddress;
				}
				if (memOrRegs.putBytes(snap, overlayAddress,
					ByteBuffer.wrap(data)) != data.length) {
					return CompletableFuture.failedFuture(new MemoryAccessException());
				}
			}
			return AsyncUtils.nil();
		}

		@Override
		public boolean useEmulatedBreakpoints() {
			return true;
		}
	},
	/**
	 * Control actions, breakpoint commands, and state edits are directed to the emulator.
	 * 
	 * <p>
	 * Edits are accomplished by appending patch steps to the current schedule and activating that
	 * schedule.
	 */
	RW_EMULATOR("Control Emulator", new GIcon("icon.debugger.control.mode.rw.emulator")) {
		@Override
		public boolean isTarget() {
			return false;
		}

		@Override
		public boolean followsPresent() {
			return false;
		}

		@Override
		public boolean canEdit(DebuggerCoordinates coordinates) {
			return coordinates.getTrace() != null;
		}

		@Override
		public boolean isVariableEditable(DebuggerCoordinates coordinates, Address address,
				int length) {
			if (coordinates.getThread() == null) {
				// A limitation in TraceSchedule, which is used to manifest patches
				return false;
			}
			if (!RW_TRACE.isVariableEditable(coordinates, address, length)) {
				return false;
			}
			// TODO: Limitation from using Sleigh for patching
			Register ctxReg = coordinates.getTrace().getBaseLanguage().getContextBaseRegister();
			if (ctxReg == Register.NO_CONTEXT) {
				return true;
			}
			AddressRange ctxRange = TraceRegisterUtils.rangeForRegister(ctxReg);
			if (ctxRange.contains(address)) {
				return false;
			}
			return true;
		}

		@Override
		public CompletableFuture<Void> setVariable(PluginTool tool,
				DebuggerCoordinates coordinates, Address address, byte[] data) {
			if (!(coordinates.getView() instanceof TraceVariableSnapProgramView)) {
				throw new IllegalArgumentException("Cannot emulate using a Fixed Program View");
			}
			TraceThread thread = coordinates.getThread();
			if (thread == null) {
				// TODO: Well, technically, only for register edits
				// It's a limitation in TraceSchedule. Every step requires a thread
				throw new IllegalArgumentException("Emulator edits require a thread.");
			}
			Language language = coordinates.getPlatform().getLanguage();
			TraceSchedule time = coordinates.getTime()
					.patched(thread, language,
						PatchStep.generateSleigh(language, address, data));

			DebuggerCoordinates withTime = coordinates.time(time);
			DebuggerTraceManagerService traceManager =
				Objects.requireNonNull(tool.getService(DebuggerTraceManagerService.class),
					"No trace manager service");
			Long found = traceManager.findSnapshot(withTime);
			// Materialize it on the same thread (even if swing)
			// It shouldn't take long, since we're only appending one step.
			if (found == null) {
				// TODO: Could still do it async on another thread, no?
				// Not sure it buys anything, since program view will call .get on swing thread
				DebuggerEmulationService emulationService = Objects.requireNonNull(
					tool.getService(DebuggerEmulationService.class), "No emulation service");
				try {
					emulationService.emulate(coordinates.getPlatform(), time,
						TaskMonitor.DUMMY);
				}
				catch (CancelledException e) {
					throw new AssertionError(e);
				}
			}
			return traceManager.activateAndNotify(withTime, ActivationCause.EMU_STATE_EDIT);
		}

		@Override
		public boolean useEmulatedBreakpoints() {
			return true;
		}
	};

	public static final List<ControlMode> ALL = List.of(values());
	public static final ControlMode DEFAULT = RO_TARGET;

	public final String name;
	public final Icon icon;

	private ControlMode(String name, Icon icon) {
		this.name = name;
		this.icon = icon;
	}

	/**
	 * Check if the UI should keep its active snapshot in sync with the recorder's latest.
	 * 
	 * @return true to follow, false if not
	 */
	public abstract boolean followsPresent();

	/**
	 * Validate and/or adjust the given coordinates pre-activation
	 * 
	 * <p>
	 * This is called by the trace manager whenever there is a request to activate new coordinates.
	 * The control mode may adjust or reject the request before the trace manager actually performs
	 * and notifies the activation.
	 * 
	 * @param tool the tool for displaying status messages
	 * @param coordinates the requested coordinates
	 * @param cause the cause of the activation
	 * @return the effective coordinates or null to reject
	 */
	public DebuggerCoordinates validateCoordinates(PluginTool tool,
			DebuggerCoordinates coordinates, ActivationCause cause) {
		if (!followsPresent()) {
			return coordinates;
		}
		Target target = coordinates.getTarget();
		if (target == null) {
			return coordinates;
		}
		if (cause == ActivationCause.USER &&
			(!coordinates.getTime().isSnapOnly() || coordinates.getSnap() != target.getSnap())) {
			tool.setStatusInfo(
				"Cannot navigate time in %s mode. Switch to Trace or Emulate mode first."
						.formatted(name),
				true);
			return null;
		}
		return coordinates;
	}

	protected TracePlatform platformFor(DebuggerCoordinates coordinates, Address address) {
		if (address.isRegisterAddress()) {
			return coordinates.getPlatform();
		}
		// This seems odd, but the memory UI components are displaying *host* addresses.
		return coordinates.getTrace().getPlatformManager().getHostPlatform();
	}

	/**
	 * Check if (broadly speaking) the mode supports editing the given coordinates
	 * 
	 * @param coordinates the coordinates to check
	 * @return true if editable, false if not
	 */
	public abstract boolean canEdit(DebuggerCoordinates coordinates);

	/**
	 * Check if the given variable can be edited under this mode
	 * 
	 * @param coordinates the coordinates to check
	 * @param address the address of the variable
	 * @param length the length of the variable, in bytes
	 * @return true if editable, false if not
	 */
	public abstract boolean isVariableEditable(DebuggerCoordinates coordinates, Address address,
			int length);

	/**
	 * Set the value of a variable
	 * 
	 * <p>
	 * Because the edit may be directed to a live target, the return value is a
	 * {@link CompletableFuture}. Additionally, when directed to the emulator, this allows the
	 * emulated state to be computed in the background.
	 * 
	 * @param tool the tool requesting the edit
	 * @param coordinates the coordinates of the edit
	 * @param address the address of the variable
	 * @param data the desired value of the variable
	 * @return a future which completes when the edit is finished
	 */
	public abstract CompletableFuture<Void> setVariable(PluginTool tool,
			DebuggerCoordinates coordinates, Address address, byte[] data);

	/**
	 * Check if this mode operates on target breakpoints or emulator breakpoints
	 * 
	 * @return false for target, true for emulator
	 */
	public abstract boolean useEmulatedBreakpoints();

	/**
	 * Check if this mode can be selected for the given coordinates
	 * 
	 * @param coordinates the current coordinates
	 * @return true to enable selection, false to disable
	 */
	public boolean isSelectable(DebuggerCoordinates coordinates) {
		return true;
	}

	/**
	 * If the mode can no longer be selected for new coordinates, get the new mode
	 * 
	 * <p>
	 * For example, if a target terminates while the mode is {@link #RO_TARGET}, this specifies the
	 * new mode.
	 * 
	 * @param coordinates the new coordinates
	 * @return the new mode
	 */
	public ControlMode getAlternative(DebuggerCoordinates coordinates) {
		throw new AssertionError("INTERNAL: Non-selectable mode must provide alternative");
	}

	/**
	 * Find the new mode (or same) mode when activating the given coordinates
	 * 
	 * <p>
	 * The default is implemented using {@link #isSelectable(DebuggerCoordinates)} followed by
	 * {@link #getAlternative(DebuggerCoordinates)}.
	 * 
	 * @param coordinates the new coordinates
	 * @return the mode
	 */
	public ControlMode modeOnChange(DebuggerCoordinates coordinates) {
		if (isSelectable(coordinates)) {
			return this;
		}
		return getAlternative(coordinates);
	}

	/**
	 * Indicates whether this mode controls the target
	 * 
	 * @return true if it controls the target
	 */
	public abstract boolean isTarget();
}
