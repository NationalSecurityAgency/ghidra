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
package ghidra.app.plugin.core.debug.service.editing;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.*;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.*;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceOpenedPluginEvent;
import ghidra.app.services.*;
import ghidra.async.AsyncUtils;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceProgramViewListener;
import ghidra.trace.model.memory.TraceMemoryOperations;
import ghidra.trace.model.program.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.PatchStep;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@PluginInfo(
	shortDescription = "Debugger machine-state editing service plugin",
	description = "Centralizes machine-state editing across the tool",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceOpenedPluginEvent.class,
		TraceClosedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerTraceManagerService.class,
		DebuggerEmulationService.class,
	},
	servicesProvided = {
		DebuggerStateEditingService.class,
	})
public class DebuggerStateEditingServicePlugin extends AbstractDebuggerPlugin
		implements DebuggerStateEditingService {

	protected abstract class AbstractStateEditor implements StateEditor {
		@Override
		public boolean isVariableEditable(Address address, int length) {
			DebuggerCoordinates coordinates = getCoordinates();
			Trace trace = coordinates.getTrace();

			switch (getCurrentMode(trace)) {
				case READ_ONLY:
					return false;
				case WRITE_TARGET:
					return isTargetVariableEditable(coordinates, address, length);
				case WRITE_TRACE:
					return isTraceVariableEditable(coordinates, address, length);
				case WRITE_EMULATOR:
					return isEmulatorVariableEditable(coordinates, address, length);
			}
			throw new AssertionError();
		}

		protected boolean isTargetVariableEditable(DebuggerCoordinates coordinates, Address address,
				int length) {
			if (!coordinates.isAliveAndPresent()) {
				return false;
			}
			TraceRecorder recorder = coordinates.getRecorder();
			return recorder.isVariableOnTarget(coordinates.getThread(), address, length);
		}

		protected boolean isTraceVariableEditable(DebuggerCoordinates coordinates, Address address,
				int length) {
			return address.isMemoryAddress() || coordinates.getThread() != null;
		}

		protected boolean isEmulatorVariableEditable(DebuggerCoordinates coordinates,
				Address address, int length) {
			if (!isTraceVariableEditable(coordinates, address, length)) {
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
		public CompletableFuture<Void> setVariable(Address address, byte[] data) {
			DebuggerCoordinates coordinates = getCoordinates();
			Trace trace = coordinates.getTrace();

			StateEditingMode mode = getCurrentMode(trace);
			switch (mode) {
				case READ_ONLY:
					return CompletableFuture
							.failedFuture(new MemoryAccessException("Read-only mode"));
				case WRITE_TARGET:
					return writeTargetVariable(coordinates, address, data);
				case WRITE_TRACE:
					return writeTraceVariable(coordinates, address, data);
				case WRITE_EMULATOR:
					return writeEmulatorVariable(coordinates, address, data);
			}
			throw new AssertionError();
		}

		protected CompletableFuture<Void> writeTargetVariable(DebuggerCoordinates coordinates,
				Address address, byte[] data) {
			TraceRecorder recorder = coordinates.getRecorder();
			if (recorder == null) {
				return CompletableFuture
						.failedFuture(new MemoryAccessException("Trace has no live target"));
			}
			if (!coordinates.isPresent()) {
				return CompletableFuture
						.failedFuture(new MemoryAccessException("View is not the present"));
			}
			return recorder.writeVariable(coordinates.getThread(), coordinates.getFrame(), address,
				data);
		}

		protected CompletableFuture<Void> writeTraceVariable(DebuggerCoordinates coordinates,
				Address address, byte[] data) {
			Trace trace = coordinates.getTrace();
			long snap = coordinates.getViewSnap();
			TraceMemoryOperations memOrRegs;
			try (UndoableTransaction txid =
				UndoableTransaction.start(trace, "Edit Variable")) {
				if (address.isRegisterAddress()) {
					TraceThread thread = coordinates.getThread();
					if (thread == null) {
						throw new IllegalArgumentException("Register edits require a thread.");
					}
					memOrRegs = trace.getMemoryManager()
							.getMemoryRegisterSpace(thread, coordinates.getFrame(),
								true);
				}
				else {
					memOrRegs = trace.getMemoryManager();
				}
				if (memOrRegs.putBytes(snap, address, ByteBuffer.wrap(data)) != data.length) {
					return CompletableFuture.failedFuture(new MemoryAccessException());
				}
			}
			return AsyncUtils.NIL;
		}

		protected CompletableFuture<Void> writeEmulatorVariable(DebuggerCoordinates coordinates,
				Address address, byte[] data) {
			if (!(coordinates.getView() instanceof TraceVariableSnapProgramView)) {
				throw new IllegalArgumentException("Cannot emulate using a Fixed Program View");
			}
			TraceThread thread = coordinates.getThread();
			if (thread == null) {
				// TODO: Well, technically, only for register edits
				throw new IllegalArgumentException("Emulator edits require a thread.");
			}
			TraceSchedule time = coordinates.getTime()
					.patched(thread, PatchStep.generateSleigh(
						coordinates.getTrace().getBaseLanguage(), address, data));

			DebuggerCoordinates withTime = coordinates.time(time);
			Long found = traceManager.findSnapshot(withTime);
			// Materialize it on the same thread (even if swing)
			// It shouldn't take long, since we're only appending one step.
			if (found == null) {
				// TODO: Could still do it async on another thread, no?
				// Not sure it buys anything, since program view will call .get on swing thread
				try {
					emulationSerivce.emulate(coordinates.getTrace(), time, TaskMonitor.DUMMY);
				}
				catch (CancelledException e) {
					throw new AssertionError(e);
				}
			}
			return traceManager.activateAndNotify(withTime, false);
		}
	}

	protected class DefaultStateEditor extends AbstractStateEditor {
		private final DebuggerCoordinates coordinates;

		public DefaultStateEditor(DebuggerCoordinates coordinates) {
			this.coordinates = Objects.requireNonNull(coordinates);
		}

		@Override
		public DebuggerStateEditingService getService() {
			return DebuggerStateEditingServicePlugin.this;
		}

		@Override
		public DebuggerCoordinates getCoordinates() {
			return this.coordinates;
		}
	}

	protected class FollowsManagerStateEditor extends AbstractStateEditor {
		private final Trace trace;

		public FollowsManagerStateEditor(Trace trace) {
			this.trace = trace;
		}

		@Override
		public DebuggerStateEditingService getService() {
			return DebuggerStateEditingServicePlugin.this;
		}

		@Override
		public DebuggerCoordinates getCoordinates() {
			if (!traceManager.getOpenTraces().contains(trace)) {
				throw new IllegalStateException(
					"Trace " + trace + " is not opened in the trace manager.");
			}
			return traceManager.resolveTrace(trace);
		}
	}

	public class FollowsViewStateEditor extends AbstractStateEditor
			implements StateEditingMemoryHandler {
		private final TraceProgramView view;

		public FollowsViewStateEditor(TraceProgramView view) {
			this.view = view;
		}

		@Override
		public DebuggerStateEditingService getService() {
			return DebuggerStateEditingServicePlugin.this;
		}

		@Override
		public DebuggerCoordinates getCoordinates() {
			return traceManager.resolveView(view);
		}

		@Override
		public void clearCache() {
			// Nothing to do
		}

		@Override
		public byte getByte(Address addr) throws MemoryAccessException {
			ByteBuffer buf = ByteBuffer.allocate(1);
			view.getTrace().getMemoryManager().getViewBytes(view.getSnap(), addr, buf);
			return buf.get(0);
		}

		@Override
		public int getBytes(Address address, byte[] buffer, int startIndex, int size)
				throws MemoryAccessException {
			return view.getTrace()
					.getMemoryManager()
					.getViewBytes(view.getSnap(), address,
						ByteBuffer.wrap(buffer, startIndex, size));
		}

		@Override
		public void putByte(Address address, byte value) throws MemoryAccessException {
			try {
				setVariable(address, new byte[] { value }).get(1, TimeUnit.SECONDS);
			}
			catch (ExecutionException e) {
				throw new MemoryAccessException("Failed to write " + address + ": " + e.getCause());
			}
			catch (TimeoutException | InterruptedException e) {
				throw new MemoryAccessException("Failed to write " + address + ": " + e);
			}
		}

		@Override
		public int putBytes(Address address, byte[] source, int startIndex, int size)
				throws MemoryAccessException {
			try {
				setVariable(address, Arrays.copyOfRange(source, startIndex, startIndex + size))
						.get(1, TimeUnit.SECONDS);
			}
			catch (ExecutionException e) {
				throw new MemoryAccessException("Failed to write " + address + ": " + e.getCause());
			}
			catch (TimeoutException | InterruptedException e) {
				throw new MemoryAccessException("Failed to write " + address + ": " + e);
			}
			return size;
		}

		@Override
		public void addLiveMemoryListener(LiveMemoryListener listener) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void removeLiveMemoryListener(LiveMemoryListener listener) {
			throw new UnsupportedOperationException();
		}
	}

	protected class ListenerForEditorInstallation implements TraceProgramViewListener {
		@Override
		public void viewCreated(TraceProgramView view) {
			installMemoryEditor(view);
		}
	}

	//@AutoServiceConsumed // via method
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerEmulationService emulationSerivce;
	@AutoServiceConsumed
	private DebuggerModelService modelService;

	protected final ListenerForEditorInstallation listenerForEditorInstallation =
		new ListenerForEditorInstallation();

	public DebuggerStateEditingServicePlugin(PluginTool tool) {
		super(tool);
	}

	private static final StateEditingMode DEFAULT_MODE = StateEditingMode.WRITE_TARGET;

	private final Map<Trace, StateEditingMode> currentModes = new HashMap<>();

	private final ListenerSet<StateEditingModeChangeListener> listeners =
		new ListenerSet<>(StateEditingModeChangeListener.class);

	@Override
	public StateEditingMode getCurrentMode(Trace trace) {
		synchronized (currentModes) {
			return currentModes.getOrDefault(Objects.requireNonNull(trace), DEFAULT_MODE);
		}
	}

	@Override
	public void setCurrentMode(Trace trace, StateEditingMode mode) {
		boolean fire = false;
		synchronized (currentModes) {
			StateEditingMode old =
				currentModes.getOrDefault(Objects.requireNonNull(trace), DEFAULT_MODE);
			if (mode != old) {
				currentModes.put(trace, mode);
				fire = true;
			}
		}
		if (fire) {
			listeners.fire.modeChanged(trace, mode);
			tool.contextChanged(null);
		}
	}

	@Override
	public void addModeChangeListener(StateEditingModeChangeListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeModeChangeListener(StateEditingModeChangeListener listener) {
		listeners.remove(listener);
	}

	@Override
	public StateEditor createStateEditor(DebuggerCoordinates coordinates) {
		return new DefaultStateEditor(coordinates);
	}

	@Override
	public StateEditor createStateEditor(Trace trace) {
		return new FollowsManagerStateEditor(trace);
	}

	@Override
	public StateEditingMemoryHandler createStateEditor(TraceProgramView view) {
		return new FollowsViewStateEditor(view);
	}

	protected void installMemoryEditor(TraceProgramView view) {
		TraceProgramViewMemory memory = view.getMemory();
		if (memory.getLiveMemoryHandler() != null) {
			return;
		}
		memory.setLiveMemoryHandler(createStateEditor(view));
	}

	protected void uninstallMemoryEditor(TraceProgramView view) {
		TraceProgramViewMemory memory = view.getMemory();
		LiveMemoryHandler handler = memory.getLiveMemoryHandler();
		if (!(handler instanceof StateEditingMemoryHandler)) {
			return;
		}
		StateEditingMemoryHandler editor = (StateEditingMemoryHandler) handler;
		if (editor.getService() != this) {
			return;
		}
		memory.setLiveMemoryHandler(null);
	}

	protected void installAllMemoryEditors(Trace trace) {
		trace.addProgramViewListener(listenerForEditorInstallation);
		for (TraceProgramView view : trace.getAllProgramViews()) {
			installMemoryEditor(view);
		}
	}

	protected void installAllMemoryEditors() {
		if (traceManager == null) {
			return;
		}

		for (Trace trace : traceManager.getOpenTraces()) {
			installAllMemoryEditors(trace);
		}
	}

	protected void uninstallAllMemoryEditors(Trace trace) {
		trace.removeProgramViewListener(listenerForEditorInstallation);
		for (TraceProgramView view : trace.getAllProgramViews()) {
			uninstallMemoryEditor(view);
		}
	}

	protected void uninstallAllMemoryEditors() {
		if (traceManager == null) {
			return;
		}
		for (Trace trace : traceManager.getOpenTraces()) {
			uninstallAllMemoryEditors(trace);
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceOpenedPluginEvent) {
			TraceOpenedPluginEvent ev = (TraceOpenedPluginEvent) event;
			installAllMemoryEditors(ev.getTrace());
		}
		else if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent ev = (TraceClosedPluginEvent) event;
			uninstallAllMemoryEditors(ev.getTrace());
		}
	}

	@AutoServiceConsumed
	private void setTraceManager(DebuggerTraceManagerService traceManager) {
		uninstallAllMemoryEditors();
		this.traceManager = traceManager;
		installAllMemoryEditors();
	}
}
