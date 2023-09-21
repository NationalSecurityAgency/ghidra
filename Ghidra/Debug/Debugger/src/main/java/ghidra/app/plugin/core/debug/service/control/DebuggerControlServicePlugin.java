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
package ghidra.app.plugin.core.debug.service.control;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.*;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.*;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceProgramViewListener;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.program.TraceProgramViewMemory;
import ghidra.util.datastruct.ListenerSet;

@PluginInfo(
	shortDescription = "Debugger control and machine-state editing service plugin",
	description = "Centralizes control and machine-state editing across the tool",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceOpenedPluginEvent.class,
		TraceActivatedPluginEvent.class,
		TraceClosedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerTraceManagerService.class,
		DebuggerEmulationService.class,
	},
	servicesProvided = {
		DebuggerControlService.class,
	})
public class DebuggerControlServicePlugin extends AbstractDebuggerPlugin
		implements DebuggerControlService {

	protected abstract class AbstractStateEditor implements StateEditor {
		@Override
		public boolean isVariableEditable(Address address, int length) {
			DebuggerCoordinates coordinates = getCoordinates();
			Trace trace = coordinates.getTrace();
			return getCurrentMode(trace).isVariableEditable(coordinates, address, length);
		}

		@Override
		public CompletableFuture<Void> setVariable(Address address, byte[] data) {
			DebuggerCoordinates coordinates = getCoordinates();
			Trace trace = coordinates.getTrace();
			return getCurrentMode(trace).setVariable(tool, coordinates, address, data);
		}
	}

	protected class DefaultStateEditor extends AbstractStateEditor {
		private final DebuggerCoordinates coordinates;

		public DefaultStateEditor(DebuggerCoordinates coordinates) {
			this.coordinates = Objects.requireNonNull(coordinates);
		}

		@Override
		public DebuggerControlService getService() {
			return DebuggerControlServicePlugin.this;
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
		public DebuggerControlService getService() {
			return DebuggerControlServicePlugin.this;
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
		public DebuggerControlService getService() {
			return DebuggerControlServicePlugin.this;
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

	protected final ListenerForEditorInstallation listenerForEditorInstallation =
		new ListenerForEditorInstallation();

	public DebuggerControlServicePlugin(PluginTool tool) {
		super(tool);
	}

	private final Map<Trace, ControlMode> currentModes = new HashMap<>();

	private final ListenerSet<ControlModeChangeListener> listeners =
		new ListenerSet<>(ControlModeChangeListener.class);

	@Override
	public ControlMode getCurrentMode(Trace trace) {
		synchronized (currentModes) {
			return currentModes.getOrDefault(Objects.requireNonNull(trace), ControlMode.DEFAULT);
		}
	}

	@Override
	public void setCurrentMode(Trace trace, ControlMode newMode) {
		ControlMode oldMode;
		synchronized (currentModes) {
			oldMode = currentModes.getOrDefault(Objects.requireNonNull(trace), ControlMode.DEFAULT);
			if (newMode != oldMode) {
				currentModes.put(trace, newMode);
			}
		}
		if (newMode != oldMode) {
			listeners.fire.modeChanged(trace, newMode);
			tool.contextChanged(null);
		}
	}

	@Override
	public void addModeChangeListener(ControlModeChangeListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeModeChangeListener(ControlModeChangeListener listener) {
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

	protected void coordinatesActivated(DebuggerCoordinates coordinates, ActivationCause cause) {
		if (cause != ActivationCause.USER) {
			return;
		}
		Trace trace = coordinates.getTrace();
		if (trace == null) {
			return;
		}
		ControlMode oldMode;
		ControlMode newMode;
		synchronized (currentModes) {
			oldMode = currentModes.getOrDefault(trace, ControlMode.DEFAULT);
			newMode = oldMode.modeOnChange(coordinates);
			if (newMode != oldMode) {
				currentModes.put(trace, newMode);
			}
		}
		if (newMode != oldMode) {
			listeners.fire.modeChanged(trace, newMode);
			tool.contextChanged(null);
		}
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
		if (event instanceof TraceOpenedPluginEvent evt) {
			installAllMemoryEditors(evt.getTrace());
		}
		else if (event instanceof TraceActivatedPluginEvent evt) {
			coordinatesActivated(evt.getActiveCoordinates(), evt.getCause());
		}
		else if (event instanceof TraceClosedPluginEvent evt) {
			uninstallAllMemoryEditors(evt.getTrace());
		}
	}

	@AutoServiceConsumed
	private void setTraceManager(DebuggerTraceManagerService traceManager) {
		uninstallAllMemoryEditors();
		this.traceManager = traceManager;
		installAllMemoryEditors();
	}
}
