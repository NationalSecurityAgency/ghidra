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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.datastruct.ListenerSet;

@PluginInfo(
	shortDescription = "Debugger control and machine-state editing service plugin",
	description = "Centralizes control and machine-state editing across the tool",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
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

	public class FollowsViewStateEditor extends AbstractStateEditor {
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
	}

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;

	private final Map<Trace, ControlMode> currentModes = new HashMap<>();

	private final ListenerSet<ControlModeChangeListener> listeners =
		new ListenerSet<>(ControlModeChangeListener.class, true);

	public DebuggerControlServicePlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void dispose() {
		super.dispose();
	}

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
			listeners.invoke().modeChanged(trace, newMode);
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
	public StateEditor createStateEditor(TraceProgramView view) {
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
			listeners.invoke().modeChanged(trace, newMode);
			tool.contextChanged(null);
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent ev) {
			coordinatesActivated(ev.getActiveCoordinates(), ev.getCause());
		}
	}
}
