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
package ghidra.app.plugin.core.debug.gui.memory;

import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.jdom.Element;

import docking.action.DockingAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.byteviewer.AbstractByteViewerPlugin;
import ghidra.app.plugin.core.byteviewer.ByteViewerComponentProvider;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.NewMemoryAction;
import ghidra.app.plugin.core.debug.gui.action.NoneLocationTrackingSpec;
import ghidra.app.services.*;
import ghidra.debug.api.action.LocationTrackingSpec;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.program.TraceProgramView;

@PluginInfo(
	shortDescription = "View bytes of trace (possibly live) memory",
	description = "Provides the memory bytes display window. Functions similarly to " +
		"the main program bytes display window, but for traces. If the trace is the " +
		"destination of a live recording, the view(s) retrieve live memory on demand.",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		// ProgramSelectionPluginEvent.class, // TODO: Later or remove
		// ProgramHighlightPluginEvent.class, // TODO: Later or remove
		TraceActivatedPluginEvent.class, // Trace/thread activation and register tracking
		TraceClosedPluginEvent.class,
		TraceLocationPluginEvent.class,
		TraceSelectionPluginEvent.class,
		TraceHighlightPluginEvent.class,
		TrackingChangedPluginEvent.class,
	},
	eventsProduced = {
		TraceLocationPluginEvent.class,
		TraceSelectionPluginEvent.class,
		TraceHighlightPluginEvent.class,
		TrackingChangedPluginEvent.class,
	},
	servicesRequired = {
		ClipboardService.class,
	})
public class DebuggerMemoryBytesPlugin
		extends AbstractByteViewerPlugin<DebuggerMemoryBytesProvider> {
	private static final String KEY_CONNECTED_PROVIDER = "connectedProvider";
	private static final String KEY_DISCONNECTED_COUNT = "disconnectedCount";
	private static final String PREFIX_DISCONNECTED_PROVIDER = "disconnectedProvider";

	protected DockingAction actionNewMemory;

	@AutoServiceConsumed
	private ProgramManager programManager;
	// NOTE: This plugin doesn't extend AbstractDebuggerPlugin
	@SuppressWarnings("unused")
	private AutoService.Wiring autoServiceWiring;

	private DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	public DebuggerMemoryBytesPlugin(PluginTool tool) {
		super(tool);
		autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);

		createActions();
	}

	@Override
	protected DebuggerMemoryBytesProvider createProvider(boolean isConnected) {
		return new DebuggerMemoryBytesProvider(tool, this, isConnected);
	}

	private void createActions() {
		actionNewMemory = NewMemoryAction.builder(this)
				.enabled(true)
				.onAction(c -> connectedProvider.cloneWindow())
				.buildAndInstall(tool);
	}

	public DebuggerMemoryBytesProvider createViewerIfMissing(LocationTrackingSpec spec,
			boolean followsCurrentThread) {
		synchronized (disconnectedProviders) {
			for (DebuggerMemoryBytesProvider provider : disconnectedProviders) {
				if (provider.getTrackingSpec() != spec) {
					continue;
				}
				if (provider.isFollowsCurrentThread() != followsCurrentThread) {
					continue;
				}
				return provider;
			}
			DebuggerMemoryBytesProvider provider = createNewDisconnectedProvider();
			provider.setTrackingSpec(spec);
			provider.setFollowsCurrentThread(followsCurrentThread);
			provider.goToCoordinates(current);
			return provider;
		}
	}

	@Override
	public void highlightChanged(ByteViewerComponentProvider provider, ProgramSelection highlight) {
		if (provider == connectedProvider) {
			tool.firePluginEvent(new TraceHighlightPluginEvent(getName(), highlight,
				(TraceProgramView) connectedProvider.getProgram()));
		}
	}

	protected void allProviders(Consumer<DebuggerMemoryBytesProvider> action) {
		action.accept(connectedProvider);
		for (DebuggerMemoryBytesProvider provider : disconnectedProviders) {
			action.accept(provider);
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		// do not delegate to super
		if (event instanceof TraceActivatedPluginEvent ev) {
			current = ev.getActiveCoordinates();
			allProviders(p -> p.coordinatesActivated(current));
		}
		else if (event instanceof TraceClosedPluginEvent ev) {
			if (current.getTrace() == ev.getTrace()) {
				current = DebuggerCoordinates.NOWHERE;
			}
			allProviders(p -> p.traceClosed(ev.getTrace()));
		}
		else if (event instanceof TraceLocationPluginEvent ev) {
			currentLocation = ev.getLocation();
		}

		connectedProvider.doHandleTraceEvent(event);
	}

	@AutoServiceConsumed
	public void setTraceManager(DebuggerTraceManagerService traceManager) {
		DebuggerMemoryBytesProvider provider = connectedProvider;
		if (provider == null || traceManager == null) {
			return;
		}
		provider.coordinatesActivated(current = traceManager.getCurrent());
	}

	@Override
	public Object getTransientState() {
		// Not needed, since I'm not coordinated with ProgramManager
		return new Object[] {};
	}

	@Override
	public void restoreTransientState(Object objectState) {
		// Not needed, since I'm not coordinated with ProgramManager
	}

	@Override
	public void writeDataState(SaveState saveState) {
		SaveState connectedProviderState = new SaveState();
		connectedProvider.writeDataState(connectedProviderState);
		saveState.putXmlElement(KEY_CONNECTED_PROVIDER, connectedProviderState.saveToXml());

		/**
		 * Arrange the follows ones first, so that we reload them into corresponding providers
		 * restored from config state
		 */
		List<DebuggerMemoryBytesProvider> disconnected = disconnectedProviders.stream()
				.filter(p -> p.isFollowsCurrentThread())
				.collect(Collectors.toList());
		for (DebuggerMemoryBytesProvider p : disconnectedProviders) {
			if (!disconnected.contains(p)) {
				disconnected.add(p);
			}
		}
		int disconnectedCount = disconnected.size();
		saveState.putInt(KEY_DISCONNECTED_COUNT, disconnectedCount);
		for (int index = 0; index < disconnectedCount; index++) {
			DebuggerMemoryBytesProvider provider = disconnected.get(index);
			String stateName = PREFIX_DISCONNECTED_PROVIDER + index;
			SaveState providerState = new SaveState();
			provider.writeDataState(providerState);
			saveState.putXmlElement(stateName, providerState.saveToXml());
		}
	}

	protected void ensureProviders(int count, boolean followCurrentThread, SaveState configState) {
		while (disconnectedProviders.size() < count) {
			int index = disconnectedProviders.size();
			String stateName = PREFIX_DISCONNECTED_PROVIDER + index;
			DebuggerMemoryBytesProvider provider = createNewDisconnectedProvider();
			provider.setFollowsCurrentThread(false);
			Element providerElement = configState.getXmlElement(stateName);
			// Read transient configs, which are not saved in tool
			if (providerElement != null) {
				SaveState providerState = new SaveState(providerElement);
				provider.readConfigState(providerState); // Yes, config
			}
			else {
				provider.setTrackingSpec(NoneLocationTrackingSpec.INSTANCE);
			}
		}
	}

	@Override
	public void readDataState(SaveState saveState) {
		Element connectedProviderElement = saveState.getXmlElement(KEY_CONNECTED_PROVIDER);
		if (connectedProviderElement != null) {
			SaveState connectedProviderState = new SaveState(connectedProviderElement);
			connectedProvider.readDataState(connectedProviderState);
		}

		int disconnectedCount = saveState.getInt(KEY_DISCONNECTED_COUNT, 0);
		ensureProviders(disconnectedCount, false, saveState);

		List<DebuggerMemoryBytesProvider> disconnected = disconnectedProviders;
		for (int index = 0; index < disconnectedCount; index++) {
			String stateName = PREFIX_DISCONNECTED_PROVIDER + index;
			Element providerElement = saveState.getXmlElement(stateName);
			if (providerElement != null) {
				SaveState providerState = new SaveState(providerElement);
				DebuggerMemoryBytesProvider provider = disconnected.get(index);
				provider.readDataState(providerState);
			}
		}
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		SaveState connectedProviderState = new SaveState();
		connectedProvider.writeConfigState(connectedProviderState);
		saveState.putXmlElement(KEY_CONNECTED_PROVIDER, connectedProviderState.saveToXml());

		List<DebuggerMemoryBytesProvider> disconnected = disconnectedProviders.stream()
				.filter(p -> p.isFollowsCurrentThread())
				.collect(Collectors.toList());
		int disconnectedCount = disconnected.size();
		saveState.putInt(KEY_DISCONNECTED_COUNT, disconnectedCount);
		for (int index = 0; index < disconnectedCount; index++) {
			DebuggerMemoryBytesProvider provider = disconnected.get(index);
			String stateName = PREFIX_DISCONNECTED_PROVIDER + index;
			SaveState providerState = new SaveState();
			provider.writeConfigState(providerState);
			saveState.putXmlElement(stateName, providerState.saveToXml());
		}
	}

	@Override
	public void readConfigState(SaveState saveState) {
		Element connectedProviderElement = saveState.getXmlElement(KEY_CONNECTED_PROVIDER);
		if (connectedProviderElement != null) {
			SaveState connectedProviderState = new SaveState(connectedProviderElement);
			connectedProvider.readConfigState(connectedProviderState);
		}

		int disconnectedCount = saveState.getInt(KEY_DISCONNECTED_COUNT, 0);
		ensureProviders(disconnectedCount, true, saveState);
	}
}
