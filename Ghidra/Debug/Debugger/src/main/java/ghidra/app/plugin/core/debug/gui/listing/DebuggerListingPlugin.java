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
package ghidra.app.plugin.core.debug.gui.listing;

import static ghidra.app.plugin.core.debug.gui.DebuggerResources.GROUP_TRANSIENT_VIEWS;

import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.jdom.Element;

import docking.ActionContext;
import docking.action.MenuData;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.codebrowser.AbstractCodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractNewListingAction;
import ghidra.app.plugin.core.debug.gui.action.*;
import ghidra.app.services.*;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.debug.api.action.AutoReadMemorySpec;
import ghidra.debug.api.action.LocationTrackingSpec;
import ghidra.debug.api.listing.MultiBlendedListingBackgroundColorModel;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.program.TraceProgramView;

@PluginInfo(
	shortDescription = "View and annotate listings of trace (possibly live) memory",
	description = "Provides the memory listing display window. Functions similarly to " +
		"the main program listing display window, but for traces. If the trace is the " +
		"destination of a live recording, the view(s) retrieve live memory on demand.",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		ProgramClosedPluginEvent.class, // For marker set cleanup
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
		DebuggerStaticMappingService.class, // For static listing sync. TODO: Optional?
		DebuggerEmulationService.class, // TODO: Optional?
		ProgramManager.class, // For static listing sync
		ClipboardService.class,
		MarkerService.class, // TODO: Make optional?
	},
	servicesProvided = {
		DebuggerListingService.class,
	})
public class DebuggerListingPlugin extends AbstractCodeBrowserPlugin<DebuggerListingProvider>
		implements DebuggerListingService {
	private static final String KEY_CONNECTED_PROVIDER = "connectedProvider";
	private static final String KEY_DISCONNECTED_COUNT = "disconnectedCount";
	private static final String PREFIX_DISCONNECTED_PROVIDER = "disconnectedProvider";

	protected class NewListingAction extends AbstractNewListingAction {
		public static final String GROUP = GROUP_TRANSIENT_VIEWS;

		public NewListingAction() {
			super(DebuggerListingPlugin.this);
			setMenuBarData(new MenuData(new String[] { "Window", DebuggerPluginPackage.NAME, NAME },
				ICON, GROUP));
			tool.addAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			createNewDisconnectedProvider();
		}
	}

	/**
	 * TODO: If I intend to color any location pointed to by a "pointer-typed" register, I should do
	 * it here or in a separate plugin. Should such markers also be mapped and shown in static
	 * programs? Well, if I'm using the marker service, that's probably the only way to make it
	 * work...
	 */

	protected NewListingAction actionNewListing;

	@AutoServiceConsumed
	private ProgramManager programManager;
	// NOTE: This plugin doesn't extend AbstractDebuggerPlugin
	@SuppressWarnings("unused")
	private AutoService.Wiring autoServiceWiring;

	private DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	public DebuggerListingPlugin(PluginTool tool) {
		super(tool);
		autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);

		createActions();

		tool.registerDefaultContextProvider(DebuggerProgramLocationActionContext.class,
			connectedProvider);
	}

	@Override
	protected void dispose() {
		tool.unregisterDefaultContextProvider(DebuggerProgramLocationActionContext.class,
			connectedProvider);
		super.dispose();
	}

	@Override
	public MultiBlendedListingBackgroundColorModel createListingBackgroundColorModel(
			ListingPanel listingPanel) {
		MultiBlendedListingBackgroundColorModel colorModel =
			new MultiBlendedListingBackgroundColorModel();
		colorModel.addModel(new MemoryStateListingBackgroundColorModel(listingPanel));
		colorModel.addModel(new CursorBackgroundColorModel(this, listingPanel));
		return colorModel;
	}

	@Override
	protected DebuggerListingProvider createProvider(FormatManager formatManager,
			boolean isConnected) {
		return new DebuggerListingProvider(this, formatManager, isConnected);
	}

	private void createActions() {
		actionNewListing = new NewListingAction();
	}

	public DebuggerListingProvider createListingIfMissing(LocationTrackingSpec spec,
			boolean followsCurrentThread) {
		synchronized (disconnectedProviders) {
			for (DebuggerListingProvider provider : disconnectedProviders) {
				if (provider.getTrackingSpec() != spec) {
					continue;
				}
				if (provider.isFollowsCurrentThread() != followsCurrentThread) {
					continue;
				}
				return provider;
			}
			DebuggerListingProvider provider = createNewDisconnectedProvider();
			provider.setTrackingSpec(spec);
			provider.setFollowsCurrentThread(followsCurrentThread);
			provider.goToCoordinates(current);
			return provider;
		}
	}

	@Override
	protected void setView(AddressSetView addrSet) {
		TraceProgramView view = current.getView();
		if (view == null) {
			super.setView(new AddressSet());
		}
		else {
			super.setView(view.getMemory());
		}
	}

	@Override
	protected void updateBackgroundColorModel() {
		// Nothing. Each provider manages its own
	}

	@Override
	public void locationChanged(CodeViewerProvider provider, ProgramLocation location) {
		// TODO: Fix cursor?
		// Do not fire ProgramLocationPluginEvent.
		if (provider == connectedProvider) {
			firePluginEvent(new TraceLocationPluginEvent(getName(), location));
		}
	}

	@Override
	public void selectionChanged(CodeViewerProvider provider, ProgramSelection selection) {
		if (provider != connectedProvider) {
			return;
		}
		TraceProgramView view = current.getView();
		if (view == null) {
			return;
		}
		// Do not fire ProgramSelectionPluginEvent.
		firePluginEvent(new TraceSelectionPluginEvent(getName(), selection, view));
	}

	@Override
	public void highlightChanged(CodeViewerProvider provider, ProgramSelection highlight) {
		if (provider != connectedProvider) {
			return;
		}
		TraceProgramView view = current.getView();
		if (view == null) {
			return;
		}
		// Do not fire ProgramHighlightPluginEvent
		firePluginEvent(new TraceHighlightPluginEvent(getName(), highlight, view));
	}

	protected boolean heedLocationEvent(PluginEvent ev) {
		PluginEvent trigger = ev.getTriggerEvent();
		/*Msg.debug(this, "Location event");
		Msg.debug(this, "   Program: " + ev.getProgram());
		Msg.debug(this, "   Location: " + ev.getLocation());
		Msg.debug(this, "   Trigger: " + trigger);
		if (trigger != null) {
			Msg.debug(this, "   Trigger Class: " + trigger.getClass());
		}*/

		if (trigger instanceof TraceActivatedPluginEvent) {
			return false;
		}
		if (trigger instanceof ProgramActivatedPluginEvent) {
			return false;
		}
		if (trigger instanceof TreeSelectionPluginEvent) {
			return false;
		}
		if (trigger instanceof ViewChangedPluginEvent) {
			return false;
		}
		//Msg.debug(this, "   Heeded");
		return true;
	}

	protected boolean heedSelectionEvent(PluginEvent ev) {
		return heedLocationEvent(ev);
	}

	@Override
	public void processEvent(PluginEvent event) {
		switch (event) {
			case ProgramClosedPluginEvent ev -> allProviders(p -> p.programClosed(ev.getProgram()));
			case TraceActivatedPluginEvent ev -> {
				current = ev.getActiveCoordinates();
				allProviders(p -> p.coordinatesActivated(current));
			}
			case TraceClosedPluginEvent ev -> {
				if (current.getTrace() == ev.getTrace()) {
					current = DebuggerCoordinates.NOWHERE;
				}
				allProviders(p -> p.traceClosed(ev.getTrace()));
			}
			case TraceLocationPluginEvent ev -> {
				// For those comparing to CodeBrowserPlugin, there is no "viewManager" here.
				connectedProvider.goTo(ev.getTraceProgramView(), ev.getLocation());
			}
			case TraceSelectionPluginEvent ev -> {
				if (ev.getTraceProgramView() == current.getView()) {
					connectedProvider.setSelection(ev.getSelection());
				}
			}
			case TraceHighlightPluginEvent ev -> {
				if (ev.getTraceProgramView() == current.getView()) {
					connectedProvider.setHighlight(ev.getHighlight());
				}
			}
			case TrackingChangedPluginEvent ev -> connectedProvider
					.setTrackingSpec(ev.getLocationTrackingSpec());
			default -> {
			}
		}
	}

	protected void allProviders(Consumer<DebuggerListingProvider> action) {
		action.accept(connectedProvider);
		for (DebuggerListingProvider provider : disconnectedProviders) {
			action.accept(provider);
		}
	}

	@AutoServiceConsumed
	public void setTraceManager(DebuggerTraceManagerService traceManager) {
		DebuggerListingProvider provider = connectedProvider;
		if (provider == null || traceManager == null) {
			return;
		}
		provider.coordinatesActivated(current = traceManager.getCurrent());
	}

	@Override
	public void setTrackingSpec(LocationTrackingSpec spec) {
		connectedProvider.setTrackingSpec(spec);
	}

	@Override
	public LocationTrackingSpec getTrackingSpec() {
		return connectedProvider.getTrackingSpec();
	}

	@Override
	public void addTrackingSpecChangeListener(LocationTrackingSpecChangeListener listener) {
		connectedProvider.addTrackingSpecChangeListener(listener);
	}

	@Override
	public void removeTrackingSpecChangeListener(LocationTrackingSpecChangeListener listener) {
		connectedProvider.removeTrackingSpecChangeListener(listener);
	}

	@Override
	public AutoReadMemorySpec getAutoReadMemorySpec() {
		return connectedProvider.getAutoReadMemorySpec();
	}

	@Override
	public void setCurrentSelection(ProgramSelection selection) {
		connectedProvider.setSelection(selection);
	}

	@Override
	public boolean goTo(Address address, boolean centerOnScreen) {
		TraceProgramView view = connectedProvider.current.getView();
		if (view == null) {
			return false;
		}
		ProgramLocation loc = new ProgramLocation(view, address);
		return goTo(loc, centerOnScreen);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This is only used by the ProgramManager. I don't need state per program. It would be nice to
	 * have state per Trace, but this facility is usurped only for the ProgramManager. Here, it gets
	 * in my way, since it restores previous, now incorrect, state on program switch. It tends to
	 * override the static sync.
	 */
	@Override
	public Object getTransientState() {
		// ProgramManager does all this for programs. I don't need that here.
		return new Object[] {};
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see #getTransientState()
	 */
	@Override
	public void restoreTransientState(Object objectState) {
		/*try (Suppression supp = cbGoTo.suppress(null)) {
			super.restoreTransientState(objectState);
		}*/
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
		List<DebuggerListingProvider> disconnected = disconnectedProviders.stream()
				.filter(p -> p.isFollowsCurrentThread())
				.collect(Collectors.toList());
		for (DebuggerListingProvider p : disconnectedProviders) {
			if (!disconnected.contains(p)) {
				disconnected.add(p);
			}
		}
		int disconnectedCount = disconnected.size();
		saveState.putInt(KEY_DISCONNECTED_COUNT, disconnectedCount);
		for (int index = 0; index < disconnectedCount; index++) {
			DebuggerListingProvider provider = disconnected.get(index);
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
			DebuggerListingProvider provider = createNewDisconnectedProvider();
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

		List<DebuggerListingProvider> disconnected = disconnectedProviders;
		for (int index = 0; index < disconnectedCount; index++) {
			String stateName = PREFIX_DISCONNECTED_PROVIDER + index;
			Element providerElement = saveState.getXmlElement(stateName);
			if (providerElement != null) {
				SaveState providerState = new SaveState(providerElement);
				DebuggerListingProvider provider = disconnected.get(index);
				provider.readDataState(providerState);
			}
		}
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		SaveState connectedProviderState = new SaveState();
		connectedProvider.writeConfigState(connectedProviderState);
		saveState.putXmlElement(KEY_CONNECTED_PROVIDER, connectedProviderState.saveToXml());

		List<DebuggerListingProvider> disconnected = disconnectedProviders.stream()
				.filter(p -> p.isFollowsCurrentThread())
				.collect(Collectors.toList());
		int disconnectedCount = disconnected.size();
		saveState.putInt(KEY_DISCONNECTED_COUNT, disconnectedCount);
		for (int index = 0; index < disconnectedCount; index++) {
			DebuggerListingProvider provider = disconnected.get(index);
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

	@Override
	public ViewManagerService getViewManager(CodeViewerProvider codeViewerProvider) {
		// The view manager applies to Programs, and need not be heeded for viewing Traces
		// Overlay spaces can bleed in and cause the DebuggerListingProvider to flip out.
		return null;
	}
}
