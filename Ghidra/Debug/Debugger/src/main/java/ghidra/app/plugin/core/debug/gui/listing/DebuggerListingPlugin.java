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

import static ghidra.app.plugin.core.debug.gui.DebuggerResources.*;

import java.awt.Color;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.jdom.Element;

import docking.ActionContext;
import docking.action.MenuData;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractNewListingAction;
import ghidra.app.plugin.core.debug.gui.action.LocationTrackingSpec;
import ghidra.app.plugin.core.debug.gui.action.NoneLocationTrackingSpec;
import ghidra.app.services.*;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.annotation.AutoOptionDefined;
import ghidra.framework.options.annotation.HelpInfo;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.Swing;
import utilities.util.SuppressableCallback;
import utilities.util.SuppressableCallback.Suppression;

@PluginInfo(
	shortDescription = "View and annotate listings of trace (possibly live) memory",
	description = "Provides the memory listing display window. Functions similarly to " +
		"the main program listing display window, but for traces. If the trace is the " +
		"destination of a live recording, the view(s) retrieve live memory on demand.",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		// ProgramSelectionPluginEvent.class, // TODO: Later or remove
		// ProgramHighlightPluginEvent.class, // TODO: Later or remove
		ProgramOpenedPluginEvent.class, // For auto-open log cleanup
		ProgramClosedPluginEvent.class, // For marker set cleanup
		ProgramLocationPluginEvent.class, // For static listing sync
		TraceActivatedPluginEvent.class, // Trace/thread activation and register tracking
		TraceClosedPluginEvent.class,
	},
	eventsProduced = {
		ProgramLocationPluginEvent.class,
		// ProgramSelectionPluginEvent.class, 
		TraceLocationPluginEvent.class,
		TraceSelectionPluginEvent.class
	},
	servicesRequired = {
		DebuggerModelService.class, // For memory capture
		DebuggerStaticMappingService.class, // For static listing sync. TODO: Optional?
		DebuggerEmulationService.class, // TODO: Optional?
		ProgramManager.class, // For static listing sync
		//GoToService.class, // For static listing sync
		ClipboardService.class,
		MarkerService.class // TODO: Make optional?
	},
	servicesProvided = {
		DebuggerListingService.class,
	})
public class DebuggerListingPlugin extends CodeBrowserPlugin implements DebuggerListingService {
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

	//@AutoServiceConsumed
	//private GoToService goToService;
	@AutoServiceConsumed
	private ProgramManager programManager;
	// NOTE: ListingPlugin doesn't extend AbstractDebuggerPlugin
	@SuppressWarnings("unused")
	private AutoService.Wiring autoServiceWiring;

	@AutoOptionDefined( //
		name = OPTION_NAME_COLORS_STALE_MEMORY, //
		description = "Color of memory addresses whose content is not known in the view's " +
			"snap", //
		help = @HelpInfo(anchor = "colors"))
	private Color staleMemoryColor = DEFAULT_COLOR_BACKGROUND_STALE;
	@AutoOptionDefined( //
		name = OPTION_NAME_COLORS_ERROR_MEMORY, //
		description = "Color of memory addresses whose content could not be read in the " +
			"view's snap", //
		help = @HelpInfo(anchor = "colors"))
	private Color errorMemoryColor = DEFAULT_COLOR_BACKGROUND_ERROR;
	// NOTE: Static programs are marked via markerSet. Dynamic are marked via custom color model
	@AutoOptionDefined( //
		name = OPTION_NAME_COLORS_REGISTER_MARKERS, //
		description = "Background color for locations referred to by a tracked register", //
		help = @HelpInfo(anchor = "colors"))
	private Color trackingColor = DEFAULT_COLOR_REGISTER_MARKERS;
	@SuppressWarnings("unused")
	private AutoOptions.Wiring autoOptionsWiring;

	//private final SuppressableCallback<Void> cbGoTo = new SuppressableCallback<>();
	private final SuppressableCallback<Void> cbProgramLocationEvents = new SuppressableCallback<>();

	private DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	public DebuggerListingPlugin(PluginTool tool) {
		super(tool);
		autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
		autoOptionsWiring = AutoOptions.wireOptions(this);

		createActions();
	}

	protected DebuggerListingProvider getConnectedProvider() {
		return (DebuggerListingProvider) connectedProvider;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	protected List<DebuggerListingProvider> getDisconnectedProviders() {
		return (List) disconnectedProviders;
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
			for (DebuggerListingProvider provider : getDisconnectedProviders()) {
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
	public DebuggerListingProvider createNewDisconnectedProvider() {
		return (DebuggerListingProvider) super.createNewDisconnectedProvider();
	}

	@Override
	protected void viewChanged(AddressSetView addrSet) {
		TraceProgramView view = current.getView();
		if (view == null) {
			super.viewChanged(new AddressSet());
		}
		else {
			super.viewChanged(view.getMemory());
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
		firePluginEvent(new TraceLocationPluginEvent(getName(), location));
	}

	@Override
	public void selectionChanged(CodeViewerProvider provider, ProgramSelection selection) {
		TraceProgramView view = current.getView();
		if (view == null) {
			return;
		}
		// Do not fire ProgramSelectionPluginEvent.
		firePluginEvent(new TraceSelectionPluginEvent(getName(), selection, view));
	}

	protected boolean heedLocationEvent(ProgramLocationPluginEvent ev) {
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

	@Override
	public void processEvent(PluginEvent event) {
		// Do not call super here. I intend to prevent it from seeing events.
		if (event instanceof ProgramLocationPluginEvent) {
			cbProgramLocationEvents.invoke(() -> {
				ProgramLocationPluginEvent ev = (ProgramLocationPluginEvent) event;
				if (heedLocationEvent(ev)) {
					getConnectedProvider().staticProgramLocationChanged(ev.getLocation());
				}
			});
		}
		if (event instanceof ProgramOpenedPluginEvent) {
			ProgramOpenedPluginEvent ev = (ProgramOpenedPluginEvent) event;
			allProviders(p -> p.programOpened(ev.getProgram()));
		}
		if (event instanceof ProgramClosedPluginEvent) {
			ProgramClosedPluginEvent ev = (ProgramClosedPluginEvent) event;
			allProviders(p -> p.programClosed(ev.getProgram()));
		}
		if (event instanceof TraceActivatedPluginEvent) {
			TraceActivatedPluginEvent ev = (TraceActivatedPluginEvent) event;
			current = ev.getActiveCoordinates();
			allProviders(p -> p.coordinatesActivated(current));
		}
		if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent ev = (TraceClosedPluginEvent) event;
			allProviders(p -> p.traceClosed(ev.getTrace()));
		}
		// TODO: Sync selection and highlights?
	}

	void fireStaticLocationEvent(ProgramLocation staticLoc) {
		assert Swing.isSwingThread();
		try (Suppression supp = cbProgramLocationEvents.suppress(null)) {
			// Use this instead of GoToService to avoid event loopback
			programManager.setCurrentProgram(staticLoc.getProgram());
			tool.firePluginEvent(new ProgramLocationPluginEvent(getName(), staticLoc,
				staticLoc.getProgram()));
			//goToService.goTo(staticLoc);
		}
	}

	protected void allProviders(Consumer<DebuggerListingProvider> action) {
		action.accept(getConnectedProvider());
		for (DebuggerListingProvider provider : getDisconnectedProviders()) {
			action.accept(provider);
		}
	}

	@Override
	protected void programClosed(Program program) {
		// Immaterial
	}

	@AutoServiceConsumed
	public void setTraceManager(DebuggerTraceManagerService traceManager) {
		DebuggerListingProvider provider = getConnectedProvider();
		if (provider == null || traceManager == null) {
			return;
		}
		provider.coordinatesActivated(traceManager.getCurrent());
	}

	@Override
	public void setTrackingSpec(LocationTrackingSpec spec) {
		getConnectedProvider().setTrackingSpec(spec);
	}

	@Override
	public void setCurrentSelection(ProgramSelection selection) {
		getConnectedProvider().setSelection(selection);
	}

	@Override
	public boolean goTo(ProgramLocation location, boolean centerOnScreen) {
		boolean result = super.goTo(location, centerOnScreen);
		if (!result) {
			return false;
		}
		//cbGoTo.invoke(() -> {
		DebuggerListingProvider provider = getConnectedProvider();
		provider.doSyncToStatic(location);
		provider.doCheckCurrentModuleMissing();
		//});
		return true;
	}

	@Override
	public boolean goTo(Address address, boolean centerOnScreen) {
		TraceProgramView view = getConnectedProvider().current.getView();
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
		getConnectedProvider().writeDataState(connectedProviderState);
		saveState.putXmlElement(KEY_CONNECTED_PROVIDER, connectedProviderState.saveToXml());

		/**
		 * Arrange the follows ones first, so that we reload them into corresponding providers
		 * restored from config state
		 */
		List<DebuggerListingProvider> disconnected = getDisconnectedProviders().stream()
				.filter(p -> p.isFollowsCurrentThread())
				.collect(Collectors.toList());
		for (DebuggerListingProvider p : getDisconnectedProviders()) {
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
		while (getDisconnectedProviders().size() < count) {
			int index = getDisconnectedProviders().size();
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
				provider.setTrackingSpec(
					LocationTrackingSpec.fromConfigName(NoneLocationTrackingSpec.CONFIG_NAME));
			}
		}
	}

	@Override
	public void readDataState(SaveState saveState) {
		Element connectedProviderElement = saveState.getXmlElement(KEY_CONNECTED_PROVIDER);
		if (connectedProviderElement != null) {
			SaveState connectedProviderState = new SaveState(connectedProviderElement);
			getConnectedProvider().readDataState(connectedProviderState);
		}

		int disconnectedCount = saveState.getInt(KEY_DISCONNECTED_COUNT, 0);
		ensureProviders(disconnectedCount, false, saveState);

		List<DebuggerListingProvider> disconnected = getDisconnectedProviders();
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
		getConnectedProvider().writeConfigState(connectedProviderState);
		saveState.putXmlElement(KEY_CONNECTED_PROVIDER, connectedProviderState.saveToXml());

		List<DebuggerListingProvider> disconnected = getDisconnectedProviders().stream()
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
			getConnectedProvider().readConfigState(connectedProviderState);
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
