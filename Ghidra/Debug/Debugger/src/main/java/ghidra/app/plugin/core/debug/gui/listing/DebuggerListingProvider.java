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

import static ghidra.app.plugin.core.debug.gui.DebuggerResources.ICON_REGISTER_MARKER;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.datatransfer.DataFlavor;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.lang.invoke.MethodHandles;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.apache.commons.lang3.StringUtils;
import org.jdom.Element;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.builder.ToggleActionBuilder;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.support.ViewerPosition;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.context.ListingActionContext;
import ghidra.app.nav.ListingPanelContainer;
import ghidra.app.plugin.core.clipboard.CodeBrowserClipboardProvider;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.codebrowser.MarkerServiceBackgroundColorModel;
import ghidra.app.plugin.core.debug.disassemble.CurrentPlatformTraceDisassembleCommand;
import ghidra.app.plugin.core.debug.disassemble.CurrentPlatformTraceDisassembleCommand.Reqs;
import ghidra.app.plugin.core.debug.disassemble.DebuggerDisassemblerPlugin;
import ghidra.app.plugin.core.debug.event.TrackingChangedPluginEvent;
import ghidra.app.plugin.core.debug.gui.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.FollowsCurrentThreadAction;
import ghidra.app.plugin.core.debug.gui.action.*;
import ghidra.app.plugin.core.debug.gui.thread.DebuggerTraceFileActionContext;
import ghidra.app.plugin.core.debug.gui.trace.DebuggerTraceTabPanel;
import ghidra.app.plugin.core.debug.utils.ProgramLocationUtils;
import ghidra.app.plugin.core.marker.MarkerMarginProvider;
import ghidra.app.plugin.core.marker.MarkerOverviewProvider;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerControlService.ControlModeChangeListener;
import ghidra.app.services.DebuggerListingService.LocationTrackingSpecChangeListener;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.debug.api.action.GoToInput;
import ghidra.debug.api.action.LocationTrackingSpec;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.listing.MultiBlendedListingBackgroundColorModel;
import ghidra.debug.api.modules.DebuggerStaticMappingChangeListener;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.features.base.memsearch.bytesource.AddressableByteSource;
import ghidra.features.base.memsearch.bytesource.EmptyByteSource;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.*;
import ghidra.util.datastruct.ListenerSet;
import utilities.util.SuppressableCallback;
import utilities.util.SuppressableCallback.Suppression;

public class DebuggerListingProvider extends CodeViewerProvider {

	private static final AutoConfigState.ClassHandler<DebuggerListingProvider> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(DebuggerListingProvider.class, MethodHandles.lookup());
	private static final String KEY_DEBUGGER_COORDINATES = "DebuggerCoordinates";

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getView(), b.getView())) {
			return false; // Subsumes trace
		}
		if (!Objects.equals(a.getTarget(), b.getTarget())) {
			return false; // For capture memory action
		}
		if (!Objects.equals(a.getTime(), b.getTime())) {
			return false;
		}
		if (!Objects.equals(a.getThread(), b.getThread())) {
			return false; // for reg/pc tracking
		}
		if (!Objects.equals(a.getFrame(), b.getFrame())) {
			return false; // for reg/pc tracking
		}
		return true;
	}

	interface AutoDisassembleAction {
		String NAME = "Auto-Disassembly";
		String DESCRIPTION = "If the tracking spec follows the PC, disassemble automatically.";
		String HELP_ANCHOR = "auto_disassembly";

		static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	protected class MarkerSetChangeListener implements ChangeListener {
		@Override
		public void stateChanged(ChangeEvent e) {
			getListingPanel().getFieldPanel().repaint();
		}
	}

	protected class ForStaticSyncMappingChangeListener
			implements DebuggerStaticMappingChangeListener {
		@Override
		public void mappingsChanged(Set<Trace> affectedTraces, Set<Program> affectedPrograms) {
			Swing.runIfSwingOrRunLater(() -> {
				if (current.getView() == null) {
					return;
				}
				if (!affectedTraces.contains(current.getTrace())) {
					return;
				}
				doMarkTrackedLocation();
			});
		}
	}

	protected class ForListingGoToTrait extends DebuggerGoToTrait {
		public ForListingGoToTrait() {
			super(DebuggerListingProvider.this.tool, DebuggerListingProvider.this.plugin,
				DebuggerListingProvider.this);
		}

		@Override
		protected GoToInput getDefaultInput() {
			return trackingTrait.getDefaultGoToInput(getLocation());
		}

		@Override
		protected boolean goToAddress(Address address) {
			return getListingPanel().goTo(address);
		}
	}

	protected class ForListingTrackingTrait extends DebuggerTrackLocationTrait {
		public ForListingTrackingTrait() {
			super(DebuggerListingProvider.this.tool, DebuggerListingProvider.this.plugin,
				DebuggerListingProvider.this);

			getListingPanel().addIndexMapChangeListener(e -> this.doTrack(TrackCause.DB_CHANGE));
		}

		@Override
		protected void specChanged(LocationTrackingSpec spec) {
			if (isMainListing()) {
				plugin.firePluginEvent(new TrackingChangedPluginEvent(getName(), spec));
			}
			updateTitle();
			trackingLabel.setText("");
			trackingLabel.setToolTipText("");
			trackingLabel.setForeground(Colors.FOREGROUND);
			trackingSpecChangeListeners.invoke().locationTrackingSpecChanged(spec);
		}

		@Override
		protected void locationTracked() {
			doGoToTracked();
			if (!autoDisassemble || !trackingTrait.shouldDisassemble()) {
				return;
			}
			disassemblyDebouncer.contact(trackedLocation.getByteAddress());
		}

		boolean shouldDisassemble() {
			return trackedLocation != null && tracker.shouldDisassemble();
		}
	}

	protected class ForListingReadsMemoryTrait extends DebuggerReadsMemoryTrait {
		public ForListingReadsMemoryTrait() {
			super(DebuggerListingProvider.this.tool, DebuggerListingProvider.this.plugin,
				DebuggerListingProvider.this);
		}

		@Override
		protected AddressSetView getSelection() {
			return DebuggerListingProvider.this.getSelection();
		}

		@Override
		protected void repaintPanel() {
			getListingPanel().getFieldPanel().repaint();
		}

		@Override
		protected void memoryWasRead(AddressSetView read) {
			if (!autoDisassemble || !trackingTrait.shouldDisassemble()) {
				return;
			}
			ProgramLocation loc = trackingTrait.getTrackedLocation();
			if (!read.contains(loc.getByteAddress())) {
				return;
			}
			disassemblyDebouncer.contact(loc.getByteAddress());
		}
	}

	protected class ForListingClipboardProvider extends CodeBrowserClipboardProvider {
		protected class PasteIntoTargetCommand extends PasteByteStringCommand
				implements PasteIntoTargetMixin {
			protected PasteIntoTargetCommand(String string) {
				super(string);
			}

			@Override
			protected boolean hasEnoughSpace(Program program, Address address, int byteCount) {
				return doHasEnoughSpace(program, address, byteCount);
			}

			@Override
			protected boolean pasteBytes(Program program, byte[] bytes) {
				return doPasteBytes(tool, controlService, consoleService, current, currentLocation,
					bytes);
			}
		}

		protected ForListingClipboardProvider() {
			super(DebuggerListingProvider.this.tool, DebuggerListingProvider.this);
		}

		@Override
		public boolean isValidContext(ActionContext context) {
			if (!(context instanceof DebuggerListingActionContext)) {
				return false;
			}
			return context.getComponentProvider() == componentProvider;
		}

		@Override
		public boolean canPaste(DataFlavor[] availableFlavors) {
			if (controlService == null) {
				return false;
			}
			Trace trace = current.getTrace();
			if (trace == null) {
				return false;
			}
			if (!controlService.getCurrentMode(trace).canEdit(current)) {
				return false;
			}
			return super.canPaste(availableFlavors);
		}

		@Override
		protected boolean pasteByteString(String string) {
			return tool.execute(new PasteIntoTargetCommand(string), currentProgram);
		}
	}

	private final DebuggerListingPlugin plugin;

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	//@AutoServiceConsumed via method
	private DebuggerStaticMappingService mappingService;
	@AutoServiceConsumed
	private DebuggerConsoleService consoleService;
	//@AutoServiceConsumed via method
	private DebuggerControlService controlService;
	//@AutoServiceConsumed via method
	private MarkerService markerService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private final Color trackingColor = DebuggerResources.COLOR_REGISTER_MARKERS;

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	protected Program markedProgram;
	protected Address markedAddress;
	protected MarkerSet trackingMarker;

	protected DockingAction actionGoTo;
	protected ToggleDockingAction actionFollowsCurrentThread;
	protected ToggleDockingAction actionAutoDisassemble;
	protected MultiStateDockingAction<AutoReadMemorySpec> actionAutoReadMemory;
	protected DockingAction actionRefreshSelectedMemory;
	protected MultiStateDockingAction<LocationTrackingSpec> actionTrackLocation;

	@AutoConfigStateField
	protected boolean followsCurrentThread = true;
	@AutoConfigStateField
	protected boolean autoDisassemble = true;

	protected final ForListingGoToTrait goToTrait;
	protected final ForListingTrackingTrait trackingTrait;
	protected final ForListingReadsMemoryTrait readsMemTrait;

	protected final AsyncDebouncer<Address> disassemblyDebouncer =
		new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, 100);

	protected final ListenerSet<LocationTrackingSpecChangeListener> trackingSpecChangeListeners =
		new ListenerSet<>(LocationTrackingSpecChangeListener.class, true);

	protected final DebuggerTraceTabPanel traceTabs;
	protected final DebuggerLocationLabel locationLabel = new DebuggerLocationLabel();
	protected final JLabel trackingLabel = new JLabel();

	protected final MultiBlendedListingBackgroundColorModel colorModel;
	protected final MarkerSetChangeListener markerChangeListener = new MarkerSetChangeListener();
	protected MarkerServiceBackgroundColorModel markerServiceColorModel;
	protected MarkerMarginProvider markerMarginProvider;
	protected MarkerOverviewProvider markerOverviewProvider;

	private final SuppressableCallback<ProgramLocation> cbGoTo = new SuppressableCallback<>();

	protected final ForStaticSyncMappingChangeListener mappingChangeListener =
		new ForStaticSyncMappingChangeListener();
	private final ControlModeChangeListener controlModeChangeListener = (trace, mode) -> {
		if (trace == current.getTrace()) {
			// for Paste action
			contextChanged();
		}
	};

	protected final boolean isMainListing;

	private long countAddressesInIndex;

	public DebuggerListingProvider(DebuggerListingPlugin plugin, FormatManager formatManager,
			boolean isConnected) {
		super(plugin, formatManager, isConnected);
		this.plugin = plugin;
		this.isMainListing = isConnected;

		// LATER: Consider an icon to distinguish dynamic from static

		goToTrait = new ForListingGoToTrait();
		trackingTrait = new ForListingTrackingTrait();
		readsMemTrait = new ForListingReadsMemoryTrait();

		disassemblyDebouncer.addListener(this::doAutoDisassemble);

		ListingPanel listingPanel = getListingPanel();
		colorModel = plugin.createListingBackgroundColorModel(listingPanel);
		colorModel.addModel(trackingTrait.createListingBackgroundColorModel(listingPanel));
		listingPanel.setBackgroundColorModel(colorModel);

		autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		setVisible(true);
		createActions();

		goToTrait.goToCoordinates(current);
		trackingTrait.goToCoordinates(current);
		readsMemTrait.goToCoordinates(current);
		locationLabel.goToCoordinates(current);

		if (isConnected) {
			traceTabs = new DebuggerTraceTabPanel(plugin);
		}
		else {
			traceTabs = null;
		}

		addDisplayListener(readsMemTrait.getDisplayListener());

		JPanel northPanel = new JPanel(new BorderLayout());
		northPanel.add(locationLabel);
		northPanel.add(trackingLabel, BorderLayout.EAST);
		if (traceTabs != null) {
			northPanel.add(traceTabs, BorderLayout.NORTH);
		}
		this.setNorthComponent(northPanel);
		if (isConnected) {
			setTitle(DebuggerResources.TITLE_PROVIDER_LISTING);
		}
		else {
			setTitle("[" + DebuggerResources.TITLE_PROVIDER_LISTING + "]");
		}
		updateTitle(); // Actually, the subtitle
		setHelpLocation(DebuggerResources.HELP_PROVIDER_LISTING);

		trackingLabel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
					doGoToTracked();
				}
			}
		});
	}

	@Override
	public boolean isConnected() {
		/*
		 * NB. Other plugins ask isConnected meaning the main static listing. We don't want to be
		 * mistaken for it.
		 */
		return false;
	}

	@Override
	public boolean isDynamic() {
		return true;
	}

	/**
	 * Check if this is the main dynamic listing.
	 * 
	 * <p>
	 * The method {@link #isConnected()} is not quite the same as this, although the concepts are a
	 * little conflated, since before the debugger, no one else presented a listing that could claim
	 * to be "main" except the "connected" one. Here, we treat "connected" to mean that the address
	 * is synchronized exactly with the other providers. "Main" on the other hand, does not
	 * necessarily have that property, but it is still <em>not</em> a clone. It is the main listing
	 * presented by this plugin, and so it has certain unique features. Calling
	 * {@link DebuggerListingPlugin#getProvider()} will return the main dynamic listing.
	 * 
	 * @return true if this is the main listing for the plugin.
	 */
	public boolean isMainListing() {
		return isMainListing;
	}

	@Override
	public boolean isReadOnly() {
		if (controlService == null) {
			return true;
		}
		Trace trace = current.getTrace();
		if (trace == null) {
			return true;
		}
		ControlMode mode = controlService.getCurrentMode(trace);
		return !mode.canEdit(current);
	}

	@Override
	public String getWindowGroup() {
		//TODO: Overriding this to align disconnected providers
		return "Core";
	}

	@Override
	public void writeDataState(SaveState saveState) {
		if (!isMainListing()) {
			current.writeDataState(tool, saveState, KEY_DEBUGGER_COORDINATES);
		}
		super.writeDataState(saveState);
	}

	@Override
	public void readDataState(SaveState saveState) {
		if (!isMainListing()) {
			DebuggerCoordinates coordinates =
				DebuggerCoordinates.readDataState(tool, saveState, KEY_DEBUGGER_COORDINATES);
			coordinatesActivated(coordinates);
		}
		super.readDataState(saveState);
	}

	void writeConfigState(SaveState saveState) {
		// TODO: Override and invoke super.saveState, but it's package private

		SaveState formatManagerState = new SaveState("formatManager");
		getListingPanel().getFormatManager().saveState(formatManagerState);
		saveState.putXmlElement("formatManager", formatManagerState.saveToXml());

		CONFIG_STATE_HANDLER.writeConfigState(this, saveState);
		trackingTrait.writeConfigState(saveState);
		readsMemTrait.writeConfigState(saveState);
	}

	void readConfigState(SaveState saveState) {
		// TODO: Override and invoke super.readState, but it's package private

		Element formatManagerElement = saveState.getXmlElement("formatManager");
		if (formatManagerElement != null) {
			SaveState formatManagerState = new SaveState(formatManagerElement);
			getListingPanel().getFormatManager().readState(formatManagerState);
		}

		CONFIG_STATE_HANDLER.readConfigState(this, saveState);
		trackingTrait.readConfigState(saveState);
		readsMemTrait.readConfigState(saveState);

		if (isMainListing()) {
			followsCurrentThread = true;
		}
		else {
			actionFollowsCurrentThread.setSelected(followsCurrentThread);
			updateBorder();
		}
		actionAutoDisassemble.setSelected(autoDisassemble);
	}

	@Override
	public void addToTool() {
		/**
		 * NOTE: This isn't great. addToTool executes the window placement logic but is called by
		 * the CodeViewer constructor, so we have no efficient path in
		 */
		setIntraGroupPosition(WindowPosition.STACK);
		setDefaultWindowPosition(WindowPosition.STACK);
		super.addToTool();
	}

	protected void updateMarkerServiceColorModel() {
		colorModel.removeModel(markerServiceColorModel);
		if (markerService != null) {
			colorModel.addModel(markerServiceColorModel = new MarkerServiceBackgroundColorModel(
				markerService, current.getView(), getListingPanel().getAddressIndexMap()));
		}
	}

	@AutoServiceConsumed
	private void setMappingService(DebuggerStaticMappingService mappingService) {
		if (this.mappingService != null) {
			this.mappingService.removeChangeListener(mappingChangeListener);
		}
		this.mappingService = mappingService;
		if (this.mappingService != null) {
			this.mappingService.addChangeListener(mappingChangeListener);
			doMarkTrackedLocation();
		}
	}

	protected void removeOldStaticTrackingMarker() {
		if (markerService != null && trackingMarker != null) {
			markerService.removeMarker(trackingMarker, markedProgram);
			trackingMarker = null;
		}
	}

	protected void createNewStaticTrackingMarker() {
		if (markerService != null && markedAddress != null) {
			trackingMarker = markerService.createPointMarker("Tracked Register",
				"An address stored by a trace register, mapped to a static program", markedProgram,
				MarkerService.HIGHLIGHT_PRIORITY + 1, true, true, true, trackingColor,
				ICON_REGISTER_MARKER, true);
			trackingMarker.add(markedAddress);
		}
	}

	@AutoServiceConsumed
	private void setMarkerService(MarkerService markerService) {
		if (this.markerService != null) {
			this.markerService.removeChangeListener(markerChangeListener);
			removeMarginProvider(markerMarginProvider);
			markerMarginProvider = null;
			removeOverviewProvider(markerOverviewProvider);
			markerOverviewProvider = null;
		}
		removeOldStaticTrackingMarker();
		this.markerService = markerService;
		createNewStaticTrackingMarker();
		updateMarkerServiceColorModel();

		if (this.markerService != null && !isMainListing()) {
			// NOTE: Connected provider marker listener is taken care of by CodeBrowserPlugin
			this.markerService.addChangeListener(markerChangeListener);
		}
		if (this.markerService != null) {
			markerMarginProvider = markerService.createMarginProvider();
			addMarginProvider(markerMarginProvider);
			markerOverviewProvider = markerService.createOverviewProvider();
			addOverviewProvider(markerOverviewProvider);
		}
	}

	@AutoServiceConsumed
	private void setControlService(DebuggerControlService controlService) {
		if (this.controlService != null) {
			this.controlService.removeModeChangeListener(controlModeChangeListener);
		}
		this.controlService = controlService;
		if (this.controlService != null) {
			this.controlService.addModeChangeListener(controlModeChangeListener);
		}
	}

	protected void markTrackedStaticLocation(ProgramLocation location) {
		Swing.runIfSwingOrRunLater(() -> {
			if (location == null) {
				removeOldStaticTrackingMarker();
				markedAddress = null;
				markedProgram = null;
			}
			else if (trackingMarker != null && location.getProgram() == markedProgram) {
				trackingMarker.clearAll();
				markedAddress = location.getAddress();
				trackingMarker.add(markedAddress);
			}
			else {
				removeOldStaticTrackingMarker();
				markedAddress = location.getAddress();
				markedProgram = location.getProgram();
				createNewStaticTrackingMarker();
			}
		});
	}

	public void programClosed(Program program) {
		if (program == markedProgram) {
			removeOldStaticTrackingMarker();
			markedProgram = null;
			markedAddress = null;
		}
	}

	@Override
	protected void doSetProgram(Program newProgram) {
		// E.g., The "Navigate Previous" could cause a change in trace
		if (newProgram != null && current.getView() != null && newProgram != current.getView()) {
			if (!(newProgram instanceof TraceProgramView view)) {
				throw new IllegalArgumentException("Dynamic Listings require trace views");
			}
			traceManager.activateTrace(view.getTrace());
		}
		if (getProgram() == newProgram) {
			return;
		}
		if (newProgram != null && !(newProgram instanceof TraceProgramView)) {
			throw new IllegalArgumentException("Dynamic Listings require trace views");
		}
		setSelection(new ProgramSelection());
		super.doSetProgram(newProgram);
		updateTitle();
		locationLabel.updateLabel();
	}

	protected String computeSubTitle() {
		TraceProgramView view = current.getView();
		List<String> parts = new ArrayList<>();
		LocationTrackingSpec trackingSpec = trackingTrait == null ? null : trackingTrait.getSpec();
		if (trackingSpec != null) {
			String specTitle = trackingSpec.computeTitle(current);
			if (specTitle != null) {
				parts.add(specTitle);
			}
		}
		if (view != null) {
			parts.add(current.getTrace().getDomainFile().getName());
		}
		return StringUtils.join(parts, ", ");
	}

	// TODO: Once refactored, this is not part of the abstract impl.
	@Override // Since we want to override, we can't rename updateSubTitle
	protected void updateTitle() {
		setSubTitle(computeSubTitle());
	}

	@Override
	protected String computePanelTitle(Program panelProgram) {
		if (!(panelProgram instanceof TraceProgramView)) {
			// really shouldn't happen anyway...
			return super.computePanelTitle(panelProgram);
		}
		TraceProgramView view = (TraceProgramView) panelProgram;
		TraceSnapshot snapshot =
			view.getTrace().getTimeManager().getSnapshot(view.getSnap(), false);
		if (snapshot == null) {
			return Long.toString(view.getSnap());
		}
		String description = snapshot.getDescription();
		String schedule = snapshot.getScheduleString();
		if (description == null) {
			description = "";
		}
		if (schedule == null) {
			schedule = "";
		}
		if (!description.isBlank() && !schedule.isBlank()) {
			return description + " (" + schedule + ")";
		}
		if (!description.isBlank()) {
			return description;
		}
		if (!schedule.isBlank()) {
			return schedule;
		}
		return DateUtils.formatDateTimestamp(new Date(snapshot.getRealTime()));
	}

	@Override
	public Icon getIcon() {
		if (isMainListing()) {
			return getBaseIcon();
		}
		return super.getIcon();
	}

	@Override
	protected ListingActionContext newListingActionContext() {
		return new DebuggerListingActionContext(this);
	}

	@Override
	protected CodeBrowserClipboardProvider newClipboardProvider() {
		return new ForListingClipboardProvider();
	}

	protected void createActions() {
		if (!isMainListing()) {
			actionFollowsCurrentThread = FollowsCurrentThreadAction.builder(plugin)
					.enabled(true)
					.selected(true)
					.onAction(
						ctx -> doSetFollowsCurrentThread(actionFollowsCurrentThread.isSelected()))
					.buildAndInstallLocal(this);
		}

		actionAutoDisassemble = AutoDisassembleAction.builder(plugin)
				.enabled(true)
				.selected(true)
				.onAction(ctx -> doSetAutoDisassemble(actionAutoDisassemble.isSelected()))
				.buildAndInstallLocal(this);

		actionGoTo = goToTrait.installAction();
		actionTrackLocation = trackingTrait.installAction();
		actionAutoReadMemory = readsMemTrait.installAutoReadAction();
		actionRefreshSelectedMemory = readsMemTrait.installRefreshSelectedAction();

		contextChanged();
	}

	protected boolean isEffectivelyDifferent(ProgramLocation cur, ProgramLocation dest) {
		if (Objects.equals(cur, dest)) {
			return false;
		}
		if (cur == null || dest == null) {
			return true;
		}
		if (dest.getClass() != ProgramLocation.class) {
			return true;
		}
		TraceProgramView curView = (TraceProgramView) cur.getProgram();
		TraceProgramView destView = (TraceProgramView) dest.getProgram();
		if (curView.getTrace() != destView.getTrace()) {
			return true;
		}
		if (!Objects.equals(cur.getAddress(), dest.getAddress())) {
			return true;
		}
		return false;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * The name isn't descriptive because this overrides a callback for {@link ChangeListener},
	 * which applies to many things in general. This one is for changes in the listing model's
	 * "size", i.e., the memory mapping or assigned view has changed. This should be the perfect
	 * place to ensure the tracked location is centered, if applicable.
	 * 
	 * <p>
	 * It seems this method gets called a bit spuriously. A change in bytes, which does not imply a
	 * change in layout, will also land us here. Thus, we do some simple test here to verify that
	 * the layout has actually changed. A good proxy is if the number of addresses in the listing
	 * has changed. To detect that, we have to record what we've seen each change.
	 */
	@Override
	public void stateChanged(ChangeEvent e) {
		super.stateChanged(e);
		long newCountAddressesInIndex =
			getListingPanel().getAddressIndexMap().getIndexedAddressSet().getNumAddresses();
		if (this.countAddressesInIndex == newCountAddressesInIndex) {
			return;
		}
		this.countAddressesInIndex = newCountAddressesInIndex;
		ProgramLocation trackedLocation = trackingTrait.getTrackedLocation();
		if (trackedLocation != null && !isEffectivelyDifferent(getLocation(), trackedLocation)) {
			cbGoTo.invoke(() -> Swing.runLater(() -> {
				boolean goneTo = getListingPanel().goTo(trackedLocation, true);
				if (goneTo) {
					getListingPanel().center(trackedLocation);
				}
			}));
		}
	}

	@Override
	public boolean goTo(Program gotoProgram, ProgramLocation location) {
		assert Swing.isSwingThread();
		return cbGoTo.invokeWithTop(goingTo -> {
			if (!isEffectivelyDifferent(goingTo, location)) {
				getListingPanel().scrollTo(location);
				return false;
			}
			try (Suppression supp = cbGoTo.suppress(location)) {
				if (!isEffectivelyDifferent(getLocation(), location)) {
					getListingPanel().scrollTo(location);
					return true;
				}
				// "Disconnected" providers normally do not allow program changes. Override that
				if (gotoProgram != getProgram()) {
					doSetProgram(gotoProgram);
				}
				if (gotoProgram == null ||
					!gotoProgram.getMemory().contains(location.getAddress())) {
					return false;
				}
				if (super.goTo(gotoProgram, location)) {
					return true;
				}
				return false;
			}
		});
	}

	@Override
	public void programLocationChanged(ProgramLocation location, EventTrigger trigger) {
		locationLabel.goToAddress(location.getAddress());
		if (traceManager != null) {
			location = ProgramLocationUtils.fixLocation(location, false);
		}
		super.programLocationChanged(location, trigger);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (traceTabs != null) {
			DebuggerTraceFileActionContext traceCtx = traceTabs.getActionContext(event);
			if (traceCtx != null) {
				return traceCtx;
			}
		}
		if (event == null || event.getSource() != locationLabel) {
			return super.getActionContext(event);
		}
		return locationLabel.getActionContext(this, event);
	}

	public void setTrackingSpec(LocationTrackingSpec spec) {
		trackingTrait.setSpec(spec);
	}

	public LocationTrackingSpec getTrackingSpec() {
		return trackingTrait.getSpec();
	}

	public void addTrackingSpecChangeListener(LocationTrackingSpecChangeListener listener) {
		trackingSpecChangeListeners.add(listener);
	}

	public void removeTrackingSpecChangeListener(LocationTrackingSpecChangeListener listener) {
		trackingSpecChangeListeners.remove(listener);
	}

	public void setFollowsCurrentThread(boolean follows) {
		if (isMainListing()) {
			throw new IllegalStateException(
				"The main dynamic listing always follows the current trace and thread");
		}
		actionFollowsCurrentThread.setSelected(follows);
		doSetFollowsCurrentThread(follows);
	}

	protected void doSetFollowsCurrentThread(boolean follows) {
		this.followsCurrentThread = follows;
		updateBorder();
		updateTitle();
		coordinatesActivated(traceManager.getCurrent());
	}

	public void setAutoDisassemble(boolean auto) {
		actionAutoDisassemble.setSelected(true);
		doSetAutoDisassemble(auto);
	}

	protected void doSetAutoDisassemble(boolean auto) {
		this.autoDisassemble = auto;
	}

	protected void updateBorder() {
		// TODO: Probably make this accessible from abstract class, instead
		ListingPanelContainer decoration = (ListingPanelContainer) getComponent();
		decoration.setConnnected(followsCurrentThread);
	}

	public boolean isFollowsCurrentThread() {
		return followsCurrentThread;
	}

	public boolean isAutoDisassemble() {
		return autoDisassemble;
	}

	public void setAutoReadMemorySpec(AutoReadMemorySpec spec) {
		readsMemTrait.setAutoSpec(spec);
	}

	public AutoReadMemorySpec getAutoReadMemorySpec() {
		return readsMemTrait.getAutoSpec();
	}

	/* testing */
	CompletableFuture<?> getLastAutoRead() {
		return readsMemTrait.getLastRead();
	}

	protected ProgramLocation doMarkTrackedLocation() {
		ProgramLocation trackedLocation = trackingTrait.getTrackedLocation();
		if (trackedLocation == null) {
			markTrackedStaticLocation(null);
			return null;
		}
		ProgramLocation trackedStatic = mappingService == null ? null
				: mappingService.getStaticLocationFromDynamic(trackedLocation);
		markTrackedStaticLocation(trackedStatic);
		return trackedStatic;
	}

	protected void goToAndUpdateTrackingLabel(TraceProgramView curView, ProgramLocation loc) {
		String labelText = trackingTrait.computeLabelText();
		trackingLabel.setText(labelText);
		trackingLabel.setToolTipText(labelText);
		if (goTo(curView, loc)) {
			trackingLabel.setForeground(Colors.FOREGROUND);
		}
		else {
			trackingLabel.setForeground(Colors.ERROR);
		}
	}

	protected void doGoToTracked() {
		Swing.runIfSwingOrRunLater(() -> {
			ProgramLocation loc = trackingTrait.getTrackedLocation();
			doMarkTrackedLocation();
			if (loc == null) {
				return;
			}
			TraceProgramView curView = current.getView();
			if (curView != current.getView()) {
				// Trace changed before Swing scheduled us
				return;
			}
			goToAndUpdateTrackingLabel(curView, loc);
		});
	}

	protected void doAutoDisassemble(Address start) {
		TraceProgramView view = current.getView();
		if (view == null) {
			return;
		}
		/**
		 * We'll avoid re-disassembly only if there already exists an instruction <em>at the start
		 * address</em>. If it's in the middle, then we're off cut and should re-disassemble at the
		 * new start.
		 */
		Instruction exists = view.getListing().getInstructionAt(start);
		if (exists != null) {
			return;
		}
		AddressSetView set = DebuggerDisassemblerPlugin.computeAutoDisassembleAddresses(start,
			current.getTrace(), current.getViewSnap());
		if (set == null) {
			return;
		}
		Reqs reqs = Reqs.fromView(tool, view);
		if (reqs == null) {
			return;
		}
		CurrentPlatformTraceDisassembleCommand dis =
			new CurrentPlatformTraceDisassembleCommand(tool, set, reqs, start);
		dis.run(tool, view);
	}

	@Override
	public void dispose() {
		super.dispose();
		removeOldStaticTrackingMarker();
	}

	protected DebuggerCoordinates adjustCoordinates(DebuggerCoordinates coordinates) {
		if (followsCurrentThread) {
			return coordinates;
		}
		// Because the view's snap is changing with or without us.... So go with.
		// i.e., take the time, but not the thread
		return current.time(coordinates.getTime());
	}

	public void goToCoordinates(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}
		current = coordinates;
		doSetProgram(current.getView());
		goToTrait.goToCoordinates(coordinates);
		trackingTrait.goToCoordinates(coordinates);
		readsMemTrait.goToCoordinates(coordinates);
		locationLabel.goToCoordinates(coordinates);
		updateTitle();
		contextChanged();
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		DebuggerCoordinates adjusted = adjustCoordinates(coordinates);
		goToCoordinates(adjusted);
		if (adjusted.getTrace() == null) {
			trackingLabel.setText("");
			trackingLabel.setForeground(Colors.FOREGROUND);
		}
	}

	public void traceClosed(Trace trace) {
		if (current.getTrace() == trace) {
			goToCoordinates(DebuggerCoordinates.NOWHERE);
		}
	}

	@Override
	public void cloneWindow() {
		final DebuggerListingProvider newProvider = plugin.createNewDisconnectedProvider();
		final ViewerPosition vp = getListingPanel().getFieldPanel().getViewerPosition();
		final SaveState saveState = new SaveState();
		writeConfigState(saveState);
		Swing.runLater(() -> {
			newProvider.readConfigState(saveState);

			newProvider.goToCoordinates(current);
			newProvider.getListingPanel()
					.getFieldPanel()
					.setViewerPosition(vp.getIndex(), vp.getXOffset(), vp.getYOffset());
		});
	}

	@Override
	public AddressableByteSource getByteSource() {
		if (current == DebuggerCoordinates.NOWHERE) {
			return EmptyByteSource.INSTANCE;
		}
		return new DebuggerByteSource(tool, current.getView(), current.getTarget(), readsMemTrait);
	}
}
