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
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.lang.invoke.MethodHandles;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.apache.commons.lang3.StringUtils;
import org.jdom.Element;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.support.ViewerPosition;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.nav.ListingPanelContainer;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.codebrowser.MarkerServiceBackgroundColorModel;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerLocationLabel;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.FollowsCurrentThreadAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.OpenProgramAction;
import ghidra.app.plugin.core.debug.gui.action.*;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerMissingModuleActionContext;
import ghidra.app.plugin.core.debug.utils.ProgramLocationUtils;
import ghidra.app.plugin.core.debug.utils.ProgramURLUtils;
import ghidra.app.plugin.core.marker.MarkerMarginProvider;
import ghidra.app.plugin.core.marker.MarkerOverviewProvider;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerListingService.LocationTrackingSpecChangeListener;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.*;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.*;
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
		if (!Objects.equals(a.getRecorder(), b.getRecorder())) {
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
				cleanMissingModuleMessages(affectedTraces);
			});
		}
	}

	protected class ForListingSyncTrait extends DebuggerStaticSyncTrait {
		public ForListingSyncTrait() {
			super(DebuggerListingProvider.this.tool, DebuggerListingProvider.this.plugin,
				DebuggerListingProvider.this, isMainListing());
		}

		@Override
		protected void staticGoTo(ProgramLocation location) {
			Swing.runIfSwingOrRunLater(() -> plugin.fireStaticLocationEvent(location));
		}

		@Override
		protected void staticSelect(Program program, ProgramSelection selection) {
			Swing.runIfSwingOrRunLater(() -> plugin.fireStaticSelectionEvent(program, selection));
			if (selection.isEmpty()) {
				return;
			}
			Optional<CodeViewerService> codeViewer =
				Stream.of(tool.getServices(CodeViewerService.class))
						.filter(cv -> cv != plugin)
						.findFirst();
			if (codeViewer.isEmpty()) {
				return;
			}
			Swing.runIfSwingOrRunLater(
				() -> codeViewer.get()
						.getListingPanel()
						.scrollTo(new ProgramLocation(program, selection.getMinAddress())));
		}

		@Override
		protected void dynamicGoTo(ProgramLocation location) {
			Swing.runIfSwingOrRunLater(() -> goTo(location.getProgram(), location));
		}

		@Override
		protected void dynamicSelect(Program program, ProgramSelection selection) {
			Swing.runIfSwingOrRunLater(() -> {
				setSelection(selection);
				if (!selection.isEmpty()) {
					getListingPanel()
							.scrollTo(new ProgramLocation(program, selection.getMinAddress()));
				}
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
			if (syncTrait.isAutoSyncCursorWithStaticListing()) {
				syncTrait.doAutoSyncCursorIntoStatic(new ProgramLocation(getProgram(), address));
			}
			return getListingPanel().goTo(address);
		}
	}

	protected class ForListingTrackingTrait extends DebuggerTrackLocationTrait {
		public ForListingTrackingTrait() {
			super(DebuggerListingProvider.this.tool, DebuggerListingProvider.this.plugin,
				DebuggerListingProvider.this);
		}

		@Override
		protected void specChanged(LocationTrackingSpec spec) {
			updateTitle();
			trackingLabel.setText("");
			trackingLabel.setForeground(Colors.FOREGROUND);
			trackingSpecChangeListeners.fire.locationTrackingSpecChanged(spec);
		}

		@Override
		protected void locationTracked() {
			doGoToTracked();
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
	}

	private final DebuggerListingPlugin plugin;

	//@AutoServiceConsumed via method
	private DebuggerTraceManagerService traceManager;
	//@AutoServiceConsumed via method
	private DebuggerStaticMappingService mappingService;
	@AutoServiceConsumed
	private DebuggerConsoleService consoleService;
	@AutoServiceConsumed
	private DebuggerControlService controlService;
	@AutoServiceConsumed
	private ProgramManager programManager;
	@AutoServiceConsumed
	private FileImporterService importerService;
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
	protected ToggleDockingAction actionAutoSyncCursorWithStaticListing;
	protected ToggleDockingAction actionAutoSyncSelectionWithStaticListing;
	protected DockingAction actionSyncSelectionIntoStaticListing;
	protected DockingAction actionSyncSelectionFromStaticListing;
	protected ToggleDockingAction actionFollowsCurrentThread;
	protected MultiStateDockingAction<AutoReadMemorySpec> actionAutoReadMemory;
	protected DockingAction actionRefreshSelectedMemory;
	protected DockingAction actionOpenProgram;
	protected MultiStateDockingAction<LocationTrackingSpec> actionTrackLocation;

	@AutoConfigStateField
	protected boolean followsCurrentThread = true;
	// TODO: followsCurrentSnap?

	protected final ForListingSyncTrait syncTrait;
	protected final ForListingGoToTrait goToTrait;
	protected final ForListingTrackingTrait trackingTrait;
	protected final ForListingReadsMemoryTrait readsMemTrait;

	protected final ListenerSet<LocationTrackingSpecChangeListener> trackingSpecChangeListeners =
		new ListenerSet<>(LocationTrackingSpecChangeListener.class);

	protected final DebuggerLocationLabel locationLabel = new DebuggerLocationLabel();
	protected final JLabel trackingLabel = new JLabel();

	protected final MultiBlendedListingBackgroundColorModel colorModel;
	protected final MarkerSetChangeListener markerChangeListener = new MarkerSetChangeListener();
	protected MarkerServiceBackgroundColorModel markerServiceColorModel;
	protected MarkerMarginProvider markerMarginProvider;
	protected MarkerOverviewProvider markerOverviewProvider;

	private SuppressableCallback<ProgramLocation> cbGoTo = new SuppressableCallback<>();

	protected final ForStaticSyncMappingChangeListener mappingChangeListener =
		new ForStaticSyncMappingChangeListener();

	protected final boolean isMainListing;

	private long countAddressesInIndex;

	public DebuggerListingProvider(DebuggerListingPlugin plugin, FormatManager formatManager,
			boolean isConnected) {
		super(plugin, formatManager, isConnected);
		this.plugin = plugin;
		this.isMainListing = isConnected;

		syncTrait = new ForListingSyncTrait();
		goToTrait = new ForListingGoToTrait();
		trackingTrait = new ForListingTrackingTrait();
		readsMemTrait = new ForListingReadsMemoryTrait();

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

		// TODO: An icon to distinguish dynamic from static

		addDisplayListener(readsMemTrait.getDisplayListener());

		JPanel northPanel = new JPanel(new BorderLayout());
		northPanel.add(locationLabel, BorderLayout.WEST);
		northPanel.add(trackingLabel, BorderLayout.EAST);
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
	 * necessarily have that property, but it is still <em>not</em> a snapshot. It is the main
	 * listing presented by this plugin, and so it has certain unique features. Calling
	 * {@link DebuggerListingPlugin#getConnectedProvider()} will return the main dynamic listing,
	 * despite it not really being "connected."
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
	public boolean isDynamicListing() {
		return true;
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
		syncTrait.readConfigState(saveState);
		trackingTrait.readConfigState(saveState);
		readsMemTrait.readConfigState(saveState);

		if (isMainListing()) {
			followsCurrentThread = true;
		}
		else {
			actionFollowsCurrentThread.setSelected(followsCurrentThread);
			updateBorder();
		}
	}

	@Override
	public void addToTool() {
		//TODO: This is lame.  AddToTool executes the window placement
		// logic but is called by the CodeViewer constructor, so we have
		// no efficient path in
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
	private void setTraceManager(DebuggerTraceManagerService traceManager) {
		this.traceManager = traceManager;
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
	private void setConsoleService(DebuggerConsoleService consoleService) {
		if (consoleService != null) {
			if (actionOpenProgram != null) {
				consoleService.addResolutionAction(actionOpenProgram);
			}
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

	public void programOpened(Program program) {
		if (!isMainListing()) {
			return;
		}
		DomainFile df = program.getDomainFile();
		DebuggerOpenProgramActionContext ctx = new DebuggerOpenProgramActionContext(df);
		if (consoleService != null) {
			consoleService.removeFromLog(ctx);
		}
	}

	public void programClosed(Program program) {
		if (program == markedProgram) {
			removeOldStaticTrackingMarker();
			markedProgram = null;
			markedAddress = null;
		}
	}

	public void staticProgramActivated(Program program) {
		syncTrait.staticProgramActivated(program);
	}

	@Override
	protected void doSetProgram(Program newProgram) {
		if (newProgram != null && current.getView() != null && newProgram != current.getView()) {
			throw new AssertionError();
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

	protected void createActions() {
		if (isMainListing()) {
			actionAutoSyncCursorWithStaticListing =
				syncTrait.installAutoSyncCursorWithStaticListingAction();
			actionAutoSyncSelectionWithStaticListing =
				syncTrait.installAutoSyncSelectionWithStaticListingAction();
		}
		else {
			actionFollowsCurrentThread = FollowsCurrentThreadAction.builder(plugin)
					.enabled(true)
					.selected(true)
					.onAction(
						ctx -> doSetFollowsCurrentThread(actionFollowsCurrentThread.isSelected()))
					.buildAndInstallLocal(this);
		}

		actionSyncSelectionIntoStaticListing =
			syncTrait.installSyncSelectionIntoStaticListingAction();
		actionSyncSelectionFromStaticListing =
			syncTrait.installSyncSelectionFromStaticListingAction();

		actionGoTo = goToTrait.installAction();
		actionTrackLocation = trackingTrait.installAction();
		actionAutoReadMemory = readsMemTrait.installAutoReadAction();
		actionRefreshSelectedMemory = readsMemTrait.installRefreshSelectedAction();

		actionOpenProgram = OpenProgramAction.builder(plugin)
				.withContext(DebuggerOpenProgramActionContext.class)
				.onAction(this::activatedOpenProgram)
				.build();

		contextChanged();
	}

	private void activatedOpenProgram(DebuggerOpenProgramActionContext context) {
		programManager.openProgram(context.getDomainFile(), DomainFile.DEFAULT_VERSION,
			ProgramManager.OPEN_CURRENT);
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
	 */
	@Override
	public void stateChanged(ChangeEvent e) {
		super.stateChanged(e);
		/*
		 * It seems this method gets called a bit spuriously. A change in bytes, which does not
		 * imply a change in layout, will also land us here. Thus, we do some simple test here to
		 * verify that the layout has actually changed. A good proxy is if the number of addresses
		 * in the listing has changed. To detect that, we have to record what we've seen each
		 * change.
		 */
		long newCountAddressesInIndex =
			getListingPanel().getAddressIndexMap().getIndexedAddressSet().getNumAddresses();
		if (this.countAddressesInIndex == newCountAddressesInIndex) {
			return;
		}
		this.countAddressesInIndex = newCountAddressesInIndex;
		ProgramLocation trackedLocation = trackingTrait.getTrackedLocation();
		if (trackedLocation != null && !isEffectivelyDifferent(getLocation(), trackedLocation)) {
			cbGoTo.invoke(() -> getListingPanel().goTo(trackedLocation, true));
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
		syncTrait.dynamicProgramLocationChanged(location, trigger);
		if (trigger == EventTrigger.GUI_ACTION) {
			doCheckCurrentModuleMissing();
		}
	}

	@Override
	public void programSelectionChanged(ProgramSelection selection, EventTrigger trigger) {
		super.programSelectionChanged(selection, trigger);
		syncTrait.dynamicSelectionChanged(getProgram(), selection, trigger);
	}

	protected void doTryOpenProgram(DomainFile df, int version, int state) {
		DebuggerOpenProgramActionContext ctx = new DebuggerOpenProgramActionContext(df);
		if (consoleService != null && consoleService.logContains(ctx)) {
			return;
		}
		if (df.canRecover()) {
			if (consoleService != null) {
				consoleService.log(DebuggerResources.ICON_MODULES, "<html>Program <b>" +
					HTMLUtilities.escapeHTML(df.getPathname()) +
					"</b> has recovery data. It must be opened manually.</html>", ctx);
			}
			return;
		}
		new TaskLauncher(new Task("Open " + df, true, false, false) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				Program program = null;
				try {
					program = (Program) df.getDomainObject(this, false, false, monitor);
					programManager.openProgram(program, state);
				}
				catch (VersionException e) {
					if (consoleService != null) {
						consoleService.log(DebuggerResources.ICON_MODULES, "<html>Program <b>" +
							HTMLUtilities.escapeHTML(df.getPathname()) +
							"</b> was created with a different version of Ghidra." +
							" It must be opened manually.</html>", ctx);
					}
					return;
				}
				catch (Exception e) {
					if (consoleService != null) {
						consoleService.log(DebuggerResources.ICON_LOG_ERROR, "<html>Program <b>" +
							HTMLUtilities.escapeHTML(df.getPathname()) +
							"</b> could not be opened: " + e + ". Try opening it manually.</html>",
							ctx);
					}
					return;
				}
				finally {
					if (program != null) {
						program.release(this);
					}
				}
			}
		}, tool.getToolFrame());
	}

	protected void doCheckCurrentModuleMissing() {
		// Is there any reason to try to open the module if we're not syncing listings?
		// I don't think so.
		if (!syncTrait.isAutoSyncCursorWithStaticListing()) {
			return;
		}
		Trace trace = current.getTrace();
		if (trace == null) {
			return;
		}
		ProgramLocation loc = getLocation();
		if (loc == null) { // Redundant?
			return;
		}
		AddressSpace space = loc.getAddress().getAddressSpace();
		if (space == null) {
			return; // Is this NO_ADDRESS or something?
		}
		if (mappingService == null) {
			return;
		}
		ProgramLocation mapped = mappingService.getStaticLocationFromDynamic(loc);
		if (mapped != null) {
			// No need to import what is already mapped and open
			return;
		}

		long snap = current.getSnap();
		Address address = loc.getAddress();
		TraceStaticMapping mapping = trace.getStaticMappingManager().findContaining(address, snap);
		if (mapping != null) {
			DomainFile df = ProgramURLUtils.getFileForHackedUpGhidraURL(tool.getProject(),
				mapping.getStaticProgramURL());
			if (df != null) {
				doTryOpenProgram(df, DomainFile.DEFAULT_VERSION, ProgramManager.OPEN_CURRENT);
			}
		}

		Set<TraceModule> missing = new HashSet<>();
		Set<DomainFile> toOpen = new HashSet<>();
		TraceModuleManager modMan = trace.getModuleManager();
		Collection<TraceModule> modules = Stream.concat(
			modMan.getModulesAt(snap, address).stream().filter(m -> m.getSections().isEmpty()),
			modMan.getSectionsAt(snap, address).stream().map(s -> s.getModule()))
				.collect(Collectors.toSet());

		// Attempt to open probable matches. All others, list to import
		// TODO: What if sections are not presented?
		for (TraceModule mod : modules) {
			DomainFile match = mappingService.findBestModuleProgram(space, mod);
			if (match == null) {
				missing.add(mod);
			}
			else {
				toOpen.add(match);
			}
		}
		if (programManager != null && !toOpen.isEmpty()) {
			for (DomainFile df : toOpen) {
				// Do not presume a goTo is about to happen. There are no mappings, yet.
				doTryOpenProgram(df, DomainFile.DEFAULT_VERSION, ProgramManager.OPEN_VISIBLE);
			}
		}

		if (importerService == null || consoleService == null) {
			return;
		}

		for (TraceModule mod : missing) {
			consoleService.log(DebuggerResources.ICON_LOG_ERROR,
				"<html>The module <b><tt>" + HTMLUtilities.escapeHTML(mod.getName()) +
					"</tt></b> was not found in the project</html>",
				new DebuggerMissingModuleActionContext(mod));
		}
		/**
		 * Once the programs are opened, including those which are successfully imported, the mapper
		 * bot should take over, eventually invoking callbacks to our mapping change listener.
		 */
	}

	protected boolean isMapped(AddressRange range) {
		if (range == null) {
			return false;
		}
		return mappingService.getStaticLocationFromDynamic(
			new ProgramLocation(getProgram(), range.getMinAddress())) != null;
	}

	protected void cleanMissingModuleMessages(Set<Trace> affectedTraces) {
		if (consoleService == null) {
			return;
		}
		nextCtx: for (ActionContext ctx : consoleService.getActionContexts()) {
			if (!(ctx instanceof DebuggerMissingModuleActionContext mmCtx)) {
				continue;
			}
			TraceModule module = mmCtx.getModule();
			if (!affectedTraces.contains(module.getTrace())) {
				continue;
			}
			if (isMapped(module.getRange())) {
				consoleService.removeFromLog(mmCtx);
				continue;
			}
			for (TraceSection section : module.getSections()) {
				if (isMapped(section.getRange())) {
					consoleService.removeFromLog(mmCtx);
					continue nextCtx;
				}
			}
		}
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

	public void setAutoSyncCursorWithStaticListing(boolean sync) {
		if (!isMainListing()) {
			throw new IllegalStateException(
				"Only the main dynamic listing can be synced to the main static listing");
		}
		syncTrait.setAutoSyncCursorWithStaticListing(sync);
	}

	public void setAutoSyncSelectionWithStaticListing(boolean sync) {
		if (!isMainListing()) {
			throw new IllegalStateException(
				"Only the main dynamic listing can be synced to the main static listing");
		}
		syncTrait.setAutoSyncSelectionWithStaticListing(sync);
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

	protected void updateBorder() {
		// TODO: Probably make this accessible from abstract class, instead
		ListingPanelContainer decoration = (ListingPanelContainer) getComponent();
		decoration.setConnnected(followsCurrentThread);
	}

	public boolean isFollowsCurrentThread() {
		return followsCurrentThread;
	}

	public void setAutoReadMemorySpec(AutoReadMemorySpec spec) {
		readsMemTrait.setAutoSpec(spec);
	}

	public AutoReadMemorySpec getAutoReadMemorySpec() {
		return readsMemTrait.getAutoSpec();
	}

	public void doAutoSyncCursorIntoStatic(ProgramLocation location) {
		syncTrait.doAutoSyncCursorIntoStatic(location);
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
		trackingLabel.setText(trackingTrait.computeLabelText());
		if (goTo(curView, loc)) {
			trackingLabel.setForeground(Colors.FOREGROUND);
		}
		else {
			trackingLabel.setForeground(Colors.ERROR);
		}
	}

	protected void doGoToTracked() {
		ProgramLocation loc = trackingTrait.getTrackedLocation();
		ProgramLocation trackedStatic = doMarkTrackedLocation();
		if (loc == null) {
			return;
		}
		TraceProgramView curView = current.getView();
		if (!syncTrait.isAutoSyncCursorWithStaticListing() || trackedStatic == null) {
			Swing.runIfSwingOrRunLater(() -> {
				if (curView != current.getView()) {
					// Trace changed before Swing scheduled us
					return;
				}
				goToAndUpdateTrackingLabel(curView, loc);
				doCheckCurrentModuleMissing();
			});
		}
		else {
			Swing.runIfSwingOrRunLater(() -> {
				if (curView != current.getView()) {
					// Trace changed before Swing scheduled us
					return;
				}
				goToAndUpdateTrackingLabel(curView, loc);
				doCheckCurrentModuleMissing();
				plugin.fireStaticLocationEvent(trackedStatic);
			});
		}
	}

	@Override
	public void dispose() {
		super.dispose();
		if (consoleService != null) {
			if (actionOpenProgram != null) {
				consoleService.removeResolutionAction(actionOpenProgram);
			}
		}
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
		syncTrait.goToCoordinates(coordinates);
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

	public void staticProgramLocationChanged(ProgramLocation location) {
		syncTrait.staticProgramLocationChanged(location);
	}

	public void staticProgramSelectionChanged(Program program, ProgramSelection selection) {
		syncTrait.staticProgramSelectionChanged(program, selection);
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
}
