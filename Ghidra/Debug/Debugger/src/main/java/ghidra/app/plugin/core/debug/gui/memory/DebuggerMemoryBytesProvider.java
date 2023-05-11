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

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.*;

import javax.swing.JLabel;
import javax.swing.JPanel;

import org.apache.commons.lang3.StringUtils;

import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.menu.MultiStateDockingAction;
import docking.widgets.fieldpanel.support.ViewerPosition;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.plugin.core.byteviewer.*;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerLocationLabel;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.FollowsCurrentThreadAction;
import ghidra.app.plugin.core.debug.gui.action.*;
import ghidra.app.plugin.core.debug.gui.action.AutoReadMemorySpec.AutoReadMemorySpecConfigFieldCodec;
import ghidra.app.plugin.core.format.ByteBlock;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceMemoryBytesChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.util.Swing;

public class DebuggerMemoryBytesProvider extends ProgramByteViewerComponentProvider {
	private static final AutoConfigState.ClassHandler<ProgramByteViewerComponentProvider> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(ProgramByteViewerComponentProvider.class,
			MethodHandles.lookup());
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

	protected class ListenerForChanges extends TraceDomainObjectListener {
		public ListenerForChanges() {
			listenFor(TraceMemoryBytesChangeType.CHANGED, this::bytesChanged);
		}

		private void bytesChanged(TraceAddressSpace space) {
			if (space.getAddressSpace().isMemorySpace()) {
				currCache.invalidate();
				prevCache.invalidate();
			}
		}
	}

	protected class ForMemoryBytesGoToTrait extends DebuggerGoToTrait {
		public ForMemoryBytesGoToTrait() {
			super(DebuggerMemoryBytesProvider.this.tool, DebuggerMemoryBytesProvider.this.plugin,
				DebuggerMemoryBytesProvider.this);
		}

		@Override
		protected GoToInput getDefaultInput() {
			return trackingTrait.getDefaultGoToInput(currentLocation);
		}

		@Override
		protected boolean goToAddress(Address address) {
			TraceProgramView view = current.getView();
			if (view == null) {
				return false;
			}
			return DebuggerMemoryBytesProvider.this.goTo(view, new ProgramLocation(view, address));
		}
	}

	protected class ForMemoryBytesTrackingTrait extends DebuggerTrackLocationTrait {
		public ForMemoryBytesTrackingTrait() {
			super(DebuggerMemoryBytesProvider.this.tool, DebuggerMemoryBytesProvider.this.plugin,
				DebuggerMemoryBytesProvider.this);
		}

		@Override
		protected void locationTracked() {
			doGoToTracked();
		}

		@Override
		protected void specChanged(LocationTrackingSpec spec) {
			updateTitle();
			trackingLabel.setText("");
			trackingLabel.setForeground(Colors.FOREGROUND);
		}
	}

	protected class ForMemoryBytesReadsMemoryTrait extends DebuggerReadsMemoryTrait {
		public ForMemoryBytesReadsMemoryTrait() {
			super(DebuggerMemoryBytesProvider.this.tool, DebuggerMemoryBytesProvider.this.plugin,
				DebuggerMemoryBytesProvider.this);
		}

		@Override
		protected AddressSetView getSelection() {
			return DebuggerMemoryBytesProvider.this.getSelection();
		}

		@Override
		protected void repaintPanel() {
			for (ByteViewerComponent view : getByteViewerPanel().getViewList()) {
				// NB. ByteViewerComponent extends FieldPanel
				view.repaint();
			}
		}
	}

	private final AutoReadMemorySpec defaultReadMemorySpec =
		AutoReadMemorySpec.fromConfigName(VisibleROOnceAutoReadMemorySpec.CONFIG_NAME);

	private final DebuggerMemoryBytesPlugin myPlugin;

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	protected DockingAction actionGoTo;
	protected ToggleDockingAction actionFollowsCurrentThread;
	protected MultiStateDockingAction<AutoReadMemorySpec> actionAutoReadMemory;
	protected DockingAction actionRefreshSelectedMemory;
	protected MultiStateDockingAction<LocationTrackingSpec> actionTrackLocation;

	protected ForMemoryBytesGoToTrait goToTrait;
	protected ForMemoryBytesTrackingTrait trackingTrait;
	protected ForMemoryBytesReadsMemoryTrait readsMemTrait;

	protected final DebuggerLocationLabel locationLabel = new DebuggerLocationLabel();
	protected final JLabel trackingLabel = new JLabel();

	@AutoConfigStateField
	protected boolean followsCurrentThread = true;
	@AutoConfigStateField(codec = AutoReadMemorySpecConfigFieldCodec.class)
	protected AutoReadMemorySpec autoReadMemorySpec = defaultReadMemorySpec;
	// TODO: followsCurrentSnap?

	private final ListenerForChanges listenerForChanges = new ListenerForChanges();

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private DebuggerCoordinates previous = DebuggerCoordinates.NOWHERE;

	private final CachedBytePage currCache = new CachedBytePage();
	private final CachedBytePage prevCache = new CachedBytePage();

	protected final boolean isMainViewer;

	protected DebuggerMemoryBytesProvider(PluginTool tool, DebuggerMemoryBytesPlugin plugin,
			boolean isConnected) {
		super(tool, plugin, DebuggerResources.TITLE_PROVIDER_MEMORY_BYTES, isConnected);
		this.myPlugin = plugin;
		this.isMainViewer = isConnected;

		autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);
		createActions();
		addDisplayListener(readsMemTrait.getDisplayListener());

		JPanel northPanel = new JPanel(new BorderLayout());
		northPanel.add(locationLabel, BorderLayout.WEST);
		northPanel.add(trackingLabel, BorderLayout.EAST);
		decorationComponent.add(northPanel, BorderLayout.NORTH);

		goToTrait.goToCoordinates(current);
		trackingTrait.goToCoordinates(current);
		readsMemTrait.goToCoordinates(current);
		locationLabel.goToCoordinates(current);

		setHelpLocation(DebuggerResources.HELP_PROVIDER_MEMORY_BYTES);

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
	protected ByteBlockChangeManager newByteBlockChangeManager(ProgramByteBlockSet blockSet,
			ByteBlockChangeManager bbcm) {
		return new ByteBlockChangeManager(blockSet, bbcm) {
			@Override
			protected boolean isChanged(ByteBlock block, BigInteger offset, int unitByteSize) {
				if (super.isChanged(block, offset, unitByteSize)) {
					return true;
				}
				if (previous.getTrace() != current.getTrace()) {
					return false;
				}
				Address address = blockSet.getAddress(block, offset);
				if (address == null) {
					return false;
				}
				return currCache.getByte(current, address) != prevCache.getByte(previous, address);
			}
		};
	}

	@Override
	protected ProgramByteBlockSet newByteBlockSet(ByteBlockChangeManager changeManager) {
		if (program == null) {
			return null;
		}
		// A bit of work to get it to ignore existing instructions. Let them be clobbered!
		return new ProgramByteBlockSet(this, program, changeManager) {
			@Override
			protected MemoryByteBlock newMemoryByteBlock(Memory memory, MemoryBlock memBlock) {
				return new MemoryByteBlock(program, memory, memBlock) {
					@Override
					protected boolean editAllowed(Address addr, long length) {
						return true;
					}
				};
			}
		};
	}

	/**
	 * TODO: I'd rather this not be here
	 */
	protected Plugin getPlugin() {
		return plugin;
	}

	protected void initTraits() {
		if (goToTrait == null) {
			goToTrait = new ForMemoryBytesGoToTrait();
		}
		if (trackingTrait == null) {
			trackingTrait = new ForMemoryBytesTrackingTrait();
		}
		if (readsMemTrait == null) {
			readsMemTrait = new ForMemoryBytesReadsMemoryTrait();
		}
	}

	@Override
	protected ByteViewerPanel newByteViewerPanel() {
		initTraits();
		// For highlighting, e.g., state, pc
		return new DebuggerMemoryBytesPanel(this);
	}

	// For testing access
	@Override
	protected ByteViewerPanel getByteViewerPanel() {
		return super.getByteViewerPanel();
	}

	@Override
	protected void addToToolbar() {
		// Prevent this from being added to the toolbar
	}

	/**
	 * Deal with the fact that initialization order is hard to control
	 */
	protected DebuggerCoordinates getCurrent() {
		return current == null ? DebuggerCoordinates.NOWHERE : current;
	}

	protected String computeSubTitle() {
		// TODO: This should be factored in a common place
		DebuggerCoordinates current = getCurrent();
		TraceProgramView view = current == null ? null : current.getView();
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

	@Override
	protected void updateTitle() {
		setSubTitle(computeSubTitle());
	}

	protected void createActions() {
		initTraits();

		if (!isMainViewer()) {
			actionFollowsCurrentThread = FollowsCurrentThreadAction.builder(plugin)
					.enabled(true)
					.selected(true)
					.onAction(
						ctx -> doSetFollowsCurrentThread(actionFollowsCurrentThread.isSelected()))
					.buildAndInstallLocal(this);
		}

		actionGoTo = goToTrait.installAction();
		actionTrackLocation = trackingTrait.installAction();
		actionAutoReadMemory = readsMemTrait.installAutoReadAction();
		actionRefreshSelectedMemory = readsMemTrait.installRefreshSelectedAction();
	}

	@Override
	protected void doSetProgram(Program newProgram) {
		if (newProgram != null && newProgram != current.getView()) {
			throw new AssertionError();
		}
		if (getProgram() == newProgram) {
			return;
		}
		if (newProgram != null && !(newProgram instanceof TraceProgramView)) {
			throw new IllegalArgumentException("Dynamic Listings require trace views");
		}
		super.doSetProgram(newProgram);
		if (newProgram != null) {
			setSelection(new ProgramSelection());
		}
		updateTitle();
		locationLabel.updateLabel();
	}

	@Override
	public boolean goTo(Program gotoProgram, ProgramLocation location) {
		if (location == null) {
			return false;
		}
		if (blockSet == null || blockSet.getByteBlockInfo(location.getAddress()) == null) {
			return false;
		}
		if (!super.goTo(gotoProgram, location)) {
			return false;
		}
		locationLabel.goToAddress(location.getAddress());
		return true;
	}

	protected void removeOldListeners() {
		if (current.getTrace() != null) {
			current.getTrace().removeListener(listenerForChanges);
		}
	}

	protected void addNewListeners() {
		if (current.getTrace() != null) {
			current.getTrace().addListener(listenerForChanges);
		}
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
		previous = current;
		removeOldListeners();
		current = coordinates;
		addNewListeners();
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

	public void setFollowsCurrentThread(boolean follows) {
		if (isMainViewer()) {
			throw new IllegalStateException(
				"The main memory bytes viewer always follows the current trace and thread");
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
		decorationComponent.setConnected(followsCurrentThread);
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
		if (editModeAction.isSelected()) {
			return;
		}
		ProgramLocation loc = trackingTrait.getTrackedLocation();
		if (loc == null) {
			return;
		}
		TraceProgramView curView = current.getView();
		Swing.runIfSwingOrRunLater(() -> {
			if (curView != current.getView()) {
				// Trace changed before Swing scheduled us
				return;
			}
			goToAndUpdateTrackingLabel(curView, loc);
		});
	}

	public void setTrackingSpec(LocationTrackingSpec spec) {
		trackingTrait.setSpec(spec);
	}

	public LocationTrackingSpec getTrackingSpec() {
		return trackingTrait.getSpec();
	}

	@Override
	public boolean isConnected() {
		return false;
	}

	@Override
	public boolean isDynamic() {
		return true;
	}

	public boolean isMainViewer() {
		return isMainViewer;
	}

	@Override
	protected void writeConfigState(SaveState saveState) {
		super.writeConfigState(saveState);
	}

	@Override
	protected void readConfigState(SaveState saveState) {
		super.readConfigState(saveState);

		CONFIG_STATE_HANDLER.readConfigState(this, saveState);
		trackingTrait.readConfigState(saveState);

		if (isMainViewer()) {
			followsCurrentThread = true;
		}
		else {
			actionFollowsCurrentThread.setSelected(followsCurrentThread);
			updateBorder();
		}
		// TODO: actionAutoReadMemory
	}

	@Override
	protected void writeDataState(SaveState saveState) {
		if (!isMainViewer()) {
			current.writeDataState(tool, saveState, KEY_DEBUGGER_COORDINATES);
		}
		super.writeDataState(saveState);
	}

	@Override
	protected void readDataState(SaveState saveState) {
		if (!isMainViewer()) {
			DebuggerCoordinates coordinates =
				DebuggerCoordinates.readDataState(tool, saveState, KEY_DEBUGGER_COORDINATES);
			coordinatesActivated(coordinates);
		}
		super.readDataState(saveState);
	}

	@Override
	protected void updateLocation(ByteBlock block, BigInteger blockOffset, int column,
			boolean export) {
		super.updateLocation(block, blockOffset, column, export);
		locationLabel.goToAddress(currentLocation == null ? null : currentLocation.getAddress());
	}

	@Override
	public void cloneWindow() {
		final DebuggerMemoryBytesProvider newProvider = myPlugin.createNewDisconnectedProvider();
		final ViewerPosition vp = panel.getViewerPosition();
		final SaveState saveState = new SaveState();
		writeConfigState(saveState);
		Swing.runLater(() -> {
			newProvider.readConfigState(saveState);

			newProvider.goToCoordinates(current);
			newProvider.setLocation(currentLocation);
			newProvider.panel.setViewerPosition(vp);
		});
	}
}
