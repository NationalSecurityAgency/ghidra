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
import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.action.*;
import docking.menu.MultiStateDockingAction;
import ghidra.app.plugin.core.byteviewer.*;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerLocationLabel;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractFollowsCurrentThreadAction;
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
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
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

	protected class FollowsCurrentThreadAction extends AbstractFollowsCurrentThreadAction {
		public FollowsCurrentThreadAction() {
			super(plugin);
			setMenuBarData(new MenuData(new String[] { NAME }));
			setSelected(true);
			addLocalAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			doSetFollowsCurrentThread(isSelected());
		}
	}

	protected class ForMemoryBytesGoToTrait extends DebuggerGoToTrait {
		public ForMemoryBytesGoToTrait() {
			super(DebuggerMemoryBytesProvider.this.tool, DebuggerMemoryBytesProvider.this.plugin,
				DebuggerMemoryBytesProvider.this);
		}

		@Override
		protected boolean goToAddress(Address address) {
			TraceProgramView view = current.getView();
			if (view == null) {
				return false;
			}
			return goTo(view, new ProgramLocation(view, address));
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
	protected FollowsCurrentThreadAction actionFollowsCurrentThread;
	protected MultiStateDockingAction<AutoReadMemorySpec> actionAutoReadMemory;
	protected DockingAction actionCaptureSelectedMemory;
	protected MultiStateDockingAction<LocationTrackingSpec> actionTrackLocation;

	protected ForMemoryBytesGoToTrait goToTrait;
	protected ForMemoryBytesTrackingTrait trackingTrait;
	protected ForMemoryBytesReadsMemoryTrait readsMemTrait;

	protected final DebuggerLocationLabel locationLabel = new DebuggerLocationLabel();

	@AutoConfigStateField
	protected boolean followsCurrentThread = true;
	@AutoConfigStateField(codec = AutoReadMemorySpecConfigFieldCodec.class)
	protected AutoReadMemorySpec autoReadMemorySpec = defaultReadMemorySpec;
	// TODO: followsCurrentSnap?

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	protected final boolean isMainViewer;

	protected DebuggerMemoryBytesProvider(PluginTool tool, DebuggerMemoryBytesPlugin plugin,
			boolean isConnected) {
		super(tool, plugin, "Memory", isConnected);
		this.myPlugin = plugin;
		this.isMainViewer = isConnected;

		autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);
		createActions();
		addDisplayListener(readsMemTrait.getDisplayListener());
		decorationComponent.add(locationLabel, BorderLayout.NORTH);

		goToTrait.goToCoordinates(current);
		trackingTrait.goToCoordinates(current);
		readsMemTrait.goToCoordinates(current);
		locationLabel.goToCoordinates(current);
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
		return new DebuggerMemoryBytesPanel(this);
	}

	// For testing access
	@Override
	protected ByteViewerPanel getByteViewerPanel() {
		return super.getByteViewerPanel();
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
			actionFollowsCurrentThread = new FollowsCurrentThreadAction();
		}

		actionGoTo = goToTrait.installAction();
		actionTrackLocation = trackingTrait.installAction();
		actionAutoReadMemory = readsMemTrait.installAutoReadAction();
		actionCaptureSelectedMemory = readsMemTrait.installCaptureSelectedAction();
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

	protected DebuggerCoordinates adjustCoordinates(DebuggerCoordinates coordinates) {
		if (followsCurrentThread) {
			return coordinates;
		}
		// Because the view's snap is changing with or without us.... So go with.
		return current.withTime(coordinates.getTime());
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
		contextChanged();
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		DebuggerCoordinates adjusted = adjustCoordinates(coordinates);
		goToCoordinates(adjusted);
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

	protected void doGoToTracked() {
		ProgramLocation loc = trackingTrait.getTrackedLocation();
		if (loc == null) {
			return;
		}
		TraceProgramView curView = current.getView();
		Swing.runIfSwingOrRunLater(() -> {
			goTo(curView, loc);
		});
	}

	public void setTrackingSpec(LocationTrackingSpec spec) {
		trackingTrait.setSpec(spec);
	}

	public LocationTrackingSpec getTrackingSpec() {
		return trackingTrait.getSpec();
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
				DebuggerCoordinates.readDataState(tool, saveState, KEY_DEBUGGER_COORDINATES, true);
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
		SaveState saveState = new SaveState();
		writeConfigState(saveState);
		newProvider.readConfigState(saveState);

		newProvider.goToCoordinates(current);
		newProvider.setLocation(currentLocation);
		newProvider.panel.setViewerPosition(panel.getViewerPosition());
	}

	@Override
	protected ProgramByteBlockSet newByteBlockSet(ByteBlockChangeManager changeManager) {
		if (program == null) {
			return null;
		}
		return new WritesTargetProgramByteBlockSet(this, program, changeManager);
	}

	@Override
	public void addLocalAction(DockingActionIf action) {
		/**
		 * TODO This is a terrible hack, but it's temporary. We do not yet support writing target
		 * memory from the bytes provider. Once we do, we should obviously take this hack out. I
		 * don't think we'll forget, because the only way to get the write toggle button back is to
		 * delete this override.
		 */
		if (action == editModeAction) {
			return;
		}
		super.addLocalAction(action);
	}
}
