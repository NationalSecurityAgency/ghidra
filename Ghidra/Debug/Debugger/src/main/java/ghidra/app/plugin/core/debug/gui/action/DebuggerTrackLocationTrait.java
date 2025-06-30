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
package ghidra.app.plugin.core.debug.gui.action;

import java.awt.Color;
import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.colors.MultiSelectionBlendedLayoutBackgroundColorManager.ColoredFieldSelection;
import ghidra.app.plugin.core.debug.gui.colors.SelectionGenerator;
import ghidra.app.plugin.core.debug.gui.colors.SelectionTranslator;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerTrackedRegisterListingBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.debug.api.action.*;
import ghidra.debug.api.action.LocationTrackingSpec.TrackingSpecConfigFieldCodec;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceEvents;
import ghidra.util.Msg;

public class DebuggerTrackLocationTrait {
	protected static final AutoConfigState.ClassHandler<DebuggerTrackLocationTrait> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(DebuggerTrackLocationTrait.class, MethodHandles.lookup());

	public enum TrackCause {
		USER, DB_CHANGE, NAVIGATION, EMU_PATCH, SPEC_CHANGE_API;
	}

	protected class ForTrackingListener extends TraceDomainObjectListener {

		public ForTrackingListener() {
			listenFor(TraceEvents.BYTES_CHANGED, this::registersChanged);
			//listenFor(TraceEvents.STACK_CHANGED, this::stackChanged);
			listenFor(TraceEvents.VALUE_CREATED, this::valueCreated);
			listenFor(TraceEvents.VALUE_LIFESPAN_CHANGED, this::valueLifespanChanged);
		}

		private void registersChanged(AddressSpace space, TraceAddressSnapRange range,
				byte[] oldValue, byte[] newValue) {
			if (current.getView() == null || spec == null) {
				// Should only happen during transitional times, if at all.
				return;
			}
			if (!tracker.affectedByBytesChange(space, range, current)) {
				return;
			}
			doTrack(TrackCause.DB_CHANGE);
		}

		private void stackChanged(TraceStack stack) {
			if (current.getView() == null || spec == null) {
				// Should only happen during transitional times, if at all.
				return;
			}
			if (!tracker.affectedByStackChange(stack, current)) {
				return;
			}
			doTrack(TrackCause.DB_CHANGE);
		}

		private void valueCreated(TraceObjectValue value) {
			if (!value.getLifespan().contains(current.getSnap())) {
				return;
			}
			if (!value.getEntryKey().equals(TraceStackFrame.KEY_PC)) {
				return;
			}
			TraceStackFrame frame = value.getParent().queryInterface(TraceStackFrame.class);
			if (frame == null) {
				return;
			}
			if (!tracker.affectedByStackChange(frame.getStack(), current)) {
				return;
			}
			doTrack(TrackCause.DB_CHANGE);
		}

		private void valueLifespanChanged(TraceObjectValue value, Lifespan oldLife,
				Lifespan newLife) {
			long snap = current.getSnap();
			if (oldLife.contains(snap) == newLife.contains(snap)) {
				return;
			}
			if (!value.getEntryKey().equals(TraceStackFrame.KEY_PC)) {
				return;
			}
			TraceStackFrame frame = value.getParent().queryInterface(TraceStackFrame.class);
			if (frame == null) {
				return;
			}
			if (!tracker.affectedByStackChange(frame.getStack(), current)) {
				return;
			}
			doTrack(TrackCause.DB_CHANGE);
		}
	}

	protected class ListingColorModel
			extends DebuggerTrackedRegisterListingBackgroundColorModel {
		public ListingColorModel(ListingPanel listingPanel) {
			super(listingPanel);
		}

		@Override
		protected ProgramLocation getTrackedLocation() {
			return trackedLocation;
		}
	}

	protected class TrackSelectionGenerator implements SelectionGenerator {
		private final Color trackingColor = DebuggerResources.COLOR_REGISTER_MARKERS;

		@Override
		public void addSelections(BigInteger layoutIndex, SelectionTranslator translator,
				List<ColoredFieldSelection> selections) {
			if (trackedLocation == null || trackingColor == null) {
				return;
			}
			FieldSelection fieldSel =
				translator.convertAddressToField(trackedLocation.getAddress());
			selections.add(new ColoredFieldSelection(fieldSel, trackingColor));
		}
	}

	protected MultiStateDockingAction<LocationTrackingSpec> action;

	private final LocationTrackingSpec defaultSpec = PCLocationTrackingSpec.INSTANCE;

	@AutoConfigStateField(codec = TrackingSpecConfigFieldCodec.class)
	protected LocationTrackingSpec spec = defaultSpec;
	protected LocationTracker tracker = spec.getTracker();

	protected final PluginTool tool;
	protected final Plugin plugin;
	protected final ComponentProvider provider;

	protected final ForTrackingListener listener = new ForTrackingListener();

	protected final TrackSelectionGenerator selectionGenerator;

	protected DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	protected ProgramLocation trackedLocation;

	public DebuggerTrackLocationTrait(PluginTool tool, Plugin plugin, ComponentProvider provider) {
		this.tool = tool;
		this.plugin = plugin;
		this.provider = provider;

		this.selectionGenerator = new TrackSelectionGenerator();
	}

	public ListingBackgroundColorModel createListingBackgroundColorModel(
			ListingPanel listingPanel) {
		return new ListingColorModel(listingPanel);
	}

	public SelectionGenerator getSelectionGenerator() {
		return selectionGenerator;
	}

	protected boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getView(), b.getView())) {
			return false; // Subsumes trace
		}
		if (!Objects.equals(a.getTime(), b.getTime())) {
			return false;
		}
		if (!Objects.equals(a.getThread(), b.getThread())) {
			return false;
		}
		if (!Objects.equals(a.getFrame(), b.getFrame())) {
			return false;
		}
		return true;
	}

	protected boolean hasSpec(LocationTrackingSpec spec) {
		for (ActionState<LocationTrackingSpec> state : action.getAllActionStates()) {
			if (spec.equals(state.getUserData())) {
				return true;
			}
		}
		return false;
	}

	public void setSpec(LocationTrackingSpec spec) {
		if (action == null) {
			// It might if the client doesn't need a new button, e.g., TraceDiff
			doSetSpec(spec, TrackCause.SPEC_CHANGE_API);
		}
		else if (!hasSpec(spec)) {
			Msg.warn(this, "No action state for given tracking spec: " + spec);
			doSetSpec(spec, TrackCause.SPEC_CHANGE_API);
		}
		else {
			action.setCurrentActionStateByUserData(spec);
		}
	}

	public LocationTrackingSpec getSpec() {
		return spec;
	}

	public ProgramLocation getTrackedLocation() {
		return trackedLocation;
	}

	public MultiStateDockingAction<LocationTrackingSpec> installAction() {
		// TODO: Only those Sleigh expressions applicable to the current thread's registers?
		action = DebuggerTrackLocationAction.builder(plugin)
				.stateGenerator(this::getStates)
				.onAction(this::clickedSpecButton)
				.onActionStateChanged(this::clickedSpecMenu)
				.buildAndInstallLocal(provider);
		action.setCurrentActionStateByUserData(defaultSpec);
		return action;
	}

	public List<ActionState<LocationTrackingSpec>> getStates() {
		Map<String, ActionState<LocationTrackingSpec>> states = new TreeMap<>();
		for (LocationTrackingSpec spec : LocationTrackingSpecFactory
				.allSuggested(tool)
				.values()) {
			states.put(spec.getConfigName(),
				new ActionState<>(spec.getMenuName(), spec.getMenuIcon(), spec));
		}
		ActionState<LocationTrackingSpec> current = action.getCurrentState();
		if (current != null) {
			states.put(current.getUserData().getConfigName(), current);
		}
		return List.copyOf(states.values());
	}

	protected void clickedSpecButton(ActionContext ctx) {
		doTrack(TrackCause.USER);
	}

	protected void clickedSpecMenu(ActionState<LocationTrackingSpec> newState,
			EventTrigger trigger) {
		doSetSpec(newState.getUserData(), TrackCause.USER);
	}

	protected void doSetSpec(LocationTrackingSpec spec, TrackCause cause) {
		if (this.spec != spec) {
			this.spec = spec;
			this.tracker = spec.getTracker();
			specChanged(spec);
		}
		doTrack(cause);
	}

	protected ProgramLocation computeTrackedLocation() {
		// Change of register values (for current frame)
		// Change of stack pc (for current frame)
		// Change of current view (if not caused by goTo)
		// Change of current thread
		// Change of current snap
		// Change of current frame
		// Change of tracking settings
		DebuggerCoordinates cur = current;
		if (cur.getView() == null) {
			return null;
		}
		TraceThread thread = cur.getThread();
		if (thread == null || spec == null) {
			return null;
		}
		// NB: view's snap may be forked for emulation
		Address address = tracker.computeTraceAddress(tool, cur);
		if (address == null) {
			return null;
		}
		return new ProgramLocation(cur.getView(), address);
	}

	public String computeLabelText() {
		if (spec == null || trackedLocation == null) {
			return "";
		}
		return spec.getLocationLabel() + " = " + trackedLocation.getByteAddress();
	}

	protected void doTrack(TrackCause cause) {
		try {
			ProgramLocation newLocation = computeTrackedLocation();
			if (Objects.equals(newLocation, trackedLocation)) {
				if (cause == TrackCause.DB_CHANGE || cause == TrackCause.EMU_PATCH) {
					return;
				}
			}
			trackedLocation = newLocation;
			locationTracked();
		}
		catch (TraceClosedException ex) {
			// Silently continue
		}
		catch (Throwable ex) {
			Msg.error(this, "Error while computing location: " + ex);
		}
	}

	protected void addNewListeners() {
		Trace trace = current.getTrace();
		if (trace != null) {
			trace.addListener(listener);
		}
	}

	protected void removeOldListeners() {
		Trace trace = current.getTrace();
		if (trace != null) {
			trace.removeListener(listener);
		}
	}

	public void goToCoordinates(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}
		boolean doListeners = !Objects.equals(current.getTrace(), coordinates.getTrace());
		if (doListeners) {
			removeOldListeners();
		}
		boolean isPatch = current.differsOnlyByPatch(coordinates);
		current = coordinates;
		if (doListeners) {
			addNewListeners();
		}
		doTrack(isPatch ? TrackCause.EMU_PATCH : TrackCause.NAVIGATION);
	}

	public void writeConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.writeConfigState(this, saveState);
	}

	public void readConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.readConfigState(this, saveState);
		tracker = spec.getTracker();
		action.setCurrentActionStateByUserData(spec);
	}

	public GoToInput getDefaultGoToInput(ProgramLocation loc) {
		if (tracker == null) {
			return NoneLocationTrackingSpec.INSTANCE.getDefaultGoToInput(tool, current, loc);
		}
		return tracker.getDefaultGoToInput(tool, current, loc);
	}

	protected void locationTracked() {
		// Listener method
	}

	protected void specChanged(LocationTrackingSpec spec) {
		// Listener method
	}
}
