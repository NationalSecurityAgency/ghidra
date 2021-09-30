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
import java.util.List;
import java.util.Objects;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.support.BackgroundColorModel;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.action.LocationTrackingSpec.TrackingSpecConfigFieldCodec;
import ghidra.app.plugin.core.debug.gui.colors.*;
import ghidra.app.plugin.core.debug.gui.colors.MultiSelectionBlendedLayoutBackgroundColorManager.ColoredFieldSelection;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerTrackedRegisterListingBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.annotation.AutoOptionConsumed;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceMemoryBytesChangeType;
import ghidra.trace.model.Trace.TraceStackChangeType;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;

public class DebuggerTrackLocationTrait {
	protected static final AutoConfigState.ClassHandler<DebuggerTrackLocationTrait> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(DebuggerTrackLocationTrait.class, MethodHandles.lookup());

	protected class ForTrackingListener extends TraceDomainObjectListener {

		public ForTrackingListener() {
			listenFor(TraceMemoryBytesChangeType.CHANGED, this::registersChanged);
			listenFor(TraceStackChangeType.CHANGED, this::stackChanged);
		}

		private void registersChanged(TraceAddressSpace space, TraceAddressSnapRange range,
				byte[] oldValue, byte[] newValue) {
			if (current.getView() == null || spec == null) {
				// Should only happen during transitional times, if at all.
				return;
			}
			if (!spec.affectedByRegisterChange(space, range, current)) {
				return;
			}
			doTrack();
		}

		private void stackChanged(TraceStack stack) {
			if (current.getView() == null || spec == null) {
				// Should only happen during transitional times, if at all.
				return;
			}
			if (!spec.affectedByStackChange(stack, current)) {
				return;
			}
			doTrack();
		}
	}

	// TODO: This may already be deprecated....
	protected class ColorModel extends DebuggerTrackedRegisterBackgroundColorModel {
		public ColorModel() {
			super(plugin);
		}

		@Override
		protected ProgramLocation getTrackedLocation() {
			return trackedLocation;
		}
	}

	protected class ListingColorModel
			extends DebuggerTrackedRegisterListingBackgroundColorModel {

		public ListingColorModel(ListingPanel listingPanel) {
			super(plugin, listingPanel);
		}

		@Override
		protected ProgramLocation getTrackedLocation() {
			return trackedLocation;
		}
	}

	protected class TrackSelectionGenerator implements SelectionGenerator {
		@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_TRACKING_MARKERS)
		private Color trackingColor;
		@SuppressWarnings("unused")
		private final AutoOptions.Wiring autoOptionsWiring;

		public TrackSelectionGenerator() {
			autoOptionsWiring = AutoOptions.wireOptions(plugin, this);
		}

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

	private final LocationTrackingSpec defaultSpec =
		LocationTrackingSpec.fromConfigName(PCLocationTrackingSpec.CONFIG_NAME);

	@AutoConfigStateField(codec = TrackingSpecConfigFieldCodec.class)
	protected LocationTrackingSpec spec = defaultSpec;

	protected final PluginTool tool;
	protected final Plugin plugin;
	protected final ComponentProvider provider;

	protected final ForTrackingListener listener = new ForTrackingListener();

	protected final ColorModel colorModel;
	protected final TrackSelectionGenerator selectionGenerator;

	protected DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	protected ProgramLocation trackedLocation;

	public DebuggerTrackLocationTrait(PluginTool tool, Plugin plugin, ComponentProvider provider) {
		this.tool = tool;
		this.plugin = plugin;
		this.provider = provider;

		this.colorModel = new ColorModel();
		this.selectionGenerator = new TrackSelectionGenerator();
	}

	public BackgroundColorModel getBackgroundColorModel() {
		return colorModel;
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

	public void setSpec(LocationTrackingSpec spec) {
		// TODO: What if action == null?
		action.setCurrentActionStateByUserData(spec);
	}

	public LocationTrackingSpec getSpec() {
		return spec;
	}

	public ProgramLocation getTrackedLocation() {
		return trackedLocation;
	}

	public MultiStateDockingAction<LocationTrackingSpec> installAction() {
		// TODO: Add "other" option, and present most-recent in menu, too
		// TODO: "other" as in arbitrary expression?
		// Only those applicable to the current thread's registers, though.
		action = DebuggerTrackLocationAction.builder(plugin)
				.onAction(this::clickedSpecButton)
				.onActionStateChanged(this::clickedSpecMenu)
				.buildAndInstallLocal(provider);
		action.setCurrentActionStateByUserData(defaultSpec);
		return action;
	}

	protected void clickedSpecButton(ActionContext ctx) {
		doTrack();
	}

	protected void clickedSpecMenu(ActionState<LocationTrackingSpec> newState,
			EventTrigger trigger) {
		doSetSpec(newState.getUserData());
	}

	protected void doSetSpec(LocationTrackingSpec spec) {
		if (this.spec != spec) {
			this.spec = spec;
			specChanged();
		}
		doTrack();
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
		TraceThread thread = cur.getThread();
		if (thread == null || spec == null) {
			return null;
		}
		// NB: view's snap may be forked for emulation
		Address address = spec.computeTraceAddress(tool, cur, current.getView().getSnap());
		return address == null ? null : new ProgramLocation(current.getView(), address);
	}

	protected void doTrack() {
		trackedLocation = computeTrackedLocation();
		locationTracked();
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
		current = coordinates;
		if (doListeners) {
			addNewListeners();
		}
		doTrack();
	}

	public void writeConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.writeConfigState(this, saveState);
	}

	public void readConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.readConfigState(this, saveState);

		action.setCurrentActionStateByUserData(spec);
	}

	protected void locationTracked() {
		// Listener method
	}

	protected void specChanged() {
		// Listener method
	}
}
