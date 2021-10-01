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

import java.lang.invoke.MethodHandles;
import java.util.Objects;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractCaptureSelectedMemoryAction;
import ghidra.app.plugin.core.debug.gui.action.AutoReadMemorySpec.AutoReadMemorySpecConfigFieldCodec;
import ghidra.app.plugin.core.debug.utils.BackgroundUtils;
import ghidra.app.services.TraceRecorder;
import ghidra.app.services.TraceRecorderListener;
import ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.program.model.address.AddressSetView;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceMemoryStateChangeType;
import ghidra.trace.model.Trace.TraceSnapshotChangeType;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.Msg;
import ghidra.util.Swing;

public abstract class DebuggerReadsMemoryTrait {
	protected static final AutoConfigState.ClassHandler<DebuggerReadsMemoryTrait> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(DebuggerReadsMemoryTrait.class, MethodHandles.lookup());

	protected class CaptureSelectedMemoryAction extends AbstractCaptureSelectedMemoryAction {
		public static final String GROUP = DebuggerResources.GROUP_GENERAL;

		public CaptureSelectedMemoryAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			AddressSetView selection = getSelection();
			if (selection == null || selection.isEmpty() || !current.isAliveAndReadsPresent()) {
				return;
			}
			Trace trace = current.getTrace();
			TraceRecorder recorder = current.getRecorder();
			BackgroundUtils.async(tool, trace, NAME, true, true, false,
				(__, monitor) -> recorder.captureProcessMemory(selection, monitor, false));
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			AddressSetView selection = getSelection();
			if (selection == null || selection.isEmpty() || !current.isAliveAndReadsPresent()) {
				return false;
			}
			TraceRecorder recorder = current.getRecorder();
			// TODO: Either allow partial, or provide action to intersect with accessible
			if (!recorder.getAccessibleProcessMemory().contains(selection)) {
				return false;
			}
			return true;
		}

		public void updateEnabled(ActionContext context) {
			setEnabled(isEnabledForContext(context));
		}
	}

	protected class ForCaptureTraceListener extends TraceDomainObjectListener {
		public ForCaptureTraceListener() {
			listenFor(TraceSnapshotChangeType.ADDED, this::snapshotAdded);
			listenFor(TraceMemoryStateChangeType.CHANGED, this::memStateChanged);
		}

		private void snapshotAdded(TraceSnapshot snapshot) {
			actionCaptureSelected.updateEnabled(null);
		}

		private void memStateChanged(TraceAddressSnapRange range, TraceMemoryState oldIsNull,
				TraceMemoryState newState) {
			if (current.getView() == null) {
				return;
			}
			if (!range.getLifespan().contains(current.getSnap())) {
				return;
			}
			// TODO: Debounce this?
			repaintPanel();

			if (newState == TraceMemoryState.UNKNOWN) {
				doAutoRead();
			}
		}
	}

	protected class ForAccessRecorderListener implements TraceRecorderListener {
		@Override
		public void processMemoryAccessibilityChanged(TraceRecorder recorder) {
			Swing.runIfSwingOrRunLater(() -> {
				actionCaptureSelected.updateEnabled(null);
			});
		}
	}

	protected class ForVisibilityListener implements AddressSetDisplayListener {
		@Override
		public void visibleAddressesChanged(AddressSetView visibleAddresses) {
			if (Objects.equals(visible, visibleAddresses)) {
				return;
			}
			visible = visibleAddresses;
			doAutoRead();
		}
	}

	protected MultiStateDockingAction<AutoReadMemorySpec> actionAutoRead;
	protected CaptureSelectedMemoryAction actionCaptureSelected;

	private final AutoReadMemorySpec defaultAutoSpec =
		AutoReadMemorySpec.fromConfigName(VisibleROOnceAutoReadMemorySpec.CONFIG_NAME);

	@AutoConfigStateField(codec = AutoReadMemorySpecConfigFieldCodec.class)
	protected AutoReadMemorySpec autoSpec = defaultAutoSpec;

	protected final PluginTool tool;
	protected final Plugin plugin;
	protected final ComponentProvider provider;

	protected final ForCaptureTraceListener traceListener =
		new ForCaptureTraceListener();
	protected final ForAccessRecorderListener recorderListener = new ForAccessRecorderListener();
	protected final ForVisibilityListener displayListener = new ForVisibilityListener();

	protected DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	protected AddressSetView visible;

	public DebuggerReadsMemoryTrait(PluginTool tool, Plugin plugin, ComponentProvider provider) {
		this.tool = tool;
		this.plugin = plugin;
		this.provider = provider;
	}

	protected boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getView(), b.getView())) {
			return false; // Subsumes trace
		}
		if (!Objects.equals(a.getTime(), b.getTime())) {
			return false;
		}
		if (!Objects.equals(a.getRecorder(), b.getRecorder())) {
			return false;
		}
		return true;
	}

	protected void addNewTraceListener() {
		if (current.getTrace() != null) {
			current.getTrace().addListener(traceListener);
		}
	}

	protected void removeOldTraceListener() {
		if (current.getTrace() != null) {
			current.getTrace().removeListener(traceListener);
		}
	}

	protected void addNewRecorderListener() {
		if (current.getRecorder() != null) {
			current.getRecorder().addListener(recorderListener);
		}
	}

	protected void removeOldRecorderListener() {
		if (current.getRecorder() != null) {
			current.getRecorder().removeListener(recorderListener);
		}
	}

	public void goToCoordinates(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}
		boolean doTraceListener = !Objects.equals(current.getTrace(), coordinates.getTrace());
		boolean doRecListener = !Objects.equals(current.getRecorder(), coordinates.getRecorder());
		if (doTraceListener) {
			removeOldTraceListener();
		}
		if (doRecListener) {
			removeOldRecorderListener();
		}
		current = coordinates;
		if (doTraceListener) {
			addNewTraceListener();
		}
		if (doRecListener) {
			addNewRecorderListener();
		}

		doAutoRead();
		// NB. provider should call contextChanged, updating actions
	}

	protected void doAutoRead() {
		autoSpec.readMemory(tool, current, visible).exceptionally(ex -> {
			Msg.error(this, "Could not auto-read memory: " + ex);
			return null;
		});
	}

	public MultiStateDockingAction<AutoReadMemorySpec> installAutoReadAction() {
		actionAutoRead = DebuggerAutoReadMemoryAction.builder(plugin)
				.onAction(this::activatedAutoRead)
				.onActionStateChanged(this::changedAutoReadMemory)
				.buildAndInstallLocal(provider);
		actionAutoRead.setCurrentActionStateByUserData(defaultAutoSpec);
		return actionAutoRead;
	}

	protected void activatedAutoRead(ActionContext ctx) {
		doAutoRead();
	}

	protected void changedAutoReadMemory(ActionState<AutoReadMemorySpec> newState,
			EventTrigger trigger) {
		doSetAutoRead(newState.getUserData());
	}

	protected void doSetAutoRead(AutoReadMemorySpec spec) {
		this.autoSpec = spec;
		if (visible != null) {
			doAutoRead();
		}
	}

	public DockingAction installCaptureSelectedAction() {
		actionCaptureSelected = new CaptureSelectedMemoryAction();
		provider.addLocalAction(actionCaptureSelected);
		return actionCaptureSelected;
	}

	public AddressSetDisplayListener getDisplayListener() {
		return displayListener;
	}

	public void writeConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.writeConfigState(this, saveState);
	}

	public void readConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.readConfigState(this, saveState);
		actionAutoRead.setCurrentActionStateByUserData(autoSpec);
	}

	public void setAutoSpec(AutoReadMemorySpec autoSpec) {
		// TODO: What if action == null?
		actionAutoRead.setCurrentActionStateByUserData(autoSpec);
	}

	public AutoReadMemorySpec getAutoSpec() {
		return autoSpec;
	}

	protected abstract AddressSetView getSelection();

	protected abstract void repaintPanel();
}
