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
import java.util.concurrent.ExecutionException;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractRefreshSelectedMemoryAction;
import ghidra.app.plugin.core.debug.gui.action.AutoReadMemorySpec.AutoReadMemorySpecConfigFieldCodec;
import ghidra.app.plugin.core.debug.gui.control.TargetActionTask;
import ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.program.model.address.*;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.util.TraceEvents;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public abstract class DebuggerReadsMemoryTrait {
	protected static final AutoConfigState.ClassHandler<DebuggerReadsMemoryTrait> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(DebuggerReadsMemoryTrait.class, MethodHandles.lookup());

	protected class RefreshSelectedMemoryAction extends AbstractRefreshSelectedMemoryAction {
		public static final String GROUP = DebuggerResources.GROUP_GENERAL;

		public RefreshSelectedMemoryAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (!current.isAliveAndReadsPresent()) {
				return;
			}
			AddressSetView selection = getSelection();
			if (selection == null || selection.isEmpty()) {
				selection = visible;
			}
			final AddressSetView sel = selection;
			Target target = current.getTarget();

			TargetActionTask.executeTask(tool, new Task(NAME, true, true, false) {
				@Override
				public void run(TaskMonitor monitor) throws CancelledException {
					target.invalidateMemoryCaches();
					try {
						target.readMemoryAsync(sel, monitor).get();
					}
					catch (InterruptedException | ExecutionException e) {
						throw new RuntimeException("Failed to read memory", e);
					}
					memoryWasRead(sel);
				}
			});
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return current.isAliveAndReadsPresent();
		}

		public void updateEnabled(ActionContext context) {
			setEnabled(isEnabledForContext(context));
		}
	}

	protected class ForReadsTraceListener extends TraceDomainObjectListener {
		public ForReadsTraceListener() {
			listenForUntyped(DomainObjectEvent.RESTORED, this::objectRestored);
			listenFor(TraceEvents.SNAPSHOT_ADDED, this::snapshotAdded);
			listenFor(TraceEvents.BYTES_STATE_CHANGED, this::memStateChanged);
		}

		private void objectRestored(DomainObjectChangeRecord rec) {
			actionRefreshSelected.updateEnabled(null);
			doAutoRead();
		}

		private void snapshotAdded(TraceSnapshot snapshot) {
			actionRefreshSelected.updateEnabled(null);
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
	protected RefreshSelectedMemoryAction actionRefreshSelected;

	private final AutoReadMemorySpec defaultAutoSpec =
		AutoReadMemorySpec.fromConfigName(VisibleROOnceAutoReadMemorySpec.CONFIG_NAME);

	@AutoConfigStateField(codec = AutoReadMemorySpecConfigFieldCodec.class)
	protected AutoReadMemorySpec autoSpec = defaultAutoSpec;

	protected final PluginTool tool;
	protected final Plugin plugin;
	protected final ComponentProvider provider;

	protected final ForReadsTraceListener traceListener =
		new ForReadsTraceListener();
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
		if (!Objects.equals(a.getTarget(), b.getTarget())) {
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

	public void goToCoordinates(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}
		boolean doTraceListener = !Objects.equals(current.getTrace(), coordinates.getTrace());
		if (doTraceListener) {
			removeOldTraceListener();
		}
		current = coordinates;
		if (doTraceListener) {
			addNewTraceListener();
		}

		doAutoRead();
		// NB. provider should call contextChanged, updating actions
	}

	protected boolean isConsistent() {
		TraceProgramView view = current.getView();
		if (view == null || visible.isEmpty()) {
			return true; // Some have special logic for empty
		}
		AddressSpace space = visible.getFirstRange().getAddressSpace();
		int id = space.getSpaceID();
		return space == view.getAddressFactory().getAddressSpace(id);
	}

	protected void doAutoRead() {
		if (!isConsistent()) {
			return;
		}
		AddressSet visible = new AddressSet(this.visible);
		autoSpec.readMemory(tool, current, visible).thenAccept(b -> {
			if (b) {
				memoryWasRead(visible);
			}
		}).exceptionally(ex -> {
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

	public DockingAction installRefreshSelectedAction() {
		actionRefreshSelected = new RefreshSelectedMemoryAction();
		provider.addLocalAction(actionRefreshSelected);
		return actionRefreshSelected;
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

	/* testing */
	public AddressSetView getVisible() {
		return visible;
	}

	protected abstract AddressSetView getSelection();

	protected abstract void repaintPanel();

	protected void memoryWasRead(AddressSetView read) {
		// Extension point
	}
}
