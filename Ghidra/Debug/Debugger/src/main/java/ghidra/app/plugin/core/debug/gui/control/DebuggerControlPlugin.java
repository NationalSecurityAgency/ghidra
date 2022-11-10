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
package ghidra.app.plugin.core.debug.gui.control;

import java.awt.event.KeyEvent;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.DockingContextListener;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.action.builder.*;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.*;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerPcodeMachine;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerEmulationService.CachedEmulator;
import ghidra.app.services.DebuggerEmulationService.EmulatorStateListener;
import ghidra.app.services.DebuggerStateEditingService.StateEditingMode;
import ghidra.app.services.DebuggerStateEditingService.StateEditingModeChangeListener;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceObjectChangeType;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.time.schedule.Scheduler;
import ghidra.util.*;

@PluginInfo(
	shortDescription = "Debugger global controls",
	description = "GUI to control target, trace, and emulator; and edit machine state",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
		TraceClosedPluginEvent.class,
		ModelObjectFocusedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerStateEditingService.class,
		DebuggerTraceManagerService.class,
	})
public class DebuggerControlPlugin extends AbstractDebuggerPlugin
		implements DockingContextListener {

	static String intSubGroup(int subGroup) {
		return String.format("%02d", subGroup);
	}

	abstract class TargetAction<T extends TargetObject> extends DockingAction {
		TraceObject object;

		public TargetAction(String name) {
			super(name, DebuggerControlPlugin.this.getName());
		}

		abstract Class<T> getTargetInterface();

		TraceObject findTraceObject() {
			TraceObject focus = current.getObject();
			if (focus == null) {
				return null;
			}
			return focus.querySuitableTargetInterface(getTargetInterface());
		}

		T getTargetObject(TraceObject object) {
			TraceRecorder recorder = current.getRecorder();
			if (recorder == null || !recorder.isRecording()) {
				return null;
			}
			Class<T> iface = getTargetInterface();
			if (object != null) {
				return iface.cast(recorder.getTargetObject(object));
			}
			TargetObject focus = recorder.getFocus();
			if (focus == null) {
				return null;
			}
			return focus.getCachedSuitable(iface);
		}

		abstract boolean isEnabledForObject(T t);

		abstract void actionPerformed(T t);

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			object = findTraceObject();
			T t = getTargetObject(object);
			if (t == null || !t.getModel().isAlive()) {
				return false;
			}
			return isEnabledForObject(t);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			T t = getTargetObject(object);
			if (t == null) {
				return;
			}
			actionPerformed(t);
		}
	}

	static class TargetActionBuilder<T extends TargetObject>
			extends AbstractActionBuilder<TargetAction<T>, ActionContext, TargetActionBuilder<T>> {
		final DebuggerControlPlugin owner;

		@SuppressWarnings("unchecked")
		Class<T> iface = (Class<T>) TargetObject.class;
		Function<T, CompletableFuture<?>> actionCallback;
		BiPredicate<TraceObject, T> enabledPredicate;

		public TargetActionBuilder(String name, DebuggerControlPlugin owner) {
			super(name, owner.getName());
			this.owner = owner;
		}

		@SuppressWarnings("unchecked")
		public <U extends TargetObject> TargetActionBuilder<U> withInterface(Class<U> iface) {
			this.iface = (Class<T>) iface;
			return (TargetActionBuilder<U>) self();
		}

		public TargetActionBuilder<T> enabledWhenTarget(
				BiPredicate<TraceObject, T> enabledPredicate) {
			this.enabledPredicate = enabledPredicate;
			return self();
		}

		public TargetActionBuilder<T> onTargetAction(
				Function<T, CompletableFuture<?>> actionCallback) {
			this.actionCallback = actionCallback;
			return self();
		}

		@Override
		protected TargetActionBuilder<T> self() {
			return this;
		}

		@Override
		public TargetAction<T> build() {
			Objects.requireNonNull(iface, "Must specify withInterface");
			Objects.requireNonNull(enabledPredicate, "Must specify enabledWhenTarget");
			Objects.requireNonNull(actionCallback, "Must specify onTargetAction");

			TargetAction<T> action = owner.new TargetAction<>(name) {
				@Override
				Class<T> getTargetInterface() {
					return iface;
				}

				@Override
				boolean isEnabledForObject(T t) {
					return enabledPredicate.test(object, t);
				}

				@Override
				void actionPerformed(T t) {
					actionCallback.apply(t).exceptionally(ex -> {
						owner.tool.setStatusInfo(name + " failed: " + ex.getMessage(), true);
						Msg.error(this, name + " failed", ex);
						return null;
					});
				}
			};
			decorateAction(action);
			return action;
		}
	}

	interface ControlAction {
		String GROUP = DebuggerResources.GROUP_CONTROL;
	}

	interface EditModeAction {
		String NAME = "Edit Mode";
		String DESCRIPTION = "Choose what to edit in dynamic views";
		String GROUP = DebuggerResources.GROUP_CONTROL;
		String HELP_ANCHOR = "edit_mode";

		static MultiStateActionBuilder<StateEditingMode> builder(Plugin owner) {
			String ownerName = owner.getName();
			return new MultiStateActionBuilder<StateEditingMode>(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(DebuggerResources.ICON_BLANK) // Docs say required
					.toolBarGroup(GROUP, "")
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR))
					.addStates(Stream.of(StateEditingMode.values())
							.map(m -> new ActionState<>(m.name, m.icon, m))
							.collect(Collectors.toList()));
		}
	}

	interface ResumeAction extends ControlAction {
		Icon ICON = DebuggerResources.ICON_RESUME;
		int SUB_GROUP = 0;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F5, 0);
	}

	interface TargetResumeAction extends ResumeAction {
		String NAME = "Resume Target";
		String DESCRIPTION = "Resume, i.e., go or continue execution of the target";
		String HELP_ANCHOR = "target_resume";

		static TargetActionBuilder<TargetResumable> builder(DebuggerControlPlugin owner) {
			String ownerName = owner.getName();
			return new TargetActionBuilder<>(NAME, owner)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR))
					.withInterface(TargetResumable.class);
		}
	}

	interface EmulateResumeAction extends ResumeAction {
		String NAME = "Resume Emulator";
		String DESCRIPTION = "Resume, i.e., go or continue execution of the integrated emulator";
		String HELP_ANCHOR = "emu_resume";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface InterruptAction extends ControlAction {
		Icon ICON = DebuggerResources.ICON_INTERRUPT;
		int SUB_GROUP = 1;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_I, KeyEvent.CTRL_DOWN_MASK);
	}

	interface TargetInterruptAction extends InterruptAction {
		String NAME = "Interrupt Target";
		String DESCRIPTION = "Interrupt, i.e., suspend, the target";
		String HELP_ANCHOR = "target_interrupt";

		static TargetActionBuilder<TargetInterruptible> builder(DebuggerControlPlugin owner) {
			String ownerName = owner.getName();
			return new TargetActionBuilder<>(NAME, owner)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR))
					.withInterface(TargetInterruptible.class);
		}
	}

	interface EmulateInterruptAction extends InterruptAction {
		String NAME = "Interrupt Emulator";
		String DESCRIPTION = "Interrupt, i.e., suspend, the integrated emulator";
		String HELP_ANCHOR = "emu_interrupt";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface TargetKillAction extends ControlAction {
		Icon ICON = DebuggerResources.ICON_KILL;
		String HELP_ANCHOR = "target_kill";
		int SUB_GROUP = 2;
		String NAME = "Kill Target";
		String DESCRIPTION = "Kill, i.e., forcibly terminate the target";
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_K,
			KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK);

		static TargetActionBuilder<TargetKillable> builder(DebuggerControlPlugin owner) {
			String ownerName = owner.getName();
			return new TargetActionBuilder<>(NAME, owner)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR))
					.withInterface(TargetKillable.class);
		}
	}

	interface DisconnectAction extends ControlAction {
		String NAME = "Disconnect";
		String DESCRIPTION = "Close the connection to the debugging agent";
		Icon ICON = DebuggerResources.ICON_DISCONNECT;
		String HELP_ANCHOR = "target_disconnect";
		int SUB_GROUP = 3;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_K,
			KeyEvent.CTRL_DOWN_MASK | KeyEvent.ALT_DOWN_MASK);

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface EmulateStepBackAction extends ControlAction {
		String NAME = "Step Emulator Back";
		String DESCRIPTION = "Step the integrated emulator a single instruction backward";
		Icon ICON = DebuggerResources.ICON_STEP_BACK;
		String HELP_ANCHOR = "emu_step_back";
		int SUB_GROUP = 4;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F7, 0);

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface StepIntoAction extends ControlAction {
		Icon ICON = DebuggerResources.ICON_STEP_INTO;
		int SUB_GROUP = 5;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F8, 0);
	}

	interface TargetStepIntoAction extends StepIntoAction {
		String NAME = "Step Target Into";
		String DESCRIPTION = "Step the target a single instruction, descending into calls";
		String HELP_ANCHOR = "target_step_into";

		static TargetActionBuilder<TargetSteppable> builder(DebuggerControlPlugin owner) {
			String ownerName = owner.getName();
			return new TargetActionBuilder<>(NAME, owner)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR))
					.withInterface(TargetSteppable.class);
		}
	}

	interface EmulateStepIntoAction extends StepIntoAction {
		String NAME = "Step Emulator Into";
		String DESCRIPTION =
			"Step the integrated emulator a single instruction, descending into calls";
		String HELP_ANCHOR = "emu_step_into";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface TargetStepOverAction extends ControlAction {
		String NAME = "Step Target Over";
		String DESCRIPTION = "Step the target a single instruction, without following calls";
		Icon ICON = DebuggerResources.ICON_STEP_OVER;
		String HELP_ANCHOR = "target_step_over";
		int SUB_GROUP = 6;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F10, 0);

		static TargetActionBuilder<TargetSteppable> builder(DebuggerControlPlugin owner) {
			String ownerName = owner.getName();
			return new TargetActionBuilder<>(NAME, owner)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR))
					.withInterface(TargetSteppable.class);
		}
	}

	interface EmulateSkipOverAction extends ControlAction {
		String NAME = "Skip Emulator";
		String DESCRIPTION =
			"Skip the integrated emulator a single instruction, ignoring its effects";
		Icon ICON = DebuggerResources.ICON_SKIP_OVER;
		String HELP_ANCHOR = "emu_skip_over";
		int SUB_GROUP = 7;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F10, KeyEvent.CTRL_DOWN_MASK);

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface TargetStepFinishAction extends ControlAction {
		String NAME = "Step Target Finish";
		String DESCRIPTION = "Step the target until it completes the current frame";
		Icon ICON = DebuggerResources.ICON_STEP_FINISH;
		String HELP_ANCHOR = "target_step_finish";
		int SUB_GROUP = 8;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F12, 0);

		static TargetActionBuilder<TargetSteppable> builder(DebuggerControlPlugin owner) {
			String ownerName = owner.getName();
			return new TargetActionBuilder<>(NAME, owner)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR))
					.withInterface(TargetSteppable.class);
		}
	}

	interface TargetStepLastAction extends ControlAction {
		String NAME = "Step Target Repeat Last";
		String DESCRIPTION = "Step the target in a target-defined way";
		Icon ICON = DebuggerResources.ICON_STEP_LAST;
		String HELP_ANCHOR = "target_step_last";
		int SUB_GROUP = 9;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F8, KeyEvent.CTRL_DOWN_MASK);

		static TargetActionBuilder<TargetSteppable> builder(DebuggerControlPlugin owner) {
			String ownerName = owner.getName();
			return new TargetActionBuilder<>(NAME, owner)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR))
					.withInterface(TargetSteppable.class);
		}
	}

	interface TraceSnapBackwardAction extends ControlAction {
		String NAME = "Trace Snapshot Backward";
		String DESCRIPTION = "Navigate the trace recording backward one snapshot";
		Icon ICON = DebuggerResources.ICON_SNAP_BACKWARD;
		String HELP_ANCHOR = "trace_snap_backward";
		int SUB_GROUP = 10;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F7, 0);

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface TraceSnapForwardAction extends ControlAction {
		String NAME = "Trace Snapshot Forward";
		String DESCRIPTION = "Navigate the trace recording forward one snapshot";
		Icon ICON = DebuggerResources.ICON_SNAP_FORWARD;
		String HELP_ANCHOR = "trace_snap_backward";
		int SUB_GROUP = 11;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F8, 0);

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	private final TraceDomainObjectListener listenerForObjects = new TraceDomainObjectListener() {
		{
			listenFor(TraceObjectChangeType.VALUE_CREATED, this::valueChanged);
			listenFor(TraceObjectChangeType.VALUE_DELETED, this::valueChanged);
			listenFor(TraceObjectChangeType.VALUE_LIFESPAN_CHANGED, this::valueLifespanChanged);
		}

		private void valueChanged(TraceObjectValue value) {
			if (value.getLifespan().contains(current.getSnap())) {
				Swing.runIfSwingOrRunLater(() -> updateActionsEnabled());
			}
		}

		private void valueLifespanChanged(TraceObjectValue value, Lifespan oldLife,
				Lifespan newLife) {
			if (newLife.contains(current.getSnap()) != oldLife.contains(current.getSnap())) {
				Swing.runIfSwingOrRunLater(() -> updateActionsEnabled());
			}
		}
	};

	private final StateEditingModeChangeListener listenerForModeChanges = this::modeChanged;
	private final EmulatorStateListener listenerForEmuStateChanges = new EmulatorStateListener() {
		@Override
		public void running(CachedEmulator emu) {
			Swing.runIfSwingOrRunLater(() -> updateActions());
		}

		@Override
		public void stopped(CachedEmulator emu) {
			Swing.runIfSwingOrRunLater(() -> updateActions());
		}
	};

	protected DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	protected MultiStateDockingAction<StateEditingMode> actionEditMode;

	DockingAction actionTargetResume;
	DockingAction actionTargetInterrupt;
	DockingAction actionTargetKill;
	DockingAction actionTargetDisconnect;
	DockingAction actionTargetStepInto;
	DockingAction actionTargetStepOver;
	DockingAction actionTargetStepFinish;
	DockingAction actionTargetStepLast;
	Set<DockingAction> actionsTarget;

	DockingAction actionEmulateResume;
	DockingAction actionEmulateInterrupt;
	DockingAction actionEmulateStepBack;
	DockingAction actionEmulateStepInto;
	DockingAction actionEmulateSkipOver;
	Set<DockingAction> actionsEmulate;

	DockingAction actionTraceSnapBackward;
	DockingAction actionTraceSnapForward;
	Set<DockingAction> actionsTrace;

	Set<Set<DockingAction>> actionSets;
	Collection<? extends DockingActionIf> curActionSet;

	ActionContext context;

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	// @AutoServiceConsumed // via method
	private DebuggerStateEditingService editingService;
	// @AutoServiceConsumed // via method
	private DebuggerEmulationService emulationService;

	public DebuggerControlPlugin(PluginTool tool) {
		super(tool);

		tool.addContextListener(this);

		createActions();
	}

	protected Set<DockingAction> getActionSet(StateEditingMode mode) {
		switch (mode) {
			case READ_ONLY:
			case WRITE_TARGET:
				return actionsTarget;
			case WRITE_TRACE:
				return actionsTrace;
			case WRITE_EMULATOR:
				return actionsEmulate;
			default:
				throw new AssertionError();
		}
	}

	protected Set<DockingAction> getActionSet() {
		return getActionSet(computeCurrentEditingMode());
	}

	protected void updateActionsEnabled(StateEditingMode mode) {
		for (DockingAction action : getActionSet(mode)) {
			action.setEnabled(action.isEnabledForContext(context));
		}
	}

	protected void updateActionsEnabled() {
		updateActionsEnabled(computeCurrentEditingMode());
	}

	@Override
	public void contextChanged(ActionContext context) {
		this.context = context;
		updateActionsEnabled();
	}

	protected void createActions() {
		actionEditMode = EditModeAction.builder(this)
				.enabled(false)
				.enabledWhen(c -> current.getTrace() != null)
				.onActionStateChanged(this::activateEditMode)
				.buildAndInstall(tool);

		actionTargetResume = TargetResumeAction.builder(this)
				.enabledWhenTarget(this::isActionTargetResumeEnabled)
				.onTargetAction(this::activatedTargetResume)
				.build();
		actionTargetInterrupt = TargetInterruptAction.builder(this)
				.enabledWhenTarget(this::isActionTargetInterruptEnabled)
				.onTargetAction(this::activatedTargetInterrupt)
				.build();
		actionTargetKill = TargetKillAction.builder(this)
				.enabledWhenTarget(this::isActionTargetKillEnabled)
				.onTargetAction(this::activatedTargetKill)
				.build();
		actionTargetDisconnect = DisconnectAction.builder(this)
				.enabledWhen(this::isActionTargetDisconnectEnabled)
				.onAction(this::activatedTargetDisconnect)
				.build();
		actionTargetStepInto = TargetStepIntoAction.builder(this)
				.enabledWhenTarget(this::isActionTargetStepEnabled)
				.onTargetAction(this::activatedTargetStepInto)
				.build();
		actionTargetStepOver = TargetStepOverAction.builder(this)
				.enabledWhenTarget(this::isActionTargetStepEnabled)
				.onTargetAction(this::activatedTargetStepOver)
				.build();
		actionTargetStepFinish = TargetStepFinishAction.builder(this)
				.enabledWhenTarget(this::isActionTargetStepEnabled)
				.onTargetAction(this::activatedTargetStepFinish)
				.build();
		actionTargetStepLast = TargetStepLastAction.builder(this)
				.enabledWhenTarget(this::isActionTargetStepEnabled)
				.onTargetAction(this::activatedTargetStepLast)
				.build();
		actionsTarget = Set.of(actionTargetResume, actionTargetInterrupt, actionTargetKill,
			actionTargetDisconnect, actionTargetStepInto, actionTargetStepOver,
			actionTargetStepFinish, actionTargetStepLast);

		actionEmulateResume = EmulateResumeAction.builder(this)
				.enabledWhen(this::isActionEmulateResumeEnabled)
				.onAction(this::activateEmulateResume)
				.build();
		actionEmulateInterrupt = EmulateInterruptAction.builder(this)
				.enabledWhen(this::isActionEmulateInterruptEnabled)
				.onAction(this::activateEmulateInterrupt)
				.build();
		actionEmulateStepBack = EmulateStepBackAction.builder(this)
				.enabledWhen(this::isActionEmulateStepBackEnabled)
				.onAction(this::activateEmulateStepBack)
				.build();
		actionEmulateStepInto = EmulateStepIntoAction.builder(this)
				.enabledWhen(this::isActionEmulateStepIntoEnabled)
				.onAction(this::activateEmulateStepInto)
				.build();
		actionEmulateSkipOver = EmulateSkipOverAction.builder(this)
				.enabledWhen(this::isActionEmulateSkipOverEnabled)
				.onAction(this::activateEmulateSkipOver)
				.build();
		actionsEmulate = Set.of(actionEmulateResume, actionEmulateInterrupt, actionEmulateStepBack,
			actionEmulateStepInto, actionEmulateSkipOver);

		actionTraceSnapBackward = TraceSnapBackwardAction.builder(this)
				.enabledWhen(this::isActionTraceSnapBackwardEnabled)
				.onAction(this::activateTraceSnapBackward)
				.build();
		actionTraceSnapForward = TraceSnapForwardAction.builder(this)
				.enabledWhen(this::isActionTraceSnapForwardEnabled)
				.onAction(this::activateTraceSnapForward)
				.build();
		actionsTrace = Set.of(actionTraceSnapBackward, actionTraceSnapForward);

		actionSets = Set.of(actionsTarget, actionsEmulate, actionsTrace);

		updateActions();
	}

	protected void activateEditMode(ActionState<StateEditingMode> state, EventTrigger trigger) {
		if (current.getTrace() == null) {
			return;
		}
		if (editingService == null) {
			return;
		}
		editingService.setCurrentMode(current.getTrace(), state.getUserData());
		// TODO: Limit selectable modes?
		// No sense showing Write Target, if the trace can never be live, again....
	}

	private void modeChanged(Trace trace, StateEditingMode mode) {
		Swing.runIfSwingOrRunLater(() -> {
			if (current.getTrace() == trace) {
				updateActions();
			}
		});
	}

	private TargetExecutionState getStateOf(TraceObject traceObject, TargetObject targetObject) {
		if (traceObject != null) {
			return traceObject.getExecutionState(current.getSnap());
		}
		TargetExecutionStateful stateful =
			targetObject.getCachedSuitable(TargetExecutionStateful.class);
		return stateful == null ? null : stateful.getExecutionState();
	}

	private boolean isActionTargetResumeEnabled(TraceObject object, TargetResumable resumable) {
		TargetExecutionState state = getStateOf(object, resumable);
		// If the object isn't stateful, always allow this action. Such models should be corrected
		return state == null || state.isStopped();
	}

	private CompletableFuture<?> activatedTargetResume(TargetResumable resumable) {
		return resumable.resume();
	}

	private boolean isActionTargetInterruptEnabled(TraceObject object,
			TargetInterruptible interruptible) {
		TargetExecutionState state = getStateOf(object, interruptible);
		// If the object isn't stateful, always allow this action.
		return state == null || state.isRunning();
	}

	private CompletableFuture<?> activatedTargetInterrupt(TargetInterruptible interruptible) {
		return interruptible.interrupt();
	}

	private boolean isActionTargetKillEnabled(TraceObject object, TargetKillable killable) {
		TargetExecutionState state = getStateOf(object, killable);
		// If the object isn't stateful, always allow this action. Such models should be corrected
		return state == null || state.isAlive();
	}

	private CompletableFuture<?> activatedTargetKill(TargetKillable killable) {
		return killable.kill();
	}

	private boolean isActionTargetDisconnectEnabled(ActionContext context) {
		return current.isAlive();
	}

	private void activatedTargetDisconnect(ActionContext context) {
		TraceRecorder recorder = current.getRecorder();
		if (recorder == null) {
			return;
		}
		DebuggerObjectModel model = recorder.getTarget().getModel();
		model.close().exceptionally(ex -> {
			tool.setStatusInfo("Disconnect failed: " + ex.getMessage(), true);
			Msg.error(this, "Disconnect failed", ex);
			return null;
		});
	}

	private boolean isActionTargetStepEnabled(TraceObject object, TargetSteppable steppable) {
		TargetExecutionState state = getStateOf(object, steppable);
		// If the object isn't stateful, always allow this action. Such models should be corrected
		return state == null || state.isStopped();
	}

	private CompletableFuture<?> activatedTargetStepInto(TargetSteppable steppable) {
		return steppable.step(TargetStepKind.INTO);
	}

	private CompletableFuture<?> activatedTargetStepOver(TargetSteppable steppable) {
		return steppable.step(TargetStepKind.OVER);
	}

	private CompletableFuture<?> activatedTargetStepFinish(TargetSteppable steppable) {
		return steppable.step(TargetStepKind.FINISH);
	}

	private CompletableFuture<?> activatedTargetStepLast(TargetSteppable steppable) {
		return steppable.step(TargetStepKind.EXTENDED);
	}

	private boolean haveEmuAndTrace() {
		if (emulationService == null) {
			return false;
		}
		if (current.getTrace() == null) {
			return false;
		}
		return true;
	}

	private boolean haveEmuAndThread() {
		if (emulationService == null) {
			return false;
		}
		if (current.getThread() == null) {
			return false;
		}
		return true;
	}

	private DebuggerPcodeMachine<?> getBusyEmulator() {
		/**
		 * NOTE: Could search for current trace, but task manager will only allow one to actually
		 * run at a time. Best not let the user queue a bunch up if another trace's emulator is
		 * hogging the manager thread.
		 */
		for (CachedEmulator ce : emulationService.getBusyEmulators()) {
			return ce.emulator();
		}
		return null;
	}

	private boolean isActionEmulateResumeEnabled(ActionContext context) {
		if (!haveEmuAndThread()) {
			return false;
		}
		return getBusyEmulator() == null;
	}

	private void activateEmulateResume(ActionContext context) {
		if (!haveEmuAndThread()) {
			return;
		}
		if (getBusyEmulator() != null) {
			return;
		}
		DebuggerCoordinates current = this.current;
		emulationService.backgroundRun(current.getPlatform(), current.getTime(),
			Scheduler.oneThread(current.getThread())).thenAcceptAsync(r -> {
				traceManager.activate(current.time(r.schedule()));
			}, AsyncUtils.SWING_EXECUTOR).exceptionally(ex -> {
				Msg.showError(this, null, "Emulate", "Error emulating", ex);
				return null;
			});
	}

	private boolean isActionEmulateInterruptEnabled(ActionContext context) {
		if (!haveEmuAndThread()) {
			return false;
		}
		return getBusyEmulator() != null;
	}

	private void activateEmulateInterrupt(ActionContext context) {
		if (emulationService == null) {
			return;
		}
		DebuggerPcodeMachine<?> emu = getBusyEmulator();
		emu.setSuspended(true);
	}

	private boolean isActionEmulateStepBackEnabled(ActionContext context) {
		if (!haveEmuAndTrace()) {
			return false;
		}
		if (current.getTime().steppedBackward(current.getTrace(), 1) == null) {
			return false;
		}
		return true;
	}

	private void activateEmulateStepBack(ActionContext context) {
		traceManager.activateTime(current.getTime().steppedBackward(current.getTrace(), 1));
	}

	private boolean isActionEmulateStepIntoEnabled(ActionContext context) {
		return haveEmuAndThread();
	}

	private void activateEmulateStepInto(ActionContext context) {
		traceManager.activateTime(current.getTime().steppedForward(current.getThread(), 1));
	}

	private boolean isActionEmulateSkipOverEnabled(ActionContext context) {
		return haveEmuAndThread();
	}

	private void activateEmulateSkipOver(ActionContext context) {
		traceManager.activateTime(current.getTime().skippedForward(current.getThread(), 1));
	}

	private boolean isActionTraceSnapBackwardEnabled(ActionContext context) {
		if (current.getTrace() == null) {
			return false;
		}
		if (!current.getTime().isSnapOnly()) {
			return true;
		}
		if (current.getSnap() <= 0) {
			return false;
		}
		return true;
	}

	private void activateTraceSnapBackward(ActionContext context) {
		if (current.getTime().isSnapOnly()) {
			traceManager.activateSnap(current.getSnap() - 1);
		}
		else {
			traceManager.activateSnap(current.getSnap());
		}
	}

	private boolean isActionTraceSnapForwardEnabled(ActionContext context) {
		Trace curTrace = current.getTrace();
		if (curTrace == null) {
			return false;
		}
		Long maxSnap = curTrace.getTimeManager().getMaxSnap();
		if (maxSnap == null || current.getSnap() >= maxSnap) {
			return false;
		}
		return true;
	}

	private void activateTraceSnapForward(ActionContext contetxt) {
		traceManager.activateSnap(current.getSnap() + 1);
	}

	protected void coordinatesActivated(DebuggerCoordinates coords) {
		if (current.getTrace() != coords.getTrace()) {
			if (current.getTrace() != null) {
				current.getTrace().removeListener(listenerForObjects);
			}
			if (coords.getTrace() != null) {
				coords.getTrace().addListener(listenerForObjects);
			}
		}
		current = coords;
		updateActions();
	}

	private StateEditingMode computeCurrentEditingMode() {
		// TODO: We're sort of piggy-backing our mode onto that of the editing service.
		// Seems we should have our own?
		if (editingService == null) {
			return StateEditingMode.READ_ONLY;
		}
		if (current.getTrace() == null) {
			return StateEditingMode.READ_ONLY;
		}
		return editingService.getCurrentMode(current.getTrace());
	}

	private void hideActions(Collection<? extends DockingActionIf> actions) {
		if (tool == null) {
			return;
		}
		if (curActionSet == actions) {
			curActionSet = null;
		}
		for (DockingActionIf action : actions) {
			tool.removeAction(action);
		}
	}

	private void showActions(Collection<? extends DockingActionIf> actions) {
		if (tool == null) {
			return;
		}
		if (curActionSet == actions) {
			return;
		}
		for (DockingActionIf action : actions) {
			tool.addAction(action);
		}
		curActionSet = actions;
	}

	private void updateActions() {
		StateEditingMode mode = computeCurrentEditingMode();
		actionEditMode.setCurrentActionStateByUserData(mode);

		Set<DockingAction> actions = getActionSet(mode);
		for (Set<DockingAction> set : actionSets) {
			if (set == actions) {
				showActions(set);
			}
			else {
				hideActions(set);
			}
		}
		updateActionsEnabled(mode);
	}

	protected void traceClosed(Trace trace) {
		if (current.getTrace() == trace) {
			trace.removeListener(listenerForObjects);
			current = DebuggerCoordinates.NOWHERE;
		}
		updateActions();
	}

	@AutoServiceConsumed
	protected void setEditingService(DebuggerStateEditingService editingService) {
		if (this.editingService != null) {
			this.editingService.removeModeChangeListener(listenerForModeChanges);
		}
		this.editingService = editingService;
		if (this.editingService != null) {
			this.editingService.addModeChangeListener(listenerForModeChanges);
		}
		updateActions();
	}

	@AutoServiceConsumed
	protected void setEmulationService(DebuggerEmulationService emulationService) {
		if (this.emulationService != null) {
			this.emulationService.removeStateListener(listenerForEmuStateChanges);
		}
		this.emulationService = emulationService;
		if (this.emulationService != null) {
			this.emulationService.addStateListener(listenerForEmuStateChanges);
		}
		updateActions();
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent ev) {
			coordinatesActivated(ev.getActiveCoordinates());
		}
		else if (event instanceof TraceClosedPluginEvent ev) {
			traceClosed(ev.getTrace());
		}
	}
}
