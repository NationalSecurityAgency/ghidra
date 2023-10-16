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
import java.util.function.BiFunction;
import java.util.stream.Collectors;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.DockingContextListener;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.service.model.TraceRecorderTarget;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerControlService.ControlModeChangeListener;
import ghidra.app.services.DebuggerEmulationService.CachedEmulator;
import ghidra.app.services.DebuggerEmulationService.EmulatorStateListener;
import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.async.AsyncUtils;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.emulation.DebuggerPcodeMachine;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.target.Target.ActionEntry;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceObjectChangeType;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.time.schedule.Scheduler;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

@PluginInfo(
	shortDescription = "Debugger global controls",
	description = "GUI to control target, trace, and emulator; and edit machine state",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
		TraceClosedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerControlService.class,
		DebuggerTraceManagerService.class,
	})
public class DebuggerControlPlugin extends AbstractDebuggerPlugin
		implements DockingContextListener {

	static String intSubGroup(int subGroup) {
		return String.format("%02d", subGroup);
	}

	interface ControlAction {
		String GROUP = DebuggerResources.GROUP_CONTROL;
	}

	protected class ControlModeAction extends MultiStateDockingAction<ControlMode> {
		public static final String NAME = "Control Mode";
		public static final String DESCRIPTION = "Choose what to control and edit in dynamic views";
		public static final String GROUP = DebuggerResources.GROUP_CONTROL;
		public static final String HELP_ANCHOR = "control_mode";

		public ControlModeAction() {
			super(NAME, DebuggerControlPlugin.this.getName());
			setDescription(DESCRIPTION);
			setToolBarData(new ToolBarData(DebuggerResources.ICON_BLANK, GROUP, ""));
			setHelpLocation(new HelpLocation(getOwner(), HELP_ANCHOR));
			setActionStates(ControlMode.ALL.stream()
					.map(m -> new ActionState<>(m.name, m.icon, m))
					.collect(Collectors.toList()));
			setEnabled(false);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return current.getTrace() != null;
		}

		@Override
		protected boolean isStateEnabled(ActionState<ControlMode> state) {
			return state.getUserData().isSelectable(current);
		}

		@Override
		public void actionStateChanged(ActionState<ControlMode> newActionState,
				EventTrigger trigger) {
			activateControlMode(newActionState, trigger);
		}
	}

	interface ResumeAction extends ControlAction {
		Icon ICON = DebuggerResources.ICON_RESUME;
		int SUB_GROUP = 0;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F5, 0);
	}

	interface TargetResumeAction extends ResumeAction {
		String HELP_ANCHOR = "target_resume";

		static ActionBuilder builder(String name, DebuggerControlPlugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(name, ownerName)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
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
		String HELP_ANCHOR = "target_interrupt";

		static ActionBuilder builder(String name, DebuggerControlPlugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(name, ownerName)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
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
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_K,
			KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK);

		static ActionBuilder builder(String name, DebuggerControlPlugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(name, ownerName)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
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
		String HELP_ANCHOR = "target_step_into";

		static ActionBuilder builder(String name, DebuggerControlPlugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(name, ownerName)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
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
		Icon ICON = DebuggerResources.ICON_STEP_OVER;
		String HELP_ANCHOR = "target_step_over";
		int SUB_GROUP = 6;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F10, 0);

		static ActionBuilder builder(String name, DebuggerControlPlugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(name, ownerName)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
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

	interface TargetStepOutAction extends ControlAction {
		Icon ICON = DebuggerResources.ICON_STEP_FINISH;
		String HELP_ANCHOR = "target_step_out";
		int SUB_GROUP = 8;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F12, 0);

		static ActionBuilder builder(String name, DebuggerControlPlugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(name, ownerName)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP))
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface TargetStepExtAction extends ControlAction {
		Icon ICON = DebuggerResources.ICON_STEP_LAST;
		String HELP_ANCHOR = "target_step_ext";
		int SUB_GROUP = 9;
		KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F8, KeyEvent.CTRL_DOWN_MASK);

		static ActionBuilder builder(String name, DebuggerControlPlugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(name, ownerName)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, intSubGroup(SUB_GROUP) + name)
					.keyBinding(KEY_BINDING)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
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

	private final ControlModeChangeListener listenerForModeChanges = this::modeChanged;
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

	protected MultiStateDockingAction<ControlMode> actionControlMode;

	DockingAction actionTargetDisconnect;
	final Set<DockingAction> actionsTarget = new HashSet<>();

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
	private DebuggerControlService controlService;
	// @AutoServiceConsumed // via method
	private DebuggerEmulationService emulationService;

	public DebuggerControlPlugin(PluginTool tool) {
		super(tool);
		tool.addContextListener(this);
		createActions();
	}

	protected Set<DockingAction> getActionSet(ControlMode mode) {
		switch (mode) {
			case RO_TARGET:
			case RW_TARGET:
				return actionsTarget;
			case RO_TRACE:
			case RW_TRACE:
				return actionsTrace;
			case RW_EMULATOR:
				return actionsEmulate;
			default:
				throw new AssertionError();
		}
	}

	protected Set<DockingAction> getActionSet() {
		return getActionSet(computeCurrentEditingMode());
	}

	protected void updateActionsEnabled(ControlMode mode) {
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
		actionControlMode = new ControlModeAction();
		tool.addAction(actionControlMode);

		actionTargetDisconnect = DisconnectAction.builder(this)
				.enabledWhen(this::isActionTargetDisconnectEnabled)
				.onAction(this::activatedTargetDisconnect)
				.build();
		updateTargetActions();

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

	protected interface TargetActionBuilderFactory
			extends BiFunction<String, DebuggerControlPlugin, ActionBuilder> {
	}

	protected DockingAction buildTargetAction(TargetActionBuilderFactory factory,
			ActionEntry entry) {
		return factory.apply(entry.display(), this)
				.description(entry.details())
				.enabledWhen(ctx -> entry.isEnabled())
				.onAction(ctx -> runTask(entry))
				.build();
	}

	protected void runTask(ActionEntry entry) {
		tool.execute(new TargetActionTask(entry));
	}

	protected void addTargetActionsForName(Target target, ActionName name,
			TargetActionBuilderFactory factory) {
		for (ActionEntry entry : target.collectActions(name, context).values()) {
			if (entry.requiresPrompt()) {
				continue;
			}
			actionsTarget.add(buildTargetAction(factory, entry));
		}
	}

	/**
	 * This is for testing purposes only. Fetch an action from "targetActions" whose name matches
	 * that given.
	 * 
	 * <p>
	 * Since the tests are still assuming {@link TraceRecorderTarget}s, actions can be reliably
	 * retrieved by name.
	 * 
	 * @param name the action name
	 * @return the action, or null
	 */
	/* testing */ DockingAction getTargetAction(String name) {
		for (DockingAction action : actionsTarget) {
			if (name.equals(action.getName())) {
				return action;
			}
		}
		return null;
	}

	protected void updateTargetActions() {
		hideActions(actionsTarget);
		actionsTarget.clear();
		actionsTarget.add(actionTargetDisconnect);

		Target target = current.getTarget();
		if (target == null || !target.isValid()) {
			return;
		}

		addTargetActionsForName(target, ActionName.RESUME, TargetResumeAction::builder);
		addTargetActionsForName(target, ActionName.INTERRUPT, TargetInterruptAction::builder);
		addTargetActionsForName(target, ActionName.KILL, TargetKillAction::builder);
		addTargetActionsForName(target, ActionName.STEP_INTO, TargetStepIntoAction::builder);
		addTargetActionsForName(target, ActionName.STEP_OVER, TargetStepOverAction::builder);
		addTargetActionsForName(target, ActionName.STEP_OUT, TargetStepOutAction::builder);
		addTargetActionsForName(target, ActionName.STEP_EXT, TargetStepExtAction::builder);
	}

	protected void activateControlMode(ActionState<ControlMode> state, EventTrigger trigger) {
		if (current.getTrace() == null) {
			return;
		}
		if (controlService == null) {
			return;
		}
		controlService.setCurrentMode(current.getTrace(), state.getUserData());
		// TODO: Limit selectable modes?
		// No sense showing Write Target, if the trace can never be live, again....
	}

	private void modeChanged(Trace trace, ControlMode mode) {
		Swing.runIfSwingOrRunLater(() -> {
			if (current.getTrace() == trace) {
				updateActions();
			}
		});
	}

	private boolean isActionTargetDisconnectEnabled(ActionContext context) {
		return current.isAlive();
	}

	private void activatedTargetDisconnect(ActionContext context) {
		Target target = current.getTarget();
		if (target == null) {
			return;
		}
		tool.execute(new Task("Disconnect", false, false, false) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				try {
					target.disconnect();
				}
				catch (Exception e) {
					tool.setStatusInfo("Disconnect failed: " + e, true);
					Msg.error(this, "Disconnect failed: " + e, e);
				}
			}
		});
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
		TraceSchedule time = current.getTime();
		emulationService.backgroundRun(current.getPlatform(), time.steppedForward(null, 0),
			Scheduler.oneThread(current.getThread())).thenAcceptAsync(r -> {
				traceManager.activate(current.time(r.schedule()), ActivationCause.USER);
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
		updateTargetActions();
		updateActions();
	}

	private ControlMode computeCurrentEditingMode() {
		if (controlService == null) {
			return ControlMode.DEFAULT;
		}
		if (current.getTrace() == null) {
			return ControlMode.DEFAULT;
		}
		return controlService.getCurrentMode(current.getTrace());
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
		ControlMode mode = computeCurrentEditingMode();
		actionControlMode.setCurrentActionStateByUserData(mode);

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
	private void setControlService(DebuggerControlService editingService) {
		if (this.controlService != null) {
			this.controlService.removeModeChangeListener(listenerForModeChanges);
		}
		this.controlService = editingService;
		if (this.controlService != null) {
			this.controlService.addModeChangeListener(listenerForModeChanges);
		}
		updateActions();
	}

	@AutoServiceConsumed
	private void setEmulationService(DebuggerEmulationService emulationService) {
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
