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

import java.util.*;

import docking.ActionContext;
import docking.DockingContextListener;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerControlService.ControlModeChangeListener;
import ghidra.app.services.DebuggerEmulationService.CachedEmulator;
import ghidra.app.services.DebuggerEmulationService.EmulatorStateListener;
import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.async.AsyncUtils;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.emulation.DebuggerPcodeMachine;
import ghidra.debug.api.model.DebuggerObjectActionContext;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.target.Target.ActionEntry;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.*;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.time.schedule.Scheduler;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.trace.util.TraceEvents;
import ghidra.util.Msg;
import ghidra.util.Swing;

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

	private final TraceDomainObjectListener listenerForObjects = new TraceDomainObjectListener() {
		{
			listenFor(TraceEvents.VALUE_CREATED, this::valueChanged);
			listenFor(TraceEvents.VALUE_DELETED, this::valueChanged);
			listenFor(TraceEvents.VALUE_LIFESPAN_CHANGED, this::valueLifespanChanged);
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

	DockingAction actionTargetResume;
	DockingAction actionTargetInterrupt;
	DockingAction actionTargetKill;
	DockingAction actionTargetStepInto;
	DockingAction actionTargetStepOver;
	DockingAction actionTargetStepOut;
	DockingAction actionTargetDisconnect;
	Set<DockingAction> actionsTarget;
	final Set<DockingAction> actionsTargetStepExt = new HashSet<>();
	final Set<DockingAction> actionsTargetAll = new HashSet<>();

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

	ActionContext context;

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	// @AutoServiceConsumed // via method
	private DebuggerControlService controlService;
	// @AutoServiceConsumed // via method
	private DebuggerEmulationService emulationService;
	@AutoServiceConsumed
	private ProgressService progressService;

	public DebuggerControlPlugin(PluginTool tool) {
		super(tool);
		tool.addContextListener(this);
		createActions();
	}

	protected Set<DockingAction> getActionSet(ControlMode mode) {
		switch (mode) {
			case RO_TARGET:
			case RW_TARGET:
				return actionsTargetAll;
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
		return getActionSet(computeCurrentControlMode());
	}

	protected void updateActionsEnabled(ControlMode mode) {
		for (DockingAction action : getActionSet(mode)) {
			action.setEnabled(action.isEnabledForContext(context));
		}
	}

	protected void updateActionsEnabled() {
		updateActionsEnabled(computeCurrentControlMode());
	}

	protected static boolean isSameContext(ActionContext ctx1, ActionContext ctx2) {
		if (ctx1 instanceof ProgramLocationActionContext locCtx1) {
			if (!(ctx2 instanceof ProgramLocationActionContext locCtx2)) {
				return false;
			}
			Program prog1 = locCtx1.getProgram();
			Program prog2 = locCtx2.getProgram();
			if (prog1 != prog2) {
				return false;
			}
			Address addr1 = locCtx1.getAddress();
			Address addr2 = locCtx2.getAddress();
			if (!Objects.equals(addr1, addr2)) {
				return false;
			}
			return true;
		}
		if (ctx1 instanceof DebuggerObjectActionContext objCtx1) {
			if (!(ctx2 instanceof DebuggerObjectActionContext objCtx2)) {
				return false;
			}
			return Objects.equals(objCtx1.getObjectValues(), objCtx2.getObjectValues());
		}
		return true; // Treat all unknowns as same.
	}

	@Override
	public void contextChanged(ActionContext context) {
		boolean same = isSameContext(this.context, context);
		this.context = context;
		if (same) {
			return;
		}
		updateTargetStepExtActions();
		updateActions();
	}

	protected void createActions() {
		actionControlMode = new ControlModeAction(this);
		tool.addAction(actionControlMode);

		actionTargetResume = TargetResumeAction.builder(this)
				.build();
		actionTargetInterrupt = TargetInterruptAction.builder(this)
				.build();
		actionTargetKill = TargetKillAction.builder(this)
				.build();
		actionTargetStepInto = TargetStepIntoAction.builder(this)
				.build();
		actionTargetStepOver = TargetStepOverAction.builder(this)
				.build();
		actionTargetStepOut = TargetStepOutAction.builder(this)
				.build();
		actionTargetDisconnect = DisconnectAction.builder(this)
				.enabledWhen(this::isActionTargetDisconnectEnabled)
				.onAction(this::activatedTargetDisconnect)
				.build();
		actionsTarget = Set.of(actionTargetResume, actionTargetInterrupt, actionTargetKill,
			actionTargetStepInto, actionTargetStepOver, actionTargetStepOut,
			actionTargetDisconnect);
		updateTargetStepExtActions();

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

		actionSets = Set.of(actionsTargetAll, actionsEmulate, actionsTrace);

		updateActions();
	}

	protected void addTargetStepExtActions(Target target) {
		for (ActionEntry entry : target.collectActions(ActionName.STEP_EXT, context).values()) {
			if (entry.requiresPrompt()) {
				continue;
			}
			actionsTargetStepExt.add(TargetStepExtAction.builder(entry.display(), this)
					.description(entry.details())
					.enabledWhen(ctx -> entry.isEnabled())
					.onAction(ctx -> TargetActionTask.runAction(tool, entry.display(), entry))
					.build());
		}
	}

	/**
	 * This is for testing purposes only. Fetch an action from {@link #actionsTargetStepExt} whose
	 * name matches that given.
	 * 
	 * @param name the action name
	 * @return the action, or null
	 */
	/* testing */ DockingAction getTargetStepExtAction(String name) {
		for (DockingAction action : actionsTargetStepExt) {
			if (name.equals(action.getName())) {
				return action;
			}
		}
		return null;
	}

	protected void updateTargetStepExtActions() {
		hideActions(actionsTargetStepExt);
		actionsTargetStepExt.clear();
		actionsTargetAll.clear();
		actionsTargetAll.addAll(actionsTarget);

		Target target = current.getTarget();
		if (target == null || !target.isValid()) {
			return;
		}

		addTargetStepExtActions(target);
		actionsTargetAll.addAll(actionsTargetStepExt);
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
		TargetActionTask.executeTask(tool, new DisconnectTask(tool, List.of(target)));
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
		boolean sameTrace = true;
		if (current.getTrace() != coords.getTrace()) {
			sameTrace = false;
			if (current.getTrace() != null) {
				current.getTrace().removeListener(listenerForObjects);
			}
			if (coords.getTrace() != null) {
				coords.getTrace().addListener(listenerForObjects);
			}
		}
		current = coords;
		if (!sameTrace) {
			updateTargetStepExtActions();
		}
		updateActions();
	}

	private ControlMode computeCurrentControlMode() {
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
		for (DockingActionIf action : actions) {
			tool.removeAction(action);
		}
	}

	private void showActions(Collection<? extends DockingActionIf> actions) {
		if (tool == null) {
			return;
		}
		Set<DockingActionIf> already = tool.getDockingActionsByOwnerName(name);
		for (DockingActionIf action : actions) {
			if (!already.contains(action)) {
				tool.addAction(action);
			}
		}
	}

	private void updateActions() {
		ControlMode mode = computeCurrentControlMode();
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
			updateTargetStepExtActions();
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
