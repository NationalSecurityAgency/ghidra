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
package ghidra.app.plugin.core.debug.gui.time;

import static ghidra.app.plugin.core.debug.gui.DebuggerResources.*;

import java.awt.event.*;
import java.lang.invoke.MethodHandles;

import javax.swing.Icon;
import javax.swing.JComponent;

import db.Transaction;
import docking.ActionContext;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerSnapActionContext;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.AutoService.Wiring;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.trace.model.time.schedule.TraceSchedule.TimeRadix;
import ghidra.trace.util.TraceEvents;
import ghidra.util.HelpLocation;

public class DebuggerTimeProvider extends ComponentProviderAdapter {
	private static final AutoConfigState.ClassHandler<DebuggerTimeProvider> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(DebuggerTimeProvider.class, MethodHandles.lookup());

	interface GoToTimeAction {
		String NAME = "Go To Time";
		String DESCRIPTION = "Go to a specific time, optionally using emulation";
		String GROUP = GROUP_TRACE;
		Icon ICON = ICON_TIME;
		String HELP_ANCHOR = "goto_time";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(DebuggerPluginPackage.NAME, NAME)
					.menuGroup(GROUP)
					.menuIcon(ICON)
					.keyBinding("CTRL G")
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface SetTimeRadixAction {
		String NAME = "Set Time Radix";
		String DESCRIPTION = "Change the time radix for this trace / target";
		String GROUP = GROUP_TRACE;
		String HELP_ANCHOR = "radix";

		static ToggleActionBuilder builder(String title, Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME + " - " + title, ownerName)
					.description(DESCRIPTION)
					.menuPath(DebuggerPluginPackage.NAME, NAME, title)
					.menuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	protected class ForRadixTraceListener extends TraceDomainObjectListener {
		{
			listenFor(TraceEvents.VALUE_CREATED, this::valueCreated);
			listenFor(TraceEvents.VALUE_DELETED, this::valueDeleted);
		}

		private void valueCreated(TraceObjectValue value) {
			if (value.getCanonicalPath().equals(KeyPath.of(TraceTimeManager.KEY_TIME_RADIX))) {
				refreshRadixSelection();
			}
		}

		private void valueDeleted(TraceObjectValue value) {
			if (value.getCanonicalPath().equals(KeyPath.of(TraceTimeManager.KEY_TIME_RADIX))) {
				refreshRadixSelection();
			}
		}
	}

	private final TraceDomainObjectListener forRadixTraceListener = new ForRadixTraceListener();

	protected final DebuggerTimePlugin plugin;

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	@AutoServiceConsumed
	protected DebuggerTraceManagerService traceManager;
	@SuppressWarnings("unused")
	private final Wiring autoServiceWiring;

	/*testing*/ final DebuggerSnapshotTablePanel mainPanel;

	protected final DebuggerTimeSelectionDialog timeDialog;

	DockingAction actionGoToTime;
	ToggleDockingAction actionHideScratch;
	ToggleDockingAction actionSetRadixDec;
	ToggleDockingAction actionSetRadixHexUpper;
	ToggleDockingAction actionSetRadixHexLower;

	private DebuggerSnapActionContext myActionContext;

	@AutoConfigStateField
	/*testing*/ boolean hideScratch = false;

	public DebuggerTimeProvider(DebuggerTimePlugin plugin) {
		super(plugin.getTool(), TITLE_PROVIDER_TIME, plugin.getName());
		this.plugin = plugin;

		autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		setTitle(TITLE_PROVIDER_TIME);
		setIcon(ICON_PROVIDER_TIME);
		setHelpLocation(HELP_PROVIDER_TIME);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		timeDialog = new DebuggerTimeSelectionDialog(tool);

		mainPanel = new DebuggerSnapshotTablePanel(tool);
		buildMainPanel();

		myActionContext = new DebuggerSnapActionContext(current.getTrace(), current.getSnap());
		createActions();
		contextChanged();

		setVisible(true);
	}

	@Override
	public void addLocalAction(DockingActionIf action) {
		super.addLocalAction(action);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	protected void buildMainPanel() {
		mainPanel.getSelectionModel().addListSelectionListener(evt -> {
			if (evt.getValueIsAdjusting()) {
				return;
			}
			Long snap = mainPanel.getSelectedSnapshot();
			if (snap == null) {
				myActionContext = null;
				return;
			}
			if (snap.longValue() == current.getSnap()) {
				return;
			}
			myActionContext = new DebuggerSnapActionContext(current.getTrace(), snap);
			contextChanged();
		});
		mainPanel.snapshotTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
					activateSelectedSnapshot(e);
				}
			}
		});
		mainPanel.snapshotTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					activateSelectedSnapshot(e);
					e.consume(); // lest it select the next row down
				}
			}
		});
	}

	private TraceSchedule computeSelectedSchedule(InputEvent e, long snap) {
		if ((e.getModifiersEx() & InputEvent.SHIFT_DOWN_MASK) != 0) {
			return TraceSchedule.snap(snap);
		}
		if (snap >= 0) {
			return TraceSchedule.snap(snap);
		}
		Trace trace = current.getTrace();
		if (trace == null) {
			return TraceSchedule.snap(snap);
		}
		TraceSnapshot snapshot = trace.getTimeManager().getSnapshot(snap, false);
		if (snapshot == null) { // Really shouldn't happen, but okay
			return TraceSchedule.snap(snap);
		}
		TraceSchedule schedule = snapshot.getSchedule();
		if (schedule == null) {
			return TraceSchedule.snap(snap);
		}
		return schedule;
	}

	private void activateSelectedSnapshot(InputEvent e) {
		if (traceManager == null) {
			return;
		}
		Long snap = mainPanel.getSelectedSnapshot();
		if (snap == null) {
			return;
		}
		traceManager.activateTime(computeSelectedSchedule(e, snap));
	}

	protected void createActions() {
		actionGoToTime = GoToTimeAction.builder(plugin)
				.enabledWhen(c -> current.getTrace() != null)
				.onAction(c -> activatedGoToTime())
				.buildAndInstall(tool);
		actionHideScratch = DebuggerResources.HideScratchSnapshotsAction.builder(plugin)
				.selected(hideScratch)
				.onAction(this::activatedHideScratch)
				.buildAndInstallLocal(this);
		actionSetRadixDec = SetTimeRadixAction.builder("Decimal", plugin)
				.enabledWhen(c -> current.getTrace() != null &&
					current.getTrace().getObjectManager().getRootObject() != null)
				.onAction(c -> activatedSetRadix(TimeRadix.DEC))
				.buildAndInstall(tool);
		actionSetRadixHexUpper = SetTimeRadixAction.builder("Upper Hex", plugin)
				.enabledWhen(c -> current.getTrace() != null &&
					current.getTrace().getObjectManager().getRootObject() != null)
				.onAction(c -> activatedSetRadix(TimeRadix.HEX_UPPER))
				.buildAndInstall(tool);
		actionSetRadixHexLower = SetTimeRadixAction.builder("Lower Hex", plugin)
				.enabledWhen(c -> current.getTrace() != null &&
					current.getTrace().getObjectManager().getRootObject() != null)
				.onAction(c -> activatedSetRadix(TimeRadix.HEX_LOWER))
				.buildAndInstall(tool);
	}

	private void activatedGoToTime() {
		TraceSchedule time = timeDialog.promptTime(current.getTrace(), current.getTime());
		if (time == null) {
			// Cancelled
			return;
		}
		traceManager.activateTime(time);
	}

	private void activatedHideScratch(ActionContext ctx) {
		hideScratch = !hideScratch;
		mainPanel.setHideScratchSnapshots(hideScratch);
	}

	private void activatedSetRadix(TimeRadix radix) {
		try (Transaction tx = current.getTrace().openTransaction("Set Time Radix")) {
			current.getTrace().getTimeManager().setTimeRadix(radix);
		}
		// NOTE: refreshRadixSelection() should happen via listener
	}

	protected void removeTraceListener() {
		if (current.getTrace() != null) {
			current.getTrace().removeListener(forRadixTraceListener);
		}
	}

	protected void addTraceListener() {
		if (current.getTrace() != null) {
			current.getTrace().addListener(forRadixTraceListener);
		}
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		removeTraceListener();
		current = coordinates;
		addTraceListener();

		mainPanel.setTrace(current.getTrace());
		mainPanel.setCurrent(current);

		refreshRadixSelection();
	}

	private void refreshRadixSelection() {
		TimeRadix radix = current.getTrace() == null ? TimeRadix.DEFAULT
				: current.getTrace().getTimeManager().getTimeRadix();
		actionSetRadixHexLower.setSelected(radix == TimeRadix.HEX_LOWER);
		actionSetRadixHexUpper.setSelected(radix == TimeRadix.HEX_UPPER);
		actionSetRadixDec.setSelected(radix == TimeRadix.DEC);
	}

	public void writeConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.writeConfigState(this, saveState);
	}

	public void readConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.readConfigState(this, saveState);

		actionHideScratch.setSelected(hideScratch);
		mainPanel.setHideScratchSnapshots(hideScratch);
	}
}
