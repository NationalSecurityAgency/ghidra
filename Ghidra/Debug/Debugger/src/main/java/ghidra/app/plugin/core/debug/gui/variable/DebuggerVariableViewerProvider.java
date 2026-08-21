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
package ghidra.app.plugin.core.debug.gui.variable;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;

import docking.*;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.MultiStateActionBuilder;
import docking.actions.PopupActionProvider;
import docking.menu.MultiStateDockingAction;
import docking.util.MessageOverlay;
import docking.widgets.table.GTable;
import docking.widgets.table.GTableFilterPanel;
import generic.theme.GIcon;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.debug.gui.DebuggerProvider;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.action.NoneLocationTrackingSpec;
import ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueUtils;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.plugin.core.debug.stack.StackUnwindWarningSet;
import ghidra.app.plugin.core.debug.stack.UnwoundFrame;
import ghidra.app.services.*;
import ghidra.debug.api.listing.DebuggerListing;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.DomainObjectListenerBuilder;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.pcode.exec.DebuggerPcodeUtils;
import ghidra.pcode.exec.PcodeExecutionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

import static ghidra.framework.model.DomainObjectEvent.RESTORED;
import static ghidra.program.util.ProgramEvent.*;
import static ghidra.trace.util.TraceEvents.BYTES_CHANGED;
import static ghidra.trace.util.TraceEvents.BYTES_STATE_CHANGED;

public class DebuggerVariableViewerProvider extends ComponentProviderAdapter
		implements DebuggerProvider, PopupActionProvider {
	enum VariableViewerStates {
		LISTING, DECOMPILER, BOTH
	}

	interface DebuggerVariableViewerPopupAction {
		String NAME = "Debugger variable viewer Popup Actions";
		String DESCRIPTION = "Popup actions for debugger variable viewer";
		String HELP_ANCHOR = "";
		String GROUP1 = "z";
		String GROUP2 = "zz";

		static ActionBuilder builder(ComponentProvider owner, String subgroup, String... path) {
			final String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR))
					.popupMenuGroup(GROUP1, subgroup)
					.popupMenuPath(path)
					.popupWhen(c -> true)
					.enabledWhen(c -> true);
		}
	}

	static class DebuggerVariableActionContext extends DefaultActionContext {
		private final List<AbstractDebuggerVariableViewerVarValue> selected;

		public DebuggerVariableActionContext(DebuggerVariableViewerProvider provider,
				List<AbstractDebuggerVariableViewerVarValue> selected, GTable source) {
			super(provider, selected, source);
			this.selected = selected;
		}

		public List<AbstractDebuggerVariableViewerVarValue> getSelected() {
			return selected;
		}
	}

	private final JComponent component;
	private final DebuggerVariableViewerModel model;
	private final MessageOverlay msgOverlay;
	private final PluginTool pluginTool;
	DebuggerCoordinates currentCoordinates;
	private Set<Program> mappedPrograms;
	private CompletableFuture<List<AbstractDebuggerVariableViewerVarValue>> currentFuture;
	private DebuggerVariableActionContext myActionContext;

	ToggleDockingAction actionEnableEdits;
	MultiStateDockingAction<VariableViewerStates> actionShowVariables;

	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;
	@AutoServiceConsumed
	DebuggerControlService controlService;
	@AutoServiceConsumed
	private ProgressService progressService;
	@AutoServiceConsumed
	private DebuggerStaticMappingService mappingService;
	@AutoServiceConsumed
	private DebuggerListingService listingService;

	private final DomainObjectListener listener =
			new DomainObjectListenerBuilder(this).ignoreWhen(() -> !isVisible())
					.any(FUNCTION_ADDED, FUNCTION_REMOVED, FUNCTION_CHANGED, SYMBOL_ADDED,
							SYMBOL_PRIMARY_STATE_CHANGED, SYMBOL_RENAMED, SYMBOL_DATA_CHANGED,
							RESTORED, BYTES_CHANGED, BYTES_STATE_CHANGED)
					.call(e -> rebuildTable())
					.build();

	public DebuggerVariableViewerProvider(DebuggerVariableViewerPlugin plugin) {
		super(plugin.getTool(), "Variable Viewer", plugin.getName());
		autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);
		pluginTool = plugin.getTool();
		model = new DebuggerVariableViewerModel(plugin.getTool(), this);
		final GTable table = new GTable(model);
		GTableFilterPanel<AbstractDebuggerVariableViewerVarValue> filterPanel =
				new GTableFilterPanel<>(table, model);

		table.getSelectionModel().addListSelectionListener(evt -> {
			if (evt.getValueIsAdjusting()) {
				return;
			}
			myActionContext =
					new DebuggerVariableActionContext(this, filterPanel.getSelectedItems(), table);
			contextChanged();
		});

		final JScrollPane pane = new JScrollPane(table);

		msgOverlay = new MessageOverlay();
		JLayer<JComponent> jLayer = new JLayer<>(pane, msgOverlay);

		final JPanel panel = new JPanel(new BorderLayout());
		panel.add(jLayer);
		panel.add(filterPanel, BorderLayout.SOUTH);

		component = panel;

		actionEnableEdits = DebuggerResources.EnableEditsAction.builder(plugin)
				.enabledWhen(
						c -> currentCoordinates != null && currentCoordinates.getTrace() != null)
				.onAction(c -> {
				})
				.buildAndInstallLocal(this);

		actionShowVariables =
				new MultiStateActionBuilder<VariableViewerStates>("Show/hide variables",
				this.getName()).onActionStateChanged((a, e) -> model.reload())
				.addState("Show Variables From Both", Icons.CONFIGURE_FILTER_ICON,
						VariableViewerStates.BOTH)
				.addState("Show Listing Variables Only",
						new GIcon("icon.plugin.codebrowser.provider"),
						VariableViewerStates.LISTING)
				.addState("Show Decompiler Variables Only",
						new GIcon("icon.decompiler.action.provider"),
						VariableViewerStates.DECOMPILER)
				.toolBarGroup("z")
				.buildAndInstallLocal(this);

		setVisible(true);
		pluginTool.addPopupActionProvider(this);
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	public void setCoordinates(DebuggerCoordinates coordinates) {
		currentCoordinates = coordinates;
		setupListeners(coordinates);
		model.setTrace(coordinates.getTrace());
		if (coordinates == DebuggerCoordinates.NOWHERE) {
			model.setModelData(List.of());
			model.fireTableDataChanged();
			return;
		}
		rebuildTable();
	}

	private void setupListeners(DebuggerCoordinates coordinates) {
		// Remove old listeners
		if (mappedPrograms != null) {
			for (Program program : mappedPrograms) {
				program.removeListener(listener);
			}
		}

		// Add listeners
		mappedPrograms = mappingService.getOpenMappedProgramsAtSnap(coordinates.getTrace(),
				coordinates.getSnap());
		if (mappedPrograms != null) {
			for (Program program : mappedPrograms) {
				program.addListener(listener);
			}
		}
	}

	public void rebuildTable() {
		if (currentFuture != null) {
			currentFuture.cancel(true);
		}
		msgOverlay.setMessage("Loading...");
		component.repaint();
		currentFuture = progressService.execute(true, true, true,
				m -> gatherVariables(m, currentCoordinates));
		currentFuture.whenComplete((result, ex) -> {
			if (ex != null && !(ex instanceof CancellationException)) {
				Throwable actual = (ex instanceof CompletionException) ? ex.getCause() : ex;
				result = List.of();
				msgOverlay.setMessage(actual.getMessage());
			}
			else {
				msgOverlay.setMessage(null);
			}
			model.setModelData(result);
			model.fireTableDataChanged();
			component.repaint();
		});
	}

	private CompletableFuture<List<AbstractDebuggerVariableViewerVarValue>> gatherVariables(
			TaskMonitor monitor, DebuggerCoordinates coordinates) {
		return CompletableFuture.supplyAsync(() -> {
			final List<AbstractDebuggerVariableViewerVarValue> varValues = new LinkedList<>();

			final TraceThread thread = coordinates.getThread();
			final Trace trace = coordinates.getTrace();
			final long snap = coordinates.getSnap();

			if (thread == null) {
				return varValues;
			}
			final TraceMemorySpace regs =
					trace.getMemoryManager().getMemoryRegisterSpace(thread, coordinates.getFrame(), false);
			final Register programCounter = trace.getBaseLanguage().getProgramCounter();

			final RegisterValue pcRegVal = regs.getValue(snap, programCounter);

			if (pcRegVal == null) {
				Msg.error(this, "Snapshot %d: PC =<unavailable>".formatted(snap));
				return varValues;
			}

			final Address dynamicPC = trace.getBaseAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(pcRegVal.getUnsignedValue().longValue());

			final TraceLocation dynamicLoc =
					new DefaultTraceLocation(trace, null, Lifespan.at(snap), dynamicPC);
			final ProgramLocation staticLoc = mappingService.getOpenMappedLocation(dynamicLoc);

			if (staticLoc == null) {
				Msg.error(this, "Snap %d: Can't map 0x%x".formatted(snap, dynamicPC.getOffset()));
				return varValues;
			}

			final Address pc = staticLoc.getAddress();
			final Program program = staticLoc.getProgram();

			final Function func =
					DebuggerStaticMappingUtils.getFunction(dynamicPC, trace, snap, pluginTool);
			if (func == null) {
				Msg.error(this,
						"Snap %d @ 0x%x : 0x%x in %s is not part of a function".formatted(snap,
								dynamicPC.getOffset(), pc.getOffset(), program.getName()));
				return varValues;
			}

			final VariableValueUtils.VariableEvaluator evaluator =
					new VariableValueUtils.VariableEvaluator(pluginTool, coordinates);
			final StackUnwindWarningSet warnings = new StackUnwindWarningSet();
			final UnwoundFrame<DebuggerPcodeUtils.WatchValue> frame =
					evaluator.getStackFrame(func, warnings, monitor, true);

			gatherListingVariables(func, frame, varValues, evaluator);
			gatherDecompilerVariables(monitor, program, func, varValues, frame, evaluator);

			return varValues;
		});
	}

	private void gatherListingVariables(Function func,
			UnwoundFrame<DebuggerPcodeUtils.WatchValue> frame,
			List<AbstractDebuggerVariableViewerVarValue> varValues,
			VariableValueUtils.VariableEvaluator evaluator) {
		for (final Variable variable : func.getAllVariables()) {
			try {
				final DebuggerPcodeUtils.WatchValue value = frame.getValue(variable);
				varValues.add(new DebuggerVariableViewerVarValue(variable, value.bytes().bytes(),
						value.address(), evaluator.getRepresentation(frame, value.address(), value,
						variable.getDataType()), this, null, value.state()));
			}
			catch (PcodeExecutionException e) {
				varValues.add(
						new DebuggerVariableViewerVarValue(variable, null, Address.NO_ADDRESS, "",
								this, e.getMessage(), null));
			}
		}
	}

	private void gatherDecompilerVariables(TaskMonitor monitor, Program program, Function func,
			List<AbstractDebuggerVariableViewerVarValue> varValues,
			UnwoundFrame<DebuggerPcodeUtils.WatchValue> frame,
			VariableValueUtils.VariableEvaluator evaluator) {
		final DecompInterface decompInterface = new DecompInterface();
		decompInterface.openProgram(program);
		final DecompileResults res = decompInterface.decompileFunction(func, 0, monitor);
		if (!res.decompileCompleted()) {
			return;
		}

		final HighFunction highFunction = res.getHighFunction();
		final Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
		while (symbols.hasNext()) {
			final HighSymbol sym = symbols.next();
			try {
				final DebuggerPcodeUtils.WatchValue value =
						frame.getValue(program, sym.getStorage());
				varValues.add(new DebuggerVariableViewerHighVarValue(sym, value.bytes().bytes(),
						value.address(), evaluator.getRepresentation(frame, value.address(), value,
						sym.getDataType()), this, null, value.state()));
			}
			catch (PcodeExecutionException e) {
				varValues.add(
						new DebuggerVariableViewerHighVarValue(sym, null, Address.NO_ADDRESS, "",
								this, e.getMessage(), null));
			}
		}
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool t, ActionContext context) {
		if ((context != myActionContext) || (context == null)) {
			return List.of();
		}
		final List<DockingActionIf> result = new ArrayList<>();

		final List<AbstractDebuggerVariableViewerVarValue> selected =
				myActionContext.getSelected();
		final boolean multipleSelected = selected.size() > 1;
		if (multipleSelected) {
			return List.of();
		}

		Address address = selected.getFirst().getAddress();
		if (address != null && !address.isRegisterAddress()) {
			addActions(result, "View %s @ 0x%x in...".formatted(selected.getFirst().getSymbol(),
					address.getOffset()), address);
		}

		address = currentCoordinates.getLanguage()
				.getAddressFactory()
				.getAddress(selected.getFirst().getValue());
		if (address != null) {
			addActions(result, "View *%s @ 0x%x in...".formatted(selected.getFirst().getSymbol(),
					address.getOffset()), address);
		}
		return result;
	}

	private void addActions(List<DockingActionIf> result, String name, Address address) {
		// Add action for each additional debugger listing window
		int i = 0;
		result.add(DebuggerVariableViewerPopupAction.builder(this, Integer.toString(i), name,
				"Main Listing").onAction(ctx -> {
			if (listingService == null) {
				return;
			}
			final ProgramLocation loc = new ProgramLocation(currentCoordinates.getView(), address);
			listingService.goTo(loc, true);
			listingService.requestFocus();
		}).build());

		pluginTool.setMenuGroup(new String[] { name }, DebuggerVariableViewerPopupAction.GROUP1);
		i++;
		for (final DebuggerListing dl : listingService.getAllListings()) {
			if (dl.isMainListing()) {
				continue;
			}

			result.add(DebuggerVariableViewerPopupAction.builder(this, Integer.toString(i), name,
					dl.getTitle()).onAction(ctx -> {
				if (listingService == null) {
					return;
				}
				final ProgramLocation loc =
						new ProgramLocation(currentCoordinates.getView(), address);
				dl.goTo(loc);
				dl.requestFocus();
			}).build());
			i++;
		}

		result.add(DebuggerVariableViewerPopupAction.builder(this, Integer.toString(i), name,
						"New Listing")
				.popupMenuGroup(DebuggerVariableViewerPopupAction.GROUP2)
				.onAction(ctx -> {
					if (listingService == null) {
						return;
					}
					final DebuggerListing dl = listingService.createNewListing();
					dl.setCustomTitle(listingService.findNextCustomTitle());
					dl.setTrackingSpec(NoneLocationTrackingSpec.INSTANCE);
					dl.setFollowsCurrentThread(true);
					final ProgramLocation loc =
							new ProgramLocation(currentCoordinates.getView(), address);
					dl.goTo(loc);
					dl.requestFocus();
				})
				.build());
	}
}
