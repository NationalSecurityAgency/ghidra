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
package ghidra.app.plugin.core.debug.gui.tracecalltree;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;

import docking.*;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.actions.PopupActionProvider;
import docking.widgets.gtreetable.GTreeTableNode;
import docking.widgets.table.TableSortState;
import docking.widgets.table.threaded.ThreadedTableModelListenerAdapter;
import ghidra.app.plugin.core.debug.gui.DebuggerProvider;
import ghidra.app.plugin.core.debug.gui.action.NoneLocationTrackingSpec;
import ghidra.app.plugin.core.debug.gui.action.PCLocationTrackingSpec;
import ghidra.app.plugin.core.debug.gui.tracecalltree.AbstractTraceCallTreeNode.ParamNameToBytes;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.services.*;
import ghidra.debug.api.listing.DebuggerListing;
import ghidra.debug.api.modules.DebuggerStaticMappingChangeListener;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.AddressEvaluator;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceModuleManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.util.TraceEvents;
import ghidra.util.HelpLocation;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

import static ghidra.program.util.ProgramEvent.*;

public class TraceCallTreeProvider extends ComponentProviderAdapter
		implements DebuggerProvider, PopupActionProvider {

	private class ClearLogAction extends DockingAction {

		ClearLogAction(ComponentProvider provider) {
			super("Clear log", provider.getOwner());
			setEnabled(true);
			Icon icon = Icons.CLEAR_ICON;
			setToolBarData(new ToolBarData(icon, "log"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			treeLogModel.clear();
		}
	}

	private class FoldRecursiveAction extends DockingAction {

		FoldRecursiveAction(ComponentProvider provider) {
			super("Collapse from selected cell recursively", provider.getOwner());
			setEnabled(true);
			Icon icon = Icons.COLLAPSE_ALL_ICON;
			setToolBarData(new ToolBarData(icon, "expand"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (treeTable.getFilterPanel()
					.getSelectedItem() instanceof final AbstractTraceCallTreeNode node) {
				node.setExpanded(false);
				node.forEachDescendant(e -> e.setExpanded(false));
				updateModel(currentRootNode);
			}
		}
	}

	private class JumpToCurrentAction extends DockingAction {

		JumpToCurrentAction(ComponentProvider provider) {
			super("Jump to current node", provider.getOwner());
			setEnabled(true);
			Icon icon = Icons.HOME_ICON;
			setToolBarData(new ToolBarData(icon, "jump"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (currentRootNode != null) {
				scrollToCurrentNode = true;
				updateModel(currentRootNode);
			}
		}
	}

	private record NodeFallthrough(Address fallthrough, AbstractTraceCallTreeNode node) {}

	private class RebuildCallTreeAction extends DockingAction {

		RebuildCallTreeAction(ComponentProvider provider) {
			super("Rebuild Call Tree", provider.getOwner());
			setEnabled(true);
			Icon icon = Icons.REFRESH_ICON;
			setToolBarData(new ToolBarData(icon, "refresh"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (currentCoords != null) {
				generateCallTreeAndUpdateModel(currentCoords);
			}
		}
	}

	record RootCache(Map<TraceThread, AbstractTraceCallTreeNode> rootNodesPerThread) {
		public RootCache() {
			this(new HashMap<>());
		}
	}

	private class ShowLogWindowAction extends ToggleDockingAction {

		ShowLogWindowAction(ComponentProvider provider) {
			super("Show/hide log window", provider.getOwner());
			setEnabled(true);
			Icon icon = Icons.WARNING_ICON;
			setToolBarData(new ToolBarData(icon, "log"));
			setSelected(showLogWindow);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			showLogWindow = isSelected();
			mainPanel.removeAll();

			final JSplitPane treeTableAndLogSplit = createTbSplit();
			treeTableAndLogSplit.setLeftComponent(treeTable);
			final GhidraFilterTable<TraceCallTreeLogModel.TraceCallTreeLogObject> logTable =
				new GhidraFilterTable<>(treeLogModel);
			treeTableAndLogSplit.setRightComponent(logTable);
			if (showLogWindow) {
				mainPanel.add(treeTableAndLogSplit, BorderLayout.CENTER);
			}
			else {
				mainPanel.add(treeTable, BorderLayout.CENTER);
			}

			mainPanel.revalidate();
		}
	}

	private class ShowReturnsToggleAction extends ToggleDockingAction {

		ShowReturnsToggleAction(ComponentProvider provider) {
			super("Show/hide returns", provider.getOwner());
			setEnabled(true);
			Icon icon = Icons.ARROW_UP_LEFT_ICON;
			setToolBarData(new ToolBarData(icon, "show"));
			setSelected(showReturns);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			showReturns = isSelected();
			if (currentRootNode != null) {
				currentRootNode.forEachDescendant(d -> {
					if (d instanceof final TraceCallTreeReturnNode descendant) {
						descendant.setVisible(showReturns);
					}
				});
				updateModel(currentRootNode);
			}
		}
	}

	private class ShowTailCallsToggleAction extends ToggleDockingAction {

		ShowTailCallsToggleAction(ComponentProvider provider) {
			super("Show/hide tail calls", provider.getOwner());
			setEnabled(true);
			Icon icon = Icons.NAVIGATE_ON_INCOMING_EVENT_ICON;
			setToolBarData(new ToolBarData(icon, "show"));
			setSelected(showTailCalls);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			showTailCalls = isSelected();
			if (currentRootNode != null) {
				currentRootNode.forEachDescendant(d -> {

					if (d instanceof final TraceCallTreeTailCallNode descendant) {
						descendant.setVisible(showTailCalls);
					}
				});
				updateModel(currentRootNode);
			}
		}
	}

	private class TraceCallTreeEventListener extends TraceDomainObjectListener {

		public TraceCallTreeEventListener() {
			listenFor(TraceEvents.SNAPSHOT_ADDED, this::snapshotEvent);
			listenFor(TraceEvents.SNAPSHOT_DELETED, this::snapshotEvent);
			listenFor(TraceEvents.SNAPSHOT_CHANGED, this::snapshotEvent);
			listenForUntyped(DomainObjectEvent.RESTORED, e -> snapshotEvent());
		}

		void snapshotEvent() {
			if (currentCoords == null) {
				return;
			}
			final Trace trace = currentCoords.getTrace();
			if (trace == null) {
				return;
			}
			final long curMaxSnap =
				Objects.requireNonNullElse(trace.getTimeManager().getMaxSnap(), 0).longValue();
			traceToMaxSnap.putIfAbsent(trace, curMaxSnap);
			final long prevMaxSnap = traceToMaxSnap.get(trace);
			if (curMaxSnap != prevMaxSnap) {
				traceToMaxSnap.put(trace, curMaxSnap);
				generateCallTreeAndUpdateModel(currentCoords);
			}
		}
	}

	interface TraceCallTreePopupAction {
		String NAME = "Trace Call Tree Popup Actions";
		String DESCRIPTION = "Popup actions for trace call tree";
		String HELP_ANCHOR = "";
		String GROUP1 = "z";
		String GROUP2 = "zz";
		String GROUP3 = "zzz";
		String GROUP4 = "zzzz";

		static ActionBuilder builder(ComponentProvider owner, String group, String subgroup,
				String... path) {
			final String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR))
					.popupMenuGroup(group, subgroup)
					.popupMenuPath(path)
					.popupWhen(c -> true)
					.enabledWhen(c -> true);
		}
	}

	private class UnfoldRecursiveAction extends DockingAction {

		UnfoldRecursiveAction(ComponentProvider provider) {
			super("Expand from selected cell recursively", provider.getOwner());
			setEnabled(true);
			Icon icon = Icons.EXPAND_ALL_ICON;
			setToolBarData(new ToolBarData(icon, "expand"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (treeTable.getFilterPanel()
					.getSelectedItem() instanceof final AbstractTraceCallTreeNode node) {
				node.setExpanded(true);
				node.forEachDescendant(e -> e.setExpanded(true));
				updateModel(currentRootNode);
			}
		}
	}

	protected static double computeResizeWeight(JSplitPane split) {
		final java.util.function.Function<Dimension, Integer> axis =
			switch (split.getOrientation()) {
				case JSplitPane.HORIZONTAL_SPLIT -> (dim -> dim.width);
				case JSplitPane.VERTICAL_SPLIT -> (dim -> dim.height);
				default -> throw new AssertionError();
			};

		// This method is off by a little, and I don't know why, but I don't
		// care.

		final Component lComp = split.getLeftComponent();
		final int lMin = axis.apply(lComp.getMinimumSize());
		final int lSize = axis.apply(lComp.getSize());
		final Component rComp = split.getRightComponent();
		final int rMin = axis.apply(rComp.getMinimumSize());
		final int rSize = axis.apply(rComp.getSize());

		final int totalExtra = (lSize + rSize) - lMin - rMin;
		final int lExtra = lSize - lMin;

		return (double) lExtra / totalExtra;
	}

	private final Map<Trace, Long> traceToMaxSnap = new HashMap<>();

	private final Map<Trace, RootCache> rootNodesForTraceThreadMap = new HashMap<>();
	private boolean rootNodeChanged = false;

	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;
	private JComponent component;
	private TraceCallTreeTable treeTable;
	private AbstractTraceCallTreeNode currentRootNode;
	private AbstractTraceCallTreeNode currentNode;
	private TraceCallTreeModel treeTableModel;

	private boolean showReturns = true;
	private boolean showTailCalls = true;
	private boolean showLogWindow = true;

	private DebuggerCoordinates currentCoords;
	private boolean scrollToCurrentNode = false;
	private final ThreadedTableModelListenerAdapter modelListenerAdapter =
		new ThreadedTableModelListenerAdapter() {
			@Override
			public void loadingFinished(boolean wasCancelled) {
				if (scrollToCurrentNode) {
					treeTable.getFilterPanel()
							.setSelectedItems(Collections.singletonList(currentNode));
					treeTable.getFilterPanel().scrollToSelectedRow();
					scrollToCurrentNode = false;
				}
			}
		};

	private final DomainObjectListener domainObjectListener = makeProgramDomainObjectListener();
	private final TraceCallTreeEventListener traceCallTreeEventListener =
		new TraceCallTreeEventListener();

	private TraceCallTreeActionContext myActionContext;

	@AutoConfigStateField
	private double tbResizeWeight = 0.7;
	@AutoServiceConsumed
	private DebuggerListingService listingService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	// @AutoServiceConsumed via method
	private DebuggerStaticMappingService mappingService;
	@AutoServiceConsumed
	private DebuggerConsoleService consoleService;
	@AutoServiceConsumed
	private ProgressService progressService;

	private CompletableFuture<AbstractTraceCallTreeNode> callTreeNodeCompletableFuture;

	private final TraceCallTreePlugin plugin;

	private final DebuggerStaticMappingChangeListener listener =
		(affectedTraces, affectedPrograms) -> {
			if ((currentCoords != null) && affectedTraces.contains(currentCoords.getTrace())) {
				generateCallTreeAndUpdateModel(currentCoords);
			}
		};

	private TraceCallTreeLogModel treeLogModel;
	private JPanel mainPanel;

	public TraceCallTreeProvider(TraceCallTreePlugin plugin) {
		super(plugin.getTool(), "Trace Call Tree", plugin.getName());
		this.plugin = plugin;

		autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		buildPanel();
		setVisible(true);
		tool.addPopupActionProvider(this);
		tool.addLocalAction(this, new FoldRecursiveAction(this));
		tool.addLocalAction(this, new UnfoldRecursiveAction(this));
		tool.addLocalAction(this, new ShowReturnsToggleAction(this));
		tool.addLocalAction(this, new ShowTailCallsToggleAction(this));
		tool.addLocalAction(this, new RebuildCallTreeAction(this));
		tool.addLocalAction(this, new JumpToCurrentAction(this));
		tool.addLocalAction(this, new ShowLogWindowAction(this));
		tool.addLocalAction(this, new ClearLogAction(this));
	}

	private void buildPanel() {
		mainPanel = new JPanel(new BorderLayout());

		treeTableModel = new TraceCallTreeModel(null);
		treeTable = new TraceCallTreeTable(treeTableModel);
		treeTable.getTable().addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (((e.getClickCount() == 2) && (treeTable.getFilterPanel()
						.getSelectedItem() instanceof final AbstractTraceCallTreeNode node)) &&
					(traceManager != null)) {
					traceManager.activateSnap(node.getSnapshotKey());
				}
			}

		});
		treeTable.getTable().getSelectionModel().addListSelectionListener(evt -> {
			if (evt.getValueIsAdjusting()) {
				return;
			}
			myActionContext = new TraceCallTreeActionContext(this,
				treeTable.getFilterPanel().getSelectedItems(), treeTable.getTable());
			contextChanged();
		});
		treeTableModel.addThreadedTableModelListener(modelListenerAdapter);

		final JSplitPane treeTableAndLogSplit = createTbSplit();
		treeTableAndLogSplit.setLeftComponent(treeTable);
		treeLogModel = new TraceCallTreeLogModel(plugin);
		final GhidraFilterTable<TraceCallTreeLogModel.TraceCallTreeLogObject> logTable =
			new GhidraFilterTable<>(treeLogModel);
		treeTableAndLogSplit.setRightComponent(logTable);
		if (showLogWindow) {
			mainPanel.add(treeTableAndLogSplit, BorderLayout.CENTER);
		}
		else {
			mainPanel.add(treeTable, BorderLayout.CENTER);
		}
		component = mainPanel;
	}

	private void changeThatMakesTreeStale() {
		if (currentRootNode != null) {
			treeTable.setStatusMessage("Tree data is stale");
		}
	}

	/**
	 * Check if instruction is a call instruction. If so add its fall through to the fall through
	 * list.
	 * Nothing is added to the call tree for calls, functions starts handle that
	 *
	 * @param monitor TaskMonitor to check for cancellation
	 * @param trace Trace we are working with
	 * @param rootNode Root of the call tree we are working with
	 * @param callStack Tracking what function we are currently in
	 * @param fallthroughs List of fall throughs to add to
	 * @param dynamicPC Current dynamic program counter
	 * @param inst Current instruction
	 * @throws CancelledException Task is canceled
	 */
	private void checkForCalls(TaskMonitor monitor, final Trace trace,
			final AbstractTraceCallTreeNode rootNode,
			final Deque<AbstractTraceCallTreeNode> callStack,
			final Deque<NodeFallthrough> fallthroughs, Address dynamicPC, TraceSnapshot snapshot,
			final Instruction inst) throws CancelledException {
		monitor.checkCancelled();

		if (inst.getFlowType().equals(RefType.UNCONDITIONAL_CALL) &&
			(inst.getFlows().length == 1)) {
			if (inst.getDefaultFallThrough() == null) {
				treeLogModel.log(trace,
					"No default fall through for %s @ 0x%x".formatted(inst,
						inst.getAddress().getOffset()),
					snapshot.getKey(), inst.getAddress(), dynamicPC);

			}
			else if (callStack.isEmpty()) {
				callStack.push(rootNode);
			}
			else {
				fallthroughs.push(new NodeFallthrough(inst.getFallThrough(), callStack.peek()));
			}
		}
	}

	/**
	 * Check if the current address is a fall through from a previous call
	 * This helps us reorient ourselves if we miss returns or there are shared returns in the binary
	 *
	 * @param monitor TaskMonitor to check for cancellation
	 * @param rootNode Root of the call tree we are working with
	 * @param callStack Tracking what function we are currently in
	 * @param fallthroughs List of fall throughs to check
	 * @param pc Current static program counter
	 * @throws CancelledException Task is canceled
	 */
	private void checkForFallThroughs(final TaskMonitor monitor,
			final AbstractTraceCallTreeNode rootNode,
			final Deque<AbstractTraceCallTreeNode> callStack,
			final Deque<NodeFallthrough> fallthroughs, final Address pc) throws CancelledException {
		monitor.checkCancelled();

		if (!fallthroughs.isEmpty()) {
			boolean removeFromFallthrough = false;
			NodeFallthrough nodeToRemoveTo = null;
			for (final NodeFallthrough nodeFallthrough : fallthroughs) {
				// If the call tree does not contain the fall through function
				// (where we returned to) we must be in a tail call function or
				// we missed the call to this function
				if (pc.getOffset() == nodeFallthrough.fallthrough().getOffset()) {
					if (callStack.contains(nodeFallthrough.node())) {
						while (!callStack.isEmpty() && (callStack.peek() != rootNode) &&
							(callStack.peek() != nodeFallthrough.node())) {
							callStack.pop();
						}
					}
					removeFromFallthrough = true;
					nodeToRemoveTo = nodeFallthrough;
					break;
				}
			}
			if (removeFromFallthrough) {
				while (fallthroughs.peek() != null) {
					if (nodeToRemoveTo == fallthroughs.peek()) {
						fallthroughs.pop();
						break;
					}
					fallthroughs.pop();
				}
			}
		}
	}

	/**
	 * Check if instruction is a return instruction. If so we add a return node to the tree.
	 * Tail calls are also handled as returns but are added as tail call nodes.
	 * This function does not pop calls off the main tree, the {@link #checkForFallThroughs}
	 * function is responsible for that
	 *
	 * @param monitor TaskMonitor to check for cancellation
	 * @param trace Trace we are working with
	 * @param thread Thread we are working with
	 * @param callStack Tracking what function we are currently in
	 * @param snapshot Current snapshot in the trace
	 * @param dynamicPC Current dynamic program counter
	 * @param func Current function we are in
	 * @param inst Current instruction
	 * @throws CancelledException Task is canceled
	 */
	private void checkForReturns(TaskMonitor monitor, final Trace trace, final TraceThread thread,
			final Deque<AbstractTraceCallTreeNode> callStack, final TraceSnapshot snapshot,
			Address dynamicPC, Function func, final Instruction inst) throws CancelledException {
		monitor.checkCancelled();

		if ((func != null) && inst.getFlowType().isTerminal()) {
			if (!callStack.isEmpty()) {
				if (inst.getFlowType().equals(FlowType.TERMINATOR)) {
					callStack.pop();

					final AbstractTraceCallTreeNode node = new TraceCallTreeReturnNode(
						func.getName(), func.getProgram().getName(), snapshot, List.of(),
						gatherReturn(trace, func, thread, snapshot, monitor));
					node.setVisible(showReturns);

					if (!callStack.isEmpty()) {
						callStack.peek().add(node);
					}
				}
				else if (inst.getFlowType().equals(FlowType.COMPUTED_CALL_TERMINATOR) ||
					inst.getFlowType().equals(FlowType.CALL_TERMINATOR)) {
					final AbstractTraceCallTreeNode node = new TraceCallTreeTailCallNode(
						func.getName(), func.getProgram().getName(), snapshot, List.of(), null);
					node.setVisible(showTailCalls);

					if (!callStack.isEmpty()) {
						callStack.peek().add(node);
					}
				}
				else {
					treeLogModel.log(trace,
						("Unable to add return from function: %s Flow Type is: " + "%s")
								.formatted(func.getName(), inst.getFlowType().getName()),
						snapshot.getKey(), inst.getAddress(), dynamicPC);
				}
			}
			else {
				treeLogModel.log(trace,
					"Return from %s is going to be at top of call stack!".formatted(func.getName()),
					snapshot.getKey(), inst.getAddress(), dynamicPC);
			}
		}
	}

	/**
	 * Check if e current program counter is at the start of a function.
	 * If so we add a call node to the tree.
	 *
	 * @param monitor TaskMonitor to check for cancellation
	 * @param trace Trace we are working with
	 * @param thread Thread we are working with
	 * @param rootNode Root of the call tree we are working with
	 * @param callStack Tracking what function we are currently in
	 * @param snapshot Current snapshot in the trace
	 * @param dynamicPC Current dynamic program counter
	 * @param pc Current static program counter
	 * @param func Current function we are in
	 * @throws CancelledException Task is canceled
	 */
	private void checkForStartOfFunctions(TaskMonitor monitor, final Trace trace,
			final TraceThread thread, final AbstractTraceCallTreeNode rootNode,
			final Deque<AbstractTraceCallTreeNode> callStack, final TraceSnapshot snapshot,
			Address dynamicPC, final Address pc, Function func) throws CancelledException {
		monitor.checkCancelled();

		if ((func != null) && (pc.getOffset() == func.getEntryPoint().getOffset())) {
			AbstractTraceCallTreeNode node;
			if (func.isThunk() && func.getThunkedFunction(true).isExternal()) {
				node = new TraceCallTreeExternalNode(func.getName(), func.getProgram().getName(),
					snapshot, gatherParameters(trace, func, thread, snapshot, monitor), null);
			}
			else {
				node = new TraceCallTreeCallNode(func.getName(), func.getProgram().getName(),
					snapshot, gatherParameters(trace, func, thread, snapshot, monitor), null);
			}
			rootNode.setLargestParamSize(
				Math.max(rootNode.getLargestParamSize(), node.getParameterNumber()));
			if (!callStack.isEmpty()) {
				callStack.peek().add(node);
			}
			else {
				treeLogModel.log(trace,
					"Can't add function %s at top of call stack".formatted(func.getName()),
					snapshot.getKey(), func.getEntryPoint(), dynamicPC);
			}

			callStack.push(node);
		}
	}

	/**
	 * Create 3 different type of actions for a given address:
	 * <ol>
	 * <li>Display in main debugger listing actions</li>
	 * <li>Display in one of the other additional existing debugger listings</li>
	 * <li>Display in a new listing</li>
	 * </ol>
	 *
	 * @param tool Tool to add actions to
	 * @param result List of resulting actions to add to
	 * @param name Name of action
	 * @param subgroup Subgroup of action
	 * @param address Target address to use for action
	 */
	private void createActionsToViewVariableInListings(Tool tool,
			final List<DockingActionIf> result, String name, String subgroup,
			final Address address) {
		// Add action for main debugger listing window
		result.add(TraceCallTreePopupAction
				.builder(this, TraceCallTreePopupAction.GROUP3, subgroup, "View " + name)
				.onAction(ctx -> {
					if (listingService == null) {
						return;
					}
					final ProgramLocation loc =
						new ProgramLocation(currentCoords.getView(), address);
					listingService.goTo(loc, true);
					listingService.requestFocus();
				})
				.build());

		// Add action for each additional debugger listing window
		tool.setMenuGroup(new String[] { name }, TraceCallTreePopupAction.GROUP3,
			"extra" + subgroup);
		for (final DebuggerListing dl : listingService.getAllListings()) {
			if (dl.isMainListing()) {
				continue;
			}

			result.add(TraceCallTreePopupAction
					.builder(this, TraceCallTreePopupAction.GROUP3, subgroup, name,
						"View In " + dl.getTitle())
					.onAction(ctx -> {
						if (listingService == null) {
							return;
						}
						final ProgramLocation loc =
							new ProgramLocation(currentCoords.getView(), address);
						dl.goTo(loc);
						dl.requestFocus();
					})
					.build());
		}

		// Add action to view in new listing
		result.add(TraceCallTreePopupAction
				.builder(this, TraceCallTreePopupAction.GROUP4, subgroup, name,
					"View In New Listing")
				.onAction(ctx -> {
					if (listingService == null) {
						return;
					}
					final DebuggerListing dl = listingService.createNewListing();
					dl.setCustomTitle(listingService.findNextCustomTitle());
					dl.setTrackingSpec(NoneLocationTrackingSpec.INSTANCE);
					dl.setFollowsCurrentThread(true);
					final ProgramLocation loc =
						new ProgramLocation(currentCoords.getView(), address);
					dl.goTo(loc);
					dl.requestFocus();
				})
				.build());
	}

	private CompletableFuture<AbstractTraceCallTreeNode> createCallTree(TaskMonitor monitor,
		DebuggerCoordinates coords) {
		return CompletableFuture.supplyAsync(() -> {
			try {
				return doCreateCallTree(monitor, coords);
			}
			catch (final CancelledException | TraceClosedException e) {
				return null;
			}
		});
	}

	protected JSplitPane createTbSplit() {
		final JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
		split.setResizeWeight(tbResizeWeight);
		split.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY, pce -> {
			tbResizeWeight = computeResizeWeight(split);
		});
		return split;
	}

	public void dispose() {
		if (mappingService != null) {
			mappingService.removeChangeListener(listener);
		}
		if ((callTreeNodeCompletableFuture != null) && !callTreeNodeCompletableFuture.isDone()) {
			callTreeNodeCompletableFuture.cancel(true);
		}

		treeTableModel.removeThreadedTableModelListener(modelListenerAdapter);
	}

	/**
	 * Create the call tree
	 *
	 * @param monitor TaskMonitor for reporting status
	 * @param coords Current debugger coordinates
	 * @return null or built AbstractTraceCallTreeNode
	 * @throws CancelledException Task is canceled
	 */
	private AbstractTraceCallTreeNode doCreateCallTree(TaskMonitor monitor,
			DebuggerCoordinates coords) throws CancelledException {
		if (mappingService == null) {
			return null;
		}

		final Trace trace = coords.getTrace();
		final TraceThread thread = coords.getThread();

		if ((trace == null) || (thread == null)) {
			return null;
		}

		consoleService.removeFromLog(new TraceCallTreeLogContext(this, trace, null));

		final List<? extends TraceSnapshot> snaps = trace.getTimeManager()
				.getAllSnapshots()
				.stream()
				.filter(s -> (s.getEventThread() == thread) && (s.getKey() >= 0))
				.toList();

		if (snaps.isEmpty()) {
			treeLogModel.log(trace, "No snapshots found in trace for current thread", 0, null,
				null);
			return null;
		}

		treeLogModel.resolve(trace, 0, null);

		final AbstractTraceCallTreeNode rootNode =
			new TraceCallTreeCallNode("Start of Trace", "", snaps.getFirst(), List.of(), null);

		final Deque<AbstractTraceCallTreeNode> callStack = new LinkedList<>();
		callStack.push(rootNode);
		monitor.initialize(snaps.size());

		final Deque<NodeFallthrough> fallthroughs = new LinkedList<>();

		for (final TraceSnapshot snapshot : snaps) {
			monitor.increment();

			final Address dynamicPC = getDynamicPcFromRegister(coords, snapshot, monitor);
			if (dynamicPC == null) {
				continue;
			}

			final ProgramLocation sloc =
				getStaticAddressFromDynamicPC(coords, snapshot, monitor, dynamicPC);
			if (sloc == null) {
				continue;
			}

			final Address pc = sloc.getAddress();
			final Program program = sloc.getProgram();

			final Function func =
				getFunctionForStaticLocation(coords, snapshot, monitor, dynamicPC, sloc);
			if (func == null) {
				continue;
			}

			checkForFallThroughs(monitor, rootNode, callStack, fallthroughs, pc);

			final Instruction inst = program.getListing().getInstructionAt(pc);
			if (inst == null) {
				treeLogModel.log(trace, "No instruction found", snapshot.getKey(), pc, dynamicPC);
				continue;
			}

			checkForStartOfFunctions(monitor, trace, thread, rootNode, callStack, snapshot,
				dynamicPC, pc, func);

			checkForCalls(monitor, trace, rootNode, callStack, fallthroughs, dynamicPC, snapshot,
				inst);

			checkForReturns(monitor, trace, thread, callStack, snapshot, dynamicPC, func, inst);

			treeLogModel.resolve(trace, snapshot.getKey(), dynamicPC);
		}

		return rootNode;
	}

	/**
	 * Get values bytes for each parameter of this function
	 *
	 * @param trace Trace we are working with
	 * @param func Current function we are in
	 * @param thread Thread we are working with
	 * @param snapshot Current snapshot in the trace
	 * @param monitor TaskMonitor to check for cancellation
	 * @return List of bytes for given all parameters
	 * @throws CancelledException Task is canceled
	 */
	private List<ParamNameToBytes> gatherParameters(Trace trace, Function func, TraceThread thread,
			TraceSnapshot snapshot, TaskMonitor monitor) throws CancelledException {
		final List<ParamNameToBytes> retMap = new LinkedList<>();

		for (final Parameter parameter : func.getParameters()) {
			monitor.checkCancelled();
			final byte[] bytes = getBytesForVariable(parameter, trace, thread, snapshot);
			retMap.add(new ParamNameToBytes(parameter.getName(), bytes));
		}

		return retMap;
	}

	/**
	 * Get values bytes for the return of this function
	 *
	 * @param trace Trace we are working with
	 * @param func Current function we are in
	 * @param thread Thread we are working with
	 * @param snapshot Current snapshot in the trace
	 * @param monitor TaskMonitor to check for cancellation
	 * @return Bytes for return value
	 * @throws CancelledException Task is canceled
	 */
	private byte[] gatherReturn(Trace trace, Function func, TraceThread thread,
			TraceSnapshot snapshot, TaskMonitor monitor) throws CancelledException {
		monitor.checkCancelled();
		final Parameter parameter = func.getReturn();

		if ((parameter != null) && (parameter.getMinAddress() != null)) {
			return getBytesForVariable(parameter, trace, thread, snapshot);
		}
		return null;
	}

	private void generateCallTreeAndUpdateModel(DebuggerCoordinates coords) {
		if ((progressService == null) || (coords == null)) {
			return;
		}
		if ((callTreeNodeCompletableFuture != null) && !callTreeNodeCompletableFuture.isDone()) {
			callTreeNodeCompletableFuture.cancel(true);
		}
		updateModel(null);
		treeTableModel.setTableSortState(TableSortState.createUnsortedSortState());
		treeTable.setStatusMessage("Updating...");
		callTreeNodeCompletableFuture =
			progressService.execute(true, true, true, m -> createCallTree(m, coords));
		callTreeNodeCompletableFuture.whenComplete((result, ex) -> {
			if ((ex != null) && !(ex instanceof CancellationException)) {
				treeTable.setStatusMessage(ex.getMessage());
			}
			else if (result != null) {
				currentRootNode = result;
				rootNodeChanged = true;
				final Map<TraceThread, AbstractTraceCallTreeNode> threadMap =
					rootNodesForTraceThreadMap
							.computeIfAbsent(coords.getTrace(), e -> new RootCache())
							.rootNodesPerThread();
				threadMap.put(coords.getThread(), result);
				refresh(coords);
			}
			treeTable.setStatusMessage(null);
		});
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	/**
	 * Get value bytes for a given variable
	 *
	 * @param var Variable to get bytes for
	 * @param trace Trace we are working with
	 * @param thread Thread we are working with
	 * @param snapshot Current snapshot in the trace
	 * @return Bytes for given variable
	 */
	private byte[] getBytesForVariable(Variable var, Trace trace, TraceThread thread,
			TraceSnapshot snapshot) {
		Address address = var.getMinAddress();
		final ByteBuffer buf = ByteBuffer.allocate(var.getLength());
		byte[] bytes;

		if (address.isStackAddress()) {
			final CompilerSpec spec = trace.getBaseCompilerSpec();
			final RegisterValue value = trace.getMemoryManager()
					.getMemoryRegisterSpace(thread, false)
					.getValue(snapshot.getKey(), spec.getStackPointer());

			final Address stackPointer =
				spec.getStackBaseSpace().getAddress(value.getUnsignedValue().longValue());

			address = stackPointer.add(address.getOffset());
			trace.getMemoryManager().getBytes(snapshot.getKey(), address, buf);
			bytes = buf.array();
		}
		else if (address.isMemoryAddress()) {
			trace.getMemoryManager().getBytes(snapshot.getKey(), address, buf);
			bytes = buf.array();
		}
		else if (address.isRegisterAddress()) {
			final RegisterValue regVal = trace.getMemoryManager()
					.getMemoryRegisterSpace(thread, false)
					.getValue(snapshot.getKey(), var.getRegister());
			bytes = regVal.getUnsignedValue().toByteArray();
		}
		else {
			bytes = new byte[0];
		}
		return bytes;
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	/**
	 * Gets the dynamic program counter for a given snapshot directly from the register holding it
	 *
	 * @param coords Current debugger coordinates
	 * @param snapshot Current snapshot in the trace
	 * @param monitor TaskMonitor to check for cancellation
	 * @return Address in the PC register
	 * @throws CancelledException Task is canceled
	 */
	private Address getDynamicPcFromRegister(DebuggerCoordinates coords, TraceSnapshot snapshot,
			TaskMonitor monitor) throws CancelledException {
		monitor.checkCancelled();

		final Trace trace = coords.getTrace();
		final TraceThread thread = coords.getThread();
		if ((thread == null) || (trace == null)) {
			treeLogModel.log(trace, "Trace/Thread is null", snapshot.getKey(), null, null);
			return null;
		}
		final Register programCounter = trace.getBaseLanguage().getProgramCounter();

		final TraceMemorySpace regs =
			trace.getMemoryManager().getMemoryRegisterSpace(thread, 0, false);
		final RegisterValue pcRegVal = regs.getValue(snapshot.getKey(), programCounter);

		if (pcRegVal == null) {
			treeLogModel.log(trace, "PC is null", snapshot.getKey(), null, null);

			return null;
		}

		treeLogModel.resolve(trace, snapshot.getKey(), null);

		return trace.getBaseAddressFactory()
				.getDefaultAddressSpace()
				.getAddress(pcRegVal.getUnsignedValue().longValue());
	}

	/**
	 * Get the function from the static program associated with this dynamic PC
	 *
	 * @param coords Current debugger coordinates
	 * @param snapshot Current snapshot in the trace
	 * @param monitor TaskMonitor to check for cancellation
	 * @param dynamicPC Current dynamic program counter
	 * @param sloc Current static program location
	 * @return Static function associated with this dynamic address
	 * @throws CancelledException Task is canceled
	 */
	private Function getFunctionForStaticLocation(DebuggerCoordinates coords,
			TraceSnapshot snapshot, TaskMonitor monitor, Address dynamicPC, ProgramLocation sloc)
			throws CancelledException {
		monitor.checkCancelled();

		final Trace trace = coords.getTrace();

		final Address pc = sloc.getAddress();
		final Program program = sloc.getProgram();

		final Function func = program.getListing().getFunctionContaining(pc);
		if (func == null) {
			treeLogModel.log(trace,
				"0x%x in %s is not part of a function".formatted(pc.getOffset(), program.getName()),
				snapshot.getKey(), pc, dynamicPC);

			return null;
		}
		return func;
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool t, ActionContext context) {
		if ((context != myActionContext) || (context == null) || (listingService == null)) {
			return List.of();
		}

		final List<AbstractTraceCallTreeNode> selected = myActionContext.getSelected();
		final boolean multipleSelected = selected.size() > 1;

		final List<DockingActionIf> result = new ArrayList<>();

		if (!multipleSelected) {
			// Add go to snap action
			String name = "Go To Snapshot %d".formatted(selected.getFirst().getSnapshotKey());
			result.add(
				TraceCallTreePopupAction.builder(this, TraceCallTreePopupAction.GROUP1, "", name)
						.onAction(ctx -> {
							if (traceManager != null) {
								traceManager.activateSnap(selected.getFirst().getSnapshotKey());
							}
						})
						.build());

			// Parameter actions
			int i = 1;
			for (final ParamNameToBytes paramNameToBytes : selected.getFirst().getParameters()) {
				final Address address =
					AddressEvaluator.evaluate(currentCoords.getTrace().getProgramView(),
						NumericUtilities.convertBytesToString(paramNameToBytes.bytes()));
				if (address == null) {
					continue;
				}

				name = "%s @ %s".formatted(paramNameToBytes.name(), address);

				createActionsToViewVariableInListings(t, result, name, Integer.toString(i),
					address);
				i++;
			}

			// Return actions
			if (selected.getFirst().getReturnVal() != null) {
				final Address address =
					AddressEvaluator.evaluate(currentCoords.getTrace().getProgramView(),
						NumericUtilities.convertBytesToString(selected.getFirst().getReturnVal()));
				if (address != null) {

					name = "Return @ %s".formatted(address);

					createActionsToViewVariableInListings(t, result, name, "", address);
				}
			}
		}

		// Add expand and collapse actions
		result.add(TraceCallTreePopupAction
				.builder(this, TraceCallTreePopupAction.GROUP2, "2", "Expand Recursively")
				.onAction(ctx -> {
					selected.forEach(n -> n.setExpanded(true));
					selected.forEach(n -> n.forEachDescendant(e -> e.setExpanded(true)));
					updateModel(currentRootNode);
				})
				.build());

		result.add(TraceCallTreePopupAction
				.builder(this, TraceCallTreePopupAction.GROUP2, "2", "Collapse Recursively")
				.onAction(ctx -> {
					selected.forEach(n -> n.setExpanded(false));
					selected.forEach(n -> n.forEachDescendant(e -> e.setExpanded(false)));
					updateModel(currentRootNode);
				})
				.build());

		result.add(
			TraceCallTreePopupAction.builder(this, TraceCallTreePopupAction.GROUP2, "1", "Expand")
					.onAction(ctx -> {
						selected.forEach(n -> n.setExpanded(true));
						updateModel(currentRootNode);
					})
					.build());

		result.add(
			TraceCallTreePopupAction.builder(this, TraceCallTreePopupAction.GROUP2, "1", "Collapse")
					.onAction(ctx -> {
						selected.forEach(n -> n.setExpanded(false));
						updateModel(currentRootNode);
					})
					.build());

		return result;
	}

	/**
	 * Get the static address/program associated with this dynamic PC
	 *
	 * @param coords Current debugger coordinates
	 * @param snapshot Current snapshot in the trace
	 * @param monitor TaskMonitor to check for cancellation
	 * @param dynamicPC Current dynamic program counter
	 * @return Associated static ProgramLocation
	 * @throws CancelledException Task is canceled
	 */
	private ProgramLocation getStaticAddressFromDynamicPC(DebuggerCoordinates coords,
			TraceSnapshot snapshot, TaskMonitor monitor, Address dynamicPC)
			throws CancelledException {
		monitor.checkCancelled();

		final Trace trace = coords.getTrace();
		final TraceModuleManager modMan = trace.getModuleManager();

		final TraceLocation dloc =
			new DefaultTraceLocation(trace, null, Lifespan.at(snapshot.getKey()), dynamicPC);
		final ProgramLocation sloc = mappingService.getOpenMappedLocation(dloc);

		final Collection<? extends TraceModule> intersecting =
			modMan.getModulesAt(snapshot.getKey(), dynamicPC);

		if (sloc == null) {

			if (intersecting.isEmpty()) {
				treeLogModel.log(trace, "Can't map 0x%x".formatted(dynamicPC.getOffset()),
					snapshot.getKey(), null, dynamicPC);
			}
			else {
				final TraceModule module = intersecting.stream().findFirst().get();
				treeLogModel.log(trace, "Module %s is not mapped".formatted(
						module.getName(snapshot.getKey())),
					snapshot.getKey(), null, dynamicPC);

			}
			return null;
		}

		return sloc;
	}

	private DomainObjectListener makeProgramDomainObjectListener() {
		return new DomainObjectListenerBuilder(this).ignoreWhen(() -> !isVisible())
				.any(FUNCTION_ADDED, FUNCTION_REMOVED, FUNCTION_CHANGED, SYMBOL_ADDED,
					SYMBOL_PRIMARY_STATE_CHANGED, SYMBOL_RENAMED, EXTERNAL_NAME_ADDED,
					EXTERNAL_NAME_REMOVED, EXTERNAL_NAME_CHANGED)
				.call(this::changeThatMakesTreeStale)
				.build();
	}

	public void programClosed(Program program) {
		program.removeListener(domainObjectListener);
	}

	public void programOpened(Program program) {
		program.addListener(domainObjectListener);
	}

	private void refresh(DebuggerCoordinates coords) {
		final Address pcAddress = PCLocationTrackingSpec.INSTANCE.computeTraceAddress(tool, coords);
		final Function func = DebuggerStaticMappingUtils.getFunction(pcAddress, coords, tool);
		if (pcAddress == null) {
			treeLogModel.log(coords.getTrace(), "Unable to resolve PC", coords.getSnap(), null,
				null);
			treeTable.setStatusMessage("Location unknown, check debug console");
			updateModel(currentRootNode);
			return;
		}

		if (func == null) {
			treeLogModel.log(coords.getTrace(), "Can't map 0x%x".formatted(pcAddress.getOffset()),
				coords.getSnap(), null, pcAddress);
			treeTable.setStatusMessage("Location unknown, check debug console");
			updateModel(currentRootNode);
			return;
		}
		final List<GTreeTableNode> list = currentRootNode.find(n -> {
			if (n instanceof final AbstractTraceCallTreeNode traceCallTreeNode) {
				return traceCallTreeNode.getName().equals(func.getName()) &&
					(coords.getSnap() >= traceCallTreeNode.getSnapshotKey());
			}
			treeTable.setStatusMessage("Can't find node for current location, check debug console");
			return false;
		});
		currentNode = (AbstractTraceCallTreeNode) list.getLast();
		currentNode.forEachAncestor(n -> n.setExpanded(true));
		scrollToCurrentNode = true;
		updateModel(currentRootNode);
		treeTable.setStatusMessage(null);
	}

	public void setCoordinates(DebuggerCoordinates coords) {
		if (currentCoords == coords) {
			return;
		}
		if ((currentCoords != null) && (currentCoords.getTrace() != null)) {
			currentCoords.getTrace().removeListener(traceCallTreeEventListener);
		}
		scrollToCurrentNode = true;
		currentCoords = coords;
		if ((currentCoords == DebuggerCoordinates.NOWHERE) || (currentCoords == null) ||
			(currentCoords.getTrace() == null)) {
			treeTable.setStatusMessage(null);
			updateModel(null);
			return;
		}

		currentCoords.getTrace().addListener(traceCallTreeEventListener);

		if (rootNodesForTraceThreadMap.containsKey(coords.getTrace())) {
			final Map<TraceThread, AbstractTraceCallTreeNode> threadMap =
				rootNodesForTraceThreadMap.get(coords.getTrace()).rootNodesPerThread();
			if (threadMap.containsKey(coords.getThread())) {
				rootNodeChanged = threadMap.get(coords.getThread()) != currentRootNode;
				currentRootNode = threadMap.get(coords.getThread());
				refresh(coords);
			}
			else {
				generateCallTreeAndUpdateModel(coords);
			}
		}
		else {
			generateCallTreeAndUpdateModel(coords);
		}
	}

	@AutoServiceConsumed
	private void setMappingService(DebuggerStaticMappingService mappingService) {
		if (this.mappingService != null) {
			this.mappingService.removeChangeListener(listener);
		}
		this.mappingService = mappingService;
		if (this.mappingService != null) {
			this.mappingService.addChangeListener(listener);
		}
	}

	public void traceClosed(Trace trace) {
		final RootCache map = rootNodesForTraceThreadMap.remove(trace);
		if (map != null) {
			map.rootNodesPerThread().clear();
		}

	}

	private void updateModel(AbstractTraceCallTreeNode node) {
		SwingUtilities.invokeLater(() -> {
			treeTableModel.setRootNode(node);
			if (rootNodeChanged) {
				rootNodeChanged = false;
				if (node != null) {
					treeTableModel.setNumberOfParameterColumns(node.getLargestParamSize());
				}
			}
		});
	}
}
