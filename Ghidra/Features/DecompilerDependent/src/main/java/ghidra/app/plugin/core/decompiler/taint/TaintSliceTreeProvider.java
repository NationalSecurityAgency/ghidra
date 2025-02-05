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
package ghidra.app.plugin.core.decompiler.taint;

import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.*;
import javax.swing.tree.TreePath;

import docking.*;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import docking.resources.icons.NumberIcon;
import docking.widgets.dialogs.NumberInputDialog;
import docking.widgets.label.GLabel;
import docking.widgets.tree.*;
import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin;
import docking.widgets.tree.support.GTreeSelectionListener;
import docking.widgets.tree.tasks.GTreeExpandAllTask;
import generic.theme.GIcon;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.decompiler.taint.slicetree.*;
import ghidra.app.services.GoToService;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.preferences.Preferences;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.SwingUpdateManager;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

public class TaintSliceTreeProvider extends ComponentProviderAdapter
		implements DomainObjectListener {

	static final String EXPAND_ACTION_NAME = "Fully Expand Selected Nodes";
	static final String TITLE = "Taint Slice Tree";

	private static final Icon EMPTY_ICON = Icons.EMPTY_ICON;
	private static final Icon EXPAND_ICON = Icons.EXPAND_ALL_ICON;
	private static final Icon COLLAPSE_ICON = Icons.COLLAPSE_ALL_ICON;

	private static Icon REFRESH_ICON = new GIcon("icon.plugin.calltree.refresh");
	private static Icon REFRESH_NOT_NEEDED_ICON =
		new GIcon("icon.plugin.calltree.refresh.not.needed");

	public static Icon HIGH_VARIABLE_ICON = new GIcon("icon.debugger.provider.stack");
	public static Icon HIGH_FUNCTION_ICON = new GIcon("icon.plugin.navigation.function");
	public static Icon IN_TAINT_ICON = new GIcon("icon.up");
	public static Icon OUT_TAINT_ICON = new GIcon("icon.down");
	public static Icon TAINT_ICON = new GIcon("icon.version.tracking.package");

	private static final String RECURSE_DEPTH_PROPERTY_NAME = "call.tree.recurse.depth";
	private static final String DEFAULT_RECURSE_DEPTH = "5";

	private final TaintPlugin plugin;

	private JComponent component;
	private JSplitPane splitPane;
	private GTree inTree;
	private GTree outTree;
	private boolean isPrimary;
	private enum Condition {IN, OUT, EITHER}

	private SwingUpdateManager reloadUpdateManager = new SwingUpdateManager(500, () -> doUpdate());

	private Program currentProgram;
	private Function currentFunction;
	private ToggleDockingAction filterDuplicates;
	private ToggleDockingAction navigationOutgoingAction;
	private ToggleDockingAction navigationIncomingAction;
	private DockingAction refreshAction;

	private boolean isFiringNavigationEvent;

	/**
	 * A variable used to restrict open-ended operations, like expanding all nodes or filtering.
	 */
	private AtomicInteger recurseDepth = new AtomicInteger();
	private NumberIcon recurseIcon;

	public TaintSliceTreeProvider(TaintPlugin plugin, boolean isPrimary) {
		super(plugin.getTool(), TITLE, plugin.getName());
		this.plugin = plugin;
		this.isPrimary = isPrimary;

		component = buildComponent();

		// try to give the trees a suitable amount of space by default
		component.setPreferredSize(new Dimension(800, 400));

		setWindowMenuGroup(TITLE);
		// This puts it into the bottom of the main window.
		// setDefaultWindowPosition(WindowPosition.BOTTOM);
		// This puts it into ITS OWN window.
		setDefaultWindowPosition(WindowPosition.WINDOW);

		setIcon(TaintPlugin.PROVIDER_ICON);
		setHelpLocation(new HelpLocation(plugin.getName(), "Taint_Slice_Tree_Plugin"));

		addToTool();
		loadRecurseDepthPreference();
		createActions();
	}

	private void createActions() {

		String expandMenu = Integer.toString(1);
		String selectionMenuGroup = Integer.toString(2);
		String goToMenu = Integer.toString(3);

		String homeToolbarGroup = Integer.toString(1);
		String filterOptionsToolbarGroup = Integer.toString(2);
		String navigationOptionsToolbarGroup = Integer.toString(3);
		String ownerName = plugin.getName();

		//@formatter:off
		
		//
		// fully expand
		//
		new ActionBuilder(EXPAND_ACTION_NAME, ownerName)
			//.description("Make program selection of function starts from selected rows")
			.helpLocation(new HelpLocation(ownerName, "Call_Tree_Context_Action_Expand_Nodes"))
			//.toolBarIcon(SELECT_FUNCTIONS_ICON)
			.popupMenuIcon(EXPAND_ICON)
			.popupMenuPath("Expand Nodes to Depth Limit")
			.popupMenuGroup(expandMenu) 
			.popupWhen(c -> isValidContext(c, Condition.EITHER))
			.enabledWhen(c -> isValidContext(c, Condition.EITHER))
			.onAction(c -> expandToDepth(c))
			.buildAndInstallLocal(this)
			;

		//
		// collapse all
		//
		new ActionBuilder("Collapse All", ownerName)
			.helpLocation(new HelpLocation(ownerName, "Call_Tree_Context_Action_Collapse_Nodes"))
			.popupMenuIcon(COLLAPSE_ICON)
			.popupMenuPath("Collapse All Nodes")
			.popupMenuGroup(expandMenu) 
			.popupWhen(c -> getSelectedPaths(c) != null)
			.enabledWhen(c -> isValidContextSel(c, Condition.EITHER))
			.onAction(c -> collapseAll(c))
			.buildAndInstallLocal(this)
			;
		
		//
		// goto
		//
		new ActionBuilder("Go To Destination", ownerName)
			.helpLocation(new HelpLocation(ownerName, "Call_Tree_Context_Action_Goto_Destination"))
			.popupMenuPath("Go To Call Destination")
			.popupMenuGroup(goToMenu) 
			.popupWhen(c -> addToPopupNotRoot(c))
			.enabledWhen(c -> isValidContextSel(c, Condition.OUT))
			.onAction(c -> gotToDest(c))
			.buildAndInstallLocal(this)
			;
		
		new ActionBuilder("Go To Source", ownerName)
			.helpLocation(new HelpLocation(ownerName, "Call_Tree_Context_Action_Goto_Source"))
			.popupMenuPath("Go To Call Source")
			.popupMenuGroup(goToMenu) 
			.popupWhen(c -> addToPopupNotRoot(c))
			.enabledWhen(c -> isValidContextSel(c, Condition.EITHER))
			.onAction(c -> gotToSrc(c))
			.buildAndInstallLocal(this)
			;
		
		//
		// recurse depth		
		//
		new ActionBuilder("Recurse Depth", ownerName)
			.description("<html>Recurse Depth<br><br>Limits the depth to " + "which recursing tree operations" +
					"<br> will go.  Example operations include <b>Expand All</b> and filtering")
			.helpLocation(new HelpLocation(ownerName, "Call_Tree_Action_Recurse_Depth"))
			.toolBarGroup(filterOptionsToolbarGroup, "2")
			.toolBarIcon(new NumberIcon(recurseDepth.get()))
			.onAction(c -> recurseDepth(c))
			.buildAndInstallLocal(this)
			;
	
		//
		// selection actions
		//
		new ActionBuilder("Select Call Source", ownerName)
			.helpLocation(new HelpLocation(ownerName, "Call_Tree_Context_Action_Select_Source"))
			.popupMenuIcon(new GIcon("icon.plugin.calltree.filter.select.source"))
			.popupMenuPath("Select Call Source")
			.popupMenuGroup(selectionMenuGroup) 
			.popupWhen(c -> addToPopupMult(c))
			.enabledWhen(c -> isValidContextMult(c, Condition.EITHER))
			.onAction(c -> makeSelectionFromPaths(c, true))
			.buildAndInstallLocal(this)
			;
	
		new ActionBuilder("Select Call Destination", ownerName)
			.helpLocation(new HelpLocation(ownerName, "Call_Tree_Context_Action_Select_Destination"))
			.popupMenuIcon(new GIcon("icon.plugin.calltree.filter.select.source"))
			.popupMenuPath("Select Call Destination")
			.popupMenuGroup(selectionMenuGroup) 
			.popupWhen(c -> addToPopupMult(c))
			.enabledWhen(c -> isValidContextMult(c, Condition.OUT))
			.onAction(c -> makeSelectionFromPaths(c, false))
			.buildAndInstallLocal(this)
			;

		//
		// home button
		//
		new ActionBuilder("Home", ownerName)
			.helpLocation(new HelpLocation(ownerName, "Call_Tree_Action_Home"))
			.toolBarGroup(homeToolbarGroup)
			.toolBarIcon(Icons.HOME_ICON)
			.enabledWhen(c -> currentFunction != null)
			.onAction(c -> home(c))
			.buildAndInstallLocal(this)
			;

		refreshAction = new ActionBuilder("Refresh", ownerName)
			.description("<html>Push at any time to refresh the current trees.<br> This is highlighted when the data <i>may</i> be stale.<br>")
			.helpLocation(new HelpLocation(ownerName, "Call_Tree_Action_Refresh"))
			.toolBarGroup(homeToolbarGroup)
			.toolBarIcon(REFRESH_NOT_NEEDED_ICON)
			.enabledWhen(c -> true)
			.onAction(c -> reloadUpdateManager.updateNow())
			.buildAndInstallLocal(this)
			;

		//
		// filter duplicates action
		//
		filterDuplicates = new ToggleActionBuilder("Filter Duplicates", ownerName)
			.description("<html>Push at any time to refresh the current trees.<br> This is highlighted when the data <i>may</i> be stale.<br>")
			.helpLocation(new HelpLocation(ownerName, "Call_Tree_Action_Filter"))
			.toolBarGroup(filterOptionsToolbarGroup, "1")
			.toolBarIcon(new GIcon("icon.plugin.calltree.filter.duplicates"))
			.selected(true)
			.onAction(c -> doUpdate())
			.buildAndInstallLocal(this)
			;

		//
		// navigate outgoing nodes on selection
		//
		navigationOutgoingAction = new ToggleActionBuilder("Navigate Outgoing Nodes", ownerName)
			.description("<html>Outgoing Navigation<br><br> Toggled <b>on</b> triggers node selections<br>in the tree to navigate the Listing to<br>the <b>source</b> location of the call")
			.helpLocation(new HelpLocation(ownerName, "Call_Tree_Action_Navigation"))
			.toolBarGroup(navigationOptionsToolbarGroup, "1")
			.toolBarIcon(Icons.NAVIGATE_ON_OUTGOING_EVENT_ICON)
			.selected(true)
			.onAction(c -> {
					//IGNORE
				})
			.buildAndInstallLocal(this)
			;

		//
		// navigate incoming nodes on selection
		//
		navigationIncomingAction = new ToggleActionBuilder("Navigate Incoming Location Changes", ownerName)
			.description(HTMLUtilities.toHTML("Incoming Navigation" +
					"<br><br>Toggle <b>On</b>  - change the displayed " +
					"function on Listing navigation events" +
					"<br>Toggled <b>Off</b> - don't change the displayed function on Listing navigation events"))
			.helpLocation(new HelpLocation(ownerName, "Call_Tree_Action_Incoming_Navigation"))
			.toolBarGroup(navigationOptionsToolbarGroup, "2")
			.toolBarIcon(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON)
			.selected(isPrimary)
			.onAction(c -> {
				if (navigationIncomingAction.isSelected()) {
					setLocation(plugin.getCurrentLocation());
				}})
			.buildAndInstallLocal(this)
			;
		
		//@formatter:on
	}


	private boolean isValidSelection(ActionContext context) {
		Object contextObject = context.getContextObject();
		GTree gTree = (GTree) contextObject;
		if (gTree.getSelectionPaths().length != 1) {
			return false;
		}

		TreePath path = gTree.getSelectionPath();
		if (path == null) {
			return false;
		}

		GTreeNode node = (GTreeNode) path.getLastPathComponent();
		return (node instanceof SliceNode);
	}

	private boolean isValidContext(ActionContext context, Condition cond) {
		Object contextObject = context.getContextObject();
		if (!(contextObject instanceof GTree)) {
			return false;
		}
		if (contextObject == inTree && cond == Condition.OUT) {
			return false;
		}
		if (contextObject == outTree && cond == Condition.IN) {
			return false;
		}
		
		return true;
	}

	private boolean isValidContextSel(ActionContext context, Condition cond) {
		return isValidContext(context, cond) && isValidSelection(context);
	}

	private boolean isValidContextMult(ActionContext context, Condition cond) {
		if (!isValidContext(context, cond)) {
			return false;
		}
		if (currentFunction == null) {
			return false;
		}
		
		Object contextObject = context.getContextObject();
		GTree gTree = (GTree) contextObject;
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		return selectionPaths.length > 0;
	}

	private TreePath[] getSelectedPaths(ActionContext context) {
		Object contextObject = context.getContextObject();
		if (!(contextObject instanceof GTree)) {
			return null;
		}

		GTree gTree = (GTree) contextObject;
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		if (selectionPaths.length == 0) {
			return null;
		}
		return selectionPaths;
	}

	private boolean addToPopupNotRoot(ActionContext context) {
		TreePath[] selectionPaths = getSelectedPaths(context);
		if (selectionPaths == null) {
			return false;
		}
		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (node.isRoot()) {
				return false;
			}
		}
		return true;
	}

	private boolean addToPopupMult(ActionContext context) {
		if (!addToPopupNotRoot(context)) {
			return false;
		}
		return isValidContextMult(context, Condition.OUT);
	}

	
	private void expandToDepth(ActionContext context) {
		Object contextObject = context.getContextObject();
		GTree gTree = (GTree) contextObject;
		TreePath[] paths = gTree.getSelectionPaths();
		for (TreePath treePath : paths) {
			GTreeNode node = (GTreeNode) treePath.getLastPathComponent();
			gTree.runTask(new ExpandToDepthTask(gTree, node, recurseDepth.get()));
		}
	}

	private void collapseAll(ActionContext context) {
		Object contextObject = context.getContextObject();
		GTree gTree = (GTree) contextObject;
		GTreeNode rootNode = gTree.getViewRoot();
		List<GTreeNode> children = rootNode.getChildren();
		for (GTreeNode child : children) {
			gTree.collapseAll(child);
		}
	}

	private void gotToDest(ActionContext context) {
		Object contextObject = context.getContextObject();
		GTree gTree = (GTree) contextObject;
		TreePath path = gTree.getSelectionPath();
		SliceNode node = (SliceNode) path.getLastPathComponent();
		goTo(node.getLocation());
	}

	private void gotToSrc(ActionContext context) {
		Object contextObject = context.getContextObject();
		GTree gTree = (GTree) contextObject;
		TreePath path = gTree.getSelectionPath();
		SliceNode node = (SliceNode) path.getLastPathComponent();
		goTo(new ProgramLocation(currentProgram, node.getSourceAddress()));
	}

	private void recurseDepth(ActionContext context) {
		NumberInputDialog dialog =
			new NumberInputDialog("", "", recurseDepth.get(), 0, Integer.MAX_VALUE, false);
		if (!dialog.show()) {
			return;
		}

		int newValue = dialog.getValue();
		setRecurseDepth(newValue);
	}

	private void home(ActionContext context) {
		FunctionSignatureFieldLocation location = new FunctionSignatureFieldLocation(
			currentProgram, currentFunction.getEntryPoint());
		goTo(location);
	}

	private void makeSelectionFromPaths(ActionContext context, boolean selectSource) {
		GTree gTree = (GTree) context.getContextObject();
		TreePath[] paths = gTree.getSelectionPaths();
		AddressSet set = new AddressSet();
		for (TreePath path : paths) {
			SliceNode sliceNode = (SliceNode) path.getLastPathComponent();
			Address address = null;
			if (selectSource) {
				address = sliceNode.getSourceAddress();
			}
			else {
				address = sliceNode.getLocation().getAddress();
			}
			set.addRange(address, address);
		}

		ProgramSelection selection = new ProgramSelection(set);
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent(plugin.getName(), selection, currentProgram));
	}

	private void goTo(ProgramLocation location) {
		isFiringNavigationEvent = true;
		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			goToService.goTo(location);
			isFiringNavigationEvent = false;
			return;
		}

		// no goto service...navigate the old fashioned way (this doesn't have history)		
		plugin.firePluginEvent(new ProgramLocationPluginEvent(getName(), location, currentProgram));
		isFiringNavigationEvent = false;
	}

	@Override
	public ActionContext getActionContext(MouseEvent e) {
		if (e == null) {
			return new DefaultActionContext(this, getActiveComponent());
		}

		Object source = e.getSource();
		if (source instanceof JTree) {
			JTree jTree = (JTree) source;
			GTree gTree = inTree;
			if (outTree.isMyJTree(jTree)) {
				gTree = outTree;
			}
			return new DefaultActionContext(this, gTree);
		}

		return null;
	}

	private Component getActiveComponent() {
		KeyboardFocusManager manager = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Component focusOwner = manager.getFocusOwner();
		if (focusOwner == null) {
			return component;
		}

		if (SwingUtilities.isDescendingFrom(focusOwner, outTree)) {
			return outTree;
		}
		if (SwingUtilities.isDescendingFrom(focusOwner, inTree)) {
			return inTree;
		}
		return component;
	}

	private JComponent buildComponent() {
		JPanel container = new JPanel(new BorderLayout());

		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

		inTree = createTree();
		outTree = createTree();

		GTreeSelectionListener treeSelectionListener = e -> {
			if (e.getEventOrigin() != EventOrigin.USER_GENERATED) {
				return;
			}

			if (!navigationOutgoingAction.isSelected()) {
				return;
			}

			if (currentFunction == null) {
				return;
			}

			TreePath path = e.getPath();
			if (path == null) {
				return;
			}

			SliceNode node = (SliceNode) path.getLastPathComponent();
			Address sourceAddress = node.getSourceAddress();
			goTo(new ProgramLocation(currentProgram, sourceAddress));
		};

		outTree.addGTreeSelectionListener(treeSelectionListener);
		inTree.addGTreeSelectionListener(treeSelectionListener);

		GTreeSelectionListener contextSelectionListener = e -> notifyContextChanged();
		inTree.addGTreeSelectionListener(contextSelectionListener);
		outTree.addGTreeSelectionListener(contextSelectionListener);

		splitPane.setLeftComponent(createTreePanel(true, inTree));
		splitPane.setRightComponent(createTreePanel(false, outTree));
		splitPane.addHierarchyListener(new HierarchyListener() {
			@Override
			public void hierarchyChanged(HierarchyEvent e) {
				long changeFlags = e.getChangeFlags();
				if (HierarchyEvent.DISPLAYABILITY_CHANGED == (changeFlags &
					HierarchyEvent.DISPLAYABILITY_CHANGED)) {

					// check for the first time we are put together
					if (splitPane.isDisplayable()) {
						SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(.5));
						splitPane.removeHierarchyListener(this);
					}
				}
			}
		});

		container.add(splitPane, BorderLayout.CENTER);

		return container;
	}

	private JPanel createTreePanel(boolean isIncoming, GTree tree) {
		JPanel panel = new JPanel(new BorderLayout());

		panel.add(
			new GLabel(
				isIncoming ? "Backward Taint Tree (in nodes)" : "Forward Taint Tree (out nodes)"),
			BorderLayout.NORTH);
		panel.add(tree, BorderLayout.CENTER);

		return panel;
	}

	private GTree createTree() {
		GTree tree = new GTree(new EmptyRootNode());
		tree.setPaintHandlesForLeafNodes(false);
		return tree;
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public void componentShown() {
		reload();
	}

	@Override
	public void componentHidden() {
		if (!isPrimary) {
			plugin.removeProvider(this);
		}
	}

	public void reload() {
		setLocation(plugin.getCurrentLocation());
	}

	public void dispose() {
		reloadUpdateManager.dispose();
		inTree.dispose();
		outTree.dispose();
		if (currentProgram != null) {
			currentProgram.removeListener(this);
			currentProgram = null;
		}

		refreshAction.dispose();
		filterDuplicates.dispose();
		navigationOutgoingAction.dispose();
		navigationIncomingAction.dispose();
	}

	public void setLocation(ProgramLocation location) {
		if (isFiringNavigationEvent) {
			return;
		}

		if (!followLocationChanges()) {
			return;
		}

		if (!isVisible()) {
			return;
		}

		doSetLocation(location);
	}

	private void doSetLocation(ProgramLocation location) {
		if (location == null) {
			setFunction(null);
			return;
		}

		if (currentProgram == null) {
			// This can happen when we were created to lock onto one location and then the program
			// for that location was closed.  Then, the user pressed the button to track location
			// changes, which means we will get here while setting the location, but our program
			// will have been null'ed out.
			currentProgram = plugin.getCurrentProgram();
			currentProgram.addListener(this);
		}

		// TODO Don't need the function - need the High Variable / High Function.
		Function function = plugin.getFunction(location);
		setFunction(function);
	}

	private void setFunction(Function function) {
		if (function != null && function.equals(currentFunction)) {
			return;
		}

		doSetFunction(function);
	}

	private void doSetFunction(Function function) {
		currentFunction = function;
		notifyContextChanged();
		if (currentFunction == null) {
			clearTrees();
			return;
		}

		// NB: This will clear out the trees and set a pending node because the "update" may take a while.
		// in our case I don't think that is the case, but we'll keep this.
		resetTrees();
		updateTitle();

		// This is where the real update and tree building happens.
		// this actually calls this classes doUpdate method.
		reloadUpdateManager.update();
	}

	private void notifyContextChanged() {
		tool.contextChanged(this);
	}

	private void clearTrees() {
		if (inTree.getModelRoot() instanceof EmptyRootNode) {
			// already empty
			return;
		}

		updateTitle();
		inTree.setRootNode(new EmptyRootNode());
		outTree.setRootNode(new EmptyRootNode());
	}

	/**
	 * NB: I think this is the real start of building the trees.
	 */
	private void resetTrees() {
		inTree.setRootNode(new PendingRootNode());
		outTree.setRootNode(new PendingRootNode());
	}

	/**
	 * NB: This is key as well.
	 * 
	 * this is called in the doSetFunctio nmethod
	 */
	private void doUpdate() {
		updateIncomingReferences(currentFunction);
		updateOutgoingReferences(currentFunction);
		setStale(false);
	}

	private void updateIncomingReferences(Function function) {
		GTreeNode rootNode = null;
		if (function == null) {
			// no function, just do an empty node.
			rootNode = new EmptyRootNode();
		}
		else {
			// The root node in the left panel.
			rootNode = new InSliceRootNode(currentProgram, function, function.getEntryPoint(),
				filterDuplicates.isSelected(), recurseDepth);
		}

		// this does the recusing?
		inTree.setRootNode(rootNode);
	}

	private void updateOutgoingReferences(Function function) {
		GTreeNode rootNode = null;
		if (function == null) {
			rootNode = new EmptyRootNode();
		}
		else {
			rootNode = new OutSliceRootNode(currentProgram, function, function.getEntryPoint(),
				filterDuplicates.isSelected(), recurseDepth);
		}

		outTree.setRootNode(rootNode);
	}

	private void updateTitle() {
		String title = TITLE;
		String subTitle = "<No Function>";
		if (currentFunction != null) {
			// TODO Don't need function name but some high variable string.
			String programName =
				(currentProgram != null) ? currentProgram.getDomainFile().getName() : "";
			title = TITLE + ": " + currentFunction.getName();
			subTitle = " (" + programName + ")";
		}

		setTitle(title);
		setSubTitle(subTitle);
	}

	public void initialize(Program program, ProgramLocation location) {
		if (program == null) { // no program open
			setLocation(null);
			return;
		}

		currentProgram = program;
		currentProgram.addListener(this);
		doSetLocation(location);
	}

	public void programActivated(Program program) {
		if (!followLocationChanges() && currentProgram != null) {
			return; // don't respond; just keep our data
		}

		currentProgram = program;
		currentProgram.addListener(this);
		setLocation(plugin.getCurrentLocation());
	}

	public void programDeactivated(Program program) {
		if (!followLocationChanges()) {
			return; // don't respond; just keep our data
		}

		clearState();
	}

	public void programClosed(Program program) {
		if (program != currentProgram) {
			return; // not my program
		}

		program.removeListener(this);
		clearState();

		currentProgram = null;
	}

	private void clearState() {
		inTree.cancelWork();
		outTree.cancelWork();
		currentFunction = null;
		reloadUpdateManager.update();
	}

	public boolean isShowingLocation(ProgramLocation location) {
		if (currentFunction == null) {
			return false;
		}

		AddressSetView body = currentFunction.getBody();
		return body.contains(location.getAddress());
	}

	private boolean followLocationChanges() {
		return navigationIncomingAction.isSelected();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent event) {
		if (!isVisible()) {
			return;
		}

		if (isEmpty()) {
			return; // nothing to update
		}

		if (event.contains(DomainObjectEvent.RESTORED)) {
			setStale(true);
			return;
		}

		for (int i = 0; i < event.numRecords(); i++) {
			DomainObjectChangeRecord domainObjectRecord = event.getChangeRecord(i);
			ProgramEvent eventType = (ProgramEvent) domainObjectRecord.getEventType();

			switch (eventType) {
				case MEMORY_BLOCK_MOVED:
				case MEMORY_BLOCK_REMOVED:
				case SYMBOL_ADDED:
				case SYMBOL_REMOVED:
				case REFERENCE_ADDED:
				case REFERENCE_REMOVED:
					setStale(true);
					break;
				case SYMBOL_RENAMED:
					Symbol symbol = (Symbol) ((ProgramChangeRecord) domainObjectRecord).getObject();
					if (!(symbol instanceof FunctionSymbol)) {
						break;
					}

					FunctionSymbol functionSymbol = (FunctionSymbol) symbol;
					Function function = (Function) functionSymbol.getObject();
					if (updateRootNodes(function)) {
						return; // the entire tree will be rebuilt
					}

					inTree.runTask(new UpdateFunctionNodeTask(inTree, function));
					outTree.runTask(new UpdateFunctionNodeTask(outTree, function));
					break;
				default:
					break;
			}
		}
	}

	private boolean isEmpty() {
		GTreeNode rootNode = inTree.getModelRoot();
		return rootNode instanceof EmptyRootNode;
	}

	private boolean updateRootNodes(Function function) {
		GTreeNode root = inTree.getModelRoot();
		// root might be a "PendingRootNode"
		//TODO do we need to use a PendingRootNode?
		if (root instanceof SliceNode) {
			SliceNode sliceNode = (SliceNode) root;
			Function nodeFunction = sliceNode.getRemoteFunction();
			if (nodeFunction.equals(function)) {
				reloadUpdateManager.update();
				return true;
			}
		}

		return false;
	}

	private class UpdateFunctionNodeTask extends GTreeTask {

		private Function function;

		protected UpdateFunctionNodeTask(GTree tree, Function function) {
			super(tree);
			this.function = function;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			SliceNode rootNode = (SliceNode) tree.getModelRoot();
			List<GTreeNode> children = rootNode.getChildren();
			for (GTreeNode node : children) {
				updateFunction((SliceNode) node);
			}
		}

		private void updateFunction(SliceNode node) {
			if (!node.isLoaded()) {
				// children not loaded, don't force a load by asking for them
				return;
			}

			// first, if the given node represents the function we have, then we don't need to 
			// go any further
			if (function.equals(node.getRemoteFunction())) {
				GTreeNode parent = node.getParent();
				parent.removeNode(node);
				parent.addNode(node.recreate());
				return;
			}

			List<GTreeNode> children = node.getChildren();
			for (GTreeNode child : children) {
				updateFunction((SliceNode) child);
			}
		}
	}

	private void setStale(boolean stale) {
		if (stale) {
			refreshAction.getToolBarData().setIcon(REFRESH_ICON);
		}
		else {
			refreshAction.getToolBarData().setIcon(REFRESH_NOT_NEEDED_ICON);
		}
	}

//==================================================================================================
// Service-like Methods
//==================================================================================================

	public void setRecurseDepth(int depth) {
		if (depth < 1) {
			return; // always have at least one level showing
		}

		if (recurseDepth.get() == depth) {
			return;
		}

		this.recurseDepth.set(depth);
		this.recurseIcon.setNumber(depth);

		removeFilterCache();
		inTree.refilterLater();
		outTree.refilterLater();

		saveRecurseDepth();
	}

	/**
	 * The nodes will cache filtered values, which are restricted by the recurse depth.  We
	 * have to remove this cache to get the nodes to reload children to the new depth.
	 */
	private void removeFilterCache() {
		//
		// I don't like this, BTW.  The problem with this approach is that you lose any loading
		// you have done.  Normally this is not that big of a problem.  However, if the loading
		// takes a long time, then you lose some work.
		//
		GTreeNode rootNode = inTree.getModelRoot();
		rootNode.removeAll();
		rootNode = outTree.getModelRoot();
		rootNode.removeAll();
	}

	private void saveRecurseDepth() {
		Preferences.setProperty(RECURSE_DEPTH_PROPERTY_NAME, Integer.toString(recurseDepth.get()));
		Preferences.store();
	}

	private void loadRecurseDepthPreference() {
		String value = Preferences.getProperty(RECURSE_DEPTH_PROPERTY_NAME, DEFAULT_RECURSE_DEPTH);
		int intValue;
		try {
			intValue = Integer.parseInt(value);
		}
		catch (NumberFormatException nfe) {
			intValue = Integer.parseInt(DEFAULT_RECURSE_DEPTH);
		}

		recurseDepth.set(intValue);
	}

	public int getRecurseDepth() {
		return recurseDepth.get();
	}

	public void setIncomingFilter(String text) {
		inTree.setFilterText(text);
	}

	public void setOutgoingFilter(String text) {
		outTree.setFilterText(text);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class ExpandToDepthTask extends GTreeExpandAllTask {

		private int maxDepth;

		public ExpandToDepthTask(GTree tree, GTreeNode node, int maxDepth) {
			super(tree, node);

			// base max depth upon you starting location
			TreePath treePath = node.getTreePath();
			int startDepth = treePath.getPathCount();
			this.maxDepth = maxDepth + startDepth - 1; // -1--don't count the root node in the depth
		}

		@Override
		protected void expandNode(GTreeNode node, boolean force, TaskMonitor monitor)
				throws CancelledException {
			TreePath treePath = node.getTreePath();
			Object[] path = treePath.getPath();
			if (path.length > maxDepth) {
				return;
			}

			if (!force && !node.isAutoExpandPermitted()) {
				return;
			}

			SliceNode sliceNode = (SliceNode) node;
			if (sliceNode.functionIsInPath()) {
				return; // this path hit a function that is already in the path
			}

			super.expandNode(node, false, monitor);
		}
	}

	private class PendingRootNode extends GTreeNode {

		@Override
		public Icon getIcon(boolean expanded) {
			return TaintPlugin.FUNCTION_ICON;
		}

		@Override
		public String getName() {
			return "Pending...";
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return true;
		}
	}

	private class EmptyRootNode extends GTreeNode {

		@Override
		public Icon getIcon(boolean expanded) {
			return EMPTY_ICON;
		}

		@Override
		public String getName() {
			return "No Function";
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return true;
		}
	}
}
