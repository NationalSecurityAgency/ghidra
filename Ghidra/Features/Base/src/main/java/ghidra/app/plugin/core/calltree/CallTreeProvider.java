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
package ghidra.app.plugin.core.calltree;

import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.*;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.*;
import docking.resources.icons.NumberIcon;
import docking.widgets.dialogs.NumberInputDialog;
import docking.widgets.label.GLabel;
import docking.widgets.tree.*;
import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin;
import docking.widgets.tree.support.GTreeSelectionListener;
import docking.widgets.tree.tasks.GTreeExpandAllTask;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
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
import resources.ResourceManager;

public class CallTreeProvider extends ComponentProviderAdapter implements DomainObjectListener {

	static final String EXPAND_ACTION_NAME = "Fully Expand Selected Nodes";
	static final String TITLE = "Function Call Trees";
	private static final Icon EMPTY_ICON = ResourceManager.loadImage("images/EmptyIcon16.gif");
	private static final Icon EXPAND_ICON = Icons.EXPAND_ALL_ICON;
	private static final Icon COLLAPSE_ICON = Icons.COLLAPSE_ALL_ICON;

	private static ImageIcon REFRESH_ICON = Icons.REFRESH_ICON;
	private static Icon REFRESH_NOT_NEEDED_ICON = ResourceManager.getDisabledIcon(REFRESH_ICON, 60);

	private static final String RECURSE_DEPTH_PROPERTY_NAME = "call.tree.recurse.depth";
	private static final String DEFAULT_RECURSE_DEPTH = "5";

	private final CallTreePlugin plugin;

	private JComponent component;
	private JSplitPane splitPane;
	private GTree incomingTree;
	private GTree outgoingTree;
	private boolean isPrimary;

	private SwingUpdateManager reloadUpdateManager = new SwingUpdateManager(500, () -> doUpdate());

	private Program currentProgram;
	private Function currentFunction;
	private DockingAction recurseDepthAction;
	private ToggleDockingAction filterDuplicates;
	private ToggleDockingAction navigationOutgoingAction;
	private ToggleDockingAction navigateIncomingToggleAction;
	private DockingAction refreshAction;

	private boolean isFiringNavigationEvent;

	/**
	 * A variable used to restrict open-ended operations, like expanding all nodes or filtering.
	 */
	private AtomicInteger recurseDepth = new AtomicInteger();
	private NumberIcon recurseIcon;

	public CallTreeProvider(CallTreePlugin plugin, boolean isPrimary) {
		super(plugin.getTool(), TITLE, plugin.getName());
		this.plugin = plugin;
		this.isPrimary = isPrimary;

		component = buildComponent();

		// try to give the trees a suitable amount of space by default
		component.setPreferredSize(new Dimension(800, 400));

		setWindowMenuGroup(TITLE);
		setDefaultWindowPosition(WindowPosition.BOTTOM);

		if (isPrimary) {
			addToToolbar();
		}
		else {
			setTransient();
		}
		setIcon(CallTreePlugin.PROVIDER_ICON);
		setHelpLocation(new HelpLocation(plugin.getName(), "Call_Tree_Plugin"));

		addToTool();
		loadRecurseDepthPreference();
		createActions();
	}

	private void createActions() {

		String expandMenu = Integer.toString(1);
		String selectionMenuGroup = Integer.toString(2);
		String goToMenu = Integer.toString(3);
		String newTreeMenu = Integer.toString(4);

		String homeToolbarGroup = Integer.toString(1);
		String filterOptionsToolbarGroup = Integer.toString(2);
		String navigationOptionsToolbarGroup = Integer.toString(3);

		//
		// fully expand
		//
		DockingAction fullyExpandNodesAction =
			new DockingAction(EXPAND_ACTION_NAME, plugin.getName()) {

				@Override
				public void actionPerformed(ActionContext context) {
					Object contextObject = context.getContextObject();
					GTree gTree = (GTree) contextObject;
					TreePath[] paths = gTree.getSelectionPaths();
					for (TreePath treePath : paths) {
						GTreeNode node = (GTreeNode) treePath.getLastPathComponent();
						gTree.runTask(new ExpandToDepthTask(gTree, node, recurseDepth.get()));
					}
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					Object contextObject = context.getContextObject();
					if (!(contextObject == outgoingTree || contextObject == incomingTree)) {
						return false;
					}
					return true;
				}

				@Override
				public boolean isAddToPopup(ActionContext context) {
					Object contextObject = context.getContextObject();
					if (!(contextObject == outgoingTree || contextObject == incomingTree)) {
						return false;
					}
					return true;
				}
			};
		fullyExpandNodesAction.setPopupMenuData(
			new MenuData(new String[] { "Expand Nodes to Depth Limit" }, EXPAND_ICON, expandMenu));
		fullyExpandNodesAction.setHelpLocation(
			new HelpLocation(plugin.getName(), "Call_Tree_Context_Action_Expand_Nodes"));
		tool.addLocalAction(this, fullyExpandNodesAction);

		//
		// Collapse All
		//
		DockingAction collapseAllNodesAction = new DockingAction("Collapse All", plugin.getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				Object contextObject = context.getContextObject();
				GTree gTree = (GTree) contextObject;
				GTreeNode rootNode = gTree.getViewRoot();
				List<GTreeNode> children = rootNode.getChildren();
				for (GTreeNode child : children) {
					gTree.collapseAll(child);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				if (!(contextObject == outgoingTree || contextObject == incomingTree)) {
					return false;
				}

				GTree gTree = (GTree) contextObject;
				if (gTree.getSelectionPaths().length != 1) {
					return false;
				}

				TreePath path = gTree.getSelectionPath();
				if (path == null) {
					return false;
				}

				GTreeNode node = (GTreeNode) path.getLastPathComponent();
				return (node instanceof CallNode);
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				Object contextObject = context.getContextObject();
				if (!(contextObject instanceof GTree)) {
					return false;
				}

				GTree gTree = (GTree) contextObject;
				TreePath[] selectionPaths = gTree.getSelectionPaths();
				if (selectionPaths.length == 0) {
					return false;
				}
				return true;
			}
		};

		collapseAllNodesAction.setPopupMenuData(
			new MenuData(new String[] { "Collapse All Nodes" }, COLLAPSE_ICON, expandMenu));
		collapseAllNodesAction.setHelpLocation(
			new HelpLocation(plugin.getName(), "Call_Tree_Context_Action_Collapse_Nodes"));
		tool.addLocalAction(this, collapseAllNodesAction);

		//
		// goto
		//
		DockingAction goToDestinationAction =
			new DockingAction("Go To Destination", plugin.getName()) {

				@Override
				public void actionPerformed(ActionContext context) {
					Object contextObject = context.getContextObject();
					GTree gTree = (GTree) contextObject;
					TreePath path = gTree.getSelectionPath();
					CallNode node = (CallNode) path.getLastPathComponent();
					goTo(node.getLocation());
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					Object contextObject = context.getContextObject();
					if (!(contextObject == outgoingTree)) {
						return false;
					}

					GTree gTree = (GTree) contextObject;
					if (gTree.getSelectionPaths().length != 1) {
						return false;
					}

					TreePath path = gTree.getSelectionPath();
					if (path == null) {
						return false;
					}

					GTreeNode node = (GTreeNode) path.getLastPathComponent();
					return (node instanceof CallNode);
				}

				@Override
				public boolean isAddToPopup(ActionContext context) {
					Object contextObject = context.getContextObject();
					if (!(contextObject instanceof GTree)) {
						return false;
					}

					GTree gTree = (GTree) contextObject;
					TreePath[] selectionPaths = gTree.getSelectionPaths();
					if (selectionPaths.length == 0) {
						return false;
					}

					for (TreePath path : selectionPaths) {
						GTreeNode node = (GTreeNode) path.getLastPathComponent();
						if (node instanceof OutgoingCallsRootNode ||
							node instanceof IncomingCallsRootNode) {
							return false;
						}
					}
					return true;
				}
			};
		goToDestinationAction.setPopupMenuData(
			new MenuData(new String[] { "Go To Call Destination" }, goToMenu));
		goToDestinationAction.setHelpLocation(
			new HelpLocation(plugin.getName(), "Call_Tree_Context_Action_Goto_Destination"));
		tool.addLocalAction(this, goToDestinationAction);

		DockingAction goToSourceAction = new DockingAction("Go To Source", plugin.getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				Object contextObject = context.getContextObject();
				GTree gTree = (GTree) contextObject;
				TreePath path = gTree.getSelectionPath();
				CallNode node = (CallNode) path.getLastPathComponent();
				goTo(new ProgramLocation(currentProgram, node.getSourceAddress()));
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				if (!(contextObject instanceof GTree)) {
					return false;
				}

				GTree gTree = (GTree) contextObject;
				if (gTree.getSelectionPaths().length != 1) {
					return false;
				}

				TreePath path = gTree.getSelectionPath();
				if (path == null) {
					return false;
				}

				GTreeNode node = (GTreeNode) path.getLastPathComponent();
				return (node instanceof CallNode);
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				Object contextObject = context.getContextObject();
				if (!(contextObject instanceof GTree)) {
					return false;
				}

				GTree gTree = (GTree) contextObject;
				TreePath[] selectionPaths = gTree.getSelectionPaths();
				if (selectionPaths.length == 0) {
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
		};
		goToSourceAction.setPopupMenuData(
			new MenuData(new String[] { "Go To Call Source" }, goToMenu));
		goToSourceAction.setHelpLocation(
			new HelpLocation(plugin.getName(), "Call_Tree_Context_Action_Goto_Source"));
		tool.addLocalAction(this, goToSourceAction);

		//
		// filter duplicates action
		//
		filterDuplicates = new ToggleDockingAction("Filter Duplicates", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				doUpdate();
			}
		};
		filterDuplicates.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/application_double.png"),
				filterOptionsToolbarGroup, "1"));
		filterDuplicates.setSelected(true);
		filterDuplicates.setHelpLocation(
			new HelpLocation(plugin.getName(), "Call_Tree_Action_Filter"));
		tool.addLocalAction(this, filterDuplicates);

		//
		// recurse depth		
		//
		recurseDepthAction = new DockingAction("Recurse Depth", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				NumberInputDialog dialog =
					new NumberInputDialog("", "", recurseDepth.get(), 0, Integer.MAX_VALUE, false);
				if (!dialog.show()) {
					return;
				}

				int newValue = dialog.getValue();
				setRecurseDepth(newValue);
			}
		};
		recurseDepthAction.setDescription(
			"<html>Recurse Depth<br><br>Limits the depth to " + "which recursing tree operations" +
				"<br> will go.  Example operations include <b>Expand All</b> and filtering");
		recurseIcon = new NumberIcon(recurseDepth.get());
		recurseDepthAction.setToolBarData(
			new ToolBarData(recurseIcon, filterOptionsToolbarGroup, "2"));
		recurseDepthAction.setHelpLocation(
			new HelpLocation(plugin.getName(), "Call_Tree_Action_Recurse_Depth"));

		tool.addLocalAction(this, recurseDepthAction);

		//
		// navigate outgoing nodes on selection
		//	
		navigationOutgoingAction =
			new ToggleDockingAction("Navigate Outgoing Nodes", plugin.getName()) {

				// nothing to do here on selection
			};
		navigationOutgoingAction.setSelected(true);
		navigationOutgoingAction.setDescription("<html>Outgoing Navigation<br><br>" +
			"Toggled <b>on</b> triggers node selections<br>in the tree to navigate the " +
			"Listing to<br>the <b>source</b> location of the call");
		navigationOutgoingAction.setToolBarData(new ToolBarData(
			Icons.NAVIGATE_ON_OUTGOING_EVENT_ICON, navigationOptionsToolbarGroup, "1"));
		navigationOutgoingAction.setHelpLocation(
			new HelpLocation(plugin.getName(), "Call_Tree_Action_Navigation"));
		tool.addLocalAction(this, navigationOutgoingAction);

		//
		// navigate incoming nodes on selection	
		//
		navigateIncomingToggleAction =
			new ToggleDockingAction("Navigation Incoming Location Changes", plugin.getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					// handled later as we receive events
				}

				@Override
				public void setSelected(boolean newValue) {
					super.setSelected(newValue);

					if (isSelected()) {
						setLocation(plugin.getCurrentLocation());
					}
				}
			};

		// note: the default state is to follow navigation events for the primary provider; 
		//       non-primary providers will function like snapshots of the function with 
		//       which they were activated.
		navigateIncomingToggleAction.setSelected(isPrimary);
		navigateIncomingToggleAction.setToolBarData(new ToolBarData(
			Icons.NAVIGATE_ON_INCOMING_EVENT_ICON, navigationOptionsToolbarGroup, "2"));
		navigateIncomingToggleAction.setDescription(HTMLUtilities.toHTML("Incoming Navigation" +
			"<br><br>Toggle <b>On</b>  - change the displayed " +
			"function on Listing navigation events" +
			"<br>Toggled <b>Off</b> - don't change the displayed function on Listing navigation events"));
		navigateIncomingToggleAction.setHelpLocation(
			new HelpLocation(plugin.getName(), "Call_Tree_Action_Incoming_Navigation"));
		tool.addLocalAction(this, navigateIncomingToggleAction);

		//
		// selection actions
		//
		DockingAction selectSourceAction =
			new DockingAction("Select Call Source", plugin.getName()) {

				@Override
				public void actionPerformed(ActionContext context) {
					GTree gTree = (GTree) context.getContextObject();
					TreePath[] selectionPaths = gTree.getSelectionPaths();
					makeSelectionFromPaths(selectionPaths, true);
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					if (currentFunction == null) {
						return false;
					}

					Object contextObject = context.getContextObject();
					if (!(contextObject instanceof GTree)) {
						return false;
					}

					GTree gTree = (GTree) contextObject;
					TreePath[] selectionPaths = gTree.getSelectionPaths();
					return selectionPaths.length > 0;
				}

				@Override
				public boolean isAddToPopup(ActionContext context) {
					Object contextObject = context.getContextObject();
					if (!(contextObject instanceof GTree)) {
						return false;
					}

					GTree gTree = (GTree) contextObject;
					TreePath[] selectionPaths = gTree.getSelectionPaths();
					if (selectionPaths.length == 0) {
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
			};
		ImageIcon icon = ResourceManager.loadImage("images/text_align_justify.png");
		selectSourceAction.setPopupMenuData(
			new MenuData(new String[] { "Select Call Source" }, icon, selectionMenuGroup));
		selectSourceAction.setHelpLocation(
			new HelpLocation(plugin.getName(), "Call_Tree_Context_Action_Select_Source"));
		tool.addLocalAction(this, selectSourceAction);

		DockingAction selectDestinationAction =
			new DockingAction("Select Call Destination", plugin.getName()) {

				@Override
				public void actionPerformed(ActionContext context) {
					GTree gTree = (GTree) context.getContextObject();
					TreePath[] selectionPaths = gTree.getSelectionPaths();
					makeSelectionFromPaths(selectionPaths, false);
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					if (currentFunction == null) {
						return false;
					}

					Object contextObject = context.getContextObject();
					if (!(contextObject == outgoingTree)) {
						return false;
					}

					GTree gTree = (GTree) contextObject;
					TreePath[] selectionPaths = gTree.getSelectionPaths();
					return selectionPaths.length > 0;
				}

				@Override
				public boolean isAddToPopup(ActionContext context) {
					Object contextObject = context.getContextObject();
					if (!(contextObject instanceof GTree)) {
						return false;
					}

					GTree gTree = (GTree) contextObject;
					TreePath[] selectionPaths = gTree.getSelectionPaths();
					if (selectionPaths.length == 0) {
						return false;
					}

					for (TreePath path : selectionPaths) {
						GTreeNode node = (GTreeNode) path.getLastPathComponent();
						if (node.isRoot()) {
							return false;
						}
					}

					return isEnabledForContext(context);
				}
			};
		selectDestinationAction.setPopupMenuData(
			new MenuData(new String[] { "Select Call Destination" }, icon, selectionMenuGroup));
		selectDestinationAction.setHelpLocation(
			new HelpLocation(plugin.getName(), "Call_Tree_Context_Action_Select_Destination"));
		tool.addLocalAction(this, selectDestinationAction);

		//
		// home button
		//
		DockingAction homeAction = new DockingAction("Home", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				FunctionSignatureFieldLocation location = new FunctionSignatureFieldLocation(
					currentProgram, currentFunction.getEntryPoint());
				goTo(location);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentFunction != null;
			}
		};
		homeAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/go-home.png"), homeToolbarGroup));
		homeAction.setHelpLocation(new HelpLocation(plugin.getName(), "Call_Tree_Action_Home"));
		tool.addLocalAction(this, homeAction);

		refreshAction = new DockingAction("Refresh", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				reloadUpdateManager.updateNow();
			}
		};
		refreshAction.setToolBarData(new ToolBarData(REFRESH_NOT_NEEDED_ICON, homeToolbarGroup));
		refreshAction.setEnabled(true);
		refreshAction.setDescription("<html>Push at any time to refresh the current trees.<br>" +
			"This is highlighted when the data <i>may</i> be stale.<br>");
		refreshAction.setHelpLocation(
			new HelpLocation(plugin.getName(), "Call_Tree_Action_Refresh"));
		tool.addLocalAction(this, refreshAction);

		//
		// Show new call tree action
		//
		DockingAction newCallTree =
			new DockingAction("Show Call Trees For Function", plugin.getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					GTree gTree = (GTree) context.getContextObject();
					TreePath[] selectionPaths = gTree.getSelectionPaths();
					CallNode callNode = (CallNode) selectionPaths[0].getLastPathComponent();

					ProgramLocation location = null;
					if (gTree == incomingTree) {
						location = new ProgramLocation(currentProgram, callNode.getSourceAddress());

						// in-place call tree
						// doSetLocation(new ProgramLocation(currentProgram,
						//	 callNode.getSourceAddress()));
					}
					else { // outgoing
						location = callNode.getLocation();

						// in-place call tree
						// doSetLocation(callNode.getLocation());
					}

					plugin.showOrCreateNewCallTree(location);
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					if (currentFunction == null) {
						return false;
					}

					Object contextObject = context.getContextObject();
					if (!(contextObject instanceof GTree)) {
						return false;
					}

					GTree gTree = (GTree) contextObject;
					TreePath[] selectionPaths = gTree.getSelectionPaths();
					return selectionPaths.length == 1;
				}

				@Override
				public boolean isAddToPopup(ActionContext context) {
					Object contextObject = context.getContextObject();
					if (!(contextObject instanceof GTree)) {
						return false;
					}

					GTree gTree = (GTree) contextObject;
					TreePath[] selectionPaths = gTree.getSelectionPaths();
					if (selectionPaths.length == 0) {
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
			};
		newCallTree.setHelpLocation(new HelpLocation(plugin.getName(),
			"Call_Tree_Context_Action_Show_Call_Tree_For_Function"));
		newCallTree.setPopupMenuData(new MenuData(new String[] { "Show Call Tree For Function" },
			CallTreePlugin.PROVIDER_ICON, newTreeMenu));
		newCallTree.setDescription("Show the Function Call Tree window for the function " +
			"selected in the call tree");
		tool.addLocalAction(this, newCallTree);
	}

	private void makeSelectionFromPaths(TreePath[] paths, boolean selectSource) {
		AddressSet set = new AddressSet();
		for (TreePath path : paths) {
			CallNode callNode = (CallNode) path.getLastPathComponent();
			Address address = null;
			if (selectSource) {
				address = callNode.getSourceAddress();
			}
			else {
				address = callNode.getLocation().getAddress();
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
			return new ActionContext(this, getActiveComponent());
		}

		Object source = e.getSource();
		if (source instanceof JTree) {
			JTree jTree = (JTree) source;
			GTree gTree = incomingTree;
			if (outgoingTree.isMyJTree(jTree)) {
				gTree = outgoingTree;
			}
			return new ActionContext(this, gTree);
		}

		return null;
	}

	private Component getActiveComponent() {
		KeyboardFocusManager manager = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Component focusOwner = manager.getFocusOwner();
		if (focusOwner == null) {
			return component;
		}

		if (SwingUtilities.isDescendingFrom(focusOwner, outgoingTree)) {
			return outgoingTree;
		}
		if (SwingUtilities.isDescendingFrom(focusOwner, incomingTree)) {
			return incomingTree;
		}
		return component;
	}

	private JComponent buildComponent() {
		JPanel container = new JPanel(new BorderLayout());

		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

		incomingTree = createTree();
		outgoingTree = createTree();
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

			CallNode node = (CallNode) path.getLastPathComponent();
			Address sourceAddress = node.getSourceAddress();
			goTo(new ProgramLocation(currentProgram, sourceAddress));
		};
		outgoingTree.addGTreeSelectionListener(treeSelectionListener);
		incomingTree.addGTreeSelectionListener(treeSelectionListener);

		GTreeSelectionListener contextSelectionListener = e -> notifyContextChanged();
		incomingTree.addGTreeSelectionListener(contextSelectionListener);
		outgoingTree.addGTreeSelectionListener(contextSelectionListener);

		splitPane.setLeftComponent(createTreePanel(true, incomingTree));
		splitPane.setRightComponent(createTreePanel(false, outgoingTree));
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

		panel.add(new GLabel(isIncoming ? "Incoming Calls" : "Outgoing Calls"), BorderLayout.NORTH);
		panel.add(tree, BorderLayout.CENTER);

		return panel;
	}

	private GTree createTree() {
		GTree tree = new GTree(new EmptyRootNode());
		tree.setPaintHandlesForLeafNodes(false);
//		tree.setFilterVisible(false);
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

	private void reload() {
		setLocation(plugin.getCurrentLocation());
	}

	void dispose() {
		reloadUpdateManager.dispose();
		incomingTree.dispose();
		outgoingTree.dispose();
		if (currentProgram != null) {
			currentProgram.removeListener(this);
			currentProgram = null;
		}

		recurseDepthAction.dispose();
		refreshAction.dispose();
		filterDuplicates.dispose();
		navigationOutgoingAction.dispose();
		navigateIncomingToggleAction.dispose();
	}

	void setLocation(ProgramLocation location) {
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

		resetTrees();
		updateTitle();
		reloadUpdateManager.update();
	}

	private void notifyContextChanged() {
		tool.contextChanged(this);
	}

	private void clearTrees() {
		if (incomingTree.getModelRoot() instanceof EmptyRootNode) {
			// already empty
			return;
		}

		updateTitle();
		incomingTree.setRootNode(new EmptyRootNode());
		outgoingTree.setRootNode(new EmptyRootNode());
	}

	private void resetTrees() {
		incomingTree.setRootNode(new PendingRootNode());
		outgoingTree.setRootNode(new PendingRootNode());
	}

	private void doUpdate() {
		updateIncomingReferencs(currentFunction);
		updateOutgoingReferences(currentFunction);
		setStale(false);
	}

	private void updateIncomingReferencs(Function function) {
		GTreeNode rootNode = null;
		if (function == null) {
			rootNode = new EmptyRootNode();
		}
		else {
			rootNode = new IncomingCallsRootNode(currentProgram, function, function.getEntryPoint(),
				filterDuplicates.isSelected(), recurseDepth);
		}
		incomingTree.setRootNode(rootNode);
	}

	private void updateOutgoingReferences(Function function) {
		GTreeNode rootNode = null;
		if (function == null) {
			rootNode = new EmptyRootNode();
		}
		else {
			rootNode = new OutgoingCallsRootNode(currentProgram, function, function.getEntryPoint(),
				filterDuplicates.isSelected(), recurseDepth);
		}

		outgoingTree.setRootNode(rootNode);
	}

	private void updateTitle() {
		String title = TITLE;
		String subTitle = "<No Function>";
		if (currentFunction != null) {
			String programName =
				(currentProgram != null) ? currentProgram.getDomainFile().getName() : "";
			title = TITLE + ": " + currentFunction.getName();
			subTitle = " (" + programName + ")";
		}

		setTitle(title);
		setSubTitle(subTitle);
	}

	void initialize(Program program, ProgramLocation location) {
		if (program == null) { // no program open
			setLocation(null);
			return;
		}

		currentProgram = program;
		currentProgram.addListener(this);
		doSetLocation(location);
	}

	void programActivated(Program program) {
		if (!followLocationChanges() && currentProgram != null) {
			return; // don't respond; just keep our data
		}

		currentProgram = program;
		currentProgram.addListener(this);
		setLocation(plugin.getCurrentLocation());
	}

	void programDeactivated(Program program) {
		if (!followLocationChanges()) {
			return; // don't respond; just keep our data
		}

		clearState();
	}

	void programClosed(Program program) {
		if (program != currentProgram) {
			return; // not my program
		}

		program.removeListener(this);
		clearState();

		currentProgram = null;
	}

	private void clearState() {
		incomingTree.cancelWork();
		outgoingTree.cancelWork();
		currentFunction = null;
		reloadUpdateManager.update();
	}

	boolean isShowingLocation(ProgramLocation location) {
		if (currentFunction == null) {
			return false;
		}

		AddressSetView body = currentFunction.getBody();
		return body.contains(location.getAddress());
	}

	private boolean followLocationChanges() {
		return navigateIncomingToggleAction.isSelected();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent event) {
		if (!isVisible()) {
			return;
		}

		if (isEmpty()) {
			return; // nothing to update
		}

		if (event.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			setStale(true);
			return;
		}

		for (int i = 0; i < event.numRecords(); i++) {
			DomainObjectChangeRecord domainObjectRecord = event.getChangeRecord(i);
			int eventType = domainObjectRecord.getEventType();

			switch (eventType) {
				case ChangeManager.DOCR_MEMORY_BLOCK_MOVED:
				case ChangeManager.DOCR_MEMORY_BLOCK_REMOVED:
				case ChangeManager.DOCR_SYMBOL_ADDED:
				case ChangeManager.DOCR_SYMBOL_REMOVED:
				case ChangeManager.DOCR_MEM_REFERENCE_ADDED:
				case ChangeManager.DOCR_MEM_REFERENCE_REMOVED:
					setStale(true);
					break;
				case ChangeManager.DOCR_SYMBOL_RENAMED:
					Symbol symbol = (Symbol) ((ProgramChangeRecord) domainObjectRecord).getObject();
					if (!(symbol instanceof FunctionSymbol)) {
						break;
					}

					FunctionSymbol functionSymbol = (FunctionSymbol) symbol;
					Function function = (Function) functionSymbol.getObject();
					if (updateRootNodes(function)) {
						return; // the entire tree will be rebuilt
					}

					incomingTree.runTask(new UpdateFunctionNodeTask(incomingTree, function));
					outgoingTree.runTask(new UpdateFunctionNodeTask(outgoingTree, function));
					break;
			}
		}
	}

	private boolean isEmpty() {
		GTreeNode rootNode = incomingTree.getModelRoot();
		return rootNode instanceof EmptyRootNode;
	}

	private boolean updateRootNodes(Function function) {
		GTreeNode root = incomingTree.getModelRoot();
		// root might be a "PendingRootNode"
		//TODO do we need to use a PendingRootNode?
		if (root instanceof CallNode) {
			CallNode callNode = (CallNode) root;
			Function nodeFunction = callNode.getRemoteFunction();
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
			CallNode rootNode = (CallNode) tree.getModelRoot();
			List<GTreeNode> children = rootNode.getChildren();
			for (GTreeNode node : children) {
				updateFunction((CallNode) node);
			}
		}

		private void updateFunction(CallNode node) {
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
				updateFunction((CallNode) child);
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

// TODO if we ever want specific staleness detection	
//	private CallNode findNode(CallNode node, Function newFunction) {
//		Function function = node.getContainingFunction();
//		if (function == null) {
//			return null;
//		}
//
//		if (function.equals(newFunction)) {
//			return node;
//		}
//
//		if (!node.isChildrenLoadedOrInProgress()) {
//			return null; // no children
//		}
//
//		List<GTreeNode> children = node.getChildren();
//		for (GTreeNode child : children) {
//			CallNode result = findNode((CallNode) child, newFunction);
//			if (result != null) {
//				return result;
//			}
//		}
//		return null;
//	}

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
		incomingTree.refilterLater();
		outgoingTree.refilterLater();

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
		GTreeNode rootNode = incomingTree.getModelRoot();
		rootNode.removeAll();
		rootNode = outgoingTree.getModelRoot();
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
		incomingTree.setFilterText(text);
	}

	public void setOutgoingFilter(String text) {
		outgoingTree.setFilterText(text);
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
		protected void expandNode(GTreeNode node, TaskMonitor monitor) throws CancelledException {
			TreePath treePath = node.getTreePath();
			Object[] path = treePath.getPath();
			if (path.length > maxDepth) {
				return;
			}

			CallNode callNode = (CallNode) node;
			if (callNode.functionIsInPath()) {
				return; // this path hit a function that is already in the path
			}

			super.expandNode(node, monitor);
		}
	}

	private class PendingRootNode extends GTreeNode {

		@Override
		public Icon getIcon(boolean expanded) {
			return CallTreePlugin.FUNCTION_ICON;
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
