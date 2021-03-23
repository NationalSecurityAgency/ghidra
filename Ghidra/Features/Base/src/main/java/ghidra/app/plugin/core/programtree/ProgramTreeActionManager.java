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
package ghidra.app.plugin.core.programtree;

import java.awt.datatransfer.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.util.*;

import javax.swing.KeyStroke;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.*;
import docking.dnd.GClipboard;
import ghidra.app.cmd.module.*;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotEmptyException;

/**
 * Class to manage actions and popup menus for the program tree.
 */
class ProgramTreeActionManager implements ClipboardOwner {
// popup for multi selection
	private Clipboard tempClipboard; // temporary clipboard used for the
	// "cut" operation
	private ProgramDnDTree tree; // tree currently in the view
	private ProgramNode root;

	private Program program;

	// actions
	private DockingAction cutAction;
	private DockingAction copyAction;
	private DockingAction pasteAction;
	private DockingAction createFolderAction;
	private DockingAction createFragmentAction;
	private DockingAction mergeAction;
	private DockingAction deleteAction;
	private DockingAction expandAction;
	private DockingAction renameAction;
	private DockingAction collapseAction;
	private DockingAction goToViewAction;
	private DockingAction removeViewAction;
	private DockingAction replaceViewAction;

	private DockingAction[] actions;

	private PasteManager pasteMgr; // handles the paste operations
	private ArrayList<TreePath> viewList;
	private SelectionListener selectionListener;
	private ProgramTreePlugin plugin;
	private boolean replacingView;

	ProgramTreeActionManager(ProgramTreePlugin plugin) {
		this.plugin = plugin;
		tempClipboard = new Clipboard("ProgramTree");
		selectionListener = new SelectionListener();
		pasteMgr = new PasteManager(this);
		createActions(plugin.getName());
	}

	void setProgramTreeView(String treeName, ProgramDnDTree tree) {
		if (this.tree != null) {
			this.tree.removeTreeSelectionListener(selectionListener);
		}

		this.tree = tree;
		pasteMgr.setProgramTreeView(tree);

		if (tree != null) {
			DefaultTreeModel treeModel = (DefaultTreeModel) tree.getModel();
			root = (ProgramNode) treeModel.getRoot();
			viewList = tree.getViewList();
			tree.addTreeSelectionListener(selectionListener);
		}
	}

	/**
	 * Notifies tree object that it is no longer the owner of
	 * the contents of the clipboard.
	 * @param clipboard the clipboard that is no longer owned
	 * @param contents the contents which tree owner had placed on the clipboard
	 */
	@Override
	public void lostOwnership(Clipboard clipboard, Transferable contents) {
		// check the temporary clipboard and revert "cut" operations
		// back to normal in the program node info.
		checkClipboard(false);

	}

	/**
	 * Set the program, and update the root node.
	 */
	void setProgram(Program program) {
		this.program = program;
		tempClipboard.setContents(null, this);
		if (viewList != null) {
			viewList.clear();
		}
	}

	String getLastGroupPasted() {
		return pasteMgr.getLastGroupPasted();
	}

	/**
	 * Return true if actions were created for the tree.
	 */
	boolean actionsCreated() {
		return cutAction != null;
	}

	/**
	 * Get the action for the tree.
	 *
	 * @return PluginAction[]
	 */
	DockingAction[] getActions() {
		return actions;
	}

	/**
	 * Enable or disable actions according to the given
	 * node.  Called by the ProgramTree when the selection changes.
	 */
	void adjustSingleActions(ProgramNode node) {

		if (program == null) {
			disableActions();
			return;
		}

		try {
			//add menu items according to the selected node
			TreePath path = node.getTreePath();

			pasteAction.setEnabled(isPasteOk(node));
			renameAction.setEnabled(true);
			goToViewAction.setEnabled(true);

			replaceViewAction.setEnabled(true);
			removeViewAction.setEnabled(true);

			if (node == root) {
				copyAction.setEnabled(false);
				cutAction.setEnabled(false);
				deleteAction.setEnabled(false);
				expandAction.setEnabled(!allPathsExpanded(path));
				collapseAction.setEnabled(!allPathsCollapsed(path));
				createFolderAction.setEnabled(true);
				createFragmentAction.setEnabled(true);
				mergeAction.setEnabled(false);
				return;
			}

			// node is either a Module or Fragment
			copyAction.setEnabled(true);
			cutAction.setEnabled(true);
			setDeleteActionEnabled();

			if (node.isFragment()) {
				createFolderAction.setEnabled(false);
				createFragmentAction.setEnabled(false);
				expandAction.setEnabled(false);
				mergeAction.setEnabled(false);
				collapseAction.setEnabled(false);

			}
			else {
				createFolderAction.setEnabled(true);
				createFragmentAction.setEnabled(true);
				expandAction.setEnabled(!allPathsExpanded(path));
				mergeAction.setEnabled(true);
				collapseAction.setEnabled(!allPathsCollapsed(path));
			}
		}
		catch (ConcurrentModificationException e) {
		}
	}

	/**
	 * Enable the actions according to what is selected.
	 * If a "root"-type node is selected, then either all of its children
	 * must be selected, or none of its children can be selected.
	 * If the "root"-type node is not selected, then any of its children
	 * may be selected.
	 * Called by the ProgramTree when the selection changes.
	 */
	void adjustMultiActions() {

		cutAction.setEnabled(false);
		copyAction.setEnabled(false);
		deleteAction.setEnabled(false);
		replaceViewAction.setEnabled(false);

		try {
			if (validMultiSelection()) {
				copyAction.setEnabled(true);
				cutAction.setEnabled(true);
				setDeleteActionEnabled();
				replaceViewAction.setEnabled(true);
				enableViewActions();
			}
			enableMergeAction();
		}
		catch (ConcurrentModificationException e) {
		}
	}

	/**
	 * Disable menu options for the single selection actions.
	 */
	void disableActions() {
		goToViewAction.setEnabled(false);
		removeViewAction.setEnabled(false);
		replaceViewAction.setEnabled(false);
		cutAction.setEnabled(false);
		copyAction.setEnabled(false);
		pasteAction.setEnabled(false);
		deleteAction.setEnabled(false);
		renameAction.setEnabled(false);
		expandAction.setEnabled(false);
		collapseAction.setEnabled(false);
		createFolderAction.setEnabled(false);
		createFragmentAction.setEnabled(false);
		mergeAction.setEnabled(false);
	}

	/**
	 * Create actions for the given owner.
	 * @param owner
	 */
	private void createActions(String owner) {

		List<DockingAction> list = new ArrayList<>();

		goToViewAction = new ProgramTreeAction("Go To start of folder/fragment in View", owner,
			new String[] { "Go To in View" },
			KeyStroke.getKeyStroke(KeyEvent.VK_G, InputEvent.CTRL_MASK)) {
			@Override
			public void actionPerformed(ActionContext context) {
				addToView();
			}
		};
		goToViewAction.setEnabled(false);

		goToViewAction
				.setPopupMenuData(new MenuData(new String[] { "Go To in View" }, null, "aview"));

		list.add(goToViewAction);

		removeViewAction = new ProgramTreeAction("Remove folder/fragment from View", owner,
			new String[] { "Remove From View" },
			KeyStroke.getKeyStroke(KeyEvent.VK_X, InputEvent.CTRL_MASK)) {
			@Override
			public void actionPerformed(ActionContext context) {
				removeFromView();
			}
		};
		removeViewAction.setEnabled(false);

		removeViewAction
				.setPopupMenuData(new MenuData(new String[] { "Remove from View" }, null, "aview"));

		list.add(removeViewAction);

		replaceViewAction =
			new ProgramTreeAction("Replace View", owner, new String[] { "Replace View" },
				KeyStroke.getKeyStroke(KeyEvent.VK_R, InputEvent.CTRL_MASK)) {
				@Override
				public void actionPerformed(ActionContext context) {
					replaceView();
				}
			};
		replaceViewAction.setEnabled(false);

		replaceViewAction
				.setPopupMenuData(new MenuData(new String[] { "Replace View" }, null, "aview"));

		list.add(replaceViewAction);

		cutAction =
			new ProgramTreeAction("Cut folder/fragment", owner, new String[] { "Cut" }, null) {
				@Override
				public void actionPerformed(ActionContext context) {
					cut();
				}
			};
		cutAction.setEnabled(false);

// ACTIONS - auto generated
		cutAction.setPopupMenuData(new MenuData(new String[] { "Cut" }, null, "edit"));

		list.add(cutAction);

		copyAction =
			new ProgramTreeAction("Copy folder/fragment", owner, new String[] { "Copy" }, null) {
				@Override
				public void actionPerformed(ActionContext context) {
					copy();
				}
			};
		copyAction.setEnabled(false);

// ACTIONS - auto generated
		copyAction.setPopupMenuData(new MenuData(new String[] { "Copy" }, null, "edit"));

		list.add(copyAction);

		pasteAction = new ProgramTreeAction("Paste folder/fragment", owner,
			new String[] { "Paste" }, null, ProgramTreeAction.SINGLE_SELECTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				TreePath path = tree.getSelectionPath();
				ProgramNode node = (ProgramNode) path.getLastPathComponent();
				pasteMgr.paste(node);
			}

		};
		pasteAction.setEnabled(false);

// ACTIONS - auto generated
		pasteAction.setPopupMenuData(new MenuData(new String[] { "Paste" }, null, "edit"));

		list.add(pasteAction);

		createFolderAction = new ProgramTreeAction("Create Folder", owner,
			new String[] { "Create Folder" }, null, ProgramTreeAction.SINGLE_SELECTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				createFolder();
			}

		};
		createFolderAction.setEnabled(false);

// ACTIONS - auto generated
		createFolderAction.setPopupMenuData(
			new MenuData(new String[] { "Create Folder" }, null, "createGroup"));

		list.add(createFolderAction);

		createFragmentAction = new ProgramTreeAction("Create Fragment", owner,
			new String[] { "Create Fragment" }, null, ProgramTreeAction.SINGLE_SELECTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				createFragment((ProgramNode) tree.getLastSelectedPathComponent());
			}
		};
		createFragmentAction.setEnabled(false);

// ACTIONS - auto generated
		createFragmentAction.setPopupMenuData(
			new MenuData(new String[] { "Create Fragment" }, null, "createGroup"));

		list.add(createFragmentAction);

		mergeAction = new ProgramTreeAction("Merge folder/fragment with Parent", owner,
			new String[] { "Merge with Parent" }, null, ProgramTreeAction.SINGLE_SELECTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				merge();
			}
		};
		mergeAction.setEnabled(false);

// ACTIONS - auto generated
		mergeAction.setPopupMenuData(
			new MenuData(new String[] { "Merge with Parent" }, null, "merge"));

		list.add(mergeAction);

		deleteAction = new ProgramTreeAction("Delete folder/fragment", owner,
			new String[] { "Delete" }, null) {
			@Override
			public void actionPerformed(ActionContext context) {
				delete();
			}
		};
		deleteAction.setEnabled(false);

// ACTIONS - auto generated
		deleteAction.setPopupMenuData(new MenuData(new String[] { "Delete" }, null, "delete"));
		deleteAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));

		list.add(deleteAction);

		renameAction = new ProgramTreeAction("Rename folder/fragment", owner,
			new String[] { "Rename" }, null, ProgramTreeAction.SINGLE_SELECTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				tree.rename();
			}
		};
		renameAction.setEnabled(false);

// ACTIONS - auto generated
		renameAction.setPopupMenuData(new MenuData(new String[] { "Rename" }, null, "delete"));

		list.add(renameAction);

		expandAction = new ProgramTreeAction("Expand All folders/fragments", owner,
			new String[] { "Expand ALL" }, null, ProgramTreeAction.SINGLE_SELECTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				expand();
			}
		};
		expandAction.setEnabled(false);

// ACTIONS - auto generated
		expandAction.setPopupMenuData(new MenuData(new String[] { "Expand All" }, null, "expand"));

		list.add(expandAction);

		collapseAction = new ProgramTreeAction("Collapse All folders/fragments", owner,
			new String[] { "Collapse ALL" }, null, ProgramTreeAction.SINGLE_SELECTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				collapse();
			}
		};
		collapseAction.setEnabled(false);

// ACTIONS - auto generated
		collapseAction
				.setPopupMenuData(new MenuData(new String[] { "Collapse All" }, null, "expand"));

		list.add(collapseAction);

		actions = new DockingAction[list.size()];
		actions = list.toArray(actions);

	}

	/**
	 * Get the temporary clipboard the holds the "cut" nodes.
	 */
	Clipboard getCutClipboard() {
		return tempClipboard;
	}

	/**
	 * Remove node from the list of ProgramNodes in the clipboard. This method is called
	 * if there was a problem pasting a group.
	 */
	void removeFromClipboard(Clipboard clipboard, ProgramNode node) {

		try {
			List<ProgramNode> list = getProgramNodeListFromClipboard();

			int listSize = 0;
			if (list != null) {
				listSize = list.size();
				list.remove(node);
			}

			node.setDeleted(false);
			tree.reloadNode(node);

			if (listSize == 0) {
				if (clipboard == GClipboard.getSystemClipboard()) {
					doClearSystemClipboard(clipboard);
				}
				else {
					clipboard.setContents(null, this);
				}
			}
		}
		catch (UnsupportedFlavorException e) {
			// data flavor is not supported
			Msg.showError(this, null, "Cut from Clipboard " + clipboard.getName() + " Failed",
				"Data flavor in clipboard is not supported.", e);

		}
		catch (IOException e) {
			// data is no longer available
			Msg.showError(this, null, "Cut from Clipboard " + clipboard.getName() + " Failed",
				"Data is no longer available for paste operation", e);
		}
		catch (Exception e) {
			String message = e.getMessage();
			Msg.showError(this, null, "Cut from Clipboard " + clipboard.getName() + " Failed",
				message == null ? e.getClass().getSimpleName() : message, e);
		}
	}

	void enablePasteAction(boolean enabled) {
		pasteAction.setEnabled(enabled);
	}

	/**
	 * Return true if the given node is on the temporary "cut" clipboard.
	 */
	boolean clipboardContains(ProgramNode node) {
		try {
			List<ProgramNode> list = getProgramNodeListFromClipboard();

			if (list == null) {
				// SCR 7990--something bad has happened to the copy buffer
				return false;
			}

			return list.contains(node);
		}
		catch (UnsupportedFlavorException e) {
			// data flavor is not supported
			throw new AssertException("Data flavor in clipboard is not supported.");

		}
		catch (IOException e) {
			// data is no longer available
			Msg.showError(this, null, "Clipboard Check Failed",
				"Data is no longer available for paste operation", e);
		}
		catch (Exception e) {
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	// the cast is generating the warning, but we verified the
	// type is correct
	private List<ProgramNode> getProgramNodeListFromClipboard()
			throws UnsupportedFlavorException, IOException {
		List<ProgramNode> nodeList = Collections.emptyList();
		Transferable t = tempClipboard.getContents(this);
		if (t == null) {
			return nodeList;
		}
		if (!t.isDataFlavorSupported(TreeTransferable.localTreeNodeFlavor)) {
			return nodeList;
		}
		List<ProgramNode> list =
			(List<ProgramNode>) t.getTransferData(TreeTransferable.localTreeNodeFlavor);
		return list;
	}

	/**
	  * Check clipboard for cut operations.
	  * @param applyCutChanges true if cut operation should be performed;
	  * false means that the nodes will revert to their normal icons
	  * (i.e., not showing as "cut")
	  */
	void checkClipboard(boolean applyCutChanges) {

		// cut the contents of the clipboard from the program, as
		// a paste was not done...
		try {
			List<ProgramNode> list = getProgramNodeListFromClipboard();

			if (list == null) {
				// SCR 7990--something bad has happened to the copy buffer
				return;
			}

			for (ProgramNode node : list) {
				if (tree.getModel().getRoot() != node.getRoot()) {
					break;
				}

				if (applyCutChanges) {

					ProgramModule parentModule = node.getParentModule();
					Group group = node.getGroup();
					try {
						parentModule.removeChild(group.getName());
					}
					catch (NotEmptyException e) {
						node.setDeleted(false);
						tree.reloadNode(node);
						//Err.log(e, "Cut from Clipboard Failed");
					}
					catch (ConcurrentModificationException e) {
					}
				}
				else {
					// reverse the indication that tree node is being cut
					// first make sure that the group still exists
					try {
						Group g = node.getGroup();
						// call a method on group to make sure it is still valid
						g.getName();

						node.setDeleted(false);
						tree.reloadNode(node);
					}
					catch (ConcurrentModificationException e) {
					}
				}

			}
		}
		catch (UnsupportedFlavorException e) {
			// data flavor is not supported
			throw new AssertException("Data flavor in clipboard is not supported.");

		}
		catch (IOException e) {
			// data is no longer available
			Msg.showError(this, null, "Cut from Clipboard Failed",
				"Data is no longer available for paste operation", e);
		}
		catch (Exception e) {
		}

		try {
			tempClipboard.setContents(null, this);
		}
		catch (Exception e) {
		}
	}

	/**
	 * Clear the system clipboard if there is tree transferable data on it.
	 */
	void clearSystemClipboard() {

		try {
			Clipboard systemClipboard = GClipboard.getSystemClipboard();
			if (!systemClipboard.isDataFlavorAvailable(TreeTransferable.localTreeNodeFlavor)) {
				return;
			}

			Object data = systemClipboard.getData(TreeTransferable.localTreeNodeFlavor);
			if (data == null) {
				return;
			}

			// we were the owner, so get rid of our data, so there is no unclaimed garbage
			doClearSystemClipboard(systemClipboard);
		}
		catch (Exception e) {
			// ignore errors
		}
	}

	private void doClearSystemClipboard(Clipboard systemClipboard) {
		// for some reason setting the contents to null for the system clipboard causes a
		// NullPointerException, so just set it with an empty transferable.
		TreeTransferable dummyContents = new TreeTransferable(new ProgramNode[0]);
		systemClipboard.setContents(dummyContents, (clipboard, contents) -> {
			// a dummy implementation that will not prevent this plugin from being
			// reclaimed when it is disposed
		});
	}

	boolean isReplacingView() {
		return replacingView;
	}

	////////////////////////////////////////////////////////////////////////
	// ** private methods **
	////////////////////////////////////////////////////////////////////////

	/**
	 * Validate the selection for a case of the multi-selection
	 * for either the popup menu or the plugin action.
	 * @return true if the root node is not selected, or
	 * a node and all of its children are selected or only
	 * a parent node is selected; return false if this is not
	 * the case.
	 */
	private boolean validMultiSelection() {

		TreePath[] paths = tree.getSelectionPaths();
		if (paths == null) {
			return false;
		}
		TreePath rootPath = root.getTreePath();
		for (TreePath element : paths) {
			if (element.equals(rootPath)) {
				return false;
			}
		}

		for (TreePath path : paths) {

			ProgramNode node = (ProgramNode) path.getLastPathComponent();
			// if the node allows children, then verify that
			// either (1) only the parent is selected, or
			// (2) all children are selected
			if (node.getAllowsChildren() && !validPathSelection(node, paths)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Enable the view range actions according what is already in the
	 * the view.
	 */
	private void enableViewActions() {
		goToViewAction.setEnabled(true);
		removeViewAction.setEnabled(true);
	}

	/**
	 * For a multi-selection case, verifies that a selection
	 * from the node's level is valid.
	 * Returns true if (1) either the paths of all children of node
	 * are selected, or if (2) none of the paths of all children of node
	 * are selected.
	 * Returns false if not all of the children of node are selected
	 */
	private boolean validPathSelection(ProgramNode node, TreePath[] selectedPaths) {

		int nchild = node.getChildCount();
		int numberSelected = 0;

		for (int i = 0; i < nchild; i++) {
			ProgramNode child = (ProgramNode) node.getChildAt(i);
			TreePath childPath = child.getTreePath();

			// see if childPath is in selected list
			for (TreePath element : selectedPaths) {
				if (childPath.equals(element)) {
					++numberSelected;
					break;
				}
			}
		}
		if (numberSelected == 0 || numberSelected == nchild) {
			return true;
		}
		return false;
	}

	///////////////////////////////////////////////////////////////////
	// ** menu item callback methods for single selection popup
	///////////////////////////////////////////////////////////////////

	private void addToView() {

		TreePath path = tree.getSelectionPath();

		if (tree.getSelectionCount() > 1) {
			path = tree.getLeadSelectionPath();
		}

		TreePath[] paths = tree.getSelectionPaths();
		for (TreePath element : paths) {
			updateViewList(element);
		}

		ProgramNode node = (ProgramNode) path.getLastPathComponent();
		ProgramFragment f = node.getFragment();
		Address addr = null;
		if (f != null && !f.isEmpty()) {
			addr = f.getMinAddress();
		}
		else if (f == null) {
			ProgramModule module = node.getModule();
			addr = module.getFirstAddress();
		}

		//notify listeners of change
		tree.fireTreeViewChanged();
		if (addr != null) {
			tree.goTo(addr);
		}
	}

	/**
	 * Remove the selected path from the current view.
	 */
	private void removeFromView() {

		if (tree.getSelectionCount() == 1) {
			TreePath path = tree.getSelectionPath();
			if (viewList.contains(path)) {
				removePathFromView(path, true);
			}
			else {
				// remove all descendants from the view
				removeChildFromView((ProgramNode) path.getLastPathComponent());
				tree.fireTreeViewChanged();
			}
		}
		else {
			removeRangeFromView();
		}
	}

	/**
	 * Remove path from the view.
	 * @param path tree path
	 * @param fireEvent true means to fire the tree view changed
	 */
	private void removePathFromView(TreePath path, boolean fireEvent) {
		if (viewList.contains(path)) {
			tree.removeFromView(path);
			if (fireEvent) {
				tree.fireTreeViewChanged();
			}
		}
	}

	/**
	 * Recursively remove nodes from view.
	 */
	private void removeChildFromView(ProgramNode node) {
		for (int i = 0; i < node.getChildCount(); i++) {
			ProgramNode child = (ProgramNode) node.getChildAt(i);
			if (child.getAllowsChildren()) {
				removeChildFromView(child);
			}
			else {
				removePathFromView(child.getTreePath(), false);
			}
		}
	}

	/**
	 * Replace the current view with the selected paths.
	 */
	private void replaceView() {
		replacingView = true;
		try {
			tree.setViewPaths(tree.getSelectionPaths());
		}
		finally {
			replacingView = false;
		}
	}

	/**
	 * Put selected paths on the clipboard.
	 */
	private void cut() {
		// revert the "cut" if something is in the temporary clipboard
		checkClipboard(false);

		if (tree.getSelectionCount() == 1) {

			// cut to clipboard
			TreePath[] paths = new TreePath[] { tree.getSelectionPath() };
			setClipboardContents(GClipboard.getSystemClipboard(), paths);
			// put on the temporary clipboard
			setClipboardContents(tempClipboard, paths);
			setNodesDeleted(paths);
		}
		else {
			cutRange();
		}
	}

	/**
	 * Put selected paths on the clipboard; clear the temp clipboard
	 * if something was there.
	 */
	private void copy() {

		// revert the "cut" if something is in the temporary clipboard
		checkClipboard(false);

		if (tree.getSelectionCount() == 1) {
			// copy to clipboard
			setClipboardContents(GClipboard.getSystemClipboard(),
				new TreePath[] { tree.getSelectionPath() });
		}
		else {
			copyRange();
		}
	}

	/**
	 * Mark the nodes that correspond to the array of paths as
	 * being deleted.
	 */
	private void setNodesDeleted(TreePath[] paths) {

		for (TreePath element : paths) {
			ProgramNode node = (ProgramNode) element.getLastPathComponent();
			node.setDeleted(true);
			tree.reloadNode(node);
		}
	}

	/**
	 * Delete node(s) from the tree; called from the action listener
	 * on the menu.
	 */
	private void delete() {

		int transactionID = tree.startTransaction("Delete");
		if (transactionID < 0) {
			return;
		}
		boolean success = false;
		try {
			synchronized (root) {
				try {
					success = deleteRange();
				}
				catch (Exception e) {
					Msg.showError(this, null, null, null, e);
				}
			}
		}
		finally {
			tree.endTransaction(transactionID, success);
		}

	}

	/**
	 * Expand the first selected node; called from an action listener
	 * on a menu.
	 */
	private void expand() {
		TreePath path = tree.getLeadSelectionPath();
		tree.expandNode((ProgramNode) tree.getLastSelectedPathComponent());
		expandAction.setEnabled(!allPathsExpanded(path));
		collapseAction.setEnabled(!allPathsCollapsed(path));
	}

	/**
	 * Collapse the first selected node; called from an action listener
	 * on a menu.
	 */
	private void collapse() {
		TreePath path = tree.getLeadSelectionPath();
		collapseNode((ProgramNode) tree.getLastSelectedPathComponent());
		expandAction.setEnabled(!allPathsExpanded(path));
		collapseAction.setEnabled(!allPathsCollapsed(path));
	}

	/**
	 * Collapse all descendants starting at node.
	 */
	private void collapseNode(ProgramNode node) {

		int nchild = node.getChildCount();
		for (int i = 0; i < nchild; i++) {

			ProgramNode child = (ProgramNode) node.getChildAt(i);

			if (child.equals(node) || child.isLeaf()) {
				continue;
			}
			collapseNode(child);
		}
		tree.collapsePath(node.getTreePath());
	}

	/**
	 * Merge a module with its parent. The module is deleted if it has
	 * no other parents; called by the action listener on a menu.
	 */
	private void merge() {
		synchronized (root) {
			ArrayList<ProgramNode> list = tree.getSortedSelection();
			CompoundCmd compCmd = new CompoundCmd("Merge with Parent");
			String treeName = tree.getTreeName();
			for (ProgramNode node : list) {
				tree.removeSelectionPath(node.getTreePath());
				ProgramNode parentNode = (ProgramNode) node.getParent();
				if (node.isModule() && parentNode != null) {
					compCmd.add(new MergeFolderCmd(treeName, node.getName(), parentNode.getName()));
				}
			}
			if (!plugin.getTool().execute(compCmd, program)) {
				plugin.getTool().setStatusInfo(compCmd.getStatusMsg());
			}
		}
	}

	/**
	 * Create a new empty fragment; called from an action listener on
	 * a menu.
	 */
	private void createFragment(ProgramNode node) {
		synchronized (root) {

			String errMsg = null;

			// sync program so we don't get a deadlock --
			// an event gets generated because of the add module.
			synchronized (program) {
				String name = tree.getNewFragmentName();
				String treeName = tree.getTreeName();
				CreateFragmentCmd cmd = new CreateFragmentCmd(treeName, name, node.getName());
				if (tree.getTool().execute(cmd, program)) {
					ProgramFragment f = program.getListing().getFragment(treeName, name);
					initiateCellEditor(node, f);
				}
				else {
					errMsg = cmd.getStatusMsg();
				}
			}
			if (errMsg != null) {
				Msg.showError(this, tree, "Create Fragment Failed", errMsg);
			}
		}
	}

	/**
	 * Create a new empty module; called from an action listener on
	 * a menu.
	 */
	private void createFolder() {
		String errorMsg = null;

		synchronized (root) {
			// sync program so we don't get a deadlock --
			// an event gets generated because of the add module.
			synchronized (program) {
				ProgramNode node = (ProgramNode) tree.getLastSelectedPathComponent();

				// if the node has not been yet visited, then when the group is added via the
				// command below, the new child node in the parent will not be found
				node.visit();

				String name = tree.getNewFolderName();
				String treeName = tree.getTreeName();
				CreateFolderCommand cmd = new CreateFolderCommand(treeName, name, node.getName());
				if (tree.getTool().execute(cmd, program)) {
					ProgramModule m = program.getListing().getModule(treeName, name);
					initiateCellEditor(node, m);
				}
				else {
					errorMsg = cmd.getStatusMsg();
				}
			}
		}
		if (errorMsg != null) {
			Msg.showError(this, tree, "Create Folder Failed", errorMsg);
		}

	}

	/**
	 * Find the node corresponding to the given group. Start the cell
	 * editor for the child node.
	 */
	private void initiateCellEditor(ProgramNode parent, Group group) {
		if (!parent.wasVisited()) {
			tree.visitNode(parent);
		}
		int nchild = parent.getChildCount();
		for (int i = 0; i < nchild; i++) {
			ProgramNode child = (ProgramNode) parent.getChildAt(i);
			if (child.getGroup() == group) {
				tree.setEditable(true);
				tree.startEditingAtPath(child.getTreePath());
				break;
			}
		}
	}

	///////////////////////////////////////////////////////////////////////
	// *** callbacks for multi selection popup
	///////////////////////////////////////////////////////////////////////
	/**
	 * Cut a range of nodes and put them on the clipboard;
	 * called from an action listener on a menu.
	 */
	private void cutRange() {

		TreePath[] paths = tree.getSelectionPaths();

		if (paths.length == 0) {
			return;
		}
		// cut to clipboard
		setClipboardContents(GClipboard.getSystemClipboard(), paths);
		// put on the temporary clipboard
		setClipboardContents(tempClipboard, paths);
		setNodesDeleted(paths);
	}

	/**
	 * Copy a range of nodes and put them on the clipboard;
	 * called from an action listener on a menu.
	 */
	private void copyRange() {

		// generate a list of selected modules that are
		// "root"-type modules, i.e., not submodules within the selection.
		TreePath[] paths = tree.getSelectionPaths();

		if (paths.length == 0) {
			return;
		}
		// cut to clipboard
		setClipboardContents(GClipboard.getSystemClipboard(), paths);
	}

	/**
	 * Delete a range of Modules; called from an action listener on a menu.
	 * @return true if program was affected
	 */
	private boolean deleteRange() {

		TreePath[] paths = tree.getSelectionPaths();

		boolean changesMade = false;
		StringBuffer sb = new StringBuffer();

		for (TreePath element : paths) {
			ProgramNode node = (ProgramNode) element.getLastPathComponent();
			if (tree.removeGroup(node, sb)) {
				changesMade = true;
			}
		}

		if (sb.length() > 0) {
			sb.insert(0, "Failed to delete the following:\n");
			Msg.showWarn(getClass(), tree, "Delete Failed", sb.toString());
		}
		return changesMade;
	}

	private void removeRangeFromView() {
		TreePath[] selPaths = tree.getSelectionPaths();
		for (TreePath element : selPaths) {
			tree.removeFromView(element);
		}
		if (selPaths.length > 0) {
			tree.fireTreeViewChanged();
		}
	}

	/**
	 * Create a TreeTransferable object from the given paths, and
	 * use it set the clipboard contents.
	 */
	private void setClipboardContents(Clipboard clipboard, TreePath[] paths) {

		ProgramNode[] nodes = new ProgramNode[paths.length];
		for (int i = 0; i < nodes.length; i++) {
			nodes[i] = (ProgramNode) paths[i].getLastPathComponent();
		}

		TreeTransferable contents = new TreeTransferable(nodes);
		clipboard.setContents(contents, this);
	}

	/**
	 * Return true if this path has all of its sub-paths expanded.
	 */
	private boolean allPathsExpanded(TreePath path) {

		ProgramNode node = (ProgramNode) path.getLastPathComponent();
		if (node.isLeaf()) {
			return true;
		}
		if (tree.isCollapsed(path)) {
			return false;
		}

		boolean allLeaves = true;

		int nchild = node.getChildCount();
		for (int i = 0; i < nchild; i++) {
			ProgramNode child = (ProgramNode) node.getChildAt(i);
			if (child.isLeaf()) {
				continue;
			}
			allLeaves = false;
			if (!tree.isExpanded(child.getTreePath())) {
				return false;
			}

			if (!allPathsExpanded(child.getTreePath())) {
				return false;
			}
		}
		if (allLeaves) {
			return tree.isExpanded(node.getTreePath());
		}
		return true;
	}

	/**
	 * Return true if this path has all of its sub-paths collapsed.
	 */
	private boolean allPathsCollapsed(TreePath path) {
		ProgramNode node = (ProgramNode) path.getLastPathComponent();

		if (tree.isExpanded(path)) {
			return false;
		}
		boolean allLeaves = true; // variable for knowing whether
		// all children are leaves

		int nchild = node.getChildCount();
		for (int i = 0; i < nchild; i++) {
			ProgramNode child = (ProgramNode) node.getChildAt(i);
			if (child.isLeaf()) {
				continue;
			}
			allLeaves = false;
			if (!tree.isCollapsed(child.getTreePath())) {
				return false;
			}

			if (!allPathsCollapsed(child.getTreePath())) {
				return false;
			}
		}
		if (allLeaves) {
			return tree.isCollapsed(node.getTreePath());
		}
		return true;
	}

	/**
	 * Returns true if the paste operation is valid for
	 * the given node.
	 * If the node and node to paste have the same name, then return
	 * false.
	 */
	@SuppressWarnings("unchecked")
	// the cast is safe, since we checked the flavor
	private boolean isPasteOk(ProgramNode destNode) {

		boolean isCutOperation = false;
		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		if (!systemClipboard.isDataFlavorAvailable(TreeTransferable.localTreeNodeFlavor)) {
			return false;
		}

		try {
			// we will put items on the 'tempClipboard' when the cut action is executed
			Transferable temp = tempClipboard.getContents(this);
			isCutOperation = (temp != null);
		}
		catch (Exception e) {
			// bad stuff on the clipboard, so ignore it
			return false;
		}

		try {
			List<ProgramNode> list =
				(List<ProgramNode>) systemClipboard.getData(TreeTransferable.localTreeNodeFlavor);
			if (list == null) {
				// SCR 7990--something bad has happened to the copy buffer
				return false;
			}

			boolean pasteEnabled = false;
			for (ProgramNode pasteNode : list) {
				boolean pasteAllowed = pasteMgr.isPasteAllowed(destNode, pasteNode, isCutOperation);
				if (isCutOperation && !pasteAllowed) {
					// for cut operation all nodes must be able to be pasted at destNode
					return false;
				}
				else if (!isCutOperation && pasteAllowed) {
					// for copy operation at least one node must be able to be pasted at destNode
					return true;
				}
				pasteEnabled |= pasteAllowed;
			}
			return pasteEnabled;

		}
		catch (UnsupportedFlavorException e) {
			// data flavor is not supported
			throw new AssertException("Data flavor in clipboard is not supported.");
		}
		catch (IOException e) {
			// data is no longer available
			Msg.showError(this, null, "Cut from Clipboard Failed",
				"Data is no longer available for paste operation", e);
		}
		catch (Exception e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			Msg.showError(this, null, "Check Clipboard Failed", msg, e);
		}
		return false;
	}

	/**
	 * Update the view list if the the given path is the an ancestor of any of
	 * the paths currently in the view; remove the descendant and add the
	 * ancestor path.
	 *
	 * @param path
	 *            path the check against the view list
	 *
	 */
	private void updateViewList(TreePath path) {
		ProgramNode node = (ProgramNode) path.getLastPathComponent();
		if (!tree.hasAncestorsInView(node) && !viewList.contains(path)) {
			for (int i = 0; i < viewList.size(); i++) {
				TreePath viewPath = viewList.get(i);
				if (path.isDescendant(viewPath)) {
					tree.removeFromView(viewPath);
					--i;
				}
			}
			tree.addToView(path);
		}
	}

	private void selectionChanged() {
		// adjust actions according to what is selected
		int count = tree.getSelectionCount();
		disableActions();
		if (count == 1) {
			adjustSingleActions((ProgramNode) tree.getSelectionPath().getLastPathComponent());
		}
		else if (validMultiSelection()) {
			copyAction.setEnabled(true);
			cutAction.setEnabled(true);
			deleteAction.setEnabled(true);
			replaceViewAction.setEnabled(true);
			enableViewActions();
		}
		enableMergeAction();
	}

	private void setDeleteActionEnabled() {
		deleteAction.setEnabled(false);

		TreePath[] paths = tree.getSelectionPaths();
		for (TreePath element : paths) {
			ProgramNode node = (ProgramNode) element.getLastPathComponent();
			if (node.isFragment()) {
				ProgramFragment f = node.getFragment();

				if (f.isEmpty() || (!f.isEmpty() && node.getFragment().getNumParents() > 1)) {
					deleteAction.setEnabled(true);
					break;
				}
			}
			else {
				ProgramModule m = node.getModule();
				if (m.getNumChildren() == 0 || m.getNumParents() > 1) {
					deleteAction.setEnabled(true);
					break;
				}
			}
		}

	}

	private void enableMergeAction() {
		mergeAction.setEnabled(false);
		TreePath[] paths = tree.getSelectionPaths();
		if (paths == null) {
			return;
		}
		for (TreePath element : paths) {
			ProgramNode node = (ProgramNode) element.getLastPathComponent();
			if (node.isModule()) {
				mergeAction.setEnabled(true);
				return;
			}
		}
	}

	/**
	 * A listener for selection events on the ProgramDnDTree.
	 */
	private class SelectionListener implements TreeSelectionListener {

		/**
		 * Called whenever the value of the selection changes.
		 */
		@Override
		public void valueChanged(TreeSelectionEvent e) {
			if (program == null) {
				return;
			}

			selectionChanged();
		}

	}
}
