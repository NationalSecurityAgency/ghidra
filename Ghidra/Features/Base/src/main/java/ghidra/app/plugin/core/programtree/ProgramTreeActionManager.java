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
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.swing.KeyStroke;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import org.apache.commons.lang3.exception.ExceptionUtils;

import docking.ActionContext;
import docking.action.*;
import docking.dnd.GClipboard;
import generic.timer.ExpiringSwingTimer;
import ghidra.app.cmd.module.*;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotEmptyException;

/**
 * Class to manage actions and popup menus for the program tree.
 */
class ProgramTreeActionManager implements ClipboardOwner {

	private Clipboard tempClipboard; // temporary clipboard used for the "cut" operation
	private ProgramNode root;

	private Program program;

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
	private DockingAction setViewAction;
	private DockingAction addToViewAction;

	private DockingAction[] actions;

	private PasteManager pasteManager;
	private List<TreePath> viewList;
	private ProgramTreePlugin plugin;
	private boolean isSettingView;

	ProgramTreeActionManager(ProgramTreePlugin plugin) {
		this.plugin = plugin;
		this.tempClipboard = new Clipboard("ProgramTree");
		this.pasteManager = new PasteManager(this);
		createActions(plugin.getName());
	}

	void setProgramTreeView(String treeName, ProgramDnDTree tree) {
		if (tree != null) {
			DefaultTreeModel treeModel = (DefaultTreeModel) tree.getModel();
			root = (ProgramNode) treeModel.getRoot();

			// TODO should not need this
			viewList = tree.getViewList();
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
		clearCutClipboardNodes();
	}

	void setProgram(Program program) {
		this.program = program;
		tempClipboard.setContents(null, this);
		if (viewList != null) {
			viewList.clear();
		}
	}

	String getLastGroupPasted() {
		return pasteManager.getLastGroupPasted();
	}

	/**
	 * Get the action for the tree.
	 *
	 * @return PluginAction[]
	 */
	DockingAction[] getActions() {
		return actions;
	}

	private void createActions(String owner) {

		List<DockingAction> list = new ArrayList<>();

		goToViewAction = new ProgramTreeAction("Go To start of folder/fragment in View", owner,
			KeyStroke.getKeyStroke("ENTER")) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (context instanceof ProgramTreeActionContext ptac) {
					return ptac.hasSingleNodeSelection() || ptac.hasFullNodeMultiSelection();
				}
				return false;
			}

			@Override
			public void actionPerformed(ActionContext context) {
				goToView((ProgramTreeActionContext) context);
			}
		};

		goToViewAction.setPopupMenuData(new MenuData(new String[] { "Go To in View" }, "aview"));

		list.add(goToViewAction);

		removeViewAction = new ProgramTreeAction("Remove folder/fragment from View", owner,
			KeyStroke.getKeyStroke("R")) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {

				if (!(context instanceof ProgramTreeActionContext ptac)) {
					return false;
				}

				if (ptac.hasSingleNodeSelection() || ptac.hasFullNodeMultiSelection()) {

					TreePath[] paths = ptac.getSelectionPaths();
					for (TreePath path : paths) {
						ProgramNode node = (ProgramNode) path.getLastPathComponent();
						if (node.isInView()) {
							return true;
						}
					}
				}
				return false;
			}

			@Override
			public void actionPerformed(ActionContext context) {
				removeFromView((ProgramTreeActionContext) context);
			}
		};

		removeViewAction
				.setPopupMenuData(new MenuData(new String[] { "Remove from View" }, "aview"));

		list.add(removeViewAction);

		setViewAction = new ProgramTreeAction("Set View", owner, KeyStroke.getKeyStroke("S")) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (context instanceof ProgramTreeActionContext ptac) {
					return ptac.hasSingleNodeSelection() || ptac.hasFullNodeMultiSelection();
				}
				return false;
			}

			@Override
			public void actionPerformed(ActionContext context) {
				setView((ProgramTreeActionContext) context);
			}
		};

		setViewAction.setPopupMenuData(new MenuData(new String[] { "Set View" }, "aview"));

		list.add(setViewAction);

		addToViewAction = new ProgramTreeAction("Add to View", owner, KeyStroke.getKeyStroke("A")) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (context instanceof ProgramTreeActionContext ptac) {
					return ptac.hasSingleNodeSelection() || ptac.hasFullNodeMultiSelection();
				}
				return false;
			}

			@Override
			public void actionPerformed(ActionContext context) {
				addToView((ProgramTreeActionContext) context);
			}
		};

		addToViewAction.setPopupMenuData(new MenuData(new String[] { "Add to View" }, "aview"));

		list.add(addToViewAction);

		cutAction = new ProgramTreeAction("Cut folder/fragment", owner, null) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof ProgramTreeActionContext ptac)) {
					return false;
				}

				if (ptac.hasFullNodeMultiSelection()) {
					return true;
				}

				if (ptac.hasSingleNodeSelection()) {
					return !ptac.isOnlyRootNodeSelected();
				}

				return false;
			}

			@Override
			public void actionPerformed(ActionContext context) {
				cut((ProgramTreeActionContext) context);
			}
		};

		cutAction.setPopupMenuData(new MenuData(new String[] { "Cut" }, "edit"));

		list.add(cutAction);

		copyAction = new ProgramTreeAction("Copy folder/fragment", owner, null) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof ProgramTreeActionContext ptac)) {
					return false;
				}

				if (ptac.hasFullNodeMultiSelection()) {
					return true;
				}

				if (ptac.hasSingleNodeSelection()) {
					return !ptac.isOnlyRootNodeSelected();
				}

				return false;
			}

			@Override
			public void actionPerformed(ActionContext context) {
				copy((ProgramTreeActionContext) context);
			}
		};

		copyAction.setPopupMenuData(new MenuData(new String[] { "Copy" }, "edit"));

		list.add(copyAction);

		pasteAction = new ProgramTreeAction("Paste folder/fragment", owner, null,
			ProgramTreeAction.SINGLE_SELECTION) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof ProgramTreeActionContext ptac)) {
					return false;
				}

				ProgramNode node = ptac.getSingleSelectedNode();
				return node != null && isPasteOk(node);
			}

			@Override
			public void actionPerformed(ActionContext context) {
				ProgramTreeActionContext ptac = (ProgramTreeActionContext) context;
				ProgramNode node = ptac.getSingleSelectedNode();
				ProgramDnDTree tree = ptac.getTree();
				pasteManager.paste(tree, node);
			}
		};

		pasteAction.setPopupMenuData(new MenuData(new String[] { "Paste" }, "edit"));

		list.add(pasteAction);

		createFolderAction = new ProgramTreeAction("Create Folder", owner, null,
			ProgramTreeAction.SINGLE_SELECTION) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof ProgramTreeActionContext ptac)) {
					return false;
				}

				if (!ptac.hasSingleNodeSelection()) {
					return false;
				}

				if (ptac.isOnlyRootNodeSelected()) {
					return true;
				}

				ProgramNode node = ptac.getSingleSelectedNode();
				return !node.isFragment();
			}

			@Override
			public void actionPerformed(ActionContext context) {
				createFolder((ProgramTreeActionContext) context);
			}

		};

		createFolderAction
				.setPopupMenuData(new MenuData(new String[] { "Create Folder" }, "createGroup"));

		list.add(createFolderAction);

		createFragmentAction = new ProgramTreeAction("Create Fragment", owner, null,
			ProgramTreeAction.SINGLE_SELECTION) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof ProgramTreeActionContext ptac)) {
					return false;
				}

				if (!ptac.hasSingleNodeSelection()) {
					return false;
				}

				if (ptac.isOnlyRootNodeSelected()) {
					return true;
				}

				ProgramNode node = ptac.getSingleSelectedNode();
				return !node.isFragment();
			}

			@Override
			public void actionPerformed(ActionContext context) {
				createFragment((ProgramTreeActionContext) context);
			}
		};

		createFragmentAction
				.setPopupMenuData(new MenuData(new String[] { "Create Fragment" }, "createGroup"));

		list.add(createFragmentAction);

		mergeAction = new ProgramTreeAction("Merge folder/fragment with Parent", owner, null,
			ProgramTreeAction.SINGLE_SELECTION) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof ProgramTreeActionContext ptac)) {
					return false;
				}

				if (ptac.hasSingleNodeSelection()) {
					ProgramNode node = ptac.getSingleSelectedNode();
					if (ptac.isOnlyRootNodeSelected() || node.isFragment()) {
						return false;
					}
				}

				return isMergeEnabled(ptac);
			}

			@Override
			public void actionPerformed(ActionContext context) {
				merge((ProgramTreeActionContext) context);
			}
		};

		mergeAction.setPopupMenuData(new MenuData(new String[] { "Merge with Parent" }, "merge"));

		list.add(mergeAction);

		deleteAction = new ProgramTreeAction("Delete folder/fragment", owner, null) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof ProgramTreeActionContext ptac)) {
					return false;
				}
				return isDeleteEnabled(ptac);
			}

			@Override
			public void actionPerformed(ActionContext context) {
				delete((ProgramTreeActionContext) context);
			}
		};

		deleteAction.setPopupMenuData(new MenuData(new String[] { "Delete" }, "delete"));
		deleteAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));

		list.add(deleteAction);

		renameAction = new ProgramTreeAction("Rename folder/fragment", owner, null,
			ProgramTreeAction.SINGLE_SELECTION) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (context instanceof ProgramTreeActionContext ptac) {
					return ptac.hasSingleNodeSelection();
				}
				return false;
			}

			@Override
			public void actionPerformed(ActionContext context) {
				ProgramDnDTree tree = ((ProgramTreeActionContext) context).getTree();
				tree.rename();
			}
		};

		renameAction.setPopupMenuData(new MenuData(new String[] { "Rename" }, "delete"));

		list.add(renameAction);

		expandAction = new ProgramTreeAction("Expand All folders/fragments", owner, null,
			ProgramTreeAction.SINGLE_SELECTION) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof ProgramTreeActionContext ptac)) {
					return false;
				}

				if (!ptac.hasSingleNodeSelection()) {
					return false;
				}

				if (ptac.isOnlyRootNodeSelected()) {
					return !allPathsExpanded(ptac);
				}

				ProgramNode node = ptac.getSingleSelectedNode();
				if (node.isFragment()) {
					return false;
				}

				return !allPathsExpanded(ptac);
			}

			@Override
			public void actionPerformed(ActionContext context) {
				expand((ProgramTreeActionContext) context);
			}
		};

		expandAction.setPopupMenuData(new MenuData(new String[] { "Expand All" }, "expand"));

		list.add(expandAction);

		collapseAction = new ProgramTreeAction("Collapse All folders/fragments", owner, null,
			ProgramTreeAction.SINGLE_SELECTION) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof ProgramTreeActionContext ptac)) {
					return false;
				}

				if (!ptac.hasSingleNodeSelection()) {
					return false;
				}

				if (ptac.isOnlyRootNodeSelected()) {
					return !allPathsCollapsed(ptac);
				}

				ProgramNode node = ptac.getSingleSelectedNode();
				if (node.isFragment()) {
					return false;
				}

				return !allPathsCollapsed(ptac);
			}

			@Override
			public void actionPerformed(ActionContext context) {
				collapse((ProgramTreeActionContext) context);
			}
		};

		collapseAction.setPopupMenuData(new MenuData(new String[] { "Collapse All" }, "expand"));

		list.add(collapseAction);

		actions = new DockingAction[list.size()];
		actions = list.toArray(actions);
	}

	/**
	 * Remove node from the list of ProgramNodes in the clipboard. This method is called
	 * if there was a problem pasting a group.
	 * @param tree the tree
	 * @param node the node
	 */
	void removeFromClipboard(ProgramDnDTree tree, ProgramNode node) {

		try {
			List<ProgramNode> list = getProgramNodeListFromClipboard();

			int listSize = 0;
			if (list != null) {
				listSize = list.size();
				list.remove(node);
			}

			clearCut(node);

			if (listSize == 0) {
				tempClipboard.setContents(null, this);
			}
		}
		catch (UnsupportedFlavorException e) {
			// data flavor is not supported
			Msg.showError(this, null, "Cut from Clipboard " + tempClipboard.getName() + " Failed",
				"Data flavor in clipboard is not supported.", e);
		}
		catch (IOException e) {
			// data is no longer available
			Msg.showError(this, null, "Cut from Clipboard " + tempClipboard.getName() + " Failed",
				"Data is no longer available for paste operation", e);
		}
		catch (Exception e) {
			String message = ExceptionUtils.getMessage(e);
			Msg.showError(this, null, "Cut from Clipboard " + tempClipboard.getName() + " Failed",
				message, e);
		}
	}

	void clearCut(ProgramNode node) {
		node.setDeleted(false);
		plugin.repaintProvider();
	}

	boolean clipboardContains(ProgramNode node) {
		try {
			List<ProgramNode> list = getProgramNodeListFromClipboard();
			if (list == null) {
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
			Msg.error(this, "Unexpected exception checking clipboard", e);
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	// the cast is generating the warning, but we verified the type is correct
	private List<ProgramNode> getProgramNodeListFromClipboard()
			throws UnsupportedFlavorException, IOException {
		List<ProgramNode> nodeList = Collections.emptyList();
		Transferable t = tempClipboard.getContents(this);
		if (t == null) {
			return nodeList;
		}
		if (!t.isDataFlavorSupported(ProgramTreeTransferable.localTreeNodeFlavor)) {
			return nodeList;
		}
		List<ProgramNode> list =
			(List<ProgramNode>) t.getTransferData(ProgramTreeTransferable.localTreeNodeFlavor);
		return list;
	}

	void cutClipboardNodes(ProgramDnDTree tree) {
		// cut the contents of the clipboard from the program, as a paste was not done
		List<ProgramNode> list = getNodesFromClipboard();
		for (ProgramNode node : list) {
			if (tree.getModel().getRoot() != node.getRoot()) {
				break;
			}

			ProgramModule parentModule = node.getParentModule();
			Group group = node.getGroup();
			try {
				parentModule.removeChild(group.getName());
			}
			catch (NotEmptyException e) {
				clearCut(node);
			}
			catch (ConcurrentModificationException e) {
				// ha!
			}
		}

		clearSystemClipboard();
		tempClipboard.setContents(null, this);
	}

	void clearCutClipboardNodes() {

		// cut the contents of the clipboard from the program, as a paste was not done
		List<ProgramNode> list = getNodesFromClipboard();
		for (ProgramNode node : list) {
			node.setDeleted(false);
		}

		plugin.repaintProvider();
		tempClipboard.setContents(null, this);
	}

	private List<ProgramNode> getNodesFromClipboard() {
		try {
			List<ProgramNode> list = getProgramNodeListFromClipboard();
			if (list != null) {
				return list;
			}
		}
		catch (UnsupportedFlavorException e) {
			throw new AssertException("Data flavor in clipboard is not supported.");
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected exception checking clipboard", e);
		}
		return List.of();
	}

	/**
	 * Clear the system clipboard if there is tree transferable data on it.
	 */

	void clearSystemClipboard() {
		try {
			Clipboard systemClipboard = GClipboard.getSystemClipboard();
			if (!systemClipboard
					.isDataFlavorAvailable(ProgramTreeTransferable.localTreeNodeFlavor)) {
				return;
			}

			Object data = systemClipboard.getData(ProgramTreeTransferable.localTreeNodeFlavor);
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
		ProgramTreeTransferable dummyContents = new ProgramTreeTransferable(new ProgramNode[0]);
		systemClipboard.setContents(dummyContents, (clipboard, contents) -> {
			// a dummy implementation that will not prevent this plugin from being
			// reclaimed when it is disposed
		});
	}

	boolean isReplacingView() {
		return isSettingView;
	}

	private void addToView(ProgramTreeActionContext context) {
		ProgramDnDTree tree = context.getTree();
		TreePath[] paths = context.getSelectionPaths();
		for (TreePath path : paths) {
			updateViewList(tree, path);
		}
		tree.fireTreeViewChanged();
	}

	private void goToView(ProgramTreeActionContext context) {

		// the selected node must be represented in the view for the 'go to' to work 
		addToView(context);

		ProgramNode node = context.getLeadSelectedNode();
		ProgramFragment f = node.getFragment();
		Address addr = null;
		if (f != null && !f.isEmpty()) {
			addr = f.getMinAddress();
		}
		else if (f == null) {
			ProgramModule module = node.getModule();
			addr = module.getFirstAddress();
		}

		if (addr != null) {
			ProgramDnDTree tree = context.getTree();
			tree.goTo(addr);
		}
	}

	private void removeFromView(ProgramTreeActionContext context) {

		ProgramDnDTree tree = context.getTree();
		TreePath[] paths = context.getSelectionPaths();
		if (paths.length == 1) {
			TreePath path = paths[0];
			if (viewList.contains(path)) {
				tree.removeFromView(path);
			}
			else {
				// remove all descendants from the view				
				ProgramNode node = (ProgramNode) path.getLastPathComponent();
				removeChildFromView(tree, node);
			}
		}
		else {
			for (TreePath path : paths) {
				tree.removeFromView(path);
			}
		}

		tree.fireTreeViewChanged();
	}

	/**
	 * Recursively remove nodes from view.
	 */
	private void removeChildFromView(ProgramDnDTree tree, ProgramNode node) {
		for (int i = 0; i < node.getChildCount(); i++) {
			ProgramNode child = (ProgramNode) node.getChildAt(i);
			if (child.getAllowsChildren()) {
				removeChildFromView(tree, child);
			}
			else {
				TreePath path = child.getTreePath();
				if (viewList.contains(path)) {
					tree.removeFromView(path);
				}
			}
		}
	}

	private void setView(ProgramTreeActionContext context) {
		isSettingView = true;
		try {
			ProgramDnDTree tree = context.getTree();
			tree.setViewPaths(context.getSelectionPaths());
		}
		finally {
			isSettingView = false;
		}
	}

	private void cut(ProgramTreeActionContext context) {
		// revert the "cut" if something is in the temporary clipboard
		clearCutClipboardNodes();

		TreePath[] paths = context.getSelectionPaths();
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
	 * Put selected paths on the clipboard; clear the temp clipboard
	 * if something was there.
	 */
	private void copy(ProgramTreeActionContext context) {

		// revert the "cut" if something is in the temporary clipboard
		clearCutClipboardNodes();

		TreePath[] paths = context.getSelectionPaths();
		if (paths.length == 0) {
			return;
		}

		// copy to clipboard
		setClipboardContents(GClipboard.getSystemClipboard(), paths);
	}

	/**
	 * Mark the nodes that correspond to the array of paths as
	 * being deleted.
	 */
	private void setNodesDeleted(TreePath[] paths) {

		for (TreePath element : paths) {
			ProgramNode node = (ProgramNode) element.getLastPathComponent();
			node.setDeleted(true);
		}

		plugin.repaintProvider();
	}

	/**
	 * Delete node(s) from the tree; called from the action listener
	 * on the menu.
	 */
	private void delete(ProgramTreeActionContext context) {

		ProgramDnDTree tree = context.getTree();
		int transactionID = tree.startTransaction("Delete");
		if (transactionID < 0) {
			return;
		}
		boolean success = false;
		try {
			synchronized (root) {
				TreePath[] paths = context.getSelectionPaths();
				success = delete(tree, paths);
			}
		}
		finally {
			tree.endTransaction(transactionID, success);
		}
	}

	private boolean delete(ProgramDnDTree tree, TreePath[] paths) {

		boolean changesMade = false;
		StringBuilder sb = new StringBuilder();

		for (TreePath element : paths) {
			ProgramNode node = (ProgramNode) element.getLastPathComponent();
			if (tree.removeGroup(node, sb)) {
				changesMade = true;
			}
		}

		if (sb.length() > 0) {
			sb.insert(0, "Failed to delete the following:\n");
			Msg.showWarn(getClass(), null, "Delete Failed", sb.toString());
		}
		return changesMade;
	}

	void expand(ProgramTreeActionContext context) {
		ProgramDnDTree tree = context.getTree();
		tree.expandNode(context.getSingleSelectedNode());
		plugin.contextChanged();
	}

	private void collapse(ProgramTreeActionContext context) {
		ProgramDnDTree tree = context.getTree();
		collapseNode(tree, context.getSingleSelectedNode());
		plugin.contextChanged();
	}

	private void collapseNode(ProgramDnDTree tree, ProgramNode node) {

		int nchild = node.getChildCount();
		for (int i = 0; i < nchild; i++) {

			ProgramNode child = (ProgramNode) node.getChildAt(i);

			if (child.equals(node) || child.isLeaf()) {
				continue;
			}
			collapseNode(tree, child);
		}
		tree.collapsePath(node.getTreePath());
	}

	/**
	 * Merge a module with its parent. The module is deleted if it has
	 * no other parents; called by the action listener on a menu.
	 */
	private void merge(ProgramTreeActionContext context) {
		synchronized (root) {

			CompoundCmd<Program> cmd = new CompoundCmd<>("Merge with Parent");
			ProgramDnDTree tree = context.getTree();
			String treeName = tree.getTreeName();
			TreePath[] paths = context.getSelectionPaths();
			for (TreePath path : paths) {

				ProgramNode node = (ProgramNode) path.getLastPathComponent();
				tree.removeSelectionPath(path);
				ProgramNode parentNode = (ProgramNode) node.getParent();
				if (node.isModule() && parentNode != null) {
					cmd.add(new MergeFolderCmd(treeName, node.getName(), parentNode.getName()));
				}
			}

			PluginTool tool = plugin.getTool();
			if (!tool.execute(cmd, program)) {
				tool.setStatusInfo(cmd.getStatusMsg());
			}
		}
	}

	private void createFragment(ProgramTreeActionContext context) {
		synchronized (root) {

			String errMsg = null;

			// sync program so we don't get a deadlock --
			// an event gets generated because of the add module.
			synchronized (program) {
				ProgramDnDTree tree = context.getTree();
				String name = tree.getNewFragmentName();
				String treeName = tree.getTreeName();
				ProgramNode node = context.getSingleSelectedNode();
				CreateFragmentCmd cmd = new CreateFragmentCmd(treeName, name, node.getName());
				if (tree.getTool().execute(cmd, program)) {
					ProgramFragment f = program.getListing().getFragment(treeName, name);
					initiateCellEditor(tree, node, f);
				}
				else {
					errMsg = cmd.getStatusMsg();
				}
			}
			if (errMsg != null) {
				Msg.showError(this, null, "Create Fragment Failed", errMsg);
			}
		}
	}

	private void createFolder(ProgramTreeActionContext context) {
		String errorMessage = null;
		synchronized (root) {
			// sync program so we don't get a deadlock --
			// an event gets generated because of the add module.
			synchronized (program) {
				ProgramNode node = context.getSingleSelectedNode();

				// if the node has not been yet visited, then when the group is added via the
				// command below, the new child node in the parent will not be found
				node.visit();

				ProgramDnDTree tree = context.getTree();
				String name = tree.getNewFolderName();
				String treeName = tree.getTreeName();
				CreateFolderCommand cmd = new CreateFolderCommand(treeName, name, node.getName());
				if (tree.getTool().execute(cmd, program)) {
					ProgramModule m = program.getListing().getModule(treeName, name);
					initiateCellEditor(tree, node, m);
				}
				else {
					errorMessage = cmd.getStatusMsg();
				}
			}
		}
		if (errorMessage != null) {
			Msg.showError(this, null, "Create Folder Failed", errorMessage);
		}

	}

	private void getModelNode(ProgramNode parent, Group group, Consumer<ProgramNode> consumer) {

		int expireMs = 3000;
		Supplier<ProgramNode> supplier = () -> {
			int nchild = parent.getChildCount();
			for (int i = 0; i < nchild; i++) {
				ProgramNode child = (ProgramNode) parent.getChildAt(i);
				if (child.getGroup() == group) {
					return child;
				}
			}
			return null;
		};
		ExpiringSwingTimer.get(supplier, expireMs, consumer);
	}

	private void initiateCellEditor(ProgramDnDTree tree, ProgramNode parent, Group group) {
		if (!parent.wasVisited()) {
			tree.visitNode(parent);
		}

		getModelNode(parent, group, c -> {
			tree.setEditable(true);
			tree.startEditingAtPath(c.getTreePath());
		});
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

		ProgramTreeTransferable contents = new ProgramTreeTransferable(nodes);
		clipboard.setContents(contents, this);
	}

	private boolean allPathsExpanded(ProgramTreeActionContext context) {

		if (!context.hasSingleNodeSelection()) {
			return false;
		}

		ProgramDnDTree tree = context.getTree();
		TreePath[] paths = context.getSelectionPaths();
		TreePath path = paths[0];
		return allPathsExpanded(tree, path);
	}

	private boolean allPathsExpanded(ProgramDnDTree tree, TreePath path) {

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

			if (!allPathsExpanded(tree, child.getTreePath())) {
				return false;
			}
		}
		if (allLeaves) {
			return tree.isExpanded(node.getTreePath());
		}
		return true;
	}

	private boolean allPathsCollapsed(ProgramTreeActionContext context) {

		if (!context.hasSingleNodeSelection()) {
			return false;
		}

		ProgramDnDTree tree = context.getTree();
		TreePath[] paths = context.getSelectionPaths();
		TreePath path = paths[0];
		return allPathsCollapsed(tree, path);
	}

	private boolean allPathsCollapsed(ProgramDnDTree tree, TreePath path) {
		ProgramNode node = (ProgramNode) path.getLastPathComponent();

		if (tree.isExpanded(path)) {
			return false;
		}

		boolean allLeaves = true; // variable for knowing whether all children are leaves
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

			if (!allPathsCollapsed(tree, child.getTreePath())) {
				return false;
			}
		}
		if (allLeaves) {
			return tree.isCollapsed(node.getTreePath());
		}
		return true;
	}

	@SuppressWarnings("unchecked")
	// the cast is safe, since we checked the flavor
	private boolean isPasteOk(ProgramNode destNode) {

		boolean isCutOperation = false;
		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		if (!systemClipboard.isDataFlavorAvailable(ProgramTreeTransferable.localTreeNodeFlavor)) {
			return false;
		}

		// we will put items on the 'tempClipboard' when the cut action is executed
		Transferable temp = tempClipboard.getContents(this);
		isCutOperation = (temp != null);

		try {
			List<ProgramNode> list = (List<ProgramNode>) systemClipboard
					.getData(ProgramTreeTransferable.localTreeNodeFlavor);
			if (list == null) {
				return false;
			}

			boolean pasteEnabled = false;
			for (ProgramNode pasteNode : list) {
				boolean pasteAllowed =
					pasteManager.isPasteAllowed(destNode, pasteNode, isCutOperation);
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
			String message = ExceptionUtils.getMessage(e);
			Msg.showError(this, null, "Check Clipboard Failed", message, e);
		}
		return false;
	}

	/**
	 * Update the view list if the given path is an ancestor of any of the paths currently 
	 * in the view; remove the descendant and add the ancestor path. 
	 * @param tree the tree
	 * @param path path the check against the view list
	 */
	private void updateViewList(ProgramDnDTree tree, TreePath path) {
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

	private boolean isDeleteEnabled(ProgramTreeActionContext context) {

		TreePath[] paths = context.getSelectionPaths();
		if (paths == null) {
			return false;
		}

		for (TreePath element : paths) {
			ProgramNode node = (ProgramNode) element.getLastPathComponent();
			if (node.isFragment()) {
				ProgramFragment f = node.getFragment();

				if (f.isEmpty() || (!f.isEmpty() && node.getFragment().getNumParents() > 1)) {
					return true;
				}
			}
			else {
				ProgramModule m = node.getModule();
				if (m.getNumChildren() == 0 || m.getNumParents() > 1) {
					return true;
				}
			}
		}

		return false;
	}

	private boolean isMergeEnabled(ProgramTreeActionContext context) {
		TreePath[] paths = context.getSelectionPaths();
		if (paths == null) {
			return false;
		}

		for (TreePath element : paths) {
			ProgramNode node = (ProgramNode) element.getLastPathComponent();
			if (node.isModule()) {
				return true;
			}
		}
		return false;
	}
}
