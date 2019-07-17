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

import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.dnd.*;
import java.awt.event.*;
import java.io.IOException;
import java.util.*;
import java.util.List;

import javax.swing.KeyStroke;
import javax.swing.event.ChangeEvent;
import javax.swing.tree.*;

import docking.DockingUtils;
import docking.action.DockingAction;
import docking.actions.KeyBindingUtils;
import docking.dnd.DropTgtAdapter;
import docking.widgets.JTreeMouseListenerDelegate;
import ghidra.app.util.SelectionTransferData;
import ghidra.app.util.SelectionTransferable;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.GroupPath;
import ghidra.util.Msg;
import ghidra.util.datastruct.StringKeyIndexer;
import ghidra.util.exception.*;

/**
 * Class that presents a Program in a tree structure; ProgramDnDTree
 * provides Drag and Drop capability, and menu options and actions
 * to support cut, copy, paste, and rename operations.
 */
public class ProgramDnDTree extends DragNDropTree {

	private Program program;
	private Listing listing;

	private ArrayList<ProgramNode> nodeList; // list of nodes from preorder enumeration
	private ArrayList<TreePath> viewList; // list of tree paths that are being viewed.

	//keeps track of module/fragment names to come up with a default name, e.g., New Folder (2)
	private StringKeyIndexer nameIndexer;

	private ProgramTreeActionManager actionManager;
	private DnDMoveManager dragDropManager; // knows what to do with the drop operation
	private TreeListener treeListener;
	private JTreeMouseListenerDelegate mouseListenerDelegate;

	private Plugin plugin;
	private String treeName;
	private NodeComparator nodeComparator;
	private final static GroupPath[] EMPTY_GROUP_SELECTION = new GroupPath[0];
	private Object versionTag;

	/**
	 * Construct a ProgramDnDTree with the given model.
	 */
	public ProgramDnDTree(String treeName, DefaultTreeModel model, ProgramTreePlugin plugin) {
		super(model);
		this.treeName = treeName;
		this.plugin = plugin;
		actionManager = plugin.getActionManager();
		initialize();
		createRootNode(null);
		nodeComparator = new NodeComparator();

		mouseListenerDelegate = new JTreeMouseListenerDelegate(this);
		initializeKeyEvents();
	}

	private void initializeKeyEvents() {

		// remove Java's default bindings for Copy/Paste on this tree, as they cause conflicts
		// with Ghidra's key bindings
		KeyBindingUtils.clearKeyBinding(this,
			KeyStroke.getKeyStroke(KeyEvent.VK_C, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		KeyBindingUtils.clearKeyBinding(this,
			KeyStroke.getKeyStroke(KeyEvent.VK_V, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		KeyBindingUtils.clearKeyBinding(this,
			KeyStroke.getKeyStroke(KeyEvent.VK_X, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
	}

	@Override
	public synchronized void addMouseListener(MouseListener l) {
		if (mouseListenerDelegate == null) {
			super.addMouseListener(l);
			return; // handled later after initialization
		}

		mouseListenerDelegate.addMouseListener(l);
	}

	@Override
	public synchronized void removeMouseListener(MouseListener l) {
		if (mouseListenerDelegate == null) {
			super.removeMouseListener(l);
			return; // handled later after initialization
		}

		mouseListenerDelegate.removeMouseListener(l);
	}

	@Override
	public synchronized MouseListener[] getMouseListeners() {
		if (mouseListenerDelegate == null) {
			return super.getMouseListeners(); // handled later after initialization
		}
		return mouseListenerDelegate.getMouseListeners();
	}

	/**
	 * Fire tree expansion event; if node has not been visited,
	 * then populate the node with its children.
	 */
	@Override
	public void fireTreeExpanded(TreePath path) {
		ProgramNode node = (ProgramNode) path.getLastPathComponent();

		if (!node.wasVisited()) {
			visitNode(node);

			buildNodeList();
		}
		super.fireTreeExpanded(path);
	}

	/**
	 * Droppable interface method called to know when the drop site is
	 * valid.
	 */
	@Override
	public boolean isDropOk(DropTargetDragEvent e) {
		synchronized (root) {
			if (!super.isDropOk(e)) {
				return false;
			}
			if (draggedNodes == null) {
				return true; // drag initiated from somewhere else, so
				// if the superclass said it was OK, then it's OK...
			}
			Point p = e.getLocation();
			ProgramNode destNode = getTreeNode(p);
			relativeMousePos = comparePointerLocation(p, destNode);
			return dragDropManager.isDropSiteOk(destNode, draggedNodes, e.getDropAction(),
				relativeMousePos);
		}
	}

	/**
	 * Droppable interface method called from the DropTargetAdapter's
	 * drop() method.
	 */
	@Override
	public void add(Object data, DropTargetDropEvent e, DataFlavor chosen) {

		synchronized (root) {
			if (destinationNode == null) {
				return;
			}
			try {
				int dropAction = DnDConstants.ACTION_COPY;
				if (e != null) {
					dropAction = e.getDropAction();
				}
				// note: must use destinationNode because the when the user
				// releases the mouse, the point could have moved, so
				// the node obtained at the point is not necessarily the
				// expected destinationNode.
				processDropRequest(destinationNode, data, chosen, dropAction);
				if (dropAction == DnDConstants.ACTION_COPY) {
					draggedNodes = null;
				}
			}
			catch (Exception ex) {
				if (!(ex instanceof UsrException)) {
					Msg.error(this, "Unexpected Exception: " + ex.getMessage(), ex);
				}
				draggedNodes = null;

				//let the drop() method handle the error reporting
				String msg = ex.getMessage();
				if (msg == null) {
					msg = ex.toString();
				}
				if (ex instanceof UsrException) {
					Msg.showError(this, this, "Error in Drop Operation", msg);
				}
				else {
					Msg.showError(this, this, "Error in Drop Operation", msg, ex);
				}
			}
		}
	}

	/**
	 * Method called from the dragDropEnd() method in the
	 * DragSourceAdapter when the drop has completed.
	 * The "copy" part is done in the add() method.
	 * @see #add(Object, DropTargetDropEvent, DataFlavor)
	 */
	@Override
	public void move() {
		draggedNodes = null;
	}

	/**
	 * Set the program for this tree.
	 */
	void setProgram(Program p) {
		if (p == program) {
			return;
		}

		program = p;

		// get rid of old objects
		disposeOfNodes();
		root.removeAllChildren();
		nodeList.clear();
		listing = null;
		if (transferable != null) {
			transferable.clearTransferData();
		}

		if (program != null) {
			listing = program.getListing();

			ProgramModule rm = listing.getRootModule(treeName);
			if (rm != null) {
				ProgramModule oldRootModule = root.getModule();
				if (oldRootModule == null || !oldRootModule.equals(rm)) {

					createRootNode(program);
				}
				// get first level of children
				layoutProgram();
			}
			else {
				createRootNode(null);
			}
		}
		else {
			createRootNode(null);
		}
	}

	/**
	 * Get the program.
	 */
	public Program getProgram() {
		return program;
	}

	///////////////////////////////////////////////////////////////

	/**
	 * Get the data flavors that this tree supports.
	 */
	@Override
	protected DataFlavor[] getAcceptableDataFlavors() {
		return getDataFlavors();
	}

	static DataFlavor[] getDataFlavors() {
		return new DataFlavor[] { TreeTransferable.localTreeNodeFlavor,
			GroupTransferable.localGroupFlavor, // a test data flavor
			DataFlavor.stringFlavor, // a test data flavor
			SelectionTransferable.localProgramSelectionFlavor };
	}

	/**
	 * Return true if the node can accept the given data flavor
	 * and allow the dropAction; called by the base class when
	 * a drag operation is in progress, and the drag did not
	 * initiate on this tree.
	 * @param node drop site
	 * @param e event that has current state of drag and drop operation 
	 * @see DragNDropTree#isDropOk
	 */
	@Override
	protected boolean isDropSiteOk(ProgramNode node, DropTargetDragEvent e) {
		int dropAction = e.getDropAction();
		DataFlavor chosen = DropTgtAdapter.getFirstMatchingFlavor(e, acceptableFlavors);
		if (chosen.equals(GroupTransferable.localGroupFlavor)) {

			// don't allow drop if node is a fragment and the
			// action is not a move
			if (node.isFragment() && dropAction != DnDConstants.ACTION_MOVE) {
				return false;
			}
		}
		else if (chosen.equals(SelectionTransferable.localProgramSelectionFlavor)) {
			if ((node.isFragment() && dropAction != DnDConstants.ACTION_MOVE) ||
				(node.isModule() && dropAction != DnDConstants.ACTION_MOVE)) {
				return false;
			}
			try {
				Object data = e.getTransferable().getTransferData(
					SelectionTransferable.localProgramSelectionFlavor);
				SelectionTransferData transferData = (SelectionTransferData) data;
				return program.getDomainFile().getPathname().equals(transferData.getProgramPath());
			}
			catch (UnsupportedFlavorException e1) {
				return false;
			}
			catch (IOException e1) {
				return false;
			}
		}
		else if (chosen.equals(TreeTransferable.localTreeNodeFlavor)) {
			// fromObject is null, so we know this is
			// from another tree, so don't allow the drop
			return false;
		}
		return true;
	}

	/**
	 * Get the string to use as the tool tip for the specified node.
	 * @return tool tip if node represents a Fragment; returns null
	 * if is not a Fragment.
	 */
	@Override
	protected String getToolTipText(ProgramNode node) {
		if (!node.isFragment()) {
			return null;
		}

		ProgramFragment f = node.getFragment();
		if (f.getNumAddresses() == 0) {
			return "[ Empty ]";
		}

		AddressRangeIterator iter = f.getAddressRanges();
		StringBuffer sb = new StringBuffer();
		int count = 0;
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			sb.append(range.toString());
			if (iter.hasNext()) {
				sb.append(" ");
			}
			++count;
			if (count > 4) {
				sb.append("...");
				break;
			}
		}
		return sb.toString();
	}

	//////////////////////////////////////////////////////////////
	// *** package -level methods
	//////////////////////////////////////////////////////////////

	/**
	 * Notification made when the program was restored from an
	 * undo operation.
	 */
	void reload() {
		Program p = program;
		program = null;
		listing = p.getListing();
		viewList.clear();
		createRootNode(p);
		setProgram(p);
	}

	Object getVersionTag() {
		return versionTag;
	}

	/**
	* Set the cursor and force a repaint on me. Called by the paste operations
	* that could potentially take a long time. The cursor is reset in the
	* domain object change listener when the event comes in for the group
	* that was last "pasted."
	*/
	void setBusyCursor(boolean busy) {
		if (busy) {
			setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
		}
		else {
			setCursor(Cursor.getDefaultCursor());
		}
		Rectangle r = getBounds();
		invalidateTreeParent();
		paintImmediately(r);
	}

	void addTreeListener(TreeListener l) {
		treeListener = l;
	}

	void removeTreeListener() {
		treeListener = null;
	}

	/**
	 * Clear the variable that has the dragged data.
	 */
	void clearDragData() {
		draggedNodes = null;
	}

	/**
	 * Get the view list.
	 * 
	 * @return ArrayList list of tree paths in the view
	 */
	ArrayList<TreePath> getViewList() {
		return viewList;
	}

	/**
	 * Get the node list.
	 */
	ArrayList<ProgramNode> getNodeList() {
		return nodeList;
	}

	StringKeyIndexer getNameIndexer() {
		return nameIndexer;
	}

	void removeFromView(TreePath path) {
		viewList.remove(path);
		ProgramNode node = (ProgramNode) path.getLastPathComponent();
		node.setInView(false);
		if (node == root || (node != root && node.getParent() != null)) {
			reloadNode(node);
		}
	}

	/**
	 * Adds path to the view.
	 * @param path
	 */
	void addToView(TreePath path) {
		if (path == null) {
			return;
		}
		addToView(path, viewList.size());
	}

	/**
	 * Add path to the view and place it in the view list at the
	 * given index.
	 * @param path path to add to view
	 * @param index index in list
	 */
	void addToView(TreePath path, int index) {
		ProgramNode node = (ProgramNode) path.getLastPathComponent();

		if (!viewList.contains(path) && !hasAncestorsInView(node)) {
			viewList.add(index, path);
			node.setInView(true);
		}
		if (!isVisible(path)) {
			// mark the first expanded ancestor as having something in the view
			ProgramNode parent = (ProgramNode) node.getParent();
			while (parent != null) {
				if (isVisible(parent.getTreePath())) {
					reloadNode(parent);
					break;
				}
				parent = (ProgramNode) parent.getParent();
			}
		}
		else {
			reloadNode(node);
		}
	}

	/**
	 * Return true if the given node has an ancestor in the view.
	 */
	boolean hasAncestorsInView(ProgramNode node) {

		TreePath path = node.getTreePath();

		for (int i = 0; i < viewList.size(); i++) {
			TreePath viewPath = viewList.get(i);
			if (viewPath.isDescendant(path) && !viewPath.equals(path)) {
				return true;
			}
		}
		return false;
	}

	int startTransaction(String operation) {
		return program.startTransaction(operation);
	}

	void endTransaction(int transactionID, boolean commit) {
		program.endTransaction(transactionID, commit);
	}

	PluginTool getTool() {
		return plugin.getTool();
	}

	/**
	 * Add group to view.
	 */
	void addGroupViewPath(GroupPath gp) {
		TreePath path = getTreePathFromGroup(gp);
		if (path != null) {
			addToView(path);
		}
	}

	/**
	 * Replace the existing view with the given paths.
	 */
	void setViewPaths(TreePath[] paths) {
		int size = viewList.size();
		for (int i = 0; i < size; i++) {
			removeFromView(viewList.get(0));
		}

		Arrays.sort(paths, nodeComparator);
		for (TreePath path : paths) {
			if (path != null) {
				addToView(path);
			}
		}
		fireTreeViewChanged();
	}

	/**
	 * Get the view using the group paths.
	 */
	void setGroupViewPaths(GroupPath[] gp) {
		ArrayList<TreePath> list = new ArrayList<>(3);
		for (GroupPath element : gp) {
			TreePath p = getTreePathFromGroup(element);
			if (p != null) {
				list.add(p);
			}
		}
		if (list.size() == 0 || (viewList.containsAll(list) && viewList.size() == list.size())) {
			return;
		}
		TreePath[] paths = new TreePath[list.size()];
		setViewPaths(list.toArray(paths));
	}

	/**
	 * Change the tree selection for the given group paths
	 * @param groupPaths group paths to set to the selection
	 */
	void setGroupSelection(GroupPath[] groupPaths) {
		// sort the groups
		ArrayList<TreePath> list = new ArrayList<>(groupPaths.length);
		for (GroupPath groupPath : groupPaths) {
			TreePath p = getTreePathFromGroup(groupPath);
			if (p != null) {
				list.add(p);
			}
		}
		TreePath[] paths = new TreePath[list.size()];

		setSelectionPaths(list.toArray(paths));
		if (paths.length > 0) {
			this.scrollPathToVisible(paths[0]);
		}
	}

	/**
	 * expand descendants in the given group path
	 *
	 * @param gp
	 */
	void expand(GroupPath gp) {
		TreePath path = getTreePathFromGroup(gp);
		if (path != null) {
			expandPath(path);
		}
	}

	/**
	 * Recursively expand all descendants in the given group path.
	 *
	 */
	void expandAll(GroupPath gp) {
		TreePath path = getTreePathFromGroup(gp);
		if (path != null) {
			expandNode((ProgramNode) path.getLastPathComponent());
		}
	}

	/**
	 * Return true if the given group path is expanded.
	 */
	boolean isExpanded(GroupPath gp) {
		TreePath path = getTreePathFromGroup(gp);
		if (path != null) {
			return isExpanded(path);
		}
		return false;
	}

	void fireTreeViewChanged() {
		if (treeListener != null) {
			treeListener.treeViewChanged(new ChangeEvent(this));
		}
	}

	/**
	 * Collapse descendants in the given group path.
	 *
	 */
	void collapse(GroupPath gp) {
		TreePath path = getTreePathFromGroup(gp);
		if (path != null) {
			collapsePath(path);
		}
	}

	/**
	 * Recursively collapse all descendants in the given group path.
	 *
	 */
	void collapseAll(GroupPath gp) {
		TreePath path = getTreePathFromGroup(gp);
		if (path != null) {
			collapseNode((ProgramNode) path.getLastPathComponent());
		}
	}

	/**
	 * Ensures that the node identified by groupPath is currently viewable.
	 */
	void makeVisible(GroupPath groupPath) {
		TreePath path = getTreePathFromGroup(groupPath);
		if (path != null) {
			this.makeVisible(path);
		}
	}

	/**
	 * Returns an Enumeration of the descendants of gp that are
	 * currently expanded. If path is not currently expanded, this will
	 * return null. If you expand/collapse nodes while iterating over the
	 * returned Enumeration this may not return all the expanded paths, or
	 * may return paths that are no longer expanded.
	 */
	Enumeration<TreePath> getExpandedDescendants(GroupPath gp) {
		TreePath path = getTreePathFromGroup(gp);
		if (path != null) {
			return getExpandedDescendants(path);
		}
		return null;
	}

	/**
	 * Update the tree in the action manager because this tree now
	 * has focus.
	 */
	void setHasFocus(boolean state) {
		if (state) {
			actionManager.setProgramTreeView(treeName, this);
		}
	}

	/**
	 * Return whether the given action should be added to popup, based
	 * on what is currently selected. Called by the ProgramTreeAction.
	 */
	boolean addActionToPopup(DockingAction action) {

		if (!(action instanceof ProgramTreeAction)) {
			return true;
		}

		ProgramTreeAction a = (ProgramTreeAction) action;

		int selectionCount = getSelectionCount();
		if (a.getSelectionType() == ProgramTreeAction.SINGLE_SELECTION) {

			if (selectionCount == 1) {
				return true;
			}
			else if (selectionCount == 0) {
				return true;
			}
			return false;
		}
		// allow 1 or many in selection
		if (selectionCount > 0) {
			return true;
		}
		return false;
	}

	/**
	 * Generate a unique name to be used as the default when
	 * a Module or Fragment is created.
	 */
	String getNewFolderName() {
		return getNewName("New Folder");
	}

	/**
	 * Get the name for a new Fragment.
	 */
	String getNewFragmentName() {
		return getNewName("New Fragment");
	}

	// needed by the Junit tests
	DnDMoveManager getDnDMoveManager() {
		return dragDropManager;
	}

	/**
	 * Build a list of ProgramNodes in preorder.
	 */
	// our data; we know it's good
	void buildNodeList() {
		synchronized (root) {
			nodeList.clear();
			Enumeration<? extends TreeNode> nodes = root.preorderEnumeration();
			while (nodes.hasMoreElements()) {
				nodeList.add((ProgramNode) nodes.nextElement());
			}
		}
	}

	/**
	 * Build a list of selected ProgramNodes in postorder.
	 */
	// our data; we know it's good
	ArrayList<ProgramNode> getSortedSelection() {
		ArrayList<ProgramNode> list = new ArrayList<>();
		Enumeration<? extends TreeNode> it = root.postorderEnumeration();
		while (it.hasMoreElements()) {
			ProgramNode node = (ProgramNode) it.nextElement();
			if (isPathSelected(node.getTreePath())) {
				list.add(node);
			}
		}
		return list;
	}

	/**
	 * Expand all descendants starting at node.
	 */
	void expandNode(ProgramNode node) {

		expandPath(node.getTreePath());

		int nchild = node.getChildCount();
		for (int i = 0; i < nchild; i++) {

			ProgramNode child = (ProgramNode) node.getChildAt(i);

			if (child.equals(node) || child.isLeaf()) {
				continue;
			}
			expandNode(child);
		}

	}

	/**
	 * Called to update the tree when a Group is removed.
	 * Called from the AWT event thread, or from the thread that
	 * distributed domain object change events.
	 * @param node node being removed
	 * @param parentModuleName name of module from which the child is
	 * being removed
	 * @param updateViewList true means to check the view for this node's
	 * path being in the view; if it is, then remove it; false means
	 * don't check the view list at all
	 */
	void groupRemoved(ProgramNode node, String parentModuleName, boolean updateViewList) {

		synchronized (root) {

			ProgramNode parent = (ProgramNode) node.getParent();

			if (parent == null) {
				return; // tree has been updated already
			}

			if (parentModuleName.equals(root.getModule().getName())) {
				// use the node name and not "Root"
				parentModuleName = root.getName();
			}

			// find all nodes where this node's group resides
			ProgramNode[] nodes = findNodes(node.getName());

			if (nodes.length == 0) {
				return; // nothing to do
			}

			for (ProgramNode child : nodes) {

				parent = (ProgramNode) child.getParent();
				if (parent == null) {
					// shouldn't happen
					throw new RuntimeException("Parent in node " + node + " is null!");
				}

				if (parentModuleName.equals(parent.getName())) {
					TreePath childPath = child.getTreePath();
					treeModel.removeNodeFromParent(child);
					child.removeAllChildren();
					child.removeFromParent();
					if (updateViewList) {
						removeDescendantsFromView(childPath);
					}
				}
			}

			// delete the name from the nameIndexer if the group no
			// longer exists...
			String name = node.getName();
			ProgramModule m = listing.getModule(treeName, name);
			ProgramFragment f = listing.getFragment(treeName, name);
			if (m == null && f == null) {
				nameIndexer.remove(name);
			}
			buildNodeList();
		}
		repaint();
	}

	/**
	 * Remove a Group from its parent.
	 * @param node node to remove
	 * @param sb string buffer to use if there was an error
	 * @return true if group was removed
	 */
	boolean removeGroup(ProgramNode node, StringBuffer sb) {

		boolean changesMade = false;

		synchronized (root) {
			ProgramNode parent = (ProgramNode) node.getParent();
			if (parent == null) {
				return false; // node has already been removed
			}

			ProgramModule parentModule = node.getParentModule();
			try {
				if (parentModule.removeChild(node.getName())) {
					changesMade = true;
				}

				//domain object change listener will update the tree...
			}
			catch (NotEmptyException e) {
				sb.append(
					"\n" + node.getName() + " from " + parentModule.getName() + ": Not Empty");
			}
		}
		return changesMade;
	}

	/**
	 * Create a new ProgramNode for the given group and
	 * add it to the treeModel.
	 * @param parent parent of the group to be inserted
	 * @param group group to add
	 * @param index index of new child
	 */
	ProgramNode insertGroup(ProgramNode parent, Group group, int index) {

		if (parent == null) {
			parent = root;
		}
		ProgramNode child = new ProgramNode(program, group);

		treeModel.insertNodeInto(child, parent, index);
		child.setParentModule(parent.getModule());

		// do the lazy population which means don't
		// populate a node until it has been visited
		// (see fireTreeExpanded())

		// update the table of names
		int keyIndex = nameIndexer.get(group.getName());
		if (keyIndex < 0) {
			nameIndexer.put(group.getName());
		}
		return child;
	}

	/**
	 * Called from the domain object listener when a group is added,
	 * or when a module is pasted at another module.
	 */
	void groupAdded(Group group) {
		groupAdded(group, false);
	}

	/**
	 * Called to create a new node for the given group and add it to
	 * all of its parents.
	 * @param group new group to add
	 * @param reparented true if this group is being reparented
	 */
	void groupAdded(Group group, boolean reparented) {

		synchronized (root) {
			String[] parentNames = group.getParentNames();

			boolean treeChanged = false;

			for (String parentName : parentNames) {
				ProgramModule parent = listing.getModule(treeName, parentName);

				ProgramNode[] nodes = findNodes(parent);
				for (ProgramNode node : nodes) {
					boolean alreadyAdded = false;
					int nchild = node.getChildCount();
					for (int k = 0; k < nchild; k++) {
						ProgramNode child = (ProgramNode) node.getChildAt(k);
						Group childGroup = child.getGroup();
						if (childGroup != null && childGroup.equals(group)) {
							alreadyAdded = true;
							break;
						}

					}
					if (!alreadyAdded) {
						if (node.wasVisited()) {
							int index = node.getChildCount();
							if (reparented) {
								index = getChildIndex(node, group);
							}
							insertGroup(node, group, index);
							treeChanged = true;
						}
					}
				}
			}
			if (treeChanged) {
				// redo the list of nodes
				buildNodeList();
				fireTreeViewChanged();
			}
		}
	}

	/**
	 * Reorder the children of  parentModule so that the given
	 * group becomes child at the specified index.
	 */
	void reorder(Group group, ProgramModule parentModule, int index) {

		synchronized (root) {
			ArrayList<TreePath> list = new ArrayList<>();
			ProgramNode[] nodes = findNodes(group);
			Group[] groups = parentModule.getChildren();

			for (ProgramNode node : nodes) {

				ProgramNode parent = (ProgramNode) node.getParent();
				if (!parent.getModule().equals(parentModule)) {
					continue;
				}
				TreePath path = parent.getTreePath();
				if (isExpanded(path)) {
					list.add(path);
				}

				Enumeration<TreePath> it = getExpandedDescendants(path);
				if (it != null) {
					while (it.hasMoreElements()) {
						list.add(it.nextElement());
					}
				}
				ProgramNode child = (ProgramNode) parent.getChildAt(index);
				if (child.getName().equals(groups[index].getName())) {
					continue;
				}

				int tempIndex = index;
				if (index == parent.getChildCount()) {
					tempIndex = index - 1;
				}

				parent.insert(node, tempIndex);
				treeModel.reload(parent);

			}
			for (int i = 0; i < list.size(); i++) {
				TreePath p = list.get(i);
				expandPath(p);
			}
		}
	}

	/**
	 * Called from the update thread to process a "module reordered" event.
	 */
	void reorder(Group group, ProgramModule parentModule) {

		Group[] children = parentModule.getChildren();
		for (int i = 0; i < children.length; i++) {
			if (children[i].equals(group)) {
				reorder(group, parentModule, i);
				return;
			}
		}
	}

	/**
	 * Start editing operation to rename node.
	 */
	void rename() {
		setEditable(true);
		TreePath path = getSelectionPath();

		if (path != null) {
			startEditingAtPath(path);
		}
	}

	/**
	 * If sourceGroup is a Fragment, then merge code units from it into
	 * destFragment. Otherwise, flatten the source module by moving all
	 * descendant fragments' code units into destFragment.
	 * @param sourceGroup group that is source for the merge
	 * @param destFragment destination fragment where all code units
	 * will end up
	 */
	void mergeGroup(Group sourceGroup, ProgramFragment destFragment)
			throws NotFoundException, NotEmptyException {
		if (sourceGroup instanceof ProgramFragment) {
			mergeFragments((ProgramFragment) sourceGroup, destFragment);
		}
		else {
			flattenModule((ProgramModule) sourceGroup, destFragment);
		}
	}

	/**
	 * Find the child with the given name in parentNode.
	 */
	ProgramNode getChild(ProgramNode parentNode, String name) {
		int nchild = parentNode.getChildCount();
		for (int i = 0; i < nchild; i++) {
			ProgramNode child = (ProgramNode) parentNode.getChildAt(i);
			if (child.getName().equals(name)) {
				return child;
			}
		}
		return null;
	}

	/**
	 * For all expanded descendants in sourceNode, expand the corresponding
	 * nodes in destNode.
	 */
	void matchExpansionState(ProgramNode sourceNode, ProgramNode destNode) {

		if (!sourceNode.getAllowsChildren()) {
			return;
		}
		if (!destNode.wasVisited()) {
			visitNode(destNode);
		}

		if (isExpanded(sourceNode.getTreePath())) {
			expandPath(destNode.getTreePath());
		}

		int nchild = sourceNode.getChildCount();
		for (int i = 0; i < nchild; i++) {
			ProgramNode sNode = (ProgramNode) sourceNode.getChildAt(i);
			if (!sNode.getAllowsChildren()) {
				continue;
			}
			ProgramNode dNode = (ProgramNode) destNode.getChildAt(i);
			if (isExpanded(sNode.getTreePath())) {
				expandPath(dNode.getTreePath());
			}
			matchExpansionState(sNode, dNode);
		}
	}

	/**
	 * Disable all actions.
	 */
	void disableActions() {
		actionManager.disableActions();
	}

	/**
	 * Adjust the selection based on the given popupPoint.
	 * @param  event mouse event
	 * @return node that is selected
	 */
	ProgramNode prepareSelectionForPopup(MouseEvent event) {
		// adjust the selection based on the popup location
		synchronized (root) {

			if (event != null && event.getSource() != this) {
				return null;
			}
			Point popupPoint = event != null ? event.getPoint() : null;
			int nselected = getSelectionCount();
			TreePath selPath = null;
			if (popupPoint != null) {
				selPath = getPathForLocation((int) popupPoint.getX(), (int) popupPoint.getY());
			}
			else {
				selPath = getSelectionPath();
			}
			ProgramNode node = null;
			if (selPath != null) {
				node = (ProgramNode) selPath.getLastPathComponent();
			}

			if (nselected <= 1) {

				if (selPath != null && !isPathSelected(selPath)) {
					setSelectionPath(selPath);
					actionManager.adjustSingleActions(node);
					return node;
				}
				if (selPath != null) {
					actionManager.adjustSingleActions(node);
					return node;
				}
				actionManager.disableActions();
				return null;
			}
			// if the path at the mouse pointer is in the selection OR
			// the path is null, then adjust the multi-popup menu.
			if ((selPath != null && isPathSelected(selPath)) || selPath == null) {
				actionManager.adjustMultiActions();
				return node;
			}
			// force the selection to be where the mouse pointer is
			setSelectionPath(selPath);
			actionManager.adjustSingleActions(node);
			return node;
		}
	}

	/**
	 * Call this when the given nodes children have changed.
	 * 
	 * @param node node to reload.
	 */
	void reloadNode(ProgramNode node) {
		List<TreePath> list = getExpandedPaths(node);
		TreePath[] paths = getSelectionPaths();

		treeModel.reload(node);

		expandPaths(list);

		addSelectionPaths(paths);
	}

	/**
	 * Find the nodes containing the given group name; this
	 * method is called when a Group has been renamed, and we
	 * have to find the node according to name (and not by Group).
	 */
	ProgramNode[] findNodes(String groupName) {

		ArrayList<ProgramNode> list = new ArrayList<>();

		for (int i = 0; i < nodeList.size(); i++) {
			ProgramNode node = nodeList.get(i);

			if (node.getName().equals(groupName)) {
				list.add(node);
			}
		}
		ProgramNode[] nodes = new ProgramNode[list.size()];
		return list.toArray(nodes);
	}

	/**
	 * Add the given group path to the tree's selection.
	 */
	void addGroupSelectionPath(GroupPath gp) {
		TreePath path = getTreePathFromGroup(gp);
		if (path != null) {
			addSelectionPath(path);
		}
	}

	/**
	 * Get the group paths that correspond to the nodes that are
	 * selected.
	 */
	GroupPath[] getSelectedGroupPaths() {
		TreePath[] paths = getSelectionPaths();
		if (paths == null || program == null) {
			return EMPTY_GROUP_SELECTION;
		}
		GroupPath[] groupPaths = new GroupPath[paths.length];
		for (int i = 0; i < groupPaths.length; i++) {
			ProgramNode node = (ProgramNode) paths[i].getLastPathComponent();
			groupPaths[i] = node.getGroupPath();
		}
		return groupPaths;
	}

	void updateGroupPath(ProgramNode node) {
		// update the module path
		setGroupPath(node);
		reloadNode(node);
		int nchild = node.getChildCount();
		// update my children's module paths
		for (int i = 0; i < nchild; i++) {
			ProgramNode child = (ProgramNode) node.getChildAt(i);
			updateGroupPath(child);
		}
	}

	/**
	 * Set the GroupPath object in the given node.
	 */
	void setGroupPath(ProgramNode node) {
		TreeNode[] pnodes = node.getPath();
		String[] names = new String[pnodes.length];

		for (int i = 0; i < pnodes.length; i++) {
			ProgramNode n = (ProgramNode) pnodes[i];
			names[i] = n.toString();
		}
		node.setGroupPath(new GroupPath(names));
	}

	void visitNode(ProgramNode node) {
		node.visit();

		// see if any children were added (would happen due to a drag and drop operation if 
		// node had not been visited before the operation);
		// if child count > 0 then we have to make sure we aren't adding duplicates
		int nChildNodes = node.getChildCount();

		// add children to this node (has to be a Module)
		ProgramModule m = node.getModule();
		Group[] groups = m.getChildren();
		for (Group group : groups) {
			if (nChildNodes == 0 || !childGroupAdded(node, group)) {
				insertGroup(node, group, node.getChildCount());
			}
		}
	}

	void goTo(Address address) {
		if (treeListener != null) {
			treeListener.goTo(address);
		}
	}

	String getTreeName() {
		return treeName;
	}

	void setTreeName(String treeName) {
		this.treeName = treeName;
	}

	/**
	 * Get a comparator that knows how to compare ProgramNodes.
	 */
	Comparator<TreePath> getNodeComparator() {
		return nodeComparator;
	}

	///////////////////////////////////////////////////////////////////////////
	// *** private methods ***
	///////////////////////////////////////////////////////////////////////////

	/**
	 * Remove descendant paths from the view.
	 * @param parentPath
	 */
	private void removeDescendantsFromView(TreePath parentPath) {
		removeFromView(parentPath);
		ProgramNode node = (ProgramNode) parentPath.getLastPathComponent();
		for (int i = 0; i < node.getChildCount(); i++) {
			ProgramNode child = (ProgramNode) node.getChildAt(i);
			if (child.getAllowsChildren()) {
				removeDescendantsFromView(child.getTreePath());
			}
			else {
				removeFromView(child.getTreePath());
			}
		}
	}

	/**
	 * Expand all paths in the list.
	 * @param list list of TreePaths.
	 */
	public void expandPaths(List<TreePath> list) {
		for (int i = 0; i < list.size(); i++) {
			TreePath path = list.get(i);
			expandPath(path);
		}
	}

	/**
	 * Initialize data structures, popups, and create listeners.
	 */
	private void initialize() {
		dragDropManager = new DnDMoveManager(this);

		setRowHeight(18);

		nodeList = new ArrayList<>();
		viewList = new ArrayList<>();

		if (treeModel != null) {
			treeModel.addTreeModelListener(new ProgramTreeModelListener(this));
		}
		setEditable(false);

		nameIndexer = new StringKeyIndexer();
	}

	/**
	 * Get the first level of children for the root module.
	 * Delay all other population of children of these nodes
	 * until they are visited.
	 */
	private void layoutProgram() {

		ProgramModule rootModule = root.getModule();
		root.visit();

		Group[] children = rootModule.getChildren();
		root.setGroupPath(new GroupPath(new String[] { rootModule.getName() }));

		// have to get first level of children, otherwise
		// root icon does not show up properly
		for (Group element : children) {
			insertGroup(root, element, root.getChildCount());
		}
		root.setTreePath(getPathForRow(0));
		buildNodeList();
	}

	/**
	 * Find the nodes containing the given Group.
	 */
	private ProgramNode[] findNodes(Group g) {

		ArrayList<ProgramNode> list = new ArrayList<>();

		for (int i = 0; i < nodeList.size(); i++) {
			ProgramNode node = nodeList.get(i);

			Group group = node.getGroup();
			if (group != null && group.equals(g)) {
				list.add(node);
			}
		}
		ProgramNode[] nodes = new ProgramNode[list.size()];
		return list.toArray(nodes);
	}

	/**
	 * Given a GroupPath, find its corresponding TreePath object.
	 */
	private TreePath findTreePath(GroupPath groupPath) {

		for (int i = 0; i < nodeList.size(); i++) {
			ProgramNode node = nodeList.get(i);
			GroupPath p = node.getGroupPath();
			if (p.equals(groupPath)) {
				return node.getTreePath();
			}
		}
		return null;
	}

	/**
	 * Collapse all descendants starting at node.
	 */
	// package level access for Junit tests
	void collapseNode(ProgramNode node) {

		int nchild = node.getChildCount();
		for (int i = 0; i < nchild; i++) {

			ProgramNode child = (ProgramNode) node.getChildAt(i);

			if (child.equals(node) || child.isLeaf()) {
				continue;
			}
			collapseNode(child);
		}
		collapsePath(node.getTreePath());
	}

	/**
	 * Add code units from the list of FragmentSelection objects
	 * to the targetNode. If targetNode is a Module, then a new
	 * fragment is created and all code units are added to the new
	 * fragment. If the targetNode is a Fragment, then code units
	 * are just added to that fragment. If the source fragment is empty
	 * after moving the code units to the destination, remove it from
	 * all of its parents.
	 * @param destNode represents either a Module or Fragment
	 * @param view address set view for code units that will be added
	 * the destination fragment
	 */
	// package level access for Junit tests
	void addCodeUnits(ProgramNode destNode, AddressSetView view) {

		if (destNode == null) {
			return;
		}
		Listing currentListing = program.getListing();
		Address start = view.getMinAddress();
		ProgramFragment sourceFrag = currentListing.getFragment(treeName, start);

		Data data = currentListing.getDefinedDataContaining(start);
		if (data != null && !view.getMinAddress().equals(data.getMinAddress())) {
			view = new AddressSet(data.getMinAddress(), data.getMaxAddress());
		}
		int transactionID = startTransaction("Move Code Units");

		boolean addEdit = false;
		try {
			if (destNode.isFragment()) {
				try {
					moveRanges(destNode.getFragment(), view);
					addEdit = true;
				}
				catch (NotFoundException e) {
					Msg.showInfo(getClass(), this, "Move Code Units Failed", e.getMessage());
					return;
				}
			}
			else {
				addEdit = createFragmentFromView(destNode, view);
			}
			if (addEdit && sourceFrag.isEmpty()) {
				try {
					removeEmptyFragment(sourceFrag);
				}
				catch (NotEmptyException e) {
					// shouldn't happen since we asked isEmpty()
				}
			}
		}
		finally {
			endTransaction(transactionID, addEdit);
		}

		if (addEdit) {
			fireTreeViewChanged();
		}

	}

	private void removeEmptyFragment(ProgramFragment frag) throws NotEmptyException {
		String name = frag.getName();
		ProgramModule[] parents = frag.getParents();
		for (ProgramModule parent2 : parents) {
			parent2.removeChild(name);
		}
	}

	/**
	 * Create a new fragment and move the code units in the view to the
	 * new fragment.
	 * @param destNode destination node that is a module
	 * @param view view containing the addresses of the code units
	 * @return boolean true if move of the code units was successful
	 */
	private boolean createFragmentFromView(ProgramNode destNode, AddressSetView view) {

		String name = generateFragmentName(view.getMinAddress());

		// make sure name is not already in use
		ProgramFragment f = listing.getFragment(treeName, name);
		if (f == null) {
			ProgramModule m = listing.getModule(treeName, name);
			if (m != null) {
				name = getNewFragmentName();
			}
		}
		else {
			name = getNewFragmentName();
		}
		ProgramModule destModule = destNode.getModule();
		ProgramFragment newFrag = null;
		try {
			newFrag = destModule.createFragment(name);
			moveRanges(newFrag, view);
			return true;
		}
		catch (DuplicateNameException e) {
			// shouldn't happen
		}
		catch (NotFoundException e) {
			try {
				// remove the new fragment
				destModule.removeChild(name);
				Msg.showError(this, this, "Move Code Units Failed", e.getMessage());
			}
			catch (NotEmptyException exc) {
				// shouldn't happen since we just added the fragment
			}

		}
		return false;
	}

	/**
	 * Processes a request to drop data at the targetNode.
	 *
	 * @param targetNode Node where data is to be dropped
	 * @param data   Data to drop onto targetNode
	 * @param chosen the data flavor of data
	 * @param dropAction action for the drop
	 * @return node that was dropped if data flavor is
	 * TreeTransferable.localTreeNodeFlavor; return null for all other
	 * data flavors
	 *
	 * @exception DuplicateNameException thrown if a module
	 * already has a group with the same name
	 * @exception NotFoundException thrown if a child is
	 * being moved and it is not found in the targetNode module.
	 * @exception CodeUnitBoundaryException thrown if
	 * @exception CircularDependencyException thrown if the
	 * targetNode module is an ancestor of the data module.
	 */
	@SuppressWarnings("unchecked")
	// the cast is OK, since it can only be data we expect
	// package level access for Junit tests
	void processDropRequest(ProgramNode targetNode, Object data, DataFlavor chosen, int dropAction)
			throws NotFoundException, CircularDependencyException, DuplicateGroupException {

		if (chosen.equals(SelectionTransferable.localProgramSelectionFlavor)) {
			// get list of Code units
			SelectionTransferData transferData = (SelectionTransferData) data;
			AddressSetView view = transferData.getAddressSet();
			if (view.getNumAddressRanges() == 0) {
				throw new RuntimeException("Nothing to drop!");
			}

			addCodeUnits(targetNode, view); // targetNode can either
			// be a Module or a Fragment; if it is a Module,
			// then a new Fragment is created to hold the
			// code units being dropped
			return;
		}
		/// *** test flavors
		if (chosen.equals(GroupTransferable.localGroupFlavor)) {
			return;
		}
		if (chosen.equals(DataFlavor.stringFlavor)) {
			return;
		}
		//// ** end of test flavors

		// this must be TreeTransferable.localTreeNodeFlavor
		List<ProgramNode> list = (List<ProgramNode>) data;
		if (list.size() == 0) {
			throw new RuntimeException("Nothing to drop!");
		}

		ProgramNode[] dropNodes = list.toArray(new ProgramNode[list.size()]);
		dragDropManager.add(targetNode, dropNodes, dropAction, relativeMousePos);
	}

	/**
	 * Return true if the node already has a child node with
	 * the given group.
	 */
	private boolean childGroupAdded(ProgramNode node, Group group) {

		int nchild = node.getChildCount();
		for (int i = 0; i < nchild; i++) {
			ProgramNode child = (ProgramNode) node.getChildAt(i);

			if (group.equals(child.getGroup())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Visit all nodes in the given node so that all nodes representing
	 * modules are fully populated.
	 */
	private void visitAllNodes(ProgramNode node) {
		if (!node.isModule()) {
			return;
		}

		visitNode(node);
		int nchild = node.getChildCount();
		for (int i = 0; i < nchild; i++) {
			ProgramNode child = (ProgramNode) node.getChildAt(i);
			visitAllNodes(child);
		}
	}

	/**
	 * Get the tree path for the given group path; populate the node
	 * if it has not been visited.
	 */
	private TreePath getTreePathFromGroup(GroupPath gp) {
		TreePath path = findTreePath(gp);
		if (path == null) {
			// Node has not been fully populated, so it wasn't found,
			// so find the first path we have
			//
			GroupPath parentgp = null;
			parentgp = gp.getParentPath();
			while (parentgp != null) {

				path = findTreePath(parentgp);
				if (path != null) {
					break;
				}
				parentgp = parentgp.getParentPath();
			}
			if (path == null) {
				return null;
			}

			// visit the node to populate its children
			ProgramNode node = (ProgramNode) path.getLastPathComponent();

			if (!node.wasVisited()) {
				visitAllNodes(node);

				buildNodeList();
			}
			path = findTreePath(gp);
		}
		return path;
	}

	/**
	 * Move code units in the address set view.
	 */
	private void moveRanges(ProgramFragment destFrag, AddressSetView setView)
			throws NotFoundException {
		// make a copy of the set view so we can iterate over
		// a constant range
		AddressSetView view = new AddressSet(setView);
		AddressRangeIterator iter = view.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			destFrag.move(range.getMinAddress(), range.getMaxAddress());
		}
	}

	/**
	 * Invalidate my parent.
	 */
	private void invalidateTreeParent() {
		Container parent = getParent();
		while (parent != null) {
			if (parent instanceof Frame) {
				((Frame) parent).invalidate();
				return;
			}
			parent = parent.getParent();
		}

	}

	/**
	 * Merge two fragments.
	 * @param sourceFragment source fragments
	 * @param destFragment destination
	 */
	private void mergeFragments(ProgramFragment sourceFragment, ProgramFragment destFragment)
			throws NotFoundException, NotEmptyException {

		moveRanges(destFragment, sourceFragment);
		if (sourceFragment.isEmpty()) {
			removeEmptyFragment(sourceFragment);
		}
	}

	/**
	 * Moves all code units from all descendant fragments in source module
	 * to the destFragment; empty modules and fragments are deleted from
	 * the program.
	 * @param sourceModule module to flatten
	 * @param destFragment destination fragment
	 */
	private void flattenModule(ProgramModule sourceModule, ProgramFragment destFragment)
			throws NotFoundException, NotEmptyException {

		Group[] groups = sourceModule.getChildren();
		for (Group group : groups) {
			if (group instanceof ProgramFragment) {
				mergeFragments((ProgramFragment) group, destFragment);
			}
			else {
				flattenModule((ProgramModule) group, destFragment);
			}
		}
		if (sourceModule.getNumChildren() == 0) {
			String name = sourceModule.getName();
			ProgramModule[] parents = sourceModule.getParents();
			for (ProgramModule parent2 : parents) {
				parent2.removeChild(name);
			}
		}
	}

	/**
	 * Clear fields in the ProgramNode objects so everything can be
	 * garbage collected.
	 */
	private void disposeOfNodes() {
		for (int i = 0; i < nodeList.size(); i++) {
			ProgramNode node = nodeList.get(i);
			node.dispose();
		}
	}

	/**
	 * Get a list of paths that are expanded, starting at node.
	 */
	private ArrayList<TreePath> getExpandedPaths(ProgramNode node) {

		ArrayList<TreePath> list = new ArrayList<>();

		int nchild = node.getChildCount();
		for (int i = 0; i < nchild; i++) {
			ProgramNode child = (ProgramNode) node.getChildAt(i);
			TreePath path = child.getTreePath();
			if (isExpanded(path)) {
				list.add(path);
				ArrayList<TreePath> templist = getExpandedPaths(child);
				list.addAll(templist);
			}
		}
		return list;
	}

	/**
	 * Generate a unique name to be used as the default when
	 * a Module or Fragment is created.
	 */
	private String getNewName(String baseName) {

		int index = 2;
		if (nameIndexer.get(baseName) < 0) {
			if (listing.getModule(treeName, baseName) == null &&
				listing.getFragment(treeName, baseName) == null) {
				return baseName;
			}
		}

		boolean done = false;
		while (!done) {
			String name = baseName + " (" + index + ")";
			if (nameIndexer.get(name) < 0) {
				if (listing.getModule(treeName, name) == null &&
					listing.getFragment(treeName, name) == null) {
					return name;
				}
			}
			++index;
		}
		return null; // should never get here
	}

	/**
	 * Generate a fragment name; if there is a symbol at the start
	 * of the fragment, and if it is user defined, then use the label 
	 * as the fragment name; otherwise, just use the address as the name.
	 * @param addr first address of fragment
	 * 
	 * @return String name of fragment
	 */
	private String generateFragmentName(Address addr) {

		Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
		if (symbol == null || symbol.isDynamic()) {
			return addr.toString();
		}
		return symbol.getName();
	}

	private void createRootNode(Program theProgram) {
		if (theProgram == null) {
			root = new ProgramNode(null, "No Program");
		}
		else {
			ProgramModule rm = theProgram.getListing().getRootModule(treeName);
			if (rm == null) {
				return;
			}
			root = new ProgramNode(theProgram, rm, rm.getName());
			versionTag = rm.getVersionTag();
		}

		treeModel.setRoot(root);
		root.setTree(this);
	}

	private int getChildIndex(ProgramNode parent, Group group) {
		Group[] kids = parent.getModule().getChildren();
		for (int i = 0; i < kids.length; i++) {
			if (group == kids[i]) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Class to compare two objects.
	 */
	private class NodeComparator implements Comparator<TreePath> {
		/**
		 * Return negative, 0, or positive number if p1 is less than
		 * equal to, or greater than p2.
		 */
		@Override
		public int compare(TreePath p1, TreePath p2) {
			if (p1.equals(p2)) {
				return 0;
			}

			ProgramNode node1 = (ProgramNode) p1.getLastPathComponent();
			ProgramNode node2 = (ProgramNode) p2.getLastPathComponent();
			int index1 = nodeList.indexOf(node1);
			int index2 = nodeList.indexOf(node2);
			if (index1 < index2) {
				return -1;
			}
			return 1;

		}
	}

}
