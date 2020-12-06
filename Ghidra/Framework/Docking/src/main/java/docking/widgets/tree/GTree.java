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
package docking.widgets.tree;

import static docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin.*;
import static ghidra.util.SystemUtilities.*;

import java.awt.*;
import java.awt.dnd.Autoscroll;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.PrintWriter;
import java.util.*;
import java.util.List;
import java.util.function.BooleanSupplier;

import javax.swing.*;
import javax.swing.Timer;
import javax.swing.event.*;
import javax.swing.tree.*;

import org.apache.commons.lang3.StringUtils;

import docking.DockingWindowManager;
import docking.actions.KeyBindingUtils;
import docking.widgets.JTreeMouseListenerDelegate;
import docking.widgets.filter.FilterTextField;
import docking.widgets.table.AutoscrollAdapter;
import docking.widgets.tree.internal.*;
import docking.widgets.tree.support.*;
import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin;
import docking.widgets.tree.tasks.*;
import generic.timer.ExpiringSwingTimer;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import ghidra.util.worker.PriorityWorker;

/**
 * Class for creating a JTree that supports filtering, threading, and a progress bar.
 */

public class GTree extends JPanel implements BusyListener {

	private AutoScrollTree tree;
	private GTreeModel model;

	/**
	 * This is the root node of the tree's data model.  It may or may not be the root node
	 * that is currently being displayed by the tree. If there is currently a 
	 * filter applied, then then the displayed root node will be a clone whose children have been
	 * trimmed to only those that match the filter.  By keeping this variable around, we can give
	 * this node to clients, regardless of the root node visible in the tree.
	 */
	private volatile GTreeNode realModelRootNode;

	/**
	 * This is the root that is currently being displayed. This node will be either exactly the 
	 * same instance as the realModelRootNode (if no filter has been applied) or it will be the
	 * filtered clone of the realModelRootNode. 
	 */
	private volatile GTreeNode realViewRootNode;

	/**
	 * The rootParent is a node that is assigned as the parent to the realRootNode. It's primary purpose is
	 * to allow nodes access to the tree. It overrides the getTree() method on GTreeNode to return
	 * this tree. This eliminated the need for clients to create special root nodes that had 
	 * public setTree/getTree methods.
	 */
	private GTreeRootParentNode rootParent = new GTreeRootParentNode(this);

	private JScrollPane scrollPane;
	private GTreeRenderer renderer;

	private FilterTransformer<GTreeNode> transformer = new DefaultGTreeDataTransformer();

	private JTreeMouseListenerDelegate mouseListenerDelegate;
	private GTreeDragNDropHandler dragNDropHandler;
	private boolean isFilteringEnabled = true;

	private ThreadLocal<TaskMonitor> threadLocalMonitor = new ThreadLocal<>();
	private PriorityWorker worker;
	private Timer showTimer;

	private TaskMonitorComponent monitor;
	private JComponent progressPanel;

	private JPanel mainPanel;

	private GTreeState filterRestoreTreeState;
	private GTreeFilterTask lastFilterTask;
	private String uniquePreferenceKey;

	private GTreeFilter filter;
	private GTreeFilterProvider filterProvider;
	private SwingUpdateManager filterUpdateManager;

	/**
	 * Creates a GTree with the given root node.  The created GTree will use a threaded model
	 * for performing tasks, which allows the GUI to be responsive for reaaaaaaaaly big trees.
	 *
	 * @param root The root node of the tree.
	 */
	public GTree(GTreeNode root) {
		uniquePreferenceKey = generateFilterPreferenceKey();
		this.realModelRootNode = root;
		this.realViewRootNode = root;
		monitor = new TaskMonitorComponent();
		monitor.setShowProgressValue(false);// the tree's progress is fabricated--don't paint it
		worker = new PriorityWorker("GTree Worker", monitor);
		root.setParent(rootParent);
		this.model = new GTreeModel(root);
		worker.setBusyListener(this);
		init();

		DockingWindowManager.registerComponentLoadedListener(this,
			(windowManager, provider) -> filterProvider.loadFilterPreference(windowManager,
				uniquePreferenceKey));

		filterUpdateManager = new SwingUpdateManager(1000, 30000, () -> updateModelFilter());
	}

	/**
	 * Should be called by threads running {@link GTreeTask}s.
	 *
	 * @param monitor the monitor being used for the currently running task.
	 * @see #getThreadLocalMonitor()
	 */
	void setThreadLocalMonitor(TaskMonitor monitor) {
		threadLocalMonitor.set(monitor);
	}

	/**
	 * Returns the monitor in associated with the GTree for the calling thread.  This method is
	 * designed to be used by slow loading nodes that are loading <b>off the Swing thread</b>.
	 * Some of the loading methods are called by the slow loading node at a point when it is
	 * not passed a monitor (like when clients ask how many children the node has).
	 * <p>
	 * When a {@link GTreeTask} is run in thread from a thread pool, it registers its monitor
	 * (which is different than the GTree's) with this tree.  Then, if a node performing work,
	 * like loading, needs a monitor, it can call {@link #getThreadLocalMonitor()} in order to
	 * get the monitor that was registered with that thread.
	 * <P>
	 * This method is necessary because the concurrent library used by this tree will provide a
	 * unique monitor for each task that is run, which will be different (but connected) to the
	 * monitor created by this tree.
	 * <p>
	 * If this method is called from a client other than a {@link GTreeTask}, then a dummy
	 * monitor will be returned.
	 *
	 * @return the monitor associated with the calling thread; null if the monitor was not set
	 * @see #setThreadLocalMonitor(TaskMonitor)
	 */
	TaskMonitor getThreadLocalMonitor() {
		TaskMonitor localMonitor = threadLocalMonitor.get();
		if (localMonitor != null) {
			return localMonitor;
		}

		return TaskMonitor.DUMMY;
	}

	@Override
	public void setEnabled(boolean enabled) {
		super.setEnabled(enabled);
		tree.setEnabled(enabled);
		scrollPane.setEnabled(enabled);
		filterProvider.setEnabled(enabled);
	}

	/**
	 * Turns tree event notifications on/off
	 * @param b true to enable events, false to disable events
	 */
	public void setEventsEnabled(boolean b) {
		model.setEventsEnabled(b);
	}

	public void setDragNDropHandler(GTreeDragNDropHandler dragNDropHandler) {
		this.dragNDropHandler = dragNDropHandler;
		new GTreeDragNDropAdapter(this, tree, dragNDropHandler);
	}

	@Override
	public void setTransferHandler(TransferHandler handler) {
		tree.setTransferHandler(handler);
	}

	public GTreeDragNDropHandler getDragNDropHandler() {
		return dragNDropHandler;
	}

	private void init() {
		tree = new AutoScrollTree(model);

		setLayout(new BorderLayout());

		scrollPane = new JScrollPane(tree);

		mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(scrollPane, BorderLayout.CENTER);

		add(mainPanel, BorderLayout.CENTER);
		renderer = new GTreeRenderer();
		tree.setCellRenderer(renderer);
		tree.setCellEditor(new GTreeCellEditor(tree, renderer));
		tree.setEditable(true);

		addGTreeSelectionListener(e -> {
			if (e.getEventOrigin() == GTreeSelectionEvent.EventOrigin.USER_GENERATED ||
				e.getEventOrigin() == GTreeSelectionEvent.EventOrigin.API_GENERATED) {
				filterRestoreTreeState = getTreeState();
			}
		});

		mouseListenerDelegate = createMouseListenerDelegate();
		filterProvider = new DefaultGTreeFilterProvider(this);
		add(filterProvider.getFilterComponent(), BorderLayout.SOUTH);
	}

	public void setCellRenderer(GTreeRenderer renderer) {
		this.renderer = renderer;
		tree.setCellRenderer(renderer);
	}

	public GTreeRenderer getCellRenderer() {
		return renderer;
	}

	public void dispose() {
		filterUpdateManager.dispose();
		worker.dispose();

		if (realModelRootNode != null) {
			realModelRootNode.dispose();
		}
		// if there is a filter applied, clean up the filtered nodes. Note that filtered nodes
		// are expected to be shallow clones of the model nodes, so we don't want to call full
		// dispose on the filtered nodes because internal clean-up should happen when the
		// model nodes are disposed. The disposeClones just breaks the child-parent ties.
		if (realViewRootNode != null && realViewRootNode != realModelRootNode) {
			realViewRootNode.disposeClones();
		}
		model.dispose();
	}

	public boolean isDisposed() {
		return worker.isDisposed();
	}

	/**
	 * Signals that any multithreaded work should be cancelled.
	 */
	public void cancelWork() {
		worker.clearAllJobs();
	}

	public void filterChanged() {
		updateModelFilter();
	}

	protected void updateModelFilter() {
		filter = filterProvider.getFilter();

		if (lastFilterTask != null) {
			// it is safe to repeatedly call cancel
			lastFilterTask.cancel();
		}

		lastFilterTask = new GTreeFilterTask(this, filter);

		if (isFilteringEnabled()) {
			worker.schedule(lastFilterTask);
		}
	}

	protected JTreeMouseListenerDelegate createMouseListenerDelegate() {
		return new GTreeMouseListenerDelegate(tree, this);
	}

	/**
	 * Returns a state object that allows this tree to later restore its expanded and selected
	 * state.
	 * <p>
	 * <b>Note: </b>See the usage note at the header of this class concerning how tree state
	 * is used relative to the <code>equals()</code> method.
	 * @return the saved state
	 */
	public GTreeState getTreeState() {
		return new GTreeState(this);
	}

	public GTreeState getTreeState(GTreeNode node) {
		return new GTreeState(this, node);
	}

	/**
	 * Restores the expanded and selected state of this tree to that contained in the given
	 * state object.
	 * <p>
	 * <b>Note: </b>See the usage note at the header of this class concerning how tree state
	 * is used relative to the <code>equals()</code> method.
	 * 
	 * @param state the state to restore
	 *
	 * @see #getTreeState()
	 * @see #getTreeState(GTreeNode)
	 */
	public void restoreTreeState(GTreeState state) {
		runTask(new GTreeRestoreTreeStateTask(this, state));
	}

	/**
	 * Signal to the tree that it should record its expanded and selected state when a 
	 * new filter is applied
	 */
	void saveFilterRestoreState() {
		// this may be called by sub-filter tasks and we wish to save only the first one
		if (filterRestoreTreeState == null) {
			filterRestoreTreeState = new GTreeState(this);
		}
	}

	GTreeState getFilterRestoreState() {
		return filterRestoreTreeState;
	}

	void clearFilterRestoreState() {
		filterRestoreTreeState = null;
	}

	/**
	 * A method that subclasses can use to be notified when tree state has been restored.  This
	 * method is called after a major structural tree change has happened <b>and</b> the paths
	 * that should be opened have been opened.  Thus any other nodes are closed and can be
	 * disposed, if desired.
	 *
	 * @param taskMonitor the TaskMonitor
	 */
	public void expandedStateRestored(TaskMonitor taskMonitor) {
		// optional
	}

	public List<TreePath> getExpandedPaths() {
		return getExpandedPaths(getViewRoot());
	}

	public List<TreePath> getExpandedPaths(GTreeNode node) {
		Enumeration<TreePath> expandedPaths = tree.getExpandedDescendants(node.getTreePath());
		if (expandedPaths == null) {
			return Collections.emptyList();
		}
		return Collections.list(expandedPaths);
	}

	public void expandTree(GTreeNode node) {
		runTask(new GTreeExpandAllTask(this, node));
	}

	public void expandAll() {
		runTask(new GTreeExpandAllTask(this, getViewRoot()));
	}

	public void collapseAll(GTreeNode node) {

		runSwingNow(() -> {
			node.fireNodeStructureChanged(node);
			tree.collapsePath(node.getTreePath());

			boolean nodeIsRoot = node.equals(model.getRoot());

			if (nodeIsRoot && !tree.isRootAllowedToCollapse()) {
				runTask(new GTreeExpandNodeToDepthTask(this, getJTree(), node, 1));
			}

		});
	}

	public void expandPath(GTreeNode node) {
		expandPaths(new TreePath[] { node.getTreePath() });
	}

	public void expandPath(TreePath path) {
		expandPaths(new TreePath[] { path });
	}

	public void expandPaths(TreePath[] paths) {
		runTask(new GTreeExpandPathsTask(this, Arrays.asList(paths)));
	}

	public void expandPaths(List<TreePath> pathsList) {
		TreePath[] treePaths = pathsList.toArray(new TreePath[pathsList.size()]);
		expandPaths(treePaths);
	}

	public void clearSelectionPaths() {
		runTask(new GTreeClearSelectionTask(this, tree));
	}

	public void setSelectedNode(GTreeNode node) {
		setSelectionPaths(new TreePath[] { node.getTreePath() });
	}

	public void setSelectedNodes(GTreeNode... nodes) {
		List<TreePath> paths = new ArrayList<>();
		for (GTreeNode node : nodes) {
			paths.add(node.getTreePath());
		}
		setSelectionPaths(paths);
	}

	public void setSelectedNodes(Collection<GTreeNode> nodes) {
		List<TreePath> paths = new ArrayList<>();
		for (GTreeNode node : nodes) {
			paths.add(node.getTreePath());
		}
		setSelectionPaths(paths);
	}

	public void setSelectionPaths(TreePath[] paths) {
		setSelectionPaths(paths, EventOrigin.API_GENERATED);
	}

	public void setSelectionPaths(List<TreePath> pathsList) {
		TreePath[] treePaths = pathsList.toArray(new TreePath[pathsList.size()]);
		setSelectionPaths(treePaths, EventOrigin.API_GENERATED);
	}

	public void setSelectionPath(TreePath path) {
		setSelectionPaths(new TreePath[] { path });
	}

	/**
	 * A convenience method to select a node by a path, starting with the tree root name, down
	 * each level until the desired node name.
	 *
	 * @param namePath The path to select
	 */
	public void setSelectedNodeByNamePath(String[] namePath) {
		runTask(new GTreeSelectNodeByNameTask(this, tree, namePath, EventOrigin.API_GENERATED));
	}

	/**
	 * A convenience method that allows clients that have created a new child node to select that
	 * node in the tree, without having to lookup the actual GTreeNode implementation.
	 *
	 * @param parentNode The parent containing a child by the given name
	 * @param childName The name of the child to select
	 */
	public void setSeletedNodeByName(GTreeNode parentNode, String childName) {
		TreePath treePath = parentNode.getTreePath();
		TreePath pathWithChild = treePath.pathByAddingChild(childName);
		setSelectedNodeByPathName(pathWithChild);
	}

	/**
	 * Selects the node that matches the each name in the given tree path.  It is worth noting
	 * that the items in the tree path themselves are not used to identify nodes, but the
	 * {@link #toString()} of those items will be used.
	 *
	 * @param treePath The path containing the names of the path of the node to select
	 */
	public void setSelectedNodeByPathName(TreePath treePath) {
		Object[] path = treePath.getPath();
		String[] namePath = new String[treePath.getPathCount()];
		for (int i = 0; i < path.length; i++) {
			namePath[i] = path[i].toString();
		}

		runTask(new GTreeSelectNodeByNameTask(this, tree, namePath, EventOrigin.API_GENERATED));
	}

	public void setSelectionPaths(TreePath[] path, EventOrigin origin) {
		runTask(new GTreeSelectPathsTask(this, tree, Arrays.asList(path), origin));
	}

	public boolean isCollapsed(TreePath path) {
		return tree.isCollapsed(path);
	}

	public void setHorizontalScrollPolicy(int policy) {
		scrollPane.setHorizontalScrollBarPolicy(policy);
	}

	protected JScrollPane getScrollPane() {
		return scrollPane;
	}

	/**
	 * Sets the size of the scroll when mouse scrolling or pressing the scroll up/down buttons.
	 * Most clients will not need this method, as the default behavior of the tree is correct,
	 * which is to scroll based upon the size of the nodes (which is usually uniform and a
	 * single row in size).  However, some clients that have variable row height, with potentially
	 * large rows, may wish to change the scrolling behavior so that it is not too fast.
	 *
	 * @param increment the new (uniform) scroll increment.
	 */
	public void setScrollableUnitIncrement(int increment) {
		tree.setScrollableUnitIncrement(increment);
	}

	/**
	 * Returns the model for this tree
	 * @return the model for this tree
	 */
	public GTreeModel getModel() {
		return model;
	}

	// don't let classes outside this package ever have access to the JTree.  It would allow
	// subclasses to break various assumptions about the state of the tree. For example, we
	// assume the TreeSelectionModel is really a GTreeSelectionModel.
	protected final JTree getJTree() {
		return tree;
	}

	/**
	 * Returns the current viewport position of the scrollable tree.
	 * @return  the current viewport position of the scrollable tree.
	 */
	public Point getViewPosition() {
		JViewport viewport = scrollPane.getViewport();
		Point p = viewport.getViewPosition();
		return p;
	}

	public void setViewPosition(Point p) {
		JViewport viewport = scrollPane.getViewport();
		viewport.setViewPosition(p);
	}

	public Rectangle getViewRect() {
		JViewport viewport = scrollPane.getViewport();
		Rectangle viewRect = viewport.getViewRect();
		return viewRect;
	}

	public GTreeNode getNodeForLocation(int x, int y) {
		TreePath pathForLocation = tree.getPathForLocation(x, y);
		if (pathForLocation != null) {
			return (GTreeNode) pathForLocation.getLastPathComponent();
		}
		return null;
	}

	/**
	 * Gets the model node for the given path. This is useful if the node that is in the path has
	 * been replaced by a new node that is equal, but a different instance.  One way this happens
	 * is if the tree is filtered and therefor the displayed nodes are clones of the model nodes.  This
	 * can also happen if the tree nodes are rebuilt for some reason.
	 * 
	 * @param path the path of the node
	 * @return the corresponding model node in the tree.  If the tree is filtered the viewed node will
	 * be a clone of the corresponding model node.
	 */
	public GTreeNode getModelNodeForPath(TreePath path) {
		return getNodeForPath(getModelRoot(), path);
	}

	/**
	 * Gets the view node for the given path. This is useful to translate to a tree path that
	 * is valid for the currently displayed tree.  (Remember that if the tree is filtered,
	 * then the displayed nodes are clones of the model nodes.)
	 * 
	 * @param path the path of the node
	 * @return the current node in the displayed (possibly filtered) tree
	 */
	public GTreeNode getViewNodeForPath(TreePath path) {
		return getNodeForPath(getViewRoot(), path);
	}

	private GTreeNode getNodeForPath(GTreeNode root, TreePath path) {
		if (path == null || root == null) {
			return null;
		}

		GTreeNode node = (GTreeNode) path.getLastPathComponent();
		if (path.getPathCount() == 1) {
			if (root.equals(node)) {
				return root;
			}
			return null; // invalid path--the root of the path is not equal to our root!
		}
		if (node.getRoot() == root) {
			return node;
		}

		GTreeNode parentNode = getNodeForPath(root, path.getParentPath());
		if (parentNode == null) {
			return null; // must be a path we don't have
		}

		GTreeNode lastPathComponent = (GTreeNode) path.getLastPathComponent();
		List<GTreeNode> children = parentNode.getChildren();
		for (GTreeNode child : children) {
			if (child.equals(lastPathComponent)) {
				return child;
			}
		}
		return null;
	}

	public void setActiveDropTargetNode(GTreeNode node) {
		renderer.setRendererDropTarget(node);
	}

	public void setFilterText(String text) {
		filterProvider.setFilterText(text);
	}

	public GTreeFilterProvider getFilterProvider() {
		return filterProvider;
	}

	public void setFilterProvider(GTreeFilterProvider filterProvider) {
		this.filterProvider = filterProvider;
		removeAll();
		add(mainPanel, BorderLayout.CENTER);
		JComponent filterComponent = filterProvider.getFilterComponent();
		if (filterComponent != null) {
			add(filterComponent, BorderLayout.SOUTH);
		}
		filterProvider.setDataTransformer(transformer);
		updateModelFilter();
	}

	/**
	 * Disabled the filter text field, but allows the tree to still filter.  This is useful if
	 * you want to allow programmatic filtering, but to not allow the user to filter.
	 *
	 * @param enabled True makes the filter field editable; false makes it uneditable
	 * @see #setFilteringEnabled(boolean)
	 */
	public void setFilterFieldEnabled(boolean enabled) {
		filterProvider.setEnabled(enabled);
	}

	/**
	 * Disables all filtering performed by this tree.  Also, the filter field of the tree will
	 * be disabled.
	 * <p>
	 * Use this method to temporarily disable filtering.
	 *
	 * @param enabled True to allow normal filtering; false to disable all filtering
	 * @see #setFilterFieldEnabled(boolean)
	 */
	public void setFilteringEnabled(boolean enabled) {
		isFilteringEnabled = enabled;
		setFilterFieldEnabled(enabled);
		validate();
		refilterNow();
	}

	/**
	 * Hides the filter field.  Filtering will still take place, as defined by the
	 * {@link GTreeFilterProvider}.
	 *
	 * @param visible true to show the filter; false to hide it.
	 * @see #setFilteringEnabled(boolean)
	 */
	public void setFilterVisible(boolean visible) {
		JComponent filterComponent = filterProvider.getFilterComponent();
		filterComponent.setVisible(visible);
		validate();
	}

	public boolean isFilteringEnabled() {
		return isFilteringEnabled;
	}

	/**
	 * Sets a transformer object used to perform filtering.  This object is responsible for
	 * turning the tree's nodes into a list of strings that can be searched when filtering.
	 *
	 * @param transformer the transformer to set
	 */
	public void setDataTransformer(FilterTransformer<GTreeNode> transformer) {
		filterProvider.setDataTransformer(transformer);
	}

	/**
	 * Returns the filter text field in this tree.
	 *
	 * @return the filter text field in this tree.
	 */
	public Component getFilterField() {
		JComponent filterComponent = filterProvider.getFilterComponent();
		if (filterComponent != null) {
			Component[] components = filterComponent.getComponents();
			for (Component component : components) {
				if (component instanceof FilterTextField) {
					return component;
				}
			}
			return filterComponent;
		}
		return tree;
	}

	/**
	 * Returns true if the given JTree is the actual JTree used by this GTree.
	 * 
	 * @param jTree the tree to test
	 * @return true if the given JTree is the actual JTree used by this GTree.
	 */
	public boolean isMyJTree(JTree jTree) {
		return tree == jTree;
	}

	/**
	 * Sets the root node for this tree. 
	 * <P>
	 * NOTE: if this method is not called from the Swing thread, then the root node will be set
	 * later on the Swing thread.  That is, this method will return before the work has been done.
	 * 
	 * @param rootNode The node to set as the new root.
	 */
	public void setRootNode(GTreeNode rootNode) {
		Swing.runIfSwingOrRunLater(() -> {
			worker.clearAllJobs();
			rootNode.setParent(rootParent);
			realModelRootNode = rootNode;
			realViewRootNode = rootNode;
			GTreeNode oldRoot;
			oldRoot = swingSetModelRootNode(rootNode);
			oldRoot.dispose();
			if (filter != null) {
				filterUpdateManager.update();
			}
		});
	}

	void swingSetFilteredRootNode(GTreeNode filteredRootNode) {
		filteredRootNode.setParent(rootParent);
		realViewRootNode = filteredRootNode;
		GTreeNode currentRoot = swingSetModelRootNode(filteredRootNode);
		if (currentRoot != realModelRootNode) {
			currentRoot.disposeClones();
		}
	}

	void swingRestoreNonFilteredRootNode() {
		realViewRootNode = realModelRootNode;
		GTreeNode currentRoot = swingSetModelRootNode(realModelRootNode);
		if (currentRoot != realModelRootNode) {
			currentRoot.disposeClones();
		}
	}

	private GTreeNode swingSetModelRootNode(GTreeNode rootNode) {
		GTreeNode oldNode = model.getModelRoot();
		model.privateSwingSetRootNode(rootNode);
		return oldNode;
	}

	/**
	 * This method returns the root node that was provided to the tree by the client, whether from the
	 * constructor or from {@link #setRootNode(GTreeNode)}. 
	 * This node represents the data model and always contains all the nodes regardless of any filter
	 * being applied. If a filter is applied to the tree, then this is not the actual root node being
	 * displayed by the {@link JTree}.
	 * @return the root node as provided by the client.
	 */
	public GTreeNode getModelRoot() {
		return realModelRootNode;
	}

	/**
	 * This method returns the root node currently being displayed by the {@link JTree}.  If there
	 * are no filters applied, then this will be the same as the model root (See {@link #getModelRoot()}).
	 * If a filter is applied, then this will be a clone of the model root that contains clones of all
	 * nodes matching the filter. 
	 * @return the root node currently being display by the {@link JTree}
	 */
	public GTreeNode getViewRoot() {
		return realViewRootNode;
	}

	/**
	 * This method is useful for debugging tree problems.  Don't know where else to put it.
	 * @param out the output writer
	 * @param name use this to indicate what tree event occurred ("node inserted" "node removed", etc.)
	 * @param e the TreeModelEvent;
	 */
	public static void printEvent(PrintWriter out, String name, TreeModelEvent e) {
		StringBuffer buf = new StringBuffer();
		buf.append(name);
		buf.append("\n\tPath: ");
		Object[] path = e.getPath();
		if (path != null) {
			for (Object object : path) {
				GTreeNode node = (GTreeNode) object;
				buf.append(node.getName() + "(" + node.hashCode() + ")");
				buf.append(",");
			}
		}
		buf.append("\n\t");
		int[] childIndices = e.getChildIndices();
		if (childIndices != null) {
			buf.append("indices [ ");
			for (int index : childIndices) {
				buf.append(Integer.toString(index) + ", ");
			}
			buf.append("]\n\t");
		}
		Object[] children = e.getChildren();
		if (children != null) {
			buf.append("children [ ");
			for (Object child : children) {
				GTreeNode node = (GTreeNode) child;
				buf.append(node.getName() + "(" + node.hashCode() + "), ");
			}
			buf.append("]");
		}
		out.println(buf.toString());
	}

//==================================================================================================
// JTree Pass-through Methods
//==================================================================================================

	public TreeSelectionModel getSelectionModel() {
		return tree.getSelectionModel();
	}

	public GTreeSelectionModel getGTSelectionModel() {
		return (GTreeSelectionModel) tree.getSelectionModel();
	}

	public void setSelectionModel(GTreeSelectionModel selectionModel) {
		tree.setSelectionModel(selectionModel);
	}

	public int getRowCount() {
		return tree.getRowCount();
	}

	public int getRowForPath(TreePath treePath) {
		return tree.getRowForPath(treePath);
	}

	public TreePath getPathForRow(int row) {
		return tree.getPathForRow(row);
	}

	public TreePath getSelectionPath() {
		return tree.getSelectionPath();
	}

	public TreePath[] getSelectionPaths() {
		TreePath[] paths = tree.getSelectionPaths();
		if (paths == null) {
			paths = new TreePath[0];
		}
		return paths;
	}

	public boolean isExpanded(TreePath treePath) {
		return tree.isExpanded(treePath);
	}

	public boolean isPathSelected(TreePath treePath) {
		return tree.isPathSelected(treePath);
	}

	public boolean isRootVisible() {
		return tree.isRootVisible();
	}

	public void setRootVisible(boolean b) {
		tree.setRootVisible(b);
	}

	public void setShowsRootHandles(boolean b) {
		tree.setShowsRootHandles(b);
	}

	public void scrollPathToVisible(TreePath treePath) {
		tree.scrollPathToVisible(treePath);
	}

	public CellEditor getCellEditor() {
		return tree.getCellEditor();
	}

	public TreePath getPathForLocation(int x, int y) {
		return tree.getPathForLocation(x, y);
	}

	public Rectangle getPathBounds(TreePath path) {
		return tree.getPathBounds(path);
	}

	public void setRowHeight(int rowHeight) {
		tree.setRowHeight(rowHeight);
	}

	public void addSelectionPath(TreePath path) {
		tree.addSelectionPath(path);
	}

	public void addTreeExpansionListener(TreeExpansionListener listener) {
		tree.addTreeExpansionListener(listener);
	}

	public void removeTreeExpansionListener(TreeExpansionListener listener) {
		tree.removeTreeExpansionListener(listener);
	}

	public void addGTreeSelectionListener(GTreeSelectionListener listener) {
		GTreeSelectionModel selectionModel = (GTreeSelectionModel) tree.getSelectionModel();
		selectionModel.addGTreeSelectionListener(listener);
	}

	public void removeGTreeSelectionListener(GTreeSelectionListener listener) {
		GTreeSelectionModel selectionModel = (GTreeSelectionModel) tree.getSelectionModel();
		selectionModel.removeGTreeSelectionListener(listener);
	}

	public void addGTModelListener(TreeModelListener listener) {
		model.addTreeModelListener(listener);
	}

	public void removeGTModelListener(TreeModelListener listener) {
		model.removeTreeModelListener(listener);
	}

	public void setEditable(boolean editable) {
		tree.setEditable(editable);
	}

	/**
	 * Requests that the node with the given name, in the given parent, be edited.  <b>This 
	 * operation (as with many others on this tree) is asynchronous.</b>  This request will be
	 * buffered as needed to wait for the given node to be added to the parent, up to a timeout
	 * period.  
	 * 
	 * @param parent the parent node
	 * @param childName the child node name
	 */
	public void startEditing(GTreeNode parent, final String childName) {

		// we call this here, even though the JTree will do this for us, so that we will trigger
		// a load call before this task is run, in case lazy nodes are involved in this tree,
		// which must be loaded before we can edit
		expandPath(parent);

		//
		// The request to edit the node may be for a node that has not yet been added to this
		// tree.  Further, some clients will buffer events, which means that the node the client 
		// wishes to edit may not yet be in the parent node even if we run this request later on
		// the Swing thread.  To deal with this, we use a construct that will run our request
		// once the given node has been added to the parent.
		//
		BooleanSupplier isReady = () -> parent.getChild(childName) != null;
		int expireMs = 3000;
		ExpiringSwingTimer.runWhen(isReady, expireMs, () -> {
			runTask(new GTreeStartEditingTask(GTree.this, tree, parent, childName));
		});
	}

	@Override
	public synchronized void addMouseListener(MouseListener listener) {
		mouseListenerDelegate.addMouseListener(listener);
	}

	@Override
	public synchronized void removeMouseListener(MouseListener listener) {
		mouseListenerDelegate.removeMouseListener(listener);
	}

	@Override
	public synchronized MouseListener[] getMouseListeners() {
		return mouseListenerDelegate.getMouseListeners();
	}

	public void setCellEditor(TreeCellEditor editor) {
		tree.setCellEditor(editor);
	}

	public boolean isPathEditable(TreePath path) {
		GTreeNode node = (GTreeNode) path.getLastPathComponent();
		return node.isEditable();
	}

	/**
	 * Passing a value of <code>false</code> signals to disable the {@link JTree}'s default behavior
	 * of showing handles for leaf nodes until they are opened.
	 *
	 * @param enable False to disable the default JTree behavior
	 */
	public void setPaintHandlesForLeafNodes(boolean enable) {
		tree.setPaintHandlesForLeafNodes(enable);
	}

	public boolean isRootAllowedToCollapse() {
		return tree.isRootAllowedToCollapse();
	}

	public void setRootNodeAllowedToCollapse(boolean allowed) {
		tree.setRootNodeAllowedToCollapse(allowed);
	}

	private void showProgressPanel(boolean show) {
		if (show) {
			progressPanel = monitor;
			mainPanel.add(progressPanel, BorderLayout.SOUTH);
			progressPanel.invalidate();
		}
		else if (progressPanel != null) {
			mainPanel.remove(progressPanel);
			progressPanel = null;
		}
		validate();
		repaint();
	}

	private void showProgress(final int delay) {
		Runnable r = () -> {
			if (delay <= 0) {
				showProgressPanel(true);
			}
			else {
				showTimer = new Timer(delay, ev -> {
					if (isBusy()) {
						showProgressPanel(true);
						showTimer = null;
					}
				});
				showTimer.setInitialDelay(delay);
				showTimer.setRepeats(false);
				showTimer.start();
			}
		};
		SwingUtilities.invokeLater(r);
	}

	public boolean isBusy() {
		return worker.isBusy();
	}

	@Override
	public void setBusy(final boolean busy) {
		SystemUtilities.runSwingLater(() -> {
			if (busy) {
				showProgress(1000);
			}
			else {
				showProgressPanel(false);
			}
		});
	}

	/**
	 * Causes the tree to refilter immediately (before this method returns)
	 */
	public void refilterNow() {
		if (isFilteringEnabled && filter != null) {
			filterUpdateManager.updateNow();
		}
	}

	/**
	 * Causes the tree to refilter some time later
	 */
	public void refilterLater() {
		if (isFilteringEnabled && filter != null) {
			filterUpdateManager.update();
		}
	}

	/**
	 * Re-filters the tree if the newNode should be included in the current filter results. If
	 * the new node doesn't match the filter, there is no need to refilter the tree.
	 * @param newNode the node that may cause the tree to refilter.
	 */
	public void refilterLater(GTreeNode newNode) {
		if (isFilteringEnabled && filter != null) {
			if (filter.acceptsNode(newNode)) {
				filterUpdateManager.updateLater();
			}
		}
	}

	public GTreeFilter getFilter() {
		return filter;
	}

	public boolean isFiltered() {
		return filter != null;
	}

	public boolean hasFilterText() {
		return !StringUtils.isBlank(filterProvider.getFilterText());
	}

	public String getFilterText() {
		return filterProvider.getFilterText();
	}

	public void clearFilter() {
		filterProvider.setFilterText("");
	}

	/**
	 * Used to run tree tasks.  This method is not meant for general clients of this tree, but
	 * rather for tasks to tell the tree to perform subtasks.
	 * 
	 * @param task the task to run
	 */
	public void runTask(GTreeTask task) {
		worker.schedule(task);
	}

	/**
	 * Used to run simple GTree tasks that can be expressed as a {@link MonitoredRunnable}
	 * (or a lambda taking a {@link TaskMonitor}).
	 * <p>
	 * @param runnableTask {@link TaskMonitor} to watch and update with progress.
	 */
	public void runTask(MonitoredRunnable runnableTask) {
		worker.schedule(new GTreeTask(this) {
			@Override
			public void run(TaskMonitor localMonitor) throws CancelledException {
				runnableTask.monitoredRun(localMonitor);
			}
		});
	}

	public void runBulkTask(GTreeBulkTask task) {
		worker.schedule(task);
	}

	public boolean isEditing() {
		return tree.isEditing();
	}

	public void stopEditing() {
		tree.stopEditing();
	}

	public void setNodeEditable(GTreeNode child) {
		// for now only subclasses of GTree will set a node editable.
	}

	@Override
	public String toString() {
		GTreeNode rootNode = getModelRoot();
		if (rootNode == null) {
			return "GTree - no root node";
		}
		return rootNode.toString();
	}

	@Override
	public String getToolTipText(MouseEvent event) {
		String text = super.getToolTipText(event);
		if (text != null) {
			return text;
		}
		return tree.getDefaultToolTipText(event);
	}

	public void clearSizeCache() {
		recurseClearSizeCache(getViewRoot());
	}

	private void recurseClearSizeCache(GTreeNode node) {
		if (isExpanded(node.getTreePath())) {
			for (GTreeNode child : node.getChildren()) {
				recurseClearSizeCache(child);
			}
		}
		node.fireNodeChanged(node.getParent(), node);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	class AutoScrollTree extends JTree implements Autoscroll {

		private AutoscrollAdapter scroller;
		private boolean paintLeafHandles = true;
		private int scrollableUnitIncrementOverride = -1;
		private boolean allowRootCollapse = true;

		public AutoScrollTree(TreeModel model) {
			super(model);
			scroller = new AutoscrollAdapter(this, 5);

			setRowHeight(-1);// variable size rows
			setSelectionModel(new GTreeSelectionModel());
			setInvokesStopCellEditing(true);// clicking outside the cell editor will trigger a save, not a cancel

			updateDefaultKeyBindings();

			ToolTipManager.sharedInstance().registerComponent(this);
		}

		private void updateDefaultKeyBindings() {

			// Remove the edit keybinding, as the GTree triggers editing via a task, since it
			// is multi-threaded.  Doing this allows users to assign their own key bindings to 
			// the edit task.
			KeyBindingUtils.clearKeyBinding(this, "startEditing");
		}

		@Override
		public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation,
				int direction) {
			if (scrollableUnitIncrementOverride != -1) {
				return scrollableUnitIncrementOverride;
			}
			return super.getScrollableUnitIncrement(visibleRect, orientation, direction);
		}

		public void setScrollableUnitIncrement(int increment) {
			this.scrollableUnitIncrementOverride = increment;
		}

		@Override
		public String getToolTipText(MouseEvent event) {
			// Use the GTree's method so clients can override the behavior; provide the
			// default method below so we they can get the default behavior when needed.
			return GTree.this.getToolTipText(event);
		}

		public String getDefaultToolTipText(MouseEvent event) {
			return super.getToolTipText(event);
		}

		@Override
		public void autoscroll(Point cursorLocn) {
			scroller.autoscroll(cursorLocn);
		}

		@Override
		public Insets getAutoscrollInsets() {
			return scroller.getAutoscrollInsets();
		}

		@Override
		public boolean isPathEditable(TreePath path) {
			return GTree.this.isPathEditable(path);
		}

		@Override
		public boolean hasBeenExpanded(TreePath path) {
			if (paintLeafHandles) {
				return super.hasBeenExpanded(path);
			}
			return true;
		}

		public void setPaintHandlesForLeafNodes(boolean enable) {
			this.paintLeafHandles = enable;
		}

		public void setRootNodeAllowedToCollapse(boolean allowed) {
			if (allowRootCollapse == allowed) {
				return;
			}
			allowRootCollapse = allowed;

			if (!allowed) {
				if (model != null && model.getRoot() != null) {
					runTask(new GTreeExpandNodeToDepthTask(GTree.this, getJTree(),
						model.getModelRoot(), 1));
				}
			}
		}

		public boolean isRootAllowedToCollapse() {
			return allowRootCollapse;
		}

		/**
		 * Need to override the addMouseListener method of the JTree to defer to the
		 *  delegate mouse listener.  The GTree uses a mouse listener delegate for itself
		 *  and the JTree it wraps.  When the delegate was installed, it moved all the existing mouse
		 *  listeners from the JTree to the delegate. Any additional listeners should also
		 *  be moved to the delegate.   Otherwise, some Ghidra components that use a convention/pattern
		 *  to avoid listener duplication by first removing a listener before adding it,
		 *  don't work and duplicates get added.
		 */
		@Override
		public synchronized void addMouseListener(MouseListener l) {
			if (mouseListenerDelegate == null) {
				super.addMouseListener(l);
			}
			else {
				mouseListenerDelegate.addMouseListener(l);
			}
		}

		/**
		 * Need to override the removeMouseListener method of the JTree to defer to the
		 *  delegate mouse listener.  The GTree uses a mouse listener delegate for itself
		 *  and the JTree it wraps.  When the delegate was installed, it moved all the existing mouse
		 *  listeners from the JTree to the delegate. All listener remove calls should also
		 *  be moved to the delegate.   Otherwise, some Ghidra components that use a convention/pattern
		 *  to avoid listener duplication by first removing a listener before adding it,
		 *  don't work and duplicates get added.
		 */
		@Override
		public synchronized void removeMouseListener(MouseListener l) {
			if (mouseListenerDelegate == null) {
				super.removeMouseListener(l);
			}
			else {
				mouseListenerDelegate.removeMouseListener(l);
			}
		}

		@Override
		public void removeSelectionPath(TreePath path) {
			// Called by the UI to add/remove selections--mark it as a user event.
			// Note: this code is based upon the fact that the BasicTreeUI calls this method on
			//       the tree when processing user clicks.  If another UI implementation were
			//       to call a different method, then we would have to re-think how we mark our
			//       events as user vs internally generated.
			GTreeSelectionModel gTreeSelectionModel = (GTreeSelectionModel) getSelectionModel();
			gTreeSelectionModel.userRemovedSelectionPath(path);
		}
	}

	private class GTreeMouseListenerDelegate extends JTreeMouseListenerDelegate {
		private final GTree gTree;

		GTreeMouseListenerDelegate(JTree jTree, GTree gTree) {
			super(jTree);
			this.gTree = gTree;
		}

		/**
		 * Calling setSelectedPaths on GTree queues the selection for after
		 * any currently scheduled tasks. This method sets the selected path immediately
		 * and does not wait for for scheduled tasks.
		 * @param path the path to select.
		 */
		@Override
		protected void setSelectedPathNow(TreePath path) {
			GTreeSelectionModel selectionModel = (GTreeSelectionModel) gTree.getSelectionModel();
			selectionModel.setSelectionPaths(new TreePath[] { path }, USER_GENERATED);
		}
	}

//==================================================================================================
// Static Methods
//==================================================================================================

	private static String generateFilterPreferenceKey() {
		Throwable throwable = new Throwable();
		StackTraceElement[] stackTrace = throwable.getStackTrace();
		return getInceptionInformationFromTheFirstClassThatIsNotUs(stackTrace);
	}

	private static String getInceptionInformationFromTheFirstClassThatIsNotUs(
			StackTraceElement[] stackTrace) {

		// To find our creation point we can use a simple algorithm: find the name of our class,
		// which is in the first stack trace element and then keep walking backwards until that
		// name is not ours.
		//
		String myClassName = GTree.class.getName();
		int myClassNameStartIndex = -1;
		for (int i = 1; i < stackTrace.length; i++) {// start at 1, because we are the first item
			StackTraceElement stackTraceElement = stackTrace[i];
			String elementClassName = stackTraceElement.getClassName();
			if (myClassName.equals(elementClassName)) {
				myClassNameStartIndex = i;
				break;
			}
		}

		int creatorIndex = myClassNameStartIndex;
		for (int i = myClassNameStartIndex; i < stackTrace.length; i++) {
			StackTraceElement stackTraceElement = stackTrace[i];
			String elementClassName = stackTraceElement.getClassName();

			if (!myClassName.equals(elementClassName) &&
				!elementClassName.toLowerCase().endsWith("tree")) {
				creatorIndex = i;
				break;
			}
		}

		return stackTrace[creatorIndex].getClassName();
	}

}
