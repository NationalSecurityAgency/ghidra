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
package ghidra.app.plugin.core.debug.gui.model;

import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.stream.*;

import javax.swing.JPanel;
import javax.swing.JTree;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;
import javax.swing.tree.TreePath;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeRenderer;
import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin;
import docking.widgets.tree.support.GTreeSelectionListener;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.model.ObjectTreeModel.AbstractNode;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.*;
import ghidra.util.Swing;

public class ObjectsTreePanel extends JPanel {

	protected class ObjectsTreeRenderer extends GTreeRenderer implements ColorsModified.InTree {
		{
			setHTMLRenderingEnabled(true);
		}

		private boolean isOnCurrentPath(TraceObjectValue value) {
			if (value == null) {
				return false;
			}
			return (value.getValue() instanceof TraceObject child && isOnCurrentPath(child));
		}

		private boolean isOnCurrentPath(TraceObject object) {
			TraceObject cur = current.getObject();
			if (cur == null) {
				return false;
			}
			return object.getCanonicalPath().isAncestor(cur.getCanonicalPath());
		}

		@Override
		public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected,
				boolean expanded, boolean leaf, int row, boolean hasFocus) {
			super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row,
				hasFocus);
			if (!(value instanceof AbstractNode)) {
				return this;
			}

			AbstractNode node = (AbstractNode) value;
			setForeground(getForegroundFor(tree, node.isModified(), selected));
			setFont(getFont(isOnCurrentPath(node.getValue())));
			return this;
		}

		@Override
		public Color getDiffForeground(JTree tree) {
			return diffColor;
		}

		@Override
		public Color getDiffSelForeground(JTree tree) {
			return diffColorSel;
		}
	}

	static class ObjectGTree extends GTree {
		public ObjectGTree(GTreeNode root) {
			super(root);
			getJTree().setToggleClickCount(0);
		}

		JTree tree() {
			return getJTree();
		}
	}

	protected static class DelayedSwingHack implements Runnable {
		public static void runWayLater(int delay, Runnable runnable) {
			Swing.runLater(new DelayedSwingHack(delay, runnable));
		}

		private int delay;
		private final Runnable runnable;

		public DelayedSwingHack(int delay, Runnable runnable) {
			this.delay = delay;
			this.runnable = runnable;
		}

		@Override
		public void run() {
			if (--delay == 0) {
				runnable.run();
			}
			else {
				Swing.runLater(this);
			}
		}
	}

	protected class ListenerForShowing implements AncestorListener {
		boolean showing = false;
		int version = 0;

		@Override
		public void ancestorRemoved(AncestorEvent event) {
			updateShowing();
		}

		@Override
		public void ancestorMoved(AncestorEvent event) {
			updateShowing();
		}

		@Override
		public void ancestorAdded(AncestorEvent event) {
			updateShowing();
		}

		public void updateShowing() {
			/**
			 * There may be several changes to visibility throughout some routines running on the
			 * Swing thread. To avoid processing such frantic changes, we aim to wait for the last
			 * change. Thus, we increment a version counter and schedule a delayed lambda on the
			 * Swing thread. That lambda will only actually do anything if the version number hasn't
			 * been incremented, i.e., some additional change hasn't occurred. This should prevent
			 * intermediate changes, e.g., when re-docking the window, from causing needless
			 * updates.
			 */
			final int v = ++version;
			DelayedSwingHack.runWayLater(2, () -> {
				if (v == version) {
					version = 0;
					setShowing(ObjectsTreePanel.this.isShowing());
				}
			});
		}

		private void setShowing(boolean showing) {
			if (this.showing == showing) {
				return;
			}
			this.showing = showing;
			showingChanged(showing);
		}
	}

	protected final ObjectTreeModel treeModel;
	protected final ObjectGTree tree;

	protected boolean showing = false;
	protected Set<TraceObjectKeyPath> savedSelection = null;
	protected DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	protected DebuggerCoordinates previous = DebuggerCoordinates.NOWHERE;
	protected boolean limitToSnap = true;
	protected boolean showHidden = false;
	protected boolean showPrimitives = false;
	protected boolean showMethods = false;

	protected Color diffColor = DebuggerResources.COLOR_VALUE_CHANGED;
	protected Color diffColorSel = DebuggerResources.COLOR_VALUE_CHANGED_SEL;

	protected final ListenerForShowing listenerForShowing = new ListenerForShowing();

	public ObjectsTreePanel() {
		super(new BorderLayout());

		addAncestorListener(listenerForShowing);

		treeModel = createModel();
		tree = new ObjectGTree(treeModel.getRoot());

		tree.setCellRenderer(new ObjectsTreeRenderer());
		add(tree, BorderLayout.CENTER);
	}

	protected ObjectTreeModel createModel() {
		return new ObjectTreeModel();
	}

	protected KeepTreeState keepTreeState() {
		return new KeepTreeState(tree);
	}

	protected void showingChanged(boolean showing) {
		if (!showing) {
			savedSelection = getSelectedKeyPaths();
		}
		this.showing = showing;
		updateTreeModelForCoordinates();
		updateTreeModelForSpan();
		updateTreeModelForShowHidden();
		updateTreeModelForShowPrimitives();
		updateTreeModelForShowMethods();
		if (showing && savedSelection != null) {
			setSelectedKeyPaths(savedSelection, EventOrigin.INTERNAL_GENERATED);
		}
		// Restore expansion? Nah.
	}

	protected Trace computeDiffTrace(Trace current, Trace previous) {
		if (current == null) {
			return null;
		}
		if (previous == null) {
			return current;
		}
		return previous;
	}

	public void goToCoordinates(DebuggerCoordinates coords) {
		if (DebuggerCoordinates.equalsIgnoreRecorderAndView(current, coords)) {
			return;
		}
		previous = current;
		current = coords;
		if (previous.getSnap() == current.getSnap() &&
			previous.getTrace() == current.getTrace() &&
			previous.getObject() == current.getObject()) {
			return;
		}
		updateTreeModelForCoordinates();
	}

	protected void updateTreeModelForCoordinates() {
		if (!showing) {
			// Clear it out and have it remove its listeners
			treeModel.setTrace(null);
			return;
		}
		try (KeepTreeState keep = keepTreeState()) {
			treeModel.setDiffTrace(computeDiffTrace(current.getTrace(), previous.getTrace()));
			treeModel.setTrace(current.getTrace());
			treeModel.setDiffSnap(previous.getSnap());
			treeModel.setSnap(current.getSnap());
			if (limitToSnap) {
				treeModel.setSpan(Lifespan.at(current.getSnap()));
			}
			//tree.filterChanged();
			// Repaint for bold current path is already going to happen
		}
	}

	public void setLimitToSnap(boolean limitToSnap) {
		if (this.limitToSnap == limitToSnap) {
			return;
		}
		this.limitToSnap = limitToSnap;
		updateTreeModelForSpan();
	}

	protected void updateTreeModelForSpan() {
		if (!showing) {
			return;
		}
		try (KeepTreeState keep = keepTreeState()) {
			treeModel.setSpan(limitToSnap ? Lifespan.at(current.getSnap()) : Lifespan.ALL);
		}
	}

	public boolean isLimitToSnap() {
		return limitToSnap;
	}

	public void setShowHidden(boolean showHidden) {
		if (this.showHidden == showHidden) {
			return;
		}
		this.showHidden = showHidden;
		updateTreeModelForShowHidden();
	}

	protected void updateTreeModelForShowHidden() {
		if (!showing) {
			return;
		}
		try (KeepTreeState keep = keepTreeState()) {
			treeModel.setShowHidden(showHidden);
		}
	}

	public boolean isShowHidden() {
		return showHidden;
	}

	public void setShowPrimitives(boolean showPrimitives) {
		if (this.showPrimitives == showPrimitives) {
			return;
		}
		this.showPrimitives = showPrimitives;
		updateTreeModelForShowPrimitives();
	}

	protected void updateTreeModelForShowPrimitives() {
		if (!showing) {
			return;
		}
		try (KeepTreeState keep = keepTreeState()) {
			treeModel.setShowPrimitives(showPrimitives);
		}
	}

	public boolean isShowPrimitives() {
		return showPrimitives;
	}

	public void setShowMethods(boolean showMethods) {
		if (this.showMethods == showMethods) {
			return;
		}
		this.showMethods = showMethods;
		updateTreeModelForShowMethods();
	}

	protected void updateTreeModelForShowMethods() {
		if (!showing) {
			return;
		}
		try (KeepTreeState keep = keepTreeState()) {
			treeModel.setShowMethods(showMethods);
		}
	}

	public boolean isShowMethods() {
		return showMethods;
	}

	public void setDiffColor(Color diffColor) {
		if (Objects.equals(this.diffColor, diffColor)) {
			return;
		}
		this.diffColor = diffColor;
		repaint();
	}

	public void setDiffColorSel(Color diffColorSel) {
		if (Objects.equals(this.diffColorSel, diffColorSel)) {
			return;
		}
		this.diffColorSel = diffColorSel;
		repaint();
	}

	public void addTreeSelectionListener(GTreeSelectionListener listener) {
		tree.addGTreeSelectionListener(listener);
	}

	public void removeTreeSelectionListener(GTreeSelectionListener listener) {
		tree.removeGTreeSelectionListener(listener);
	}

	public void setSelectionMode(int selectionMode) {
		tree.getSelectionModel().setSelectionMode(selectionMode);
	}

	public int getSelectionMode() {
		return tree.getSelectionModel().getSelectionMode();
	}

	protected <R, A> R getItemsFromPaths(TreePath[] paths,
			Collector<? super AbstractNode, A, R> collector) {
		return Stream.of(paths)
				.map(p -> (AbstractNode) p.getLastPathComponent())
				.collect(collector);
	}

	protected AbstractNode getItemFromPath(TreePath path) {
		if (path == null) {
			return null;
		}
		return (AbstractNode) path.getLastPathComponent();
	}

	public List<AbstractNode> getSelectedItems() {
		return getItemsFromPaths(tree.getSelectionPaths(), Collectors.toList());
	}

	public AbstractNode getSelectedItem() {
		return getItemFromPath(tree.getSelectionPath());
	}

	public AbstractNode getNode(TraceObjectKeyPath path) {
		return treeModel.getNode(path);
	}

	public void setSelectedKeyPaths(Collection<TraceObjectKeyPath> keyPaths, EventOrigin origin) {
		savedSelection = keyPaths instanceof Set<TraceObjectKeyPath> s ? s : Set.copyOf(keyPaths);
		List<TreePath> treePaths = new ArrayList<>();
		for (TraceObjectKeyPath path : keyPaths) {
			AbstractNode node = getNode(path);
			if (node != null) {
				treePaths.add(node.getTreePath());
			}
		}
		tree.setSelectionPaths(treePaths.toArray(TreePath[]::new), origin);
	}

	public Set<TraceObjectKeyPath> getSelectedKeyPaths() {
		Set<TraceObjectKeyPath> result = new HashSet<>();
		for (AbstractNode node : getSelectedItems()) {
			TraceObjectValue value = node.getValue();
			if (value == null) {
				result.add(TraceObjectKeyPath.of());
			}
			else {
				result.add(value.getCanonicalPath());
			}
		}
		return result;
	}

	public void setSelectedKeyPaths(Collection<TraceObjectKeyPath> keyPaths) {
		setSelectedKeyPaths(keyPaths, EventOrigin.API_GENERATED);
	}

	public void expandCurrent() {
		TraceObject object = current.getObject();
		if (object == null) {
			return;
		}
		AbstractNode node = getNode(object.getCanonicalPath());
		TreePath parentPath = node.getTreePath().getParentPath();
		if (parentPath != null) {
			tree.expandPath(parentPath);
		}
	}

	public void setSelectedObject(TraceObject object) {
		if (object == null) {
			tree.clearSelectionPaths();
			return;
		}
		AbstractNode node = getNode(object.getCanonicalPath());
		if (node != null) {
			tree.addSelectionPath(node.getTreePath());
		}
	}

	public void selectCurrent() {
		setSelectedObject(current.getObject());
	}
}
