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
import java.awt.event.MouseListener;
import java.util.*;
import java.util.List;
import java.util.stream.*;

import javax.swing.JPanel;
import javax.swing.JTree;
import javax.swing.tree.TreePath;

import com.google.common.collect.Range;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeRenderer;
import docking.widgets.tree.support.GTreeSelectionListener;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.model.ObjectTreeModel.AbstractNode;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObjectKeyPath;

public class ObjectsTreePanel extends JPanel {

	protected class ObjectsTreeRenderer extends GTreeRenderer implements ColorsModified.InTree {
		{
			setHTMLRenderingEnabled(true);
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

	protected final ObjectTreeModel treeModel;
	protected final GTree tree;

	protected DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	protected boolean limitToSnap = true;
	protected boolean showHidden = false;
	protected boolean showPrimitives = false;
	protected boolean showMethods = false;

	protected Color diffColor = DebuggerResources.DEFAULT_COLOR_VALUE_CHANGED;
	protected Color diffColorSel = DebuggerResources.DEFAULT_COLOR_VALUE_CHANGED_SEL;

	public ObjectsTreePanel() {
		super(new BorderLayout());
		treeModel = createModel();
		tree = new GTree(treeModel.getRoot());

		tree.setCellRenderer(new ObjectsTreeRenderer());
		add(tree, BorderLayout.CENTER);
	}

	protected ObjectTreeModel createModel() {
		return new ObjectTreeModel();
	}

	protected KeepTreeState keepTreeState() {
		return new KeepTreeState(tree);
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
		// TODO: thread should probably become a TraceObject once we transition
		if (DebuggerCoordinates.equalsIgnoreRecorderAndView(current, coords)) {
			return;
		}
		DebuggerCoordinates previous = current;
		this.current = coords;
		try (KeepTreeState keep = keepTreeState()) {
			treeModel.setDiffTrace(computeDiffTrace(current.getTrace(), previous.getTrace()));
			treeModel.setTrace(current.getTrace());
			treeModel.setDiffSnap(previous.getSnap());
			treeModel.setSnap(current.getSnap());
			if (limitToSnap) {
				treeModel.setSpan(Range.singleton(current.getSnap()));
			}
			tree.filterChanged();
		}
	}

	public void setLimitToSnap(boolean limitToSnap) {
		if (this.limitToSnap == limitToSnap) {
			return;
		}
		this.limitToSnap = limitToSnap;
		try (KeepTreeState keep = keepTreeState()) {
			treeModel.setSpan(limitToSnap ? Range.singleton(current.getSnap()) : Range.all());
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

	@Override
	public synchronized void addMouseListener(MouseListener l) {
		super.addMouseListener(l);
		// Is this a HACK?
		tree.addMouseListener(l);
	}

	@Override
	public synchronized void removeMouseListener(MouseListener l) {
		super.removeMouseListener(l);
		// HACK?
		tree.removeMouseListener(l);
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

	public void setSelectedKeyPaths(Collection<TraceObjectKeyPath> keyPaths) {
		List<GTreeNode> nodes = new ArrayList<>();
		for (TraceObjectKeyPath path : keyPaths) {
			AbstractNode node = getNode(path);
			if (node != null) {
				nodes.add(node);
			}
		}
		tree.setSelectedNodes(nodes);
	}
}
