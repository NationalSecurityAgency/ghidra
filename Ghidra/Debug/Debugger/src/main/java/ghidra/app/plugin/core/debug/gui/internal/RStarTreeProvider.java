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
package ghidra.app.plugin.core.debug.gui.internal;

import java.awt.BorderLayout;
import java.util.*;

import javax.swing.*;

import docking.widgets.tree.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.util.database.spatial.*;

public class RStarTreeProvider extends ComponentProviderAdapter {
	private final RStarDiagnosticsPlugin plugin;

	interface HasShape {
		TraceAddressSnapRange getShape();
	}

	class RootRStarNode extends GTreeLazyNode implements HasShape {
		@Override
		public TraceAddressSnapRange getShape() {
			if (plugin == null || plugin.space == null) {
				return null;
			}
			return plugin.space.getRootBounds();
		}

		@Override
		public String getName() {
			TraceAddressSnapRange root = getShape();
			if (root == null) {
				return "No Shape";
			}
			return root.toString();
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}

		@Override
		protected List<GTreeNode> generateChildren() {
			if (!(getShape() instanceof DBTreeNodeRecord<?> rec)) {
				return List.of();
			}
			return plugin.space.getChildrenOf(rec).stream().map(n -> nodeFor(n)).toList();
		}
	}

	class NodeRStarNode extends GTreeLazyNode implements HasShape {
		final DBTreeNodeRecord<?> rec;

		public NodeRStarNode(DBTreeNodeRecord<?> rec) {
			this.rec = rec;
		}

		@Override
		public TraceAddressSnapRange getShape() {
			return (TraceAddressSnapRange) rec.getShape();
		}

		@Override
		public String getName() {
			return rec.toString();
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}

		@Override
		protected List<GTreeNode> generateChildren() {
			return plugin.space.getChildrenOf(rec).stream().map(n -> nodeFor(n)).toList();
		}
	}

	class DataRStarNode extends GTreeNode implements HasShape {
		final DBTreeDataRecord<?, ?, ?> rec;

		public DataRStarNode(DBTreeDataRecord<?, ?, ?> rec) {
			this.rec = rec;
		}

		@Override
		public TraceAddressSnapRange getShape() {
			return (TraceAddressSnapRange) rec.getShape();
		}

		@Override
		public String getName() {
			return rec.toString();
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
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

	final Map<DBTreeRecord<?, ?>, GTreeNode> nodes = new HashMap<>();

	private GTreeNode nodeFor(DBTreeRecord<?, ?> rec) {
		if (rec == plugin.space.getRootBounds()) {
			return root;
		}
		return nodes.computeIfAbsent(rec, r -> switch (rec) {
			case DBTreeNodeRecord<?> n -> new NodeRStarNode(n);
			case DBTreeDataRecord<?, ?, ?> d -> new DataRStarNode(d);
			default -> throw new AssertionError();
		});
	}

	final RootRStarNode root = new RootRStarNode();
	final GTree tree = new GTree(root);
	final JPanel panel = new JPanel(new BorderLayout());

	public RStarTreeProvider(RStarDiagnosticsPlugin plugin) {
		super(plugin.getTool(), "R*-Tree Diagnostic Tree", plugin.getName());
		this.plugin = plugin;
		this.panel.add(tree);

		tree.addGTreeSelectionListener(e -> {
			plugin.plotProvider.component.repaint();
		});
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	public void select(TraceAddressSnapRange shape) {
		if (!(shape instanceof DBTreeRecord<?, ?> rec)) {
			return;
		}
		tree.getSelectionModel().setSelectionPath(nodeFor(rec).getTreePath());
	}

	void refresh() {
		root.unloadChildren();
		nodes.clear();
	}
}
