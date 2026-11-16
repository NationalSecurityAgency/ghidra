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
package docking.widgets.gtreetable;

import java.util.*;

import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GTreeTableModel<T extends GTreeTableNode> extends ThreadedTableModelStub<T> {
	public abstract static class AbstractTreeColumn<T extends GTreeTableNode>
			extends AbstractDynamicTableColumnStub<T, GTreeTableNode> {

		@Override
		public GTreeTableNode getValue(T rowObject, Settings settings, ServiceProvider provider)
				throws IllegalArgumentException {
			return rowObject;
		}

		@Override
		public Comparator<GTreeTableNode> getComparator() {
			return Comparator.comparingInt(GTreeTableNode::getIndex);
		}

		@Override
		public abstract GTreeTableCellRenderer<GTreeTableNode> getColumnRenderer();
	}

	public static class TreeColumn<T extends GTreeTableNode> extends AbstractTreeColumn<T> {
		private final GTreeTableCellRenderer<GTreeTableNode> renderer;

		public TreeColumn() {
			this.renderer = new GTreeTableCellRenderer<>();
		}

		@Override
		public String getColumnName() {
			return "Tree";
		}

		@Override
		public GTreeTableCellRenderer<GTreeTableNode> getColumnRenderer() {
			return renderer;
		}
	}

	private GTreeTableNode rootNode;

	public GTreeTableModel(GTreeTableNode rootNode) {
		super("", null);
		this.rootNode = rootNode;
	}

	/**
	 * Add the {@link TreeColumn} by default, override to add additional columns
	 * <p>
	 * {@inheritDoc}
	 */
	@Override
	protected TableColumnDescriptor<T> createTableColumnDescriptor() {
		final TableColumnDescriptor<T> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new TreeColumn<>(), 0, true);

		return descriptor;
	}

	/**
	 * Any rows that match the filter have all of their ancestors added to the filtered tree to
	 * ensure the tree structure remains intact
	 * <p>
	 * {@inheritDoc}
	 */
	@SuppressWarnings("unchecked")
	@Override
	protected List<T> doFilter(List<T> data, TableSortingContext<T> lastSortingContext,
			TaskMonitor monitor) throws CancelledException {
		if ((data.isEmpty()) || !hasFilter()) {
			return data;
		}

		final TableFilter<T> filterCopy = getTableFilter();
		final Set<T> filteredList = new HashSet<>();
		final List<T> returnFilteredList = new ArrayList<>();

		monitor.initialize(data.size());

		for (final T rowObject : data) {
			if (monitor.isCancelled()) {
				return new ArrayList<>(filteredList);
			}

			if (filterCopy.acceptsRow(rowObject)) {
				filteredList.add(rowObject);
				rowObject.forEachAncestor(c -> filteredList.add((T) c));
			}
			monitor.incrementProgress(1);
		}

		// Reorder them
		for (final T rowObject : data) {
			if (monitor.isCancelled()) {
				return new ArrayList<>(filteredList);
			}

			if (filteredList.contains(rowObject)) {
				returnFilteredList.add(rowObject);
			}
		}

		return returnFilteredList;
	}

	@SuppressWarnings("unchecked")
	@Override
	protected void doLoad(Accumulator<T> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (rootNode != null) {
			rootNode.reindex();
			for (final GTreeTableNode c : rootNode.expandedDescendants()) {
				monitor.checkCancelled();
				if (c.isVisible()) {
					accumulator.add((T) c);
				}
			}
		}
	}

	/**
	 * Set the root node of this model
	 *
	 * @param node Root node to set
	 * @return True if node is different, false otherwise
	 */
	public boolean setRootNode(GTreeTableNode node) {
		boolean ret = rootNode != node;
		rootNode = node;
		reload();
		return ret;
	}
}
