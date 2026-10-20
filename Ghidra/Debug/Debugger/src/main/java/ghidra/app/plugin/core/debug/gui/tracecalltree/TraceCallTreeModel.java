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
package ghidra.app.plugin.core.debug.gui.tracecalltree;

import java.util.HashSet;
import java.util.Set;

import docking.widgets.gtreetable.GTreeTableModel;
import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;

class TraceCallTreeModel extends GTreeTableModel<AbstractTraceCallTreeNode> {

	private static class ModuleColumn
			extends AbstractDynamicTableColumnStub<AbstractTraceCallTreeNode, String> {
		private final String columnName;

		ModuleColumn(String columnName) {
			this.columnName = columnName;
		}

		@Override
		public String getColumnName() {
			return columnName;
		}

		@Override
		public String getValue(AbstractTraceCallTreeNode rowObject, Settings settings,
				ServiceProvider provider) {
			return rowObject.getModule();
		}

	}

	private static class ParameterColumn
			extends AbstractDynamicTableColumnStub<AbstractTraceCallTreeNode, String> {
		private final int paramNum;

		ParameterColumn(int paramNum) {
			this.paramNum = paramNum;
		}

		@Override
		public String getColumnName() {
			return "Parameter %d".formatted(paramNum);
		}

		@Override
		public String getValue(AbstractTraceCallTreeNode rowObject, Settings settings,
				ServiceProvider provider) {
			return rowObject.getParameterString(paramNum);
		}
	}

	private static class ReturnColumn
			extends AbstractDynamicTableColumnStub<AbstractTraceCallTreeNode, String> {
		private final String columnName;

		ReturnColumn(String columnName) {
			this.columnName = columnName;
		}

		@Override
		public String getColumnName() {
			return columnName;
		}

		@Override
		public String getValue(AbstractTraceCallTreeNode rowObject, Settings settings,
				ServiceProvider provider) {
			return rowObject.getReturnValString();
		}
	}

	private static class SnapColumn
			extends AbstractDynamicTableColumnStub<AbstractTraceCallTreeNode, Long> {
		private final String columnName;

		SnapColumn(String columnName) {
			this.columnName = columnName;
		}

		@Override
		public String getColumnName() {
			return columnName;
		}

		@Override
		public Long getValue(AbstractTraceCallTreeNode rowObject, Settings settings,
				ServiceProvider provider) {
			return rowObject.getSnapshotKey();
		}

	}

	Set<DynamicTableColumn<AbstractTraceCallTreeNode, ?, ?>> parameterColumns = new HashSet<>();

	public TraceCallTreeModel(AbstractTraceCallTreeNode rootNode) {
		super(rootNode);
	}

	@Override
	protected TableColumnDescriptor<AbstractTraceCallTreeNode> createTableColumnDescriptor() {
		final TableColumnDescriptor<AbstractTraceCallTreeNode> descriptor =
			super.createTableColumnDescriptor();
		descriptor.addVisibleColumn(new SnapColumn("Snapshot"));
		descriptor.addVisibleColumn(new ModuleColumn("Module"));
		descriptor.addVisibleColumn(new ReturnColumn("Return"));
		return descriptor;
	}

	public void setNumberOfParameterColumns(int num) {
		removeTableColumns(parameterColumns);
		parameterColumns.clear();
		for (int i = 0; i < num; i++) {
			final ParameterColumn column = new ParameterColumn(i);
			parameterColumns.add(column);
		}
		if (!parameterColumns.isEmpty()) {
			addTableColumns(parameterColumns);
		}
	}

	@Override
	protected String treeColumnName() {
		return "Function";
	}
}
