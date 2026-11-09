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
package ghidra.app.plugin.core.debug.gui.slice;

import docking.widgets.gtreetable.GTreeTableModel;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;

class SliceModel extends GTreeTableModel<AbstractSliceNode> {
	RootSliceNode root;

	public SliceModel(Trace trace, Program image, Address staticPc) {
		RootSliceNode root = new RootSliceNode(trace, image, staticPc);
		this.root = root;
		super(root);
	}

	public RootSliceNode getRoot() {
		return root;
	}

	@Override
	protected TableColumnDescriptor<AbstractSliceNode> createTableColumnDescriptor() {
		// Do not call super. Replace default "Tree" column.
		TableColumnDescriptor<AbstractSliceNode> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new ItemSliceColumn());
		descriptor.addVisibleColumn(new LocationSliceColumn());
		descriptor.addVisibleColumn(new SnapSliceColumn());
		descriptor.addHiddenColumn(new BytesSliceColumn());
		descriptor.addVisibleColumn(new CheckedSliceColumn());
		return descriptor;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return getColumn(columnIndex) instanceof CheckedSliceColumn;
	}

	@Override
	public void setValueAt(Object value, int rowIndex, int columnIndex) {
		if (!isCellEditable(rowIndex, columnIndex) || !(value instanceof Boolean checked)) {
			return;
		}
		AbstractSliceNode node = getRowObject(rowIndex);
		if (node == null) {
			return;
		}
		node.setChecked(checked);
		fireTableCellUpdated(rowIndex, columnIndex);
	}
}
