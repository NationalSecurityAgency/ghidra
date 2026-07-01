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
package ghidra.app.plugin.core.debug.gui.emulation;

import javax.swing.table.TableModel;

import db.Transaction;
import ghidra.app.services.DataTypeManagerService;
import ghidra.base.widgets.table.AbstractDataTypeTableCellEditor;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;

class VarDataTypeEditor extends AbstractDataTypeTableCellEditor {
	static final VarDataTypeEditor INSTANCE = new VarDataTypeEditor();

	@Override
	protected boolean validateSelection(DataType dataType, TableModel model) {
		if (!(model instanceof VarTableModel<?, ?> vModel)) {
			return false;
		}

		VarRow row = vModel.getModelData().get(table.getEditingRow());
		if (row == null) {
			return false;
		}
		int dtLength = dataType.getLength();
		if (dtLength != -1 && dtLength != row.length) {
			vModel.getDialog()
					.setStatusText("Invalid DataType %s. Length must be %d.".formatted(dataType,
						row.length));
			return false;
		}
		return true;
	}

	@Override
	protected DataTypeManagerService getService(TableModel model) {
		if (!(model instanceof VarTableModel<?, ?> vModel)) {
			return null;
		}
		return vModel.getServiceProvider().getService(DataTypeManagerService.class);
	}

	@Override
	protected DataType resolveSelection(DataType dataType, TableModel model) {
		if (dataType == null || !(model instanceof VarTableModel<?, ?> vModel)) {
			return null;
		}
		Program program = vModel.getProgram();
		try (Transaction tx = program.openTransaction("Resolve DataTye")) {
			return program.getDataTypeManager().resolve(dataType, null);
		}
	}
}
