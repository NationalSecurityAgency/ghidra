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
package ghidra.app.plugin.core.compositeeditor;

import java.awt.Component;

import docking.DockingWindowManager;
import ghidra.program.model.data.*;

/**
 * Editor panel for Union datatype
 */
public class StructureEditorPanel extends CompEditorPanel<Structure, StructureEditorModel> {

	public StructureEditorPanel(StructureEditorModel model, StructureEditorProvider provider) {
		super(model, provider);
	}

	@Override
	boolean launchBitFieldEditor(int modelRow, int modelColumn) {
		if (!model.viewComposite.isPackingEnabled() &&
			model.getDataTypeColumn() == modelColumn && modelRow < model.getNumComponents()) {
			// check if we are attempting to edit a bitfield
			DataTypeComponent dtComponent = model.getComponent(modelRow);
			if (dtComponent.isBitFieldComponent()) {
				table.getCellEditor().cancelCellEditing();
				BitFieldEditorDialog dlg = new BitFieldEditorDialog(model.viewComposite,
					provider.dtmService, modelRow, model.showHexNumbers,
					ordinal -> refreshTableAndSelection(model, ordinal));
				Component c = provider.getComponent();
				DockingWindowManager.showDialog(c, dlg);
				return true;
			}
		}
		return false;
	}

	private void refreshTableAndSelection(StructureEditorModel editorModel, int ordinal) {
		editorModel.notifyCompositeChanged();
		editorModel.setSelection(new int[] { ordinal, ordinal });
	}

	void goToOffset(int offset) {

		int row = model.getRowForOffset(offset);
		if (row >= 0) {
			goToRow(row);
		}
	}

	void goToNextDefinedRow(boolean forward) {

		Integer nextRow = findNextDefinedRow(forward);
		if (nextRow == null) {
			getToolkit().beep();
		}
		else {
			goToRow(nextRow);
		}
	}

	private Integer findNextDefinedRow(boolean forward) {

		int currentRow = Math.max(0, model.getRow());
		DtcMatcher isUndefined = dtc -> isUndefined(dtc);
		int undefinedRow = findNextMatchingDtc(currentRow, forward, isUndefined);
		int startRow = undefinedRow + (forward ? 1 : -1);
		int n = model.getRowCount();
		if (startRow >= n) {
			return null;
		}

		DtcMatcher isDefined = dtc -> !isUndefined(dtc);
		return findNextMatchingDtc(startRow, forward, isDefined);
	}

	private int findNextMatchingDtc(int row, boolean forward, DtcMatcher matcher) {

		int start = row;
		int end = forward ? model.getRowCount() : -1;
		int direction = forward ? 1 : -1;
		for (int i = start; i != end; i += direction) {
			DataTypeComponent dtc = model.getComponent(i);
			if (matcher.matches(dtc)) {
				return i;
			}
		}
		return -1;
	}

	// just a nicer predicate
	private interface DtcMatcher {
		public boolean matches(DataTypeComponent dtc);
	}

	private boolean isUndefined(DataTypeComponent dtc) {
		if (dtc == null) {
			return true;
		}

		DataType dt = dtc.getDataType();
		return Undefined.isUndefined(dt);
	}
}
