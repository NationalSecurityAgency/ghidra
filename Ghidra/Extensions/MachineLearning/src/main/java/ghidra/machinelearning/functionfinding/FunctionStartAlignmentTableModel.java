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
package ghidra.machinelearning.functionfinding;

import java.util.List;

import docking.widgets.table.AbstractSortedTableModel;

/**
 * A table used to show how many functions have addresses aligned (or not aligned) relative to a 
 * given modulus.
 */
public class FunctionStartAlignmentTableModel
		extends AbstractSortedTableModel<FunctionStartAlignmentRowObject> {

	private List<FunctionStartAlignmentRowObject> rows;

	/**
	 * Creates a table with the supplies rows
	 * @param rows rows
	 */
	public FunctionStartAlignmentTableModel(List<FunctionStartAlignmentRowObject> rows) {
		this.rows = rows;
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public int getColumnCount() {
		return 2;
	}

	@Override
	public String getColumnName(int columnIndex) {
		switch (columnIndex) {
			case 0:
				return "Remainder";
			case 1:
				return "Number of Functions";
			default:
				throw new IllegalArgumentException("Invalid column index");
		}
	}

	@Override
	public String getName() {
		return "Alignment";
	}

	@Override
	public List<FunctionStartAlignmentRowObject> getModelData() {
		return rows;
	}

	@Override
	public Object getColumnValueForRow(FunctionStartAlignmentRowObject t, int columnIndex) {
		switch (columnIndex) {
			case 0:
				return t.getRemainder();
			case 1:
				return t.getNumFuncs();
			default:
				throw new IllegalArgumentException("Invalid column index");
		}
	}
}
