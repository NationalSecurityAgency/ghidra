/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package docking.widgets.table;

import ghidra.util.SystemUtilities;

import java.util.ArrayList;
import java.util.List;

import javax.swing.table.TableModel;

/**
 * An object that represents a row in a table.  Most tables used in the system create tables that
 * use their own row objects (see {@link AbstractSortedTableModel}).  This class exists to 
 * compensate for those models that do not do this, but instead rely on the classic Java 
 * {@link TableModel} method {@link TableModel#getValueAt(int, int)}.
 * <p>
 * For the best behavior, a table model implementation should extend 
 * {@link AbstractSortedTableModel}, as the system is written to work for those models.  Use of
 * this class as a workaround is a suitable default, but will not always result in the desired
 * behavior.  A major reason for this is that if any of the table's cell values change, the 
 * row objects that created for non-{@link AbstractSortedTableModel}s will not be equal to 
 * those created before the data change.  This causes some features to break, such as selection
 * restoration after user edits.
 */
public class RowObject {

	/**
	 * Factory method to create and initialize a row object.
	 * 
	 * @param model the model required to gather data for the row object.
	 * @param row the row for which to create a row object	 * @return
	 */
	public static RowObject createRowObject(TableModel model, int row) {
		RowObject rowObject = new RowObject();
		int columns = model.getColumnCount();
		for (int i = 0; i < columns; i++) {
			rowObject.addElement(model.getValueAt(row, i));
		}
		return rowObject;
	}

	List<Object> values = new ArrayList<Object>();
	int hash = -1;

	void addElement(Object object) {
		values.add(object);
		hash = -1;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}

		if (obj == null) {
			return false;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		RowObject other = (RowObject) obj;
		if (values.size() != other.values.size()) {
			return false;
		}

		for (int i = 0; i < values.size(); i++) {
			Object object = values.get(i);
			if (!SystemUtilities.isEqual(object, other.values.get(i))) {
				return false;
			}
		}

		return true;
	}

	@Override
	public int hashCode() {
		if (hash != -1) {
			return hash;
		}
		computeHash();
		return hash;
	}

	private void computeHash() {
		int result = 17;
		result = 31 * result + values.hashCode();
		hash = result;
	}

	@Override
	public String toString() {
		return "RowObject: " + getValuesAsString();
	}

	private String getValuesAsString() {
		StringBuilder buildy = new StringBuilder();
		for (Object object : values) {
			if (buildy.length() > 0) {
				buildy.append(", ");
			}

			buildy.append(object == null ? "" : object.toString());
		}
		return buildy.toString();
	}
}
