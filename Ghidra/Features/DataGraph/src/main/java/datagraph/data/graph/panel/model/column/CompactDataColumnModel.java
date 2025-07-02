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
package datagraph.data.graph.panel.model.column;

import java.util.List;

import org.apache.commons.lang3.StringUtils;

import datagraph.data.graph.panel.model.row.DataRowObject;
import docking.widgets.trable.*;

/**
 * A GTrable column model for showing information about data and sub-data items. This model
 * shows the information in a compact format generally showing the field name and the current
 * value for that field. For the top element that has no field name, the datatype name is shown
 * instead. Also for the value field, if it doesn't have a value because it has sub pieces that
 * have values (structure), then the datatype name is shown in the value value field.
 */
public class CompactDataColumnModel extends GTrableColumnModel<DataRowObject> {

	@Override
	protected void populateColumns(List<GTrableColumn<DataRowObject, ?>> columnList) {
		columnList.add(new NameColumn());
		columnList.add(new ValueColumn());
		columnList.add(new PointerButtonColumn());
	}

	/**
	 * {@return true if the given column represents the pointer icon column where the user can
	 * click to add new vertices to the graph.}
	 * @param column the column to check
	 */
	public boolean isPointerButtonColumn(int column) {
		return column == 2;
	}

	private class NameColumn extends GTrableColumn<DataRowObject, String> {
		@Override
		public String getValue(DataRowObject row) {
			// if in compact format, show type in name field if it doesn't have a name
			if (row.getIndentLevel() == 0) {
				return row.getDataType();
			}
			return row.getName();
		}

		@Override
		protected int getPreferredWidth() {
			return 150;
		}

	}

	private static class TypeColumn extends GTrableColumn<DataRowObject, String> {
		@Override
		public String getValue(DataRowObject row) {
			return row.getDataType();
		}

		@Override
		protected int getPreferredWidth() {
			return 120;
		}
	}

	private class ValueColumn extends GTrableColumn<DataRowObject, String> {
		private GTrableCellRenderer<String> renderer = new ValueColumnRenderer();

		@Override
		public String getValue(DataRowObject row) {
			String value = row.getValue();
			if (!StringUtils.isBlank(value)) {
				value = " = " + value;
			}
			else if (row.getIndentLevel() > 0) {
				// special case if in compact for to show data types in the value column
				// on entries that can be opened to show inner values.
				value = "    " + row.getDataType();
			}
			return value;
		}

		@Override
		protected int getPreferredWidth() {
			return 100;
		}

		@Override
		public GTrableCellRenderer<String> getRenderer() {
			return renderer;
		}

	}

	private static class PointerButtonColumn extends GTrableColumn<DataRowObject, Boolean> {
		private GTrableCellRenderer<Boolean> renderer = new PointerColumnRenderer();

		@Override
		public Boolean getValue(DataRowObject row) {
			return row.hasOutgoingReferences();
		}

		@Override
		protected int getPreferredWidth() {
			return 24;
		}

		@Override
		public boolean isResizable() {
			return false;
		}

		@Override
		public GTrableCellRenderer<Boolean> getRenderer() {
			return renderer;
		}
	}

}
