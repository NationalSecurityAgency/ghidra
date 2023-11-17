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
package ghidra.features.bsim.gui.filters;

import java.awt.BorderLayout;
import java.util.*;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.DataToStringConverter;
import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;

/**
 * Dialog for selection one or more choices from a list of possible values.
 *
 * @param <T> the type of choices
 */
public class MultiChoiceSelectionDialog<T> extends DialogComponentProvider {

	private List<T> selectedChoices;
	private GFilterTable<ChoiceRowObject> filterTable;
	private ChoiceTableModel model;

	public MultiChoiceSelectionDialog(String dataTitle, List<T> choices, Set<T> selected) {
		this(dataTitle, choices, selected, t -> t.toString());
	}

	public MultiChoiceSelectionDialog(String dataTitle, List<T> choices, Set<T> selected,
		DataToStringConverter<T> dataConverter) {
		super(dataTitle + " Chooser");
		addWorkPanel(buildMainPanel(choices, selected, dataConverter, dataTitle));
		addOKButton();
		addCancelButton();
	}

	private JComponent buildMainPanel(List<T> choices, Set<T> selected,
		DataToStringConverter<T> dataConverter, String dataTitle) {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		model = new ChoiceTableModel(choices, selected, dataConverter, dataTitle);
		filterTable = new GFilterTable<ChoiceRowObject>(model);
		panel.add(filterTable);
		return panel;
	}

	@Override
	protected void okCallback() {
		selectedChoices = getSelectedChoicesFromTable();
		close();
	}

	private List<T> getSelectedChoicesFromTable() {
		return model.getSelectedData();
	}

	public List<T> getSelectedChoices() {
		return selectedChoices;
	}

	class ChoiceRowObject {
		private T data;
		private boolean selected;

		ChoiceRowObject(T data, boolean selected) {
			this.data = data;
			this.selected = selected;
		}

		public boolean isSelected() {
			return selected;
		}

		public T getData() {
			return data;
		}

		public void setSelected(boolean b) {
			selected = b;
		}

	}

	class ChoiceTableModel extends GDynamicColumnTableModel<ChoiceRowObject, Object> {
		private List<ChoiceRowObject> rows = new ArrayList<>();
		private DataToStringConverter<T> stringConverter;
		private String dataColumnTitle;

		ChoiceTableModel(List<T> data, Set<T> selected, DataToStringConverter<T> stringConverter,
			String dataColumnTitle) {
			super(new ServiceProviderStub());
			this.stringConverter = stringConverter;
			this.dataColumnTitle = dataColumnTitle;
			for (T t : data) {
				rows.add(new ChoiceRowObject(t, selected.contains(t)));
			}
		}

		@Override
		public String getName() {
			return "Chooser";
		}

		public List<T> getSelectedData() {
			List<T> selected = new ArrayList<>();
			for (ChoiceRowObject row : rows) {
				if (row.isSelected()) {
					selected.add(row.getData());
				}
			}
			return selected;
		}

		@Override
		public List<MultiChoiceSelectionDialog<T>.ChoiceRowObject> getModelData() {
			return rows;
		}

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex) {
			return columnIndex == 0;
		}

		@Override
		public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
			boolean b = ((Boolean) aValue).booleanValue();
			rows.get(rowIndex).setSelected(b);
		}

		@Override
		protected TableColumnDescriptor<ChoiceRowObject> createTableColumnDescriptor() {
			TableColumnDescriptor<ChoiceRowObject> descriptor = new TableColumnDescriptor<>();
			descriptor.addVisibleColumn(new SelectedColumn());
			descriptor.addVisibleColumn(new DataColumn(), 1, true);
			return descriptor;
		}

		@Override
		public Object getDataSource() {
			return null;
		}

		private class SelectedColumn
			extends AbstractDynamicTableColumn<ChoiceRowObject, Boolean, Object> {

			@Override
			public String getColumnName() {
				return "Selected";
			}

			@Override
			public Boolean getValue(ChoiceRowObject rowObject, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {

				return rowObject.isSelected();
			}

			@Override
			public int getColumnPreferredWidth() {
				return 40;
			}
		}

		private class DataColumn
			extends AbstractDynamicTableColumn<ChoiceRowObject, String, Object> {

			@Override
			public String getColumnName() {
				return dataColumnTitle;
			}

			@Override
			public String getValue(ChoiceRowObject rowObject, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {

				return stringConverter.getString(rowObject.getData());
			}

			@Override
			public int getColumnPreferredWidth() {
				return 300;
			}
		}
	}
}
