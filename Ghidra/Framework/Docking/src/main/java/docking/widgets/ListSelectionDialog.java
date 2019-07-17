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
package docking.widgets;

import java.awt.BorderLayout;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.label.GLabel;
import docking.widgets.table.AbstractGTableModel;
import docking.widgets.table.RowObjectTableModel;

public class ListSelectionDialog<T> extends DialogComponentProvider {

	private DropDownSelectionTextField<T> field;
	protected boolean cancelled;
	private RowObjectTableModel<T> userTableModel;
	private DataToStringConverter<T> searchConverter;
	private DataToStringConverter<T> descriptionConverter;
	private List<T> data;

	// Listener for selections on the list. This must be a field since
	// the listeners are added to a weak set in the drop down class and will
	// be garbage-collected otherwise.
	private SelectionListener<T> selectionListener;

	public static ListSelectionDialog<String> getStringListSelectionDialog(String title,
			String label, List<String> data) {
		return new ListSelectionDialog<>(title, label, new ArrayList<>(data),
			DataToStringConverter.stringDataToStringConverter);
	}

	public ListSelectionDialog(String title, String label, List<T> data,
			DataToStringConverter<T> searchConverter) {
		this(title, label, data, searchConverter, null);
	}

	public ListSelectionDialog(String title, String label, List<T> data,
			DataToStringConverter<T> searchConverter,
			DataToStringConverter<T> descriptionConverter) {
		super(title, true, false, true, false);
		this.data = data;
		this.searchConverter = searchConverter;
		this.descriptionConverter = descriptionConverter;
		DefaultDropDownSelectionDataModel<T> model = new DefaultDropDownSelectionDataModel<>(
			new ArrayList<>(data), searchConverter, descriptionConverter) {

			// overridden to return all data for an empty search; this lets the down-arrow
			// show the full list
			@Override
			public List<T> getMatchingData(String searchText) {
				if (searchText.trim().isEmpty()) {
					return this.data;
				}
				return super.getMatchingData(searchText);
			}
		};
		addWorkPanel(buildWorkPanel(label, model));

		addOKButton();
		setOkEnabled(false);
		addCancelButton();

	}

	@Override
	protected void cancelCallback() {
		cancelled = true;
		super.cancelCallback();
	}

	@Override
	protected void okCallback() {
		close();
	}

	public boolean wasCancelled() {
		return cancelled;
	}

	public T show(Component parent) {
		DockingWindowManager.showDialog(parent, this);
		return getSelectedItem();
	}

	public T getSelectedItem() {
		if (!cancelled) {
			return field.getSelectedValue();
		}
		return null;
	}

	protected JComponent buildWorkPanel(String label, DropDownTextFieldDataModel<T> model) {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(40, 40, 30, 40));

		field = new DropDownSelectionTextField<>(model) {

			// overridden to return all data for an empty search; this lets the down-arrow
			// show the full list
			@Override
			protected List<T> getMatchingData(String searchText) {
				if (searchText.trim().isEmpty()) {
					return this.dataModel.getMatchingData(searchText);
				}
				return super.getMatchingData(searchText);
			}
		};

		selectionListener = new SelectionListener<>();
		field.addDropDownSelectionChoiceListener(selectionListener);

		JLabel jLabel = new GLabel(label);
		jLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 20));
		panel.add(jLabel, BorderLayout.WEST);
		panel.add(field, BorderLayout.CENTER);

		JButton browseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		browseButton.addActionListener(e -> browse());
		panel.add(browseButton, BorderLayout.EAST);
		return panel;
	}

	protected void browse() {
		RowObjectTableModel<T> model = getTableModel();
		ListSelectionTableDialog<T> dialog = new ListSelectionTableDialog<>(getTitle(), model);
		T selectedItem = dialog.show(this.getComponent());
		if (selectedItem != null) {
			field.setSelectedValue(selectedItem);
			setOkEnabled(true);
		}
	}

	private RowObjectTableModel<T> getTableModel() {
		if (userTableModel != null) {
			return userTableModel;
		}

		return new DefaultTableModel();
	}

	private class DefaultTableModel extends AbstractGTableModel<T> {
		@Override
		public String getColumnName(int columnIndex) {
			if (columnIndex == 0) {
				return "Name";
			}
			return "Description";
		}

		@Override
		public String getName() {
			return getTitle();
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return String.class;
		}

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex) {
			return false;
		}

		@Override
		public List<T> getModelData() {
			return data;
		}

		@Override
		public Object getColumnValueForRow(T t, int columnIndex) {
			if (columnIndex == 0) {
				return searchConverter.getString(t);
			}
			return descriptionConverter.getString(t);
		}

		@Override
		public int getColumnCount() {
			return descriptionConverter == null ? 1 : 2;
		}

	}

	private class SelectionListener<T1> implements DropDownSelectionChoiceListener<T1> {
		@Override
		public void selectionChanged(T1 t) {
			setOkEnabled(t != null);
		}
	}

	public static void main(String[] args) {
		JFrame jFrame = new JFrame();
		jFrame.setVisible(true);
		ArrayList<String> list = new ArrayList<>();
		list.add("aaa");
		list.add("Bob");
		list.add("BOb");
		list.add("BoB");
		list.add("bob");
		list.add("bOb");
		list.add("bobby");
		list.add("zzz");
		ListSelectionDialog<String> dialog = ListSelectionDialog.getStringListSelectionDialog(
			"String Picker", "Choose String:", list);

		String selectedValue = dialog.show(jFrame);
		System.out.println("Selected: " + selectedValue);
		System.exit(0);
	}
}
