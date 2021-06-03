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
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.table.*;

public class ListSelectionTableDialog<T> extends DialogComponentProvider {

	private GTable gTable;
	private T selectedValue;
	private List<T> selectedValues = new ArrayList<>();
	private GTableFilterPanel<T> filterPanel;
	private RowObjectTableModel<T> model;

	public ListSelectionTableDialog(String title, List<T> list) {
		super(title, true, false, true, false);
		this.model = new ListTableModel(list);
		addWorkPanel(build());
		addOKButton();
		addCancelButton();
		updateOkButtonEnablement();
		setFocusComponent(filterPanel);
	}

	public ListSelectionTableDialog(String title, RowObjectTableModel<T> model) {
		super(title, true, false, true, false);
		this.model = model;
		addWorkPanel(build());
		addOKButton();
		addCancelButton();
		updateOkButtonEnablement();
		setFocusComponent(filterPanel);
	}

	@Override
	protected void okCallback() {
		int[] selectedRows = gTable.getSelectedRows();
		if (selectedRows.length > 0) {
			selectedValues.clear();
			for (int selectedRow : selectedRows) {
				int modelRow = filterPanel.getModelRow(selectedRow);
				T rowObject = model.getRowObject(modelRow);
				selectedValues.add(rowObject);
			}
			selectedValue = selectedValues.isEmpty() ? null : selectedValues.get(0);
			close();
		}
	}

	@Override
	public void close() {
		super.close();
		filterPanel.dispose();
	}

	private JComponent build() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
		gTable = new GTable();
		gTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		JScrollPane scroll = new JScrollPane(gTable);
		filterPanel = new GTableFilterPanel<>(gTable, model);
		panel.add(scroll, BorderLayout.CENTER);
		panel.add(filterPanel, BorderLayout.SOUTH);
		gTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyChar() == '\n') {
					okCallback();
					e.consume();
				}
			}
		});
		gTable.getSelectionModel().addListSelectionListener(e -> updateOkButtonEnablement());
		gTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getButton() == MouseEvent.BUTTON1 && e.getClickCount() == 2) {
					okCallback();
				}
			}
		});
		return panel;
	}

	private void updateOkButtonEnablement() {
		setOkEnabled(!gTable.getSelectionModel().isSelectionEmpty());
	}

	public T getSelectedItem() {
		return selectedValue;
	}

	public List<T> getSelectedItems() {
		return selectedValues;
	}

	public T show(Component parent) {
		setSelectionMode(false);
		DockingWindowManager.showDialog(parent, this);
		return getSelectedItem();
	}

	public List<T> showSelectMultiple(Component parent) {
		setSelectionMode(true);
		DockingWindowManager.showDialog(parent, this);
		return getSelectedItems();
	}

	/**
	 * Calling this method does does not work correctly when used with 
	 * {@link #show(Component)} or {@link #showSelectMultiple(Component)}.   To use this method, you
	 * must show the dialog by calling: 
	 * <pre>
	 * 	DockingWindowManager.showDialog(parent, dialog);
	 * </pre>
	 * 
	 * <P>There is no need to use this method when using either of the aforementioned 
	 * {@code show} methods
	 * 
	 * @param enable true to allow multiple selection
	 * 
	 * @deprecated to be removed sometime after the 9.3 release
	 */
	@Deprecated
	public void setMultiSelectionMode(boolean enable) {
		setSelectionMode(enable);
	}

	private void setSelectionMode(boolean allowMultipleSelections) {
		ListSelectionModel selectionModel = gTable.getSelectionModel();
		if (allowMultipleSelections) {
			selectionModel.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		}
		else {
			selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		}
	}

	/**
	 * Removes the ok button from the dialog.  This is useful if you are using this dialog 
	 * as a presentation of data and do not wish to do anything when the user makes selections.
	 */
	public void hideOkButton() {
		removeButton(okButton);
	}

	private class ListTableModel extends AbstractGTableModel<T> {

		private List<T> data;

		ListTableModel(List<T> list) {
			this.data = list;
		}

		@Override
		public String getColumnName(int columnIndex) {
			return "Name";
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
			return t;
		}

		@Override
		public int getColumnCount() {
			return 1;
		}

	}
}
