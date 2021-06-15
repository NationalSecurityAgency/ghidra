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
package docking.widgets.dialogs;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Arrays;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.table.*;

/**
 * @param <T> the type
 *
 *
 * @deprecated  This class has been replaced by {@link TableSelectionDialog}.   At the time of
 * writing, both classes are identical.   This version introduced a naming conflict with another
 * API.   Thus, the new version better matches the existing dialog choosing API.
 */
@Deprecated(forRemoval = true, since = "9.3")
public class TableChooserDialog<T> extends DialogComponentProvider {

	private RowObjectTableModel<T> model;
	private GFilterTable<T> gFilterTable;
	private List<T> selectedItems;

	/**
	 * Create a new Dialog for displaying and choosing table row items
	 *
	 * @param title The title for the dialog
	 * @param model a {@link RowObjectTableModel} that has the tRable data
	 * @param allowMultipleSelection if true, the dialog allows the user to select more
	 * than one row; otherwise, only single selection is allowed
	 * @deprecated see the class header
	 */
	@Deprecated(forRemoval = true, since = "9.3")
	public TableChooserDialog(String title, RowObjectTableModel<T> model,
			boolean allowMultipleSelection) {
		super(title);
		this.model = model;
		addWorkPanel(buildTable(allowMultipleSelection));
		addOKButton();
		addCancelButton();
	}

	/**
	 * Returns the list of selected items or null if the dialog was cancelled.
	 * @return  the list of selected items or null if the dialog was cancelled.
	 * @deprecated see the class header
	 */
	@Deprecated(forRemoval = true, since = "9.3")
	public List<T> getSelectionItems() {
		return selectedItems;
	}

	private void initializeTable(boolean allowMultipleSelection) {
		GTable table = gFilterTable.getTable();

		table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);

		int selectionMode = allowMultipleSelection ? ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
				: ListSelectionModel.SINGLE_SELECTION;
		table.getSelectionModel().setSelectionMode(selectionMode);

	}

	protected void processMouseClicked(MouseEvent e) {

		if (e.getClickCount() != 2) {
			return;
		}

		int rowAtPoint = gFilterTable.getTable().rowAtPoint(e.getPoint());
		if (rowAtPoint < 0) {
			return;
		}

		T selectedRowObject = gFilterTable.getSelectedRowObject();
		selectedItems = Arrays.asList(selectedRowObject);
		close();
	}

	@Override
	protected void okCallback() {
		selectedItems = gFilterTable.getSelectedRowObjects();
		close();
		gFilterTable.dispose();
	}

	@Override
	protected void cancelCallback() {
		selectedItems = null;
		close();
		gFilterTable.dispose();
	}

	@Override
	protected void dialogShown() {
		gFilterTable.focusFilter();
	}

	private JComponent buildTable(boolean allowMultipleSelection) {
		gFilterTable = new GFilterTable<>(model);
		initializeTable(allowMultipleSelection);
		gFilterTable.getTable().addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (!e.isShiftDown()) {
					processMouseClicked(e);
				}
				updateOkEnabled();
			}
		});
		setOkEnabled(false);
		return gFilterTable;
	}

	protected void updateOkEnabled() {
		setOkEnabled(gFilterTable.getSelectedRowObject() != null);
	}
}
