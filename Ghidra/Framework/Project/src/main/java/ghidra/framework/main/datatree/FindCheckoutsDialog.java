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
package ghidra.framework.main.datatree;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.swing.BorderFactory;
import javax.swing.JTable;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import docking.widgets.table.threaded.GThreadedTablePanel;
import docking.widgets.table.threaded.ThreadedTableModelListener;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.main.datatable.ProjectDataActionContext;
import ghidra.framework.main.projectdata.actions.VersionControlCheckInAction;
import ghidra.framework.main.projectdata.actions.VersionControlUndoCheckOutAction;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Dialog that shows all checkouts in a specific folder and all of its subfolders.
 *
 */
public class FindCheckoutsDialog extends DialogComponentProvider {

	private FindCheckoutsTableModel model;
	private Plugin plugin;
	private DomainFolder folder;
	private JTable table;
	private SimpleDateFormat formatter;
	private VersionControlCheckInAction checkInAction;
	private VersionControlUndoCheckOutAction undoCheckOutAction;
	private boolean showMessage = true;
	private GThreadedTablePanel<CheckoutInfo> threadedTablePanel;

	public FindCheckoutsDialog(Plugin plugin, DomainFolder folder) {
		super("Find Checkouts");
		this.plugin = plugin;
		this.folder = folder;
		formatter = new SimpleDateFormat("yyyy MMM dd hh:mm aaa");
		create();
		setHelpLocation(new HelpLocation(GenericHelpTopics.REPOSITORY, "Find_Checkouts"));
	}

	private void create() {

		model = new FindCheckoutsTableModel(folder, plugin.getTool());
		model.addInitialLoadListener(new ThreadedTableModelListener() {

			@Override
			public void loadPending() {
				// don't care
			}

			@Override
			public void loadingStarted() {
				// don't care
			}

			@Override
			public void loadingFinished(boolean wasCancelled) {
				if (wasCancelled) {
					setStatusText("Find Checkouts Cancelled");
					return;
				}

				boolean hasData = model.getRowCount() > 0;
				if (!hasData && showMessage) {
					Msg.showInfo(getClass(), threadedTablePanel,
						"Find Checkouts", "No checkouts were found.");
					FindCheckoutsDialog.this.close();
				}
			}
		});

		threadedTablePanel = new GThreadedTablePanel<CheckoutInfo>(model);
		table = threadedTablePanel.getTable();

		TableColumnModel columnModel = table.getColumnModel();
		MyCellRenderer cellRenderer = new MyCellRenderer();

		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			TableColumn column = columnModel.getColumn(i);
			column.setCellRenderer(cellRenderer);
			String name = (String) column.getIdentifier();
			if (name.equals(FindCheckoutsTableModel.CHECKOUT_DATE)) {
				column.setPreferredWidth(180);
			}
		}
		table.setPreferredScrollableViewportSize(new Dimension(
			threadedTablePanel.getPreferredSize().width, 150));
		table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				setActionsEnabled();
			}
		});
		addWorkPanel(threadedTablePanel);
		addDismissButton();

		createActions();
	}

	private void createActions() {
		checkInAction = new VersionControlCheckInAction(plugin, table);
		undoCheckOutAction = new VersionControlUndoCheckOutAction(plugin);

		addAction(checkInAction);
		addAction(undoCheckOutAction);
		setActionsEnabled();
	}

	private void setActionsEnabled() {
		boolean hasSelection = table.getSelectedRowCount() > 0;
		checkInAction.setEnabled(hasSelection);
		undoCheckOutAction.setEnabled(hasSelection);
	}

	private List<DomainFile> getFileList() {
		List<DomainFile> list = new ArrayList<DomainFile>();
		int[] selectedRows = table.getSelectedRows();
		for (int selectedRow : selectedRows) {
			list.add(model.getDomainFile(selectedRow));
		}
		return list;
	}

	@Override
	public void close() {
		super.close();
		model.dispose();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new ProjectDataActionContext(null, null, null, null, getFileList(), null, true);
	}

	private class MyCellRenderer extends GTableCellRenderer {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			super.getTableCellRendererComponent(data);

			Object value = data.getValue();

			if (value instanceof Date) {
				setText(formatter.format((Date) value));
			}

			setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 0));

			String toolTipText = null;

			int col = data.getColumnModelIndex();
			if (col == CheckoutsTableModel.DATE_COL) {
				toolTipText = "Date when file was checked out";
			}
			setToolTipText(toolTipText);
			return this;
		}
	}
}
