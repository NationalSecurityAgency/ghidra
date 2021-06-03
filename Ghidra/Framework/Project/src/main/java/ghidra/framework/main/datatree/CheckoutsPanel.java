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

import java.awt.*;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.GenericDateCellRenderer;
import docking.widgets.OptionDialog;
import docking.widgets.table.ColumnSortState.SortDirection;
import docking.widgets.table.GTable;
import docking.widgets.table.TableSortStateEditor;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.projectdata.actions.CheckoutsActionContext;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.remote.User;
import ghidra.framework.store.ItemCheckoutStatus;

/**
 * Panel that shows check out information for a domain file.
 */
public class CheckoutsPanel extends JPanel {
	private static final long serialVersionUID = 1L;

	private Component parent;
	private PluginTool tool;
	private DomainFile domainFile;
	private CheckoutsTableModel tableModel;
	private GTable table;
	private MyFolderListener listener;

	private User user;

	/**
	 * Constructor
	 * @param parent parent dialog
	 * @param tool tool to get project data for adding a listener
	 * @param user user that is logged in
	 * @param domainFile domain file to view checkouts
	 * @param checkouts the checkouts to show
	 */
	public CheckoutsPanel(Component parent, PluginTool tool, User user, DomainFile domainFile,
			ItemCheckoutStatus[] checkouts) {

		super(new BorderLayout());
		this.parent = parent;
		this.tool = tool;
		this.user = user;
		this.domainFile = domainFile;
		create(checkouts);
		listener = new MyFolderListener();
		tool.getProject().getProjectData().addDomainFolderChangeListener(listener);
	}

	public void dispose() {
		tool.getProject().getProjectData().removeDomainFolderChangeListener(listener);
		domainFile = null;
	}

	private void refresh() {
		try {
			tableModel.refresh(domainFile.getCheckouts());
		}
		catch (IOException e) {
			tableModel.refresh(new ItemCheckoutStatus[0]);
			ClientUtil.handleException(tool.getProject().getRepository(), e, "Get Check Out Status",
				parent);
		}
	}

	private void create(ItemCheckoutStatus[] checkouts) {
		tableModel = new CheckoutsTableModel(checkouts);

		// set up table sorter stuff
		TableSortStateEditor tsse = new TableSortStateEditor();
		tsse.addSortedColumn(CheckoutsTableModel.DATE_COL, SortDirection.DESCENDING);
		tableModel.setTableSortState(tsse.createTableSortState());

		table = new GTable(tableModel);
		JScrollPane sp = new JScrollPane(table);
		table.setPreferredScrollableViewportSize(new Dimension(680, 120));
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		add(sp, BorderLayout.CENTER);

		TableColumnModel columnModel = table.getColumnModel();
		//MyCellRenderer cellRenderer = new MyCellRenderer();

		TableColumn column;

		column = columnModel.getColumn(CheckoutsTableModel.DATE_COL);
		column.setPreferredWidth(120);
		column.setCellRenderer(new GenericDateCellRenderer("Date when file was checked out"));
		columnModel.getColumn(CheckoutsTableModel.VERSION_COL).setPreferredWidth(50);
		columnModel.getColumn(CheckoutsTableModel.USER_COL).setPreferredWidth(80);
		columnModel.getColumn(CheckoutsTableModel.HOST_COL).setPreferredWidth(120);
		columnModel.getColumn(CheckoutsTableModel.PROJECT_NAME_COL).setPreferredWidth(120);
		columnModel.getColumn(CheckoutsTableModel.PROJECT_LOC_COL).setPreferredWidth(180);
	}

	private void terminateCheckout(int[] rows) {

		Set<ItemCheckoutStatus> toTerminate = new HashSet<>();
		for (int row : rows) {
			ItemCheckoutStatus item = tableModel.getRowObject(row);
			toTerminate.add(item);
		}

		for (ItemCheckoutStatus item : toTerminate) {
			int result = OptionDialog.showYesNoDialog(this, "Confirm Terminate Checkout",
				"Are you sure want to terminate the checkout for " + item.getUser() + ", version " +
					item.getCheckoutVersion() + "?");
			if (result == OptionDialog.CANCEL_OPTION) {
				return;
			}

			if (result == OptionDialog.OPTION_ONE) {

				try {
					domainFile.terminateCheckout(item.getCheckoutId());
				}
				catch (IOException e) {
					ClientUtil.handleException(tool.getProject().getRepository(), e,
						"Terminate Checkout", this);
					tableModel.refresh(new ItemCheckoutStatus[0]);
				}
			}
		}
	}

	public void createActions(DialogComponentProvider provider) {
		DockingAction terminateCheckoutAction =
			new DockingAction("Terminate Checkout", "Checkouts Panel", false) {
				@Override
				public void actionPerformed(ActionContext context) {

					CheckoutsActionContext checkoutsContext = (CheckoutsActionContext) context;
					int[] rows = checkoutsContext.getSelectedRows();
					terminateCheckout(rows);
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {

					// user will be null for private projects with local versioning
					if (user != null && !user.isAdmin()) {
						return false;
					}

					if (!(context instanceof CheckoutsActionContext)) {
						return false;
					}

					CheckoutsActionContext checkoutsContext = (CheckoutsActionContext) context;
					int[] rows = checkoutsContext.getSelectedRows();
					return rows.length > 0;
				}
			};
		terminateCheckoutAction.setDescription("Terminates the selected Checkout");
		terminateCheckoutAction.setPopupMenuData(
			new MenuData(new String[] { "Terminate Checkout" }, "AAA"));

		provider.addAction(terminateCheckoutAction);
	}

	public int[] getSelectedRows() {
		return table.getSelectedRows();
	}

	private class MyFolderListener extends DomainFolderListenerAdapter {

		@Override
		public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
			if (file.equals(domainFile)) {
				refresh();
			}
		}

		@Override
		public void domainFileRemoved(DomainFolder parentFolder, String name, String fileID) {
			if (parentFolder.equals(domainFile.getParent()) && domainFile.getName().equals(name)) {
				parent.setVisible(false);
				dispose();
			}
		}
	}

}
