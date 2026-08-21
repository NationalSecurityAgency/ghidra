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
package ghidra.features.bsim.gui.search.dialog;

import java.awt.BorderLayout;
import java.sql.Connection;
import java.sql.SQLException;

import javax.swing.*;

import org.bouncycastle.util.Arrays;

import docking.*;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.PasswordChangeDialog;
import docking.widgets.table.GFilterTable;
import docking.widgets.table.GTable;
import generic.theme.GIcon;
import ghidra.features.bsim.gui.BSimServerManager;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.FunctionDatabase.BSimError;
import ghidra.features.bsim.query.FunctionDatabase.ErrorCategory;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import resources.Icons;

/**
 * Dialog for managing BSim database server definitions
 */
public class BSimServerDialog extends DialogComponentProvider {

	private PluginTool tool;
	private BSimServerManager serverManager;
	private BSimServerTableModel serverTableModel;
	private GFilterTable<BSimServerInfo> serverTable;
	private BSimServerInfo lastAdded = null;

	private ToggleDockingAction dbConnectionAction;

	public BSimServerDialog(PluginTool tool, BSimServerManager serverManager) {
		super("BSim Server Manager");
		this.tool = tool;
		this.serverManager = serverManager;
		addWorkPanel(buildMainPanel());
		createToolbarActions();
		addDismissButton();
		setPreferredSize(600, 400);
		notifyContextChanged();  // kick actions to initialized enabled state
		setHelpLocation(new HelpLocation("BSimSearchPlugin", "BSim_Servers_Dialog"));
	}

	@Override
	protected void dismissCallback() {
		serverTableModel.dispose();
		super.dismissCallback();
	}

	private void createToolbarActions() {
		HelpLocation help = new HelpLocation("BSimSearchPlugin", "Manage_Servers_Actions");

		DockingAction addServerAction =
			new ActionBuilder("Add BSim Database", "Dialog").toolBarIcon(Icons.ADD_ICON)
					.helpLocation(help)
					.onAction(e -> defineBsimServer())
					.build();
		addAction(addServerAction);
		DockingAction removeServerAction =
			new ActionBuilder("Delete BSim Database", "Dialog").toolBarIcon(Icons.DELETE_ICON)
					.helpLocation(help)
					.onAction(e -> deleteBsimServer())
					.enabledWhen(c -> hasSelection())
					.build();
		addAction(removeServerAction);

		dbConnectionAction =
			new ToggleActionBuilder("Toggle Database Connection", "Dialog").helpLocation(help)
					.toolBarIcon(new GIcon("icon.bsim.disconnected"))
					.onAction(e -> toggleSelectedJDBCDataSourceConnection())
					.enabledWhen(c -> isNonActiveJDBCDataSourceSelected(c))
					.build();
		addAction(dbConnectionAction);

		DockingAction changePasswordAction =
			new ActionBuilder("Change User Password", "Dialog").helpLocation(help)
					.toolBarIcon(new GIcon("icon.bsim.change.password"))
					.onAction(e -> changePassword())
					.enabledWhen(c -> canChangePassword())
					.build();
		addAction(changePasswordAction);

	}

	private void toggleSelectedJDBCDataSourceConnection() {

		BSimServerInfo serverInfo = serverTable.getSelectedRowObject();
		if (serverInfo == null || serverInfo.getDBType() == DBType.elastic) {
			return;
		}

		BSimJDBCDataSource dataSource = BSimServerManager.getDataSourceIfExists(serverInfo);
		if (dataSource == null) {
			// connect
			dataSource = BSimServerManager.getDataSource(serverInfo);
			try (Connection connection = dataSource.getConnection()) {
				// do nothing
			}
			catch (SQLException e) {
				Msg.showError(this, rootPanel, "BSim Connection Failure", e.getMessage());
			}
		}
		else {
			dataSource.dispose();
		}
		serverTableModel.fireTableDataChanged();
		notifyContextChanged();
	}

	private boolean isNonActiveJDBCDataSourceSelected(ActionContext c) {
		BSimServerInfo serverInfo = serverTable.getSelectedRowObject();
		if (serverInfo == null) {
			return false;
		}

		// TODO: May need connection listener on dataSource to facilitate GUI update,
		// although modal dialog avoids the issue somewhat

		dbConnectionAction.setDescription(dbConnectionAction.getName());

		ConnectionPoolStatus status = serverTableModel.getConnectionPoolStatus(serverInfo);
		if (status.isActive) {

			// Show connected icon
			dbConnectionAction
					.setToolBarData(new ToolBarData(new GIcon("icon.bsim.connected"), null));
			dbConnectionAction.setSelected(true);
			dbConnectionAction.setDescription("Disconnect idle BSim Database connection");

			// disconnect permitted when no active connections
			return status.activeCount == 0;
		}

		// Show disconnected icon (elastic always shown as disconnected)
		dbConnectionAction
				.setToolBarData(new ToolBarData(new GIcon("icon.bsim.disconnected"), null));
		dbConnectionAction.setSelected(false);
		dbConnectionAction.setDescription("Connect BSim Database");

		// Action never enabled for elastic DB (i.e., does not use pooled JDBC data source)
		return serverInfo.getDBType() != DBType.elastic;
	}

	private void changePassword() {
		BSimServerInfo serverInfo = serverTable.getSelectedRowObject();
		if (serverInfo == null) {
			return;
		}
		char[] pwd = null;
		try (FunctionDatabase db = BSimClientFactory.buildClient(serverInfo, true)) {
			if (!db.initialize()) {
				// TODO: Need standardized error handler
				BSimError lastError = db.getLastError();
				if (lastError.category != ErrorCategory.AuthenticationCancelled) {
					Msg.showError(this, getComponent(), "BSim DB Connection Failed",
						lastError.message);
				}
				return;
			}
			if (!db.isPasswordChangeAllowed()) {
				Msg.showError(this, getComponent(), "Unsupported Operation",
					"BSim DB password change not supported");
				return;
			}
			PasswordChangeDialog dlg = new PasswordChangeDialog("Change Password", "BSim DB",
				serverInfo.toString(), db.getUserName());
			tool.showDialog(dlg);
			pwd = dlg.getPassword();
			if (pwd == null) {
				return; // password dialog entry cancelled by user
			}

			String resp = db.changePassword(pwd);
			if (resp == null) {
				Msg.showInfo(this, getComponent(), "Password Changed",
					"BSim DB password successfully changed");
			}
			else {
				Msg.showError(this, getComponent(), "Password Changed Failed", resp);
			}
		}
		finally {
			if (pwd != null) {
				Arrays.fill(pwd, '\0');
			}
		}
	}

	private boolean canChangePassword() {
		BSimServerInfo serverInfo = serverTable.getSelectedRowObject();
		return serverInfo != null && serverInfo.getDBType() != DBType.file;
	}

	private void deleteBsimServer() {
		BSimServerInfo selected = serverTable.getSelectedRowObject();
		if (selected != null) {
			int answer =
				OptionDialog.showYesNoDialog(getComponent(), "Delete Server Configuration?",
					"Are you sure you want to delete: " + selected + "?");
			if (answer == OptionDialog.YES_OPTION) {
				if (!serverManager.removeServer(selected, false)) {
					answer = OptionDialog.showOptionDialogWithCancelAsDefaultButton(getComponent(),
						"Active Server Configuration!",
						"Database connections are still active!\n" +
							"Are you sure you want to terminate connections and delete server?",
						"Yes", OptionDialog.WARNING_MESSAGE);
					if (answer == OptionDialog.YES_OPTION) {
						serverManager.removeServer(selected, true);
					}
				}
			}
		}
	}

	private void defineBsimServer() {
		CreateBsimServerInfoDialog dialog = new CreateBsimServerInfoDialog();
		DockingWindowManager.showDialog(dialog);
		BSimServerInfo newServerInfo = dialog.getBsimServerInfo();
		if (newServerInfo != null) {
			serverManager.addServer(newServerInfo);
			lastAdded = newServerInfo;
			Swing.runLater(() -> serverTable.setSelectedRowObject(newServerInfo));
		}
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		serverTableModel = new BSimServerTableModel(serverManager);
		serverTable = new GFilterTable<>(serverTableModel);
		GTable table = serverTable.getTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.getSelectionModel().addListSelectionListener(e -> notifyContextChanged());
		panel.add(serverTable, BorderLayout.CENTER);

		if (serverTableModel.getRowCount() > 0) {
			table.setRowSelectionInterval(0, 0);
		}

		return panel;
	}

	private boolean hasSelection() {
		return serverTable.getSelectedRowObject() != null;
	}

	public BSimServerInfo getLastAdded() {
		return lastAdded;
	}

}
