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

import javax.swing.*;

import org.bouncycastle.util.Arrays;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.PasswordChangeDialog;
import docking.widgets.table.GFilterTable;
import docking.widgets.table.GTable;
import generic.theme.GIcon;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.FunctionDatabase.Error;
import ghidra.features.bsim.query.FunctionDatabase.ErrorCategory;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import resources.Icons;

/**
 * Dialog for managing BSim database server definitions
 */
public class BSimServerDialog extends DialogComponentProvider {

	// TODO: Add connected status indicator (not sure how this relates to elastic case which will likely have a Session concept)
	// TODO: Add "Disconnect" action (only works when active connections is 0; does not apply to elastic)

	private PluginTool tool;
	private BSimServerManager serverManager;
	private BSimServerTableModel serverTableModel;
	private GFilterTable<BSimServerInfo> filterTable;
	private BSimServerInfo lastAdded = null;

	public BSimServerDialog(PluginTool tool, BSimServerManager serverManager) {
		super("BSim Server Manager");
		this.tool = tool;
		this.serverManager = serverManager;
		addWorkPanel(buildMainPanel());
		createToolbarActions();
		addDismissButton();
		setPreferredSize(600, 400);
		notifyContextChanged();  // kick actions to initialized enabled state
		setHelpLocation(new HelpLocation("BSimSearchPlugin","BSim_Servers_Dialog" ));
	}

	@Override
	protected void dismissCallback() {
		serverTableModel.dispose();
		super.dismissCallback();
	}

	private void createToolbarActions() {
		HelpLocation help = new HelpLocation("BSimSearchPlugin","Manage_Servers_Actions" );
		
		DockingAction addServerAction =
			new ActionBuilder("Add Server", "Dialog").toolBarIcon(Icons.ADD_ICON)
				.helpLocation(help)
				.onAction(e -> defineBsimServer())
				.build();
		addAction(addServerAction);
		DockingAction removeServerAction =
			new ActionBuilder("Delete Server", "Dialog").toolBarIcon(Icons.DELETE_ICON)
				.helpLocation(help)
				.onAction(e -> deleteBsimServer())
				.enabledWhen(c -> hasSelection())
				.build();
		addAction(removeServerAction);

		DockingAction changePasswordAction = new ActionBuilder("Change User Password", "Dialog")
			.helpLocation(help)
			.toolBarIcon(new GIcon("icon.bsim.change.password"))
			.onAction(e -> changePassword())
			.enabledWhen(c -> hasSelection())
			.build();
		addAction(changePasswordAction);

	}

	private void changePassword() {
		BSimServerInfo serverInfo = filterTable.getSelectedRowObject();
		if (serverInfo == null) {
			return;
		}
		char[] pwd = null;
		try (FunctionDatabase db = BSimClientFactory.buildClient(serverInfo, true)) {
			if (!db.initialize()) {
				// TODO: Need standardized error handler
				Error lastError = db.getLastError();
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

			String resp = db.changePassword(db.getUserName(), pwd);
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

	private void deleteBsimServer() {
		BSimServerInfo selected = filterTable.getSelectedRowObject();
		if (selected != null) {
			int answer =
				OptionDialog.showYesNoDialog(getComponent(), "Delete Server Configuration?",
					"Are you sure you want to delete: " + selected + "?");
			if (answer == OptionDialog.YES_OPTION) {
				if (!serverManager.removeServer(selected, false)) {
					answer = OptionDialog.showOptionDialogWithCancelAsDefaultButton(getComponent(),
						"Active Server Configuration!",
						"Database connections are still active!\n" +
							"Are you sure you want to delete server?",
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
			Swing.runLater(() -> filterTable.setSelectedRowObject(newServerInfo));
		}
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		serverTableModel = new BSimServerTableModel(serverManager);
		filterTable = new GFilterTable<>(serverTableModel);
		GTable table = filterTable.getTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.getSelectionModel().addListSelectionListener(e -> notifyContextChanged());
		panel.add(filterTable, BorderLayout.CENTER);

		if (serverTableModel.getRowCount() > 0) {
			table.setRowSelectionInterval(0, 0);
		}

		return panel;
	}

	private boolean hasSelection() {
		return filterTable.getSelectedRowObject() != null;
	}

	public BSimServerInfo getLastAdded() {
		return lastAdded;
	}

}
