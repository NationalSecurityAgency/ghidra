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
package ghidra.framework.main.projectdata.actions;

import java.awt.event.MouseEvent;

import docking.ActionContext;
import docking.DialogComponentProvider;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.datatree.CheckoutsPanel;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.remote.User;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.util.HelpLocation;

/**
 * Dialog for viewing all the current checkouts for a single domain file.
 */
public class CheckoutsDialog extends DialogComponentProvider implements ProjectListener {

	private CheckoutsPanel panel;

	public CheckoutsDialog(PluginTool tool, User user, DomainFile domainFile,
			ItemCheckoutStatus[] checkouts) {

		super("View Checkouts for " + domainFile.getName(), false);
		setHelpLocation(new HelpLocation(GenericHelpTopics.REPOSITORY, "View_Check_Outs"));
		panel = new CheckoutsPanel(rootPanel, tool, user, domainFile, checkouts);
		addWorkPanel(panel);
		addDismissButton();
		AppInfo.getFrontEndTool().addProjectListener(this);

		createActions();
	}

	@Override
	protected void dismissCallback() {
		AppInfo.getFrontEndTool().removeProjectListener(this);
		close();
		panel.dispose();
	}

	@Override
	public void projectClosed(Project project) {
		dismissCallback();
	}

	@Override
	public void projectOpened(Project project) {
		// don't care
	}

	private void createActions() {
		panel.createActions(this);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {

		int[] selectedRows = panel.getSelectedRows();
		return new CheckoutsActionContext(selectedRows);
	}
}
