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
package ghidra.app.plugin.core.references;

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.dialogs.InputDialog;
import ghidra.app.cmd.refs.AddExternalNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.ResourceManager;


public class AddExternalReferenceNameAction extends DockingAction {
	private static ImageIcon ADD_ICON = ResourceManager.loadImage("images/Plus.png");
	private final ExternalReferencesProvider provider;

	public AddExternalReferenceNameAction(ExternalReferencesProvider provider) {
		super("Add External Program Name", provider.getOwner());
		this.provider = provider;
		setPopupMenuData( new MenuData( new String[] {"Add External Program"}, ADD_ICON, null ) );
		setToolBarData( new ToolBarData(ADD_ICON, null ) );
	}
	
	@Override
	public void actionPerformed(ActionContext context) {
		InputDialog dialog = new InputDialog("New External Program", "Enter Name");
		dialog.setHelpLocation(new HelpLocation("ReferencesPlugin", "Add_External_Program_Name"));
		provider.getTool().showDialog(dialog, provider);
		if (dialog.isCanceled()) {
			return;
		}
		String newExternalName = dialog.getValue().trim();
		if (newExternalName.isEmpty()) {
			Msg.showError(this, dialog.getComponent(), "Invalid Input",
				"External program name cannot be empty");
			return;
		}
		AddExternalNameCmd cmd = new AddExternalNameCmd(newExternalName, SourceType.USER_DEFINED);
		provider.getTool().execute(cmd, provider.getProgram());
	}
}
