/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.cmd.refs.SetExternalNameCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.util.HelpLocation;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

import javax.swing.ImageIcon;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;


public class SetExternalNameAssociationAction extends DockingAction {
	private static ImageIcon EDIT_ICON = ResourceManager.loadImage("images/editbytes.gif");
	private final ExternalReferencesProvider provider;


	public SetExternalNameAssociationAction(ExternalReferencesProvider provider) {
		super("Set External Name Association", provider.getOwner());
		this.provider = provider;
		this.setPopupMenuData( 
			new MenuData( new String[] {"Set External Name Association"}, EDIT_ICON, null ) );

		this.setToolBarData( new ToolBarData(EDIT_ICON, null ) );

		setEnabled(true);
	}
	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}
	@Override
	public void actionPerformed(ActionContext context) {
		List<String> selectedExternalNames = provider.getSelectedExternalNames();
		final String externalName = selectedExternalNames.get(0);	// must be exactly one for us to be enabled.
		final DataTreeDialog dialog = new DataTreeDialog( provider.getComponent(),
					"Choose External Program ("+externalName+")", DataTreeDialog.OPEN );

		dialog.setSearchText(externalName);

		dialog.addOkActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e1) {
				DomainFile domainFile = dialog.getDomainFile();
				if (domainFile == null) {
					return;
				}
				String pathName = domainFile.toString();
				dialog.close();
				ExternalManager externalManager = provider.getProgram().getExternalManager();
				String externalLibraryPath = externalManager.getExternalLibraryPath(externalName);
				if (!pathName.equals(externalLibraryPath)) {
					Command cmd = new SetExternalNameCmd(externalName, domainFile.getPathname());
					provider.getTool().execute(cmd, provider.getProgram());
				}
			}
		});
		dialog.setHelpLocation(new HelpLocation("ReferencesPlugin","ChooseExternalProgram"));
		provider.getTool().showDialog(dialog);
	}

}
