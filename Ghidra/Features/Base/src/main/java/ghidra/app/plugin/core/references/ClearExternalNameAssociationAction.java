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

import ghidra.app.cmd.refs.ClearExternalNameCmd;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.program.model.listing.Program;

import java.util.List;

import javax.swing.ImageIcon;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;


public class ClearExternalNameAssociationAction extends DockingAction {
	private static ImageIcon CLEAR_ICON = ResourceManager.loadImage("images/erase16.png");
	private final ExternalReferencesProvider provider;


	public ClearExternalNameAssociationAction(ExternalReferencesProvider provider) {
		super("Clear External Name Association", provider.getOwner());
		this.provider = provider;
		this.setPopupMenuData( new MenuData( 
			new String[] {"Clear External Name Association"}, CLEAR_ICON, null ) );

		this.setToolBarData( new ToolBarData(CLEAR_ICON, null ) );

		setEnabled(true);
	}
	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}
	
	@Override
	public void actionPerformed(ActionContext context) {
		Program program = provider.getProgram();
		List<String> externalNames = provider.getSelectedExternalNames();
		CompoundCmd cmd = new CompoundCmd("Clear External Program Associations");
		for (String externalName : externalNames) {
			cmd.add(new ClearExternalNameCmd(externalName));
		}
		provider.getTool().execute(cmd, program);
	}
}
