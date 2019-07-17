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

import ghidra.app.cmd.refs.RemoveExternalNameCmd;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.util.Msg;

import java.util.List;

import javax.swing.ImageIcon;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;

public class DeleteExternalReferenceNameAction extends DockingAction {
	private static ImageIcon DELETE_ICON = ResourceManager.loadImage("images/edit-delete.png");
	private final ExternalReferencesProvider provider;

	public DeleteExternalReferenceNameAction(ExternalReferencesProvider provider) {
		super("Delete External Program Name", provider.getOwner());
		this.provider = provider;
// ACTIONS - auto generated
		this.setPopupMenuData(new MenuData(new String[] { "Delete External Program" }, DELETE_ICON,
			null));

		this.setToolBarData(new ToolBarData(DELETE_ICON, null));

		setEnabled(true);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Program program = provider.getProgram();
		ExternalManager externalManager = program.getExternalManager();
		List<String> externalNames = provider.getSelectedExternalNames();
		StringBuffer buf = new StringBuffer();
		CompoundCmd cmd = new CompoundCmd("Delete External Program Name");
		for (String externalName : externalNames) {
			boolean hasLocations = externalManager.getExternalLocations(externalName).hasNext();
			if (hasLocations) {
				buf.append("\n     ");
				buf.append(externalName);
			}
			else {
				cmd.add(new RemoveExternalNameCmd(externalName));
			}
		}
		if (cmd.size() > 0) {
			provider.getTool().execute(cmd, program);
		}
		if (buf.length() > 0) {
			Msg.showError(getClass(), provider.getComponent(),
				"Delete Failure", "The following external reference names could not be deleted\n" +
					"because they contain external locations:\n" + buf.toString());
		}

	}

}
