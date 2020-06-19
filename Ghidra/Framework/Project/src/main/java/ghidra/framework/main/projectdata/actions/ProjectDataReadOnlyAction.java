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

import docking.action.MenuData;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.main.datatable.ProjectDataContextToggleAction;
import ghidra.framework.main.datatree.DomainFileNode;
import ghidra.framework.model.DomainFile;
import ghidra.util.Msg;

public class ProjectDataReadOnlyAction extends ProjectDataContextToggleAction {

	public ProjectDataReadOnlyAction(String owner, String group) {
		super("Read-Only", owner);
		setPopupMenuData(new MenuData(new String[] { "Read-Only" }, group));
		setSelected(false);
		markHelpUnnecessary();
	}

	@Override
	protected void actionPerformed(ProjectDataContext context) {
		DomainFile file = context.getSelectedFiles().get(0);
		toggleReadOnly(file);
		Object contextObject = context.getContextObject();
		if (contextObject instanceof DomainFileNode) {
			DomainFileNode node = (DomainFileNode) contextObject;
			node.fireNodeChanged(node.getParent(), node);
		}
	}

	@Override
	public boolean isAddToPopup(ProjectDataContext context) {
		if (!context.isInActiveProject()) {
			return false;
		}
		if (context.getFolderCount() != 0 || context.getFileCount() != 1) {
			return false;
		}

		DomainFile domainFile = context.getSelectedFiles().get(0);
		setSelected(domainFile.isReadOnly());
		return true;
	}

	@Override
	protected boolean isEnabledForContext(ProjectDataContext context) {
		if (context.getFolderCount() != 0 || context.getFileCount() != 1) {
			return false;
		}
		DomainFile domainFile = context.getSelectedFiles().get(0);
		return !domainFile.isVersioned();
	}

	/**
	 * Toggle the read-only property on the domain file.
	 */
	private void toggleReadOnly(DomainFile file) {
		try {
			file.setReadOnly(!file.isReadOnly());
		}
		catch (Exception e) {
			Msg.showError(this, null, "Error setting read-only state for " + file.getName(),
				e.getMessage(), e);
		}
	}
}
