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

import java.awt.Component;
import java.util.List;

import javax.swing.Icon;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.action.MenuData;
import docking.widgets.table.GTable;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.main.datatable.*;
import ghidra.framework.main.datatree.DataTree;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.util.Msg;
import resources.ResourceManager;

public class ProjectDataRenameAction extends FrontendProjectTreeAction {
	private static Icon icon = ResourceManager.loadImage("images/page_edit.png");

	public ProjectDataRenameAction(String owner, String group) {
		super("Rename", owner);
		setPopupMenuData(new MenuData(new String[] { "Rename" }, icon, group));
		markHelpUnnecessary();
	}

	@Override
	protected void actionPerformed(ProjectDataContext context) {
		if (context.getFileCount() == 1) {

			DomainFile file = context.getSelectedFiles().get(0);

			// if a file is selected make sure it is not checked out.
			if (file.isCheckedOut()) {
				Msg.showInfo(getClass(), context.getComponent(), "Rename Not Allowed",
					"Can't rename a file that is checked out!");
				return;
			}

			if (!file.getConsumers().isEmpty() || file.isBusy()) {
				Msg.showInfo(getClass(), context.getComponent(), "Rename Not Allowed",
					"Can't rename a file that is open!");
				return;
			}
		}

		Component component = context.getComponent();
		if (component instanceof DataTree) {
			DataTree tree = (DataTree) component;
			GTreeNode node = (GTreeNode) context.getContextObject();
			tree.setEditable(true);
			tree.startEditing(node.getParent(), node.getName());
		}
		else if (component instanceof GTable) {
			GTable table = (GTable) component;
			DomainFileInfo info = (DomainFileInfo) context.getContextObject();
			ProjectDataTableModel model = (ProjectDataTableModel) table.getModel();
			List<DomainFileInfo> modelData = model.getModelData();
			int indexOf = modelData.indexOf(info);
			if (indexOf >= 0) {
				model.setEditing(true);
				table.editCellAt(indexOf, findNameColumn(table));
				model.setEditing(false);
			}
		}

	}

	private int findNameColumn(GTable table) {
		TableColumnModel model = table.getColumnModel();
		int columnCount = model.getColumnCount();
		for (int col = 0; col < columnCount; col++) {
			TableColumn column = model.getColumn(col);
			if ("Name".equals(column.getHeaderValue().toString())) {
				return col;
			}
		}
		return 0;
	}

	@Override
	protected boolean isEnabledForContext(ProjectDataContext context) {
		if (!context.hasExactlyOneFileOrFolder()) {
			return false;
		}
		if (context.getFileCount() == 1) {
			DomainFile file = context.getSelectedFiles().get(0);
			if (file.isReadOnly()) {
				return false;
			}
		}
		else {
			DomainFolder folder = context.getSelectedFolders().get(0);
			if (folder.getParent() == null) {
				return false;  // can't rename root folder
			}
		}
		if (context.isReadOnlyProject()) {
			return false;
		}
		return true;
	}
}
