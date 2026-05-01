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
package ghidra.app.plugin.core.datamgr.actions;

import javax.swing.tree.TreePath;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.program.model.dtarchive.PersistentDataTypeArchive;

public abstract class AbstractUndoRedoArchiveTransactionAction extends DockingAction {

	private String actionName; // Undo / Redo

	/**
	 * Construct Undo/Redo action
	 * @param actionName "Undo" or "Redo" action name
	 * @param plugin {@link DataTypeManagerPlugin}
	 */
	public AbstractUndoRedoArchiveTransactionAction(String actionName,
			DataTypeManagerPlugin plugin) {
		super(actionName + " Archive Change", plugin.getName());
		this.actionName = actionName;
		setPopupMenuData(getMenuData(null));
		setEnabled(true);
	}

	private MenuData getMenuData(String txName) {
		String name = actionName + " Change";
		if (!StringUtils.isEmpty(txName)) {
			name += ": " + txName;
		}
		return new MenuData(new String[] { name }, null, "FileEdit");
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		TreePath[] selectionPaths = getSelectionPaths(context);
		return getModifiableProjectOrFileArchive(selectionPaths) != null;
	}

	/**
	 * Determine if the corresponding undo/redo can be performed
	 * @param archive datatype archive
	 * @return true if action can be performed on archive
	 */
	abstract protected boolean canExecute(PersistentDataTypeArchive archive);

	/**
	 * Determine the next undo/redo transaction name
	 * @param archive datatype archive
	 * @return next undo/redo transaction name
	 */
	abstract protected String getNextName(PersistentDataTypeArchive archive);

	/**
	 * Execute the undo/redo operation on the specified archive.
	 * @param archive datatype archive
	 */
	abstract protected void execute(PersistentDataTypeArchive archive);

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		TreePath[] selectionPaths = getSelectionPaths(context);
		PersistentDataTypeArchive dta = getModifiableProjectOrFileArchive(selectionPaths);
		if (dta != null && canExecute(dta)) {
			setPopupMenuData(getMenuData(getNextName(dta)));
			return true;
		}
		setPopupMenuData(getMenuData(null));
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		if (!(context instanceof DataTypesActionContext)) {
			return;
		}

		TreePath[] selectionPaths = getSelectionPaths(context);
		PersistentDataTypeArchive dta = getModifiableProjectOrFileArchive(selectionPaths);
		if (dta != null && canExecute(dta)) {
			execute(dta);
		}
	}

	private TreePath[] getSelectionPaths(ActionContext context) {
		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		return selectionPaths;
	}

	private PersistentDataTypeArchive getModifiableProjectOrFileArchive(TreePath[] selectionPaths) {
		// only valid if single file or project archive node is selected
		if (selectionPaths.length != 1) {
			return null;
		}

		TreePath path = selectionPaths[0];
		if (path.getPathCount() < 2) {
			return null;
		}

		GTreeNode node = (GTreeNode) path.getPathComponent(1);
		if (!(node instanceof FileArchiveNode) && !(node instanceof ProjectArchiveNode)) {
			return null;
		}

		ArchiveNode archiveNode = (ArchiveNode) node;
		if (archiveNode.isModifiable()) {
			PersistentDataTypeArchive archive = archiveNode.getArchive();
			if (archive instanceof PersistentDataTypeArchive dta) {
				return dta;
			}
		}
		return null;
	}
}
