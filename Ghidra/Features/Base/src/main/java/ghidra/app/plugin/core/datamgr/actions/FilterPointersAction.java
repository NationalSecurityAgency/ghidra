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

import java.util.List;

import javax.swing.Icon;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.util.HTMLUtilities;
import resources.ResourceManager;

public class FilterPointersAction extends ToggleDockingAction {
	private static final Icon FILTER_POINTERS_ICON =
		ResourceManager.loadImage("images/FilterPointers.png");
	private static final Icon POINTER_ICON = ResourceManager.loadImage("images/fingerPointer.png");

	public FilterPointersAction(DataTypeManagerPlugin plugin) {
		super("Filter Pointers", plugin.getName());

		this.setToolBarData(new ToolBarData(FILTER_POINTERS_ICON, "filters"));

		setDescription(HTMLUtilities.toHTML(
			"Toggle whether or not Pointers are\n" + "displayed in the Data Type Manager tree."));
		setSelected(true);
		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// this doesn't actually cause a filter task to happen, so we need to save and restore the state here
		DataTypeArchiveGTree gtree = (DataTypeArchiveGTree) context.getContextObject();
		List<TreePath> expandedPaths = gtree.getExpandedPaths(gtree.getViewRoot());
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		gtree.enablePointerFilter(isSelected());
		gtree.expandPaths(expandedPaths);
		gtree.setSelectionPaths(selectionPaths);

	}

	@Override
	public void setSelected(boolean selected) {
		getToolBarData().setIcon(selected ? FILTER_POINTERS_ICON : POINTER_ICON);
		super.setSelected(selected);
	}
}
