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

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.datamgr.tree.*;
import resources.Icons;

public class DtFilterAction extends DockingAction {

	private DataTypeManagerPlugin plugin;

	public DtFilterAction(DataTypeManagerPlugin plugin) {
		super("Show Filter", plugin.getName());
		this.plugin = plugin;

		setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON, "filters"));

		setDescription("Shows the Data Types filter");
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		ComponentProvider provider = context.getComponentProvider();
		return provider instanceof DataTypesProvider;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		DataTypeArchiveGTree gtree = (DataTypeArchiveGTree) context.getContextObject();
		List<TreePath> expandedPaths = gtree.getExpandedPaths(gtree.getViewRoot());
		TreePath[] selectionPaths = gtree.getSelectionPaths();

		DataTypesProvider provider = (DataTypesProvider) context.getComponentProvider();
		DtFilterState currentFilterState = provider.getFilterState();
		DtFilterDialog dialog = new DtFilterDialog(currentFilterState);
		plugin.getTool().showDialog(dialog);

		// if not cancelled
		if (dialog.isCancelled()) {
			return;
		}

		DtFilterState newFilterState = dialog.getFilterState();
		if (currentFilterState.equals(newFilterState)) {
			return;
		}

		provider.setFilterState(newFilterState);

		gtree.expandPaths(expandedPaths);
		gtree.setSelectionPaths(selectionPaths);
	}
}
