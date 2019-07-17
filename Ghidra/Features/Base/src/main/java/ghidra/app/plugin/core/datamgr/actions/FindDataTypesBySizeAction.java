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

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.dialogs.NumberInputDialog;
import docking.widgets.tree.*;
import docking.widgets.tree.support.CombinedGTreeFilter;
import docking.widgets.tree.support.GTreeFilter;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.program.model.data.DataType;
import ghidra.util.HelpLocation;

public class FindDataTypesBySizeAction extends DockingAction {

	private DataTypeManagerPlugin plugin;

	public FindDataTypesBySizeAction(DataTypeManagerPlugin plugin) {
		super("Find Data Types By Size", plugin.getName());
		this.plugin = plugin;

		setMenuBarData(
			new MenuData(new String[] { "Find Data Types by Size..." }, null, "VeryLast", -1, "2"));

		setEnabled(true);
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Find_Data_Types_By_Size"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		NumberInputDialog numberInputDialog = new NumberInputDialog("bytes", 1, 1);

		if (!numberInputDialog.show()) {
			return;
		}

		int value = numberInputDialog.getValue();

		String title = "Find Data Types With Size";
		final DataTypesProvider newProvider = plugin.createProvider();
		newProvider.setTitle(title);
		DataTypeArchiveGTree tree = newProvider.getGTree();
		tree.setFilterProvider(new MyTreeFilterProvider(tree, new SizeGTreeFilter(value)));
		newProvider.setVisible(true);
	}

	private class MyTreeFilterProvider extends DefaultGTreeFilterProvider {
		private GTreeFilter secondaryFilter;

		MyTreeFilterProvider(GTree tree, GTreeFilter secondaryFilter) {
			super(tree);
			this.secondaryFilter = secondaryFilter;
		}

		@Override
		public GTreeFilter getFilter() {
			GTreeFilter filter = super.getFilter();
			if (filter == null) {
				return secondaryFilter;
			}
			return new CombinedGTreeFilter(filter, secondaryFilter);
		}
	}

	private class SizeGTreeFilter implements GTreeFilter {

		private final int size;

		SizeGTreeFilter(int size) {
			this.size = size;
		}

		@Override
		public boolean showFilterMatches() {
			return true;
		}

		@Override
		public boolean acceptsNode(GTreeNode node) {
			if (!(node instanceof DataTypeNode)) {
				return false;
			}
			DataTypeNode dataTypeNode = (DataTypeNode) node;
			DataType dataType = dataTypeNode.getDataType();
			int length = dataType.getLength();
			return length == size;
		}
	}
}
