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
import docking.widgets.dialogs.NumberRangeInputDialog;
import docking.widgets.tree.*;
import docking.widgets.tree.support.CombinedGTreeFilter;
import docking.widgets.tree.support.GTreeFilter;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.program.model.data.DataType;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.Range;
import ghidra.util.datastruct.SortedRangeList;

public class FindDataTypesBySizeAction extends DockingAction {

	public static final String NAME = "Find Data Types by Size";

	private DataTypeManagerPlugin plugin;

	public FindDataTypesBySizeAction(DataTypeManagerPlugin plugin, String menuSubGroup) {
		this(plugin, NAME, menuSubGroup);
	}

	FindDataTypesBySizeAction(DataTypeManagerPlugin plugin, String name, String menuSubGroup) {
		super(name, plugin.getName());
		this.plugin = plugin;

		setMenuBarData(
			new MenuData(new String[] { name + "..." }, null, "VeryLast", -1, menuSubGroup));
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Find_Data_Types_By_Size"));
	}

	@Override
	public void actionPerformed(ActionContext context) {

		NumberRangeInputDialog inputDialog =
			new NumberRangeInputDialog(getName(), "Size(s)");
		if (!inputDialog.show()) {
			return;
		}

		SortedRangeList values = inputDialog.getValue();
		DataTypesProvider newProvider = plugin.createProvider();
		newProvider.setTitle(getName());
		DataTypeArchiveGTree tree = newProvider.getGTree();
		GTreeFilter filter = createFilter(values);
		tree.setFilterProvider(new MyTreeFilterProvider(tree, filter));
		newProvider.setVisible(true);
	}

	protected GTreeFilter createFilter(SortedRangeList values) {
		return new SizeGTreeFilter(values);
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

		private final SortedRangeList sizes;

		SizeGTreeFilter(SortedRangeList sizes) {
			this.sizes = sizes;
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
			DataType dt = dataTypeNode.getDataType();
			int length = dt.getLength();
			for (Range range : sizes) {
				if (range.contains(length)) {
					return true;
				}
			}

			return false;
		}
	}
}
