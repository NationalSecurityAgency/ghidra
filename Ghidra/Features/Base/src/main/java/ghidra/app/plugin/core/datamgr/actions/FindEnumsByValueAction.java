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

import java.util.Iterator;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.dialogs.NumberRangeInputDialog;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeFilter;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.Range;
import ghidra.util.datastruct.SortedRangeList;
import util.CollectionUtils;

/**
 * Finds enum data types by matching user supplied enum values or ranges.
 */
public class FindEnumsByValueAction extends DockingAction {

	public static final String NAME = "Find Enums by Value";

	private DataTypeManagerPlugin plugin;

	public FindEnumsByValueAction(DataTypeManagerPlugin plugin, String menuSubGroup) {
		super(NAME, plugin.getName());
		this.plugin = plugin;

		setMenuBarData(
			new MenuData(new String[] { NAME + "..." }, null, "VeryLast", -1, menuSubGroup));
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Find_Enums_By_Value"));
	}

	@Override
	public void actionPerformed(ActionContext context) {

		NumberRangeInputDialog inputDialog = new NumberRangeInputDialog(NAME, "Values(s)");
		inputDialog.setHelpLocation(getHelpLocation());
		if (!inputDialog.show()) {
			return;
		}

		SortedRangeList values = inputDialog.getValue();
		DataTypesProvider newProvider = plugin.createProvider();
		newProvider.setTitle(NAME);
		DataTypeArchiveGTree tree = newProvider.getGTree();
		tree.setFilterProvider(
			new SecondaryTreeFilterProvider(tree, new OffsetGTreeFilter(values)));
		newProvider.setVisible(true);
	}

	private class OffsetGTreeFilter implements GTreeFilter {

		private final SortedRangeList offsets;

		OffsetGTreeFilter(SortedRangeList offsets) {
			this.offsets = offsets;
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
			if (!(dataType instanceof Enum)) {
				return false;
			}

			Enum enuum = (Enum) dataType;
			OffsetIterator it = new OffsetIterator(enuum);
			for (Long value : CollectionUtils.asIterable(it)) {
				for (Range range : offsets) {
					int offset = value.intValue();
					if (range.contains(offset)) {
						return true;
					}
					if (offset < range.min) {
						// ranges are ascending sorted order; the enum value is already 
						// smaller than this range, so no more ranges can match
						break;
					}
				}
			}

			return false;
		}

		private class OffsetIterator implements Iterator<Long> {

			private int index = 0;
			private int length;
			private long[] values;

			OffsetIterator(Enum enuum) {
				this.values = enuum.getValues();
				this.length = values.length;
			}

			@Override
			public boolean hasNext() {
				if (index >= length) {
					return false;
				}
				return true;
			}

			@Override
			public Long next() {
				return values[index++];
			}
		}
	}
}
