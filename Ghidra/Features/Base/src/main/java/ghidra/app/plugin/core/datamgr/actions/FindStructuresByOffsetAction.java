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
import docking.widgets.tree.*;
import docking.widgets.tree.support.CombinedGTreeFilter;
import docking.widgets.tree.support.GTreeFilter;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.program.model.data.*;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.Range;
import ghidra.util.datastruct.SortedRangeList;
import util.CollectionUtils;

/**
 * Allows the user to supply one or more offsets that are used to search for structures that have
 * any of those offsets.   
 */
public class FindStructuresByOffsetAction extends DockingAction {

	public static final String NAME = "Find Structures by Offset";

	private DataTypeManagerPlugin plugin;

	public FindStructuresByOffsetAction(DataTypeManagerPlugin plugin, String menuSubGroup) {
		super(NAME, plugin.getName());
		this.plugin = plugin;

		setMenuBarData(
			new MenuData(new String[] { NAME + "..." }, null, "VeryLast", -1, menuSubGroup));
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Find_Structures_By_Offset"));
	}

	@Override
	public void actionPerformed(ActionContext context) {

		NumberRangeInputDialog inputDialog =
			new NumberRangeInputDialog(NAME, "Offset(s)");
		if (!inputDialog.show()) {
			return;
		}

		SortedRangeList values = inputDialog.getValue();
		DataTypesProvider newProvider = plugin.createProvider();
		newProvider.setTitle(NAME);
		DataTypeArchiveGTree tree = newProvider.getGTree();
		tree.setFilterProvider(new MyTreeFilterProvider(tree, new OffsetGTreeFilter(values)));
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
			if (!(dataType instanceof Structure)) {
				return false;
			}

			Structure structure = (Structure) dataType;
			OffsetIterator it = new OffsetIterator(structure);
			for (Integer structureOffset : CollectionUtils.asIterable(it)) {
				for (Range range : offsets) {
					if (range.contains(structureOffset)) {
						return true;
					}
					if (structureOffset > range.max) {
						// ranges are ascending sorted order; the structure offset is already 
						// bigger than this range, so no more ranges can match
						break;
					}
				}
			}

			return false;
		}

		private class OffsetIterator implements Iterator<Integer> {

			private DataTypeComponent[] components;
			private int index = 0;
			private int length;

			OffsetIterator(Structure s) {
				this.components = s.getComponents();
				this.length = components.length;
			}

			@Override
			public boolean hasNext() {
				if (index >= length) {
					return false;
				}
				return true;
			}

			@Override
			public Integer next() {
				DataTypeComponent dtc = components[index++];
				return dtc.getOffset();
			}
		}
	}
}
