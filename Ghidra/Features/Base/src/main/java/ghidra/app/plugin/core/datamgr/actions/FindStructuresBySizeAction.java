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

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeFilter;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.Range;
import ghidra.util.datastruct.SortedRangeList;

/**
 * Allows the user to supply one or more sizes that are used to search for structures that have
 * that size.
 */
public class FindStructuresBySizeAction extends FindDataTypesBySizeAction {

	@SuppressWarnings("hiding")
	public static final String NAME = "Find Structures by Size";

	public FindStructuresBySizeAction(DataTypeManagerPlugin plugin, String menuSubGroup) {
		super(plugin, NAME, menuSubGroup);
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Find_Structures_By_Size"));
	}

	@Override
	protected GTreeFilter createFilter(SortedRangeList values) {
		return new StructureSizeGTreeFilter(values);
	}

	private class StructureSizeGTreeFilter implements GTreeFilter {

		private final SortedRangeList sizes;

		StructureSizeGTreeFilter(SortedRangeList sizes) {
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
			DataType dataType = dataTypeNode.getDataType();
			if (!(dataType instanceof Structure)) {
				return false;
			}

			Structure structure = (Structure) dataType;
			int length = structure.getLength();
			for (Range range : sizes) {
				if (range.contains(length)) {
					return true;
				}
			}

			return false;
		}
	}
}
