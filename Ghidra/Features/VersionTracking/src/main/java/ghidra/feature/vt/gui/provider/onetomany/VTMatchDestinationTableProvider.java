/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.gui.provider.onetomany;

import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTSubToolManager;
import ghidra.feature.vt.gui.util.VTSymbolRenderer;
import ghidra.feature.vt.gui.util.AbstractVTMatchTableModel.SourceLabelTableColumn;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.table.GhidraTable;

import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

/**
 * This is a docking window provider for the Destination (main) tool. 
 * It displays info for the function currently containing the cursor within the listing.
 * It also shows a table of the matches within the source program for the current function.
 */
public class VTMatchDestinationTableProvider extends VTMatchOneToManyTableProvider {

	public VTMatchDestinationTableProvider(PluginTool tool, VTController controller,
			VTSubToolManager subToolManager) {
		super(tool, controller, subToolManager, false);
	}

	@Override
	public VTMatchOneToManyTableModel getMatchesTableModel() {
		if (oneToManyTableModel == null) {
			oneToManyTableModel = new VTMatchDestinationTableModel(controller);
		}
		return oneToManyTableModel;
	}

	@Override
	protected GhidraTable initializeMatchesTable() {

		final GhidraTable table = super.initializeMatchesTable();
		// setup the renderers
		TableColumnModel columnModel = table.getColumnModel();

		int sourceLabelColumnIndex =
			oneToManyTableModel.getColumnIndex(SourceLabelTableColumn.class);
		TableColumn sourceLabelColumn = columnModel.getColumn(sourceLabelColumnIndex);
		sourceLabelColumn.setCellRenderer(new VTSymbolRenderer(controller.getServiceProvider(),
			table));

		return table;
	}
}
