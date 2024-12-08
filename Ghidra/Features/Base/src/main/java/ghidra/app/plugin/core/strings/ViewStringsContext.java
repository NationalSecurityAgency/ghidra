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
package ghidra.app.plugin.core.strings;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import docking.DefaultActionContext;
import ghidra.app.context.DataLocationListContext;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.table.GhidraTable;

public class ViewStringsContext extends DefaultActionContext implements DataLocationListContext {

	private final ViewStringsProvider viewStringsProvider;
	private final GhidraTable table;
	private final ViewStringsTableModel tableModel;

	ViewStringsContext(ViewStringsProvider provider, GhidraTable table,
			ViewStringsTableModel tableModel) {
		super(provider, table);
		this.viewStringsProvider = provider;
		this.table = table;
		this.tableModel = tableModel;
	}

	@Override
	public int getCount() {
		return table.getSelectedRowCount();
	}

	@Override
	public Program getProgram() {
		return viewStringsProvider.getProgram();
	}

	@Override
	public List<ProgramLocation> getDataLocationList() {
		return getDataLocationList(null);
	}

	@Override
	public List<ProgramLocation> getDataLocationList(Predicate<Data> filter) {
		List<ProgramLocation> result = new ArrayList<>();
		int[] selectedRows = table.getSelectedRows();
		for (int row : selectedRows) {
			ProgramLocation location = tableModel.getRowObject(row);
			Data data = DataUtilities.getDataAtLocation(location);
			if (passesFilter(data, filter)) {
				result.add(location);
			}
		}
		return result;
	}

	private boolean passesFilter(Data data, Predicate<Data> filter) {
		if (data == null) {
			return false;
		}
		if (filter == null) {
			return true;
		}
		return filter.test(data);
	}

	ProgramSelection getProgramSelection() {
		return table.getProgramSelection();
	}

	public int getSelectedRowCount() {
		return table.getSelectedRowCount();
	}

	public Data getSelectedData() {
		int selectedRow = table.getSelectedRow();
		if (selectedRow < 0) {
			return null;
		}
		ProgramLocation location = tableModel.getRowObject(selectedRow);
		return DataUtilities.getDataAtLocation(location);
	}

}
