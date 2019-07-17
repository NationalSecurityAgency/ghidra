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
package ghidra.app.plugin.core.references;

import java.awt.Window;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.table.AbstractSortedTableModel;
import ghidra.app.cmd.refs.UpdateExternalNameCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

public class ExternalNamesTableModel extends AbstractSortedTableModel<ExternalPath> {

	final static int NAME_COL = 0;
	final static int PATH_COL = 1;
	final static String EXTERNAL_NAME = "Name";
	final static String PATH_NAME = "Ghidra Program";
	private final List<String> columns = List.of(EXTERNAL_NAME, PATH_NAME);

	private PluginTool tool;
	private Program program;
	private List<ExternalPath> paths = new ArrayList<>();

	public ExternalNamesTableModel(PluginTool tool) {
		this.tool = tool;
	}

	@Override
	public int getColumnCount() {
		return columns.size();
	}

	@Override
	public String getColumnName(int column) {
		return columns.get(column);
	}

	@Override
	public String getName() {
		return "External Programs Model";
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (columnIndex == NAME_COL) {
			return true;
		}
		return false;
	}

	@Override
	public List<ExternalPath> getModelData() {
		return paths;
	}

	@Override
	public Object getColumnValueForRow(ExternalPath t, int columnIndex) {

		switch (columnIndex) {
			case NAME_COL:
				return t.getName();
			case PATH_COL:
				return t.getPath();
		}
		return "Unknown Column!";
	}

	@Override
	public void setValueAt(Object aValue, int row, int column) {

		String newName = ((String) aValue).trim();
		if (StringUtils.isBlank(newName)) {
			return;
		}

		int index = indexOf(newName);
		if (index >= 0) {
			Window window = tool.getActiveWindow();
			Msg.showInfo(getClass(), window, "Duplicate Name", "Name already exists: " + newName);
			return;
		}

		ExternalPath path = paths.get(row);
		String oldName = path.getName();
		Command cmd = new UpdateExternalNameCmd(oldName, newName, SourceType.USER_DEFINED);
		if (!tool.execute(cmd, program)) {
			tool.setStatusInfo(cmd.getStatusMsg());
		}
	}

	private int indexOf(String name) {
		for (int i = 0; i < paths.size(); i++) {
			ExternalPath path = paths.get(i);
			if (path.getName().equals(name)) {
				return i;
			}
		}
		return 0;
	}

	void setProgram(Program program) {
		this.program = program;
		updateTableData();
	}

	void updateTableData() {

		paths.clear();

		if (program == null) {
			fireTableDataChanged();
			return;
		}

		ExternalManager extMgr = program.getExternalManager();
		String[] programNames = extMgr.getExternalLibraryNames();
		Arrays.sort(programNames);

		for (String programName : programNames) {
			if (Library.UNKNOWN.equals(programName)) {
				continue;
			}

			ExternalPath path =
				new ExternalPath(programName, extMgr.getExternalLibraryPath(programName));
			paths.add(path);
		}
		fireTableDataChanged();
	}
}
