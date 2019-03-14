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
package ghidra.app.plugin.core.references;

import ghidra.app.cmd.refs.UpdateExternalNameCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

import java.awt.Window;
import java.util.*;

import javax.swing.table.AbstractTableModel;

/**
 * TableModel for the external program names and corresponding ghidra path names.
 */
class ExternalNamesTableModel extends AbstractTableModel {

	final static int NAME_COL = 0;
	final static int PATH_COL = 1;
	final static String EXTERNAL_NAME = "Name";
	final static String PATH_NAME = "Ghidra Program";

	private final String[] columnNames = { EXTERNAL_NAME, PATH_NAME };

	private List<String> nameList = new ArrayList<String>();
	private List<String> pathNameList = new ArrayList<String>();
	private Program program;
	private PluginTool tool;

	public ExternalNamesTableModel(PluginTool tool) {
		this.tool = tool;
	}

	public int getColumnCount() {
		return columnNames.length;
	}

	public int getRowCount() {
		return nameList.size();
	}

	@Override
	public String getColumnName(int column) {
		return columnNames[column];
	}

	public Object getValueAt(int rowIndex, int columnIndex) {
		if (rowIndex >= nameList.size()) {
			return "";
		}
		switch (columnIndex) {
			case NAME_COL:
				return nameList.get(rowIndex);

			case PATH_COL:
				return pathNameList.get(rowIndex);
		}
		return "Unknown Column!";
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (columnIndex == NAME_COL) {
			return true;
		}
		return false;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		String extName = ((String) aValue).trim();

		if ("".equals(extName)) {
			return;
		}

		if (nameList.contains(extName)) {
			if (nameList.indexOf(extName) != rowIndex) {
				Window window = tool.getActiveWindow();
				Msg.showInfo(getClass(), window, "Duplicate Name", "Name already exists: " +
					extName);
			}
			return;
		}

		Command cmd =
			new UpdateExternalNameCmd(nameList.get(rowIndex), extName, SourceType.USER_DEFINED);

		if (!tool.execute(cmd, program)) {
			tool.setStatusInfo(cmd.getStatusMsg());
		}
	}

	void setProgram(Program program) {
		this.program = program;
		updateTableData();
	}

	///////////////////////////////////////////////////////////////////////////

	void updateTableData() {
		nameList.clear();
		pathNameList.clear();

		if (program == null) {
			fireTableDataChanged();
			return;
		}
		ExternalManager extMgr = program.getExternalManager();
		String[] programNames = extMgr.getExternalLibraryNames();
		Arrays.sort(programNames);

		for (int i = 0; i < programNames.length; i++) {
			if (Library.UNKNOWN.equals(programNames[i])) {
				continue;
			}
			nameList.add(programNames[i]);
			pathNameList.add(extMgr.getExternalLibraryPath(programNames[i]));
		}
		fireTableDataChanged();
	}
}
