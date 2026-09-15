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
package ghidra.test;

import static org.junit.Assert.*;

import javax.swing.JTabbedPane;

import docking.test.AbstractDockingTest;
import docking.widgets.table.GTable;
import generic.test.AbstractGuiTest;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.main.datatable.DomainFileInfo;
import ghidra.framework.main.datatable.ProjectDataTableModel;
import ghidra.framework.main.datatree.DataTree;
import ghidra.util.Swing;

/**
 * This class provides some convenience methods for interacting with a {@link DataTree}.
 */
public class FrontEndDataTableHelper {

	private FrontEndTool frontEndTool;
	private GTable table;
	private ProjectDataTableModel model;

	public FrontEndDataTableHelper(FrontEndTool frontEndTool) {
		this.frontEndTool = frontEndTool;
		table = AbstractGuiTest.findComponent(frontEndTool.getToolFrame(), GTable.class);
		model = (ProjectDataTableModel) table.getModel();
	}

	public void showTablePanel() {

		JTabbedPane projectTabbedPane = (JTabbedPane) AbstractGuiTest
				.findComponentByName(frontEndTool.getToolFrame(), "PROJECT_TABBED_PANE");
		assertNotNull("Project Data tabbed pane not found", projectTabbedPane);

		Swing.runNow(() -> {
			for (int i = 0; i < projectTabbedPane.getTabCount(); i++) {
				if (projectTabbedPane.getTitleAt(i).equals("Table View")) {
					projectTabbedPane.setSelectedIndex(i);
					break;
				}
			}
		});
	}

	public void waitForTable() {
		AbstractDockingTest.waitForTableModel(model);
	}

	public GTable getTable() {
		return table;
	}

	public DomainFileInfo getDomainFileInfoByPath(String path) {
		int rowCount = model.getRowCount();
		for (int row = 0; row < rowCount; ++row) {
			DomainFileInfo fileInfo = model.getRowObject(row);
			if (path.equals(fileInfo.getDomainFile().getPathname())) {
				return fileInfo;
			}
		}
		return null;
	}
}
