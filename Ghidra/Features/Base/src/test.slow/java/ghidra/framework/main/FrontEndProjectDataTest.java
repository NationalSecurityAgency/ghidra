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
package ghidra.framework.main;

import static org.junit.Assert.*;

import javax.swing.table.TableColumn;

import org.junit.*;

import docking.widgets.table.GTable;
import docking.widgets.table.GTableColumnModel;
import ghidra.framework.main.datatable.ProjectDataTablePanel;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class FrontEndProjectDataTest extends AbstractGhidraHeadedIntegrationTest {

	private FrontEndTool frontEndTool;
	private TestEnv env;

	public FrontEndProjectDataTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		env.resetDefaultTools();

		frontEndTool = getFrontEndTool();
		AbstractGhidraHeadedIntegrationTest.showTool(frontEndTool);

	}

	@After
	public void tearDown() throws Exception {
		runSwing(() -> frontEndTool.setVisible(false));
		env.dispose();
	}

	@Test
	public void testTableColumnsPersist() throws Exception {

		ProjectDataTablePanel tablePanel =
			findComponent(frontEndTool.getToolFrame(), ProjectDataTablePanel.class);
		assertNotNull(tablePanel);

		GTable table = (GTable) getInstanceField("gTable", tablePanel);

		final GTableColumnModel columnModel = (GTableColumnModel) table.getColumnModel();
		runSwing(() -> {
			TableColumn column = columnModel.getAllColumns().get(0);
			assertEquals("Type", column.getHeaderValue().toString());
			columnModel.setVisible(column, false);
		});

		waitForSwing();

		closeFrontEndTool();

		frontEndTool = getFrontEndTool();
		AbstractGhidraHeadedIntegrationTest.showTool(frontEndTool);

		tablePanel = findComponent(frontEndTool.getToolFrame(), ProjectDataTablePanel.class);
		assertNotNull(tablePanel);
		waitForSwing();
		table = (GTable) getInstanceField("gTable", tablePanel);
		GTableColumnModel columnModel2 = (GTableColumnModel) table.getColumnModel();
		TableColumn column = columnModel2.getAllColumns().get(0);
		assertEquals("Type", column.getHeaderValue().toString());
		assertFalse(columnModel2.isVisible(column));

	}

	private FrontEndTool getFrontEndTool() {
		if (frontEndTool == null) {
			runSwing(() -> {
				frontEndTool = new TestFrontEndTool(env.getProjectManager());
				AppInfo.setFrontEndTool(frontEndTool);
				frontEndTool.setActiveProject(env.getProject());
				frontEndTool.setConfigChanged(false);
			});
		}
		return frontEndTool;
	}

	private void closeFrontEndTool() {
		invokeInstanceMethod("saveToolConfigurationToDisk", frontEndTool);
		runSwing(() -> frontEndTool.setVisible(false));
		frontEndTool = null;
		waitForSwing();
	}

}
