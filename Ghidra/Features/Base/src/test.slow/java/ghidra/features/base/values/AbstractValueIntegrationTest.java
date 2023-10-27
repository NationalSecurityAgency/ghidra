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
package ghidra.features.base.values;

import javax.swing.JButton;
import javax.swing.JTextField;

import org.junit.After;
import org.junit.Before;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.values.AbstractValue;
import docking.widgets.values.ValuesMapDialog;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.features.base.values.ProjectBrowserPanel;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractValueIntegrationTest extends AbstractGhidraHeadedIntegrationTest {

	protected ValuesMapDialog dialog;
	protected GhidraValuesMap values = new GhidraValuesMap();

	protected TestEnv env;
	protected DomainFolder rootFolder;
	protected DomainFolder folder;
	protected DomainFile fileA;
	protected DomainFile fileB;
	protected ProgramDB programA;
	protected ProgramDB programB;

	@Before
	public void setup() throws Exception {
		env = new TestEnv();
		Project project = env.getProject();
		runSwing(() -> env.getFrontEndTool().setActiveProject(project));
		rootFolder = project.getProjectData().getRootFolder();
		folder = rootFolder.createFolder("A");
		ProgramBuilder programBuilderA = new ProgramBuilder("A", ProgramBuilder._TOY);
		ProgramBuilder programBuilderB = new ProgramBuilder("B", ProgramBuilder._TOY);
		programA = programBuilderA.getProgram();
		programB = programBuilderB.getProgram();
		fileA = folder.createFile("A", programA, TaskMonitor.DUMMY);
		fileB = folder.createFile("B", programB, TaskMonitor.DUMMY);

	}

	@After
	public void tearDown() {
		env.dispose();
	}

	protected void showDialogOnSwingWithoutBlocking() {

		runSwing(() -> {
			dialog = new ValuesMapDialog("Test", null, values);
			DockingWindowManager.showDialog(dialog);
		}, false);

		waitForDialogComponent(DialogComponentProvider.class);
	}

	protected void pressOk() {
		JButton okButton = (JButton) getInstanceField("okButton", dialog);
		runSwing(() -> okButton.doClick());
	}

	protected void pressCancel() {
		JButton okButton = (JButton) getInstanceField("cancelButton", dialog);
		runSwing(() -> okButton.doClick());
	}

	protected void setProjectFileOnProjectTree(AbstractValue<?> value, DomainFile file) {
		ProjectBrowserPanel projectWidget = (ProjectBrowserPanel) value.getComponent();
		pressButtonByName(projectWidget, "BrowseButton", false);

		DataTreeDialog dataTreeDialog = waitForDialogComponent(DataTreeDialog.class);
		runSwing(() -> {
			dataTreeDialog.selectDomainFile(file);
		});
		waitForSwing();
		pressButtonByText(dataTreeDialog, "OK");

	}

	protected void setProjectFolderOnProjectTree(AbstractValue<?> value, DomainFolder folder) {
		ProjectBrowserPanel projectWidget = (ProjectBrowserPanel) value.getComponent();
		pressButtonByName(projectWidget, "BrowseButton", false);

		DataTreeDialog dataTreeDialog = waitForDialogComponent(DataTreeDialog.class);
		runSwing(() -> {
			dataTreeDialog.selectFolder(folder);
		});
		waitForSwing();
		pressButtonByText(dataTreeDialog, "OK");

	}

	protected void setTextOnComponent(AbstractValue<?> nameValue, String text) {
		runSwing(() -> {
			JTextField field = (JTextField) nameValue.getComponent();
			field.setText(text);
		});
	}

	protected AddressFactory createAddressFactory() {
		GenericAddressSpace space1 = new GenericAddressSpace("A", 64, AddressSpace.TYPE_RAM, 0);
		GenericAddressSpace space2 = new GenericAddressSpace("B", 64, AddressSpace.TYPE_RAM, 0);
		return new DefaultAddressFactory(new AddressSpace[] { space1, space2 });
	}

}
