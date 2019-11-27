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
package ghidra.app.plugin.core.codebrowser;

import static org.junit.Assert.*;

import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

import org.junit.Test;

import docking.DockingDialog;
import docking.widgets.table.GTable;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.gotoquery.GoToHelper;
import ghidra.app.plugin.core.navigation.NavigationOptions;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.main.datatree.DataTree;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.framework.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.TaskMonitor;
import mockit.*;

public class ExternalCodeBrowserNavigationTest extends AbstractCodeBrowserNavigationTest {

	private volatile Program lastNavigationProgram;
	private volatile ProgramLocation lastNavigationLocation;

	@Override
	public void setUp() throws Exception {
		super.setUp();

		// this call triggers jMockit to load our spy
		new SpyGoToHelper();

		Project project = getTool().getProject();
		DomainFolder rootFolder = project.getProjectData().getRootFolder();
		rootFolder.createFile("FILE1", program, TaskMonitor.DUMMY);
		rootFolder.createFile("FILE2", program, TaskMonitor.DUMMY);

		int txId = program.startTransaction("Set Path");
		program.getExternalManager().setExternalPath("ADVAPI32.dll", "/FILE1", true);

		//
		// Create a call reference to a thunk function
		// Create a thunk function to an external location
		//
		String arbitraryAddress = "0x1001000";
		ExternalLocation externalLocation = builder.createExternalFunction(arbitraryAddress,
			"ADVAPI32.dll", "externalFunctionXyz", "_Zxyz");
		String thunkAddress = "0x1006300";
		Function thunk = builder.createFunction(thunkAddress);
		thunk.setThunkedFunction(externalLocation.getFunction());

		builder.createMemoryCallReference("0x1001030", thunkAddress);

		program.endTransaction(txId, true);
		program.flushEvents();
		waitForSwing();
	}

	private void addThunkToExternalFunction(String libraryName, String label,
			Address thunkAddress) {
		ExternalLocation externalLocation =
			program.getExternalManager().getExternalLocation(libraryName, label);
		Function extFunction = externalLocation.getFunction();

		CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(thunkAddress,
			new AddressSet(thunkAddress), extFunction.getEntryPoint());
		int txId = program.startTransaction("Add Thunk");
		cmd.applyTo(program);
		program.endTransaction(txId, true);
	}

	/*
	 * This test is intended to verify proper navigation on operand external
	 * reference associated with an operand when the External Navigation option
	 * indicates Navigate to Linkage (default behavior) and external program
	 * path has already been established.
	 */
	@Test
	public void testOperandExternalLinkageNavigation() throws Exception {

		cb.goTo(new OperandFieldLocation(program, addr("1001020"), null, null, null, 0, 0));
		assertEquals(addr("1001020"), cb.getCurrentAddress());

		// verify that we navigate to import address table entry (i.e., linkage)
		// at 1001000 associated with external location which is also referenced at 1001020
		click(cb, 2);
		assertEquals(addr("1001000"), cb.getCurrentAddress());

		assertEquals(program, lastNavigationProgram);
		assertEquals("FILE2", lastNavigationProgram.getDomainFile().getName());
		assertEquals(addr("1001000"), lastNavigationLocation.getAddress());

		// move to operand field at 1001000
		cb.goTo(new OperandFieldLocation(program, addr("1001000"), null, null, null, 0, 0));
		assertEquals(addr("1001000"), cb.getCurrentAddress());

		// verify that navigation to the external program, address 0x1001888, is performed
		// since navigation initiated from linkage location
		click(cb, 2);
		assertEquals(addr("1001888"), cb.getCurrentAddress());

		assertEquals("FILE1", lastNavigationProgram.getDomainFile().getName());
		assertEquals(addr("1001888"), lastNavigationLocation.getAddress());

	}

	/*
	 * This test is intended to verify proper navigation on operand external
	 * reference associated with an operand when the External Navigation option
	 * indicates Navigate to Linkage (default behavior) and multiple linkages
	 * exist which will cause a list of linkage locations to be displayed
	 * allowing one to be selected.
	 */
	@Test
	public void testOperandExternalMultipleLinkageNavigation() throws Exception {

		addThunkToExternalFunction("ADVAPI32.dll", "IsTextUnicode", addr("0x1001100"));

		cb.goTo(new OperandFieldLocation(program, addr("1001020"), null, null, null, 0, 0));
		assertEquals(addr("1001020"), cb.getCurrentAddress());

		// verify that we navigate to import address table entry (i.e., linkage)
		// at 1001000 associated with external location which is also referenced at 1001020
		click(cb, 2);

		GTable table = waitForResults();

		TableColumnModel columnModel = table.getColumnModel();
		int columnIndex = columnModel.getColumnIndex("Location");
		TableModel model = table.getModel();

		assertEquals("01001000", model.getValueAt(0, columnIndex).toString()); // pointer
		assertEquals("01001100", model.getValueAt(1, columnIndex).toString()); // thunk

		// selection triggers navigation
		changeSelectionToNavigate(table, 1, 0);

		runSwing(() -> getProviders()[0].closeComponent());

		assertEquals(addr("1001100"), cb.getCurrentAddress());
	}

	private void changeSelectionToNavigate(GTable gTable, int row, int col) {

		// Note: due to focus issues, we will call navigate directly

		GhidraTable table = (GhidraTable) gTable;
		runSwing(() -> table.navigate(row, col));
	}

	/*
	 * This test is intended to verify proper navigation on operand external
	 * reference associated with an operand when the External Navigation option
	 * indicates Navigate to External Program (non-default behavior) and
	 * external program path has already been established.
	 */
	@Test
	public void testOperandExternalProgramNavigation() throws Exception {

		getTool().getOptions("Navigation").setEnum("External Navigation",
			NavigationOptions.ExternalNavigationEnum.NavigateToExternalProgram);

		cb.goTo(new OperandFieldLocation(program, addr("1001020"), null, null, null, 0, 0));
		assertEquals(addr("1001020"), cb.getCurrentAddress());
		assertEquals("FILE2", program.getDomainFile().getName());

		// verify that navigation to the external program, address 0x1001888, is performed
		// since navigation initiated from linkage location
		click(cb, 2);

		// note: we have to use a 'wait' here, since the tool must open another program
		Address expected = addr("1001888");
		waitForCondition(() -> expected.equals(cb.getCurrentAddress()));

		assertEquals("FILE1", lastNavigationProgram.getDomainFile().getName());
		assertEquals(addr("1001888"), lastNavigationLocation.getAddress());
	}

	@Test
	public void testOperandExternalProgramNavigation_OnThunk() throws Exception {

		getTool().getOptions("Navigation").setEnum("External Navigation",
			NavigationOptions.ExternalNavigationEnum.NavigateToExternalProgram);

		String fromAddress = "1001030";
		cb.goTo(new OperandFieldLocation(program, addr(fromAddress), null, null, null, 0, 0));
		assertEquals(addr(fromAddress), cb.getCurrentAddress());
		assertEquals("FILE2", program.getDomainFile().getName());

		// verify that navigation to the external program, address 0x1001888, is performed
		// since navigation initiated from linkage location
		click(cb, 2);

		// note: we have to use a 'wait' here, since the tool must open another program
		Address expected = addr("0x01001000");
		waitForCondition(() -> expected.equals(cb.getCurrentAddress()));

		assertEquals("FILE1", lastNavigationProgram.getDomainFile().getName());
		assertEquals(expected, lastNavigationLocation.getAddress());
	}

	/*
	 * This test is intended to verify proper navigation on operand external
	 * reference associated with an operand when the External Navigation option
	 * indicates Navigate to External Program (non-default behavior) and
	 * external program path has NOT been established.
	 */
	@Test
	public void testOperandExternalProgramMissingPathNavigation() throws Exception {

		getTool().getOptions("Navigation").setEnum("External Navigation",
			NavigationOptions.ExternalNavigationEnum.NavigateToExternalProgram);

		// clear external program path
		int txId = program.startTransaction("Set Path");
		program.getExternalManager().setExternalPath("ADVAPI32.dll", null, true);
		program.endTransaction(txId, true);

		cb.goTo(new OperandFieldLocation(program, addr("1001020"), null, null, null, 0, 0));
		assertEquals(addr("1001020"), cb.getCurrentAddress());

		assertEquals("FILE2", program.getDomainFile().getName());

		// verify that navigation to the external program, address 0x1001888, is performed
		// since navigation initiated from linkage location
		click(cb, 2, false);

		DockingDialog dialog = (DockingDialog) waitForWindow("No Program Association");
		assertNotNull("Expected No Program Association Dialog", dialog);
		pressButtonByText(dialog, "Cancel"); // cancel on first try
		waitForSwing();

		assertEquals(addr("1001020"), cb.getCurrentAddress()); // location should not change

		click(cb, 2, false); // try again

		dialog = (DockingDialog) waitForWindow("No Program Association");
		assertNotNull("Expected No Program Association Dialog", dialog);
		pressButtonByText(dialog, "Create Association");
		waitForSwing();

		chooseProjectFile("/FILE1");

		assertEquals(addr("1001888"), cb.getCurrentAddress());

		assertEquals("FILE1", lastNavigationProgram.getDomainFile().getName());
		assertEquals(addr("1001888"), lastNavigationLocation.getAddress());

	}

	private void chooseProjectFile(String filePath) {
		DomainFile extFile = getTool().getProject().getProjectData().getFile(filePath);
		assertNotNull("FILE1 not found", extFile);

		DataTreeDialog projectTreeDialog = waitForDialogComponent(DataTreeDialog.class);
		projectTreeDialog.selectDomainFile(extFile);

		waitForDialogTree(projectTreeDialog);

		pressButtonByText(projectTreeDialog, "OK");
		waitForSwing();
	}

	private void waitForDialogTree(DataTreeDialog dialog) {
		waitForSwing();
		ProjectDataTreePanel treePanel =
			(ProjectDataTreePanel) getInstanceField("treePanel", dialog);
		DataTree dataTree = treePanel.getDataTree();
		waitForTree(dataTree);
	}

	public class SpyGoToHelper extends MockUp<GoToHelper> {

		@Mock
		public boolean goTo(Invocation inv, final Navigatable navigatable, ProgramLocation loc,
				Program p) {

			Msg.debug(this, "goTo() called with " + loc);

			// Track last navigation location
			lastNavigationLocation = loc;
			lastNavigationProgram = p;
			return inv.proceed(navigatable, loc, p); // pass-thru to real
		}
	}
}
