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
package ghidra.app.util.datatype;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.*;

import docking.widgets.*;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.test.*;

public class DataTypeSelectionTextFieldTest extends AbstractDropDownTextFieldTest<DataType> {

	private TestEnv env;
	private PluginTool tool;
	private Program program;

	@Override
	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();
		tool = env.launchDefaultTool(program);

		closeUndesiredArchives();

		initializeGui();
	}

	@Override
	protected ApplicationConfiguration createApplicationConfiguration() {
		GhidraApplicationConfiguration config = new GhidraApplicationConfiguration();
		config.setShowSplashScreen(false);
		return config;
	}

	@Override
	protected DropDownTextFieldDataModel<DataType> createModel() {
		return new DataTypeDropDownSelectionDataModel(tool);
	}

	@Override
	protected DropDownTextField<DataType> createTextField(
			DropDownTextFieldDataModel<DataType> model) {
		return new DropDownSelectionTextField<DataType>(model) {
			@Override
			protected void hideMatchingWindow() {
				// This test does not exercise the 'window hiding' feature.  So, disable it
				// here, which will prevent test issues related to focus.
			}
		};
	}

	// close all archives but the builtin and the program archive
	private void closeUndesiredArchives() {
		DataTypeManagerPlugin plugin = env.getPlugin(DataTypeManagerPlugin.class);
		DataTypeManagerHandler dataTypeManagerHandler = plugin.getDataTypeManagerHandler();
		List<Archive> archivesToClose = dataTypeManagerHandler.getAllFileOrProjectArchives();
		for (Archive archive : archivesToClose) {
			dataTypeManagerHandler.closeArchive(archive);
		}
	}

	@Override
	@After
	public void tearDown() throws Exception {

		// flush any pending events, so they don't happen while we are disposing
		waitForSwing();
		runSwing(() -> {
			parentFrame.setVisible(false);
		});
		waitForSwing();

		env.dispose();
	}

	@Test
	public void testSetText() {
		// make sure the text field is showing, but the window is not
		assertTrue("The text field is not showing as expected.", textField.isShowing());

		setText("d");

		// make sure our set text call did not trigger the window to be created
		assertMatchingWindowHidden();

		clearText();
		typeText("d", true);

		// one more time
		clearText();
		setText("c");

		assertMatchingWindowHidden();
	}

	@Test
	public void testSetGetDataType() {

		addDataTypeToProgram(new DoubleDataType());

		assertTrue("The text field is not showing as expected.", textField.isShowing());

		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		List<DataType> dataTypeList = service.getSortedDataTypeList();

		// this should return at least two 'double's, one from the BuiltIns and one from the program
		// May also get double and double *  from windows archive.
		List<DataType> doubleList = getMatchingSubList("double", dataTypeList);
		String listContents = toString(doubleList);
		assertTrue(listContents, doubleList.size() >= 2);
		DataType builtInDouble = doubleList.get(0);

		// sanity check
		assertEquals("The number and type of 'double's in the test program has changed.",
			builtInDouble.getName(), "double");
		assertEquals(builtInDouble.getDataTypeManager().getName(), "BuiltInTypes");

		String text = "zzzzz";
		setText(text);

		assertTextFieldText(text);

		// test the basic set and get
		setSelectedValue(null);
		assertTextFieldText("");
		assertSelectedValue(null);

		setSelectedValue(builtInDouble);
		assertTextFieldText(builtInDouble.getName());
		assertSelectedValue(builtInDouble);

		// make sure the type is not changed after cancelling the window
		// this call triggers the window to show

		down();

		assertMatchingWindowShowing();
		mimicEscape();
		assertMatchingWindowHidden();
		assertSelectedValue(builtInDouble);

		// make sure setting the second data type gets taken
		DataType programDouble = doubleList.get(1);

		// sanity check
		String programName = "sample";
		assertEquals("The number and type of 'double's in the test program has changed.",
			programDouble.getName(), "double");
		assertEquals(programDouble.getDataTypeManager().getName(), programName);

		setSelectedValue(programDouble);
		assertTextFieldText(programDouble.getName());
		assertSelectedValue(programDouble);

		down();
		assertMatchingWindowShowing();
		mimicEscape();
		assertMatchingWindowHidden();
		assertSelectedValue(programDouble);
	}

	private void mimicEscape() {
		closeMatchingWindow();
	}

	// SCR 2036
	@Test
	public void testStaleDataTypeCache() throws Exception {

		// Step 1 - Setup a potential invalid cache situation
		int transactionID = program.startTransaction("Test");

		DataType dt = new StructureDataType("test", 0);
		dt.setCategoryPath(new CategoryPath("/myPath"));

		DataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType newDt = dataTypeManager.addDataType(dt, null);
		assertEquals("/myPath/test", newDt.getPathName());

		program.endTransaction(transactionID, true);

		triggerText(textField, "t");
		clearText();

		AbstractGhidraHeadlessIntegrationTest.undo(program);

		// Step 2 - Use the DataTypeSelectionTextField to verify there are no explosions
		typeText("t", true);
	}

	@Test
	public void testDropDownSelection_CaseSensitive_For_SCR_6898() throws Exception {

		// add some datatypes for this test
		int transactionID = program.startTransaction("Test");

		// INT for upper-case match
		String name = "INT";
		DataType dt = new StructureDataType(name, 0);
		dt.setCategoryPath(new CategoryPath("/myPath"));

		DataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType newDt = dataTypeManager.addDataType(dt, null);
		assertEquals("/myPath/" + name, newDt.getPathName());

		// intyInt (should not get matched
		name = "intyInt";
		dt = new StructureDataType(name, 0);
		dt.setCategoryPath(new CategoryPath("/myPath"));

		dataTypeManager = program.getDataTypeManager();
		newDt = dataTypeManager.addDataType(dt, null);
		assertEquals("/myPath/" + name, newDt.getPathName());

		// INTStruct (should not get matched
		name = "INTStruct";
		dt = new StructureDataType(name, 0);
		dt.setCategoryPath(new CategoryPath("/myPath"));

		dataTypeManager = program.getDataTypeManager();
		newDt = dataTypeManager.addDataType(dt, null);
		assertEquals("/myPath/" + name, newDt.getPathName());

		program.endTransaction(transactionID, true);

		assertTrue("The text field is not showing as expected.", textField.isShowing());

		// insert some text and make sure the window is created
		typeText("int", true);

		DataType dataType = getSelectedListItem();
		assertEquals("", "int", dataType.getName());

		clearText();
		triggerText(textField, "INT");
		dataType = getSelectedListItem();
		assertEquals("", "INT", dataType.getName());
	}

//==================================================================================================
// Helper methods
//==================================================================================================

	private void addDataTypeToProgram(DoubleDataType doubleDataType) {
		int txID = program.startTransaction("Add Datatype");
		try {
			DataTypeManager dtm = program.getDataTypeManager();
			dtm.addDataType(doubleDataType, null);
		}
		finally {
			program.endTransaction(txID, true);
		}
	}

	private List<DataType> getMatchingSubList(String searchText, List<DataType> dataTypeList) {
		List<DataType> matchingList = new ArrayList<>();
		for (DataType dataType : dataTypeList) {
			if (dataType.getName().startsWith(searchText)) {
				matchingList.add(dataType);
			}
		}

		return matchingList;
	}

}
