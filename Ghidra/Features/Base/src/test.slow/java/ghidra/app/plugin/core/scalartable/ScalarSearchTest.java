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
package ghidra.app.plugin.core.scalartable;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.*;
import org.junit.experimental.categories.Category;

import docking.action.DockingActionIf;
import generic.test.category.NightlyCategory;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.RollbackException;

@Category(NightlyCategory.class)
public class ScalarSearchTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String COMPOSITE_DATA_ADDRESS = "00400050";
	private static final String DATA_STRING_ADDRESS = "0041fee4";
	private static final String BYTE_SCALAR_ADDRESS = "00421eb0";
	private static final String CHAR_SCALAR_ADDRESS = "00421ed0";
	private static final String DWORD_SCALAR_ADDRESS = "00421ef0";
	private static final String INTEGER3_SCALAR_ADDRESS = "00421f30";
	private static final String INTEGER5_SCALAR_ADDRESS = "00421f50";
	private static final String INTEGER6_SCALAR_ADDRESS = "00421f70";
	private static final String INTEGER7_SCALAR_ADDRESS = "00421f90";
	private static final String LONG_SCALAR_ADDRESS = "00421fd0";
	private static final String LONGLONG_SCALAR_ADDRESS = "00421ff0";
	private static final String QWORD_SCALAR_ADDRESS = "00422010";
	private static final String SHORT_SCALAR_ADDRESS = "00422030";
	private static final String SIGNEDBYTE_SCALAR_ADDRESS = "00422050";
	private static final String SIGNEDDWORD_SCALAR_ADDRESS = "00422070";
	private static final String SIGNEDWORD_SCALAR_ADDRESS = "004220b0";
	private static final String UNSIGNEDINTEGER3_SCALAR_ADDRESS = "004220f0";
	private static final String UNSIGNEDINTEGER5_SCALAR_ADDRESS = "00422110";
	private static final String UNSIGNEDINTEGER6_SCALAR_ADDRESS = "00422130";
	private static final String UNSIGNEDINTEGER7_SCALAR_ADDRESS = "00422150";
	private static final String UNSIGNEDLONG_SCALAR_ADDRESS = "00422190";
	private static final String UNSIGNEDLONGLONG_SCALAR_ADDRESS = "004221b0";
	private static final String UNSIGNEDSHORT_SCALAR_ADDRESS = "004221d0";
	private static final String WORD_SCALAR_ADDRESS = "004221f0";

	private static final String NESTED_STRUCTURE_DATA_ADDRESS = "00400000";

	private int nestedStructureLength;

	private Program program;

	private TestEnv env;
	private PluginTool tool;
	private ScalarSearchPlugin plugin;
	private ScalarSearchProvider provider;
	private DataTypeManager dataTypeManager;

	private long maxScalarVal;
	private long minScalarVal;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		program = buildProgram();

		int defaultPointerSize = program.getDefaultPointerSize();
		maxScalarVal = (long) Math.pow(2, (defaultPointerSize * 8) + 1);
		minScalarVal = -maxScalarVal;

		dataTypeManager = program.getDataTypeManager();

		int txId = program.startTransaction("Test");
		try {
			createCompositeDataType();
			createByteDataType();
			createCharDataType();
			createDWordDataType();
			createInteger3DataType();
			createInteger5DataType();
			createInteger6DataType();
			createInteger7DataType();
			createLongDataType();
			createLongLongDataType();
			createQWordDataType();
			createShortDataType();
			createSignedByteDataType();
			createSignedDWordDataType();
			createSignedWordDataType();
			createUnsignedInteger3DataType();
			createUnsignedInteger5DataType();
			createUnsignedInteger6DataType();
			createUnsignedInteger7DataType();
			createUnsignedLongDataType();
			createUnsignedLongLongDataType();
			createUnsignedShortDataType();
			createWordDataType();
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testMinValueSearchDialogFilter() throws Exception {
		int value = 2;
		searchProgramAndDisplayResults(program, null, value, maxScalarVal);
		assertAllRowsGreaterThan(value);
	}

	@Test
	public void testMaxValueSearchDialogFilter() throws Exception {
		int value = 5;
		searchProgramAndDisplayResults(program, null, minScalarVal, value);
		assertAllRowsLessThan(value);
	}

	@Test
	public void testMinAndMaxSearchDialogFilter() throws Exception {
		int minValue = 2;
		int maxValue = 5;
		searchProgramAndDisplayResults(program, null, minValue, maxValue);
		assertAllRowsGreaterThanMinAndLessThanMax(minValue, maxValue);
	}

	@Test
	public void testMinGreaterThanMaxSearchDialog() throws Exception {
		int minValue = 5;
		int maxValue = 2;
		searchProgramAndDisplayResults(program, null, minValue, maxValue);
		assertNoRowsGiven(minValue, maxValue);
	}

	@Test
	public void testSearchSpecific() throws Exception {
		int searchValue = 5;
		searchProgramAndDisplayResults(program, null, searchValue, 0);
		assertAllRowsEqualTo(searchValue);
	}

	@Test
	public void testSelectionSearch() throws Exception {
		Address selectionAddr = program.getAddressFactory().getAddress("00401107");
		searchProgramAndDisplayResults(program, new AddressSet(selectionAddr, selectionAddr),
			minScalarVal, maxScalarVal);
		assertOnlySelectedDataInTable("00401107");
	}

	@Test
	public void testMinValueFilter() throws Exception {
		int value = 2;
		searchProgramAndDisplayResults(program, null, minScalarVal, maxScalarVal);
		setFilterValues(value, Integer.MAX_VALUE);
		assertAllRowsGreaterThan(value);
	}

	@Test
	public void testMaxValueFilter() throws Exception {
		int value = 5;
		searchProgramAndDisplayResults(program, null, minScalarVal, maxScalarVal);
		setFilterValues(Integer.MIN_VALUE, value);
		assertAllRowsLessThan(value);
	}

	@Test
	public void testMinAndMaxFilter() throws Exception {
		int minValue = 2;
		int maxValue = 5;
		searchProgramAndDisplayResults(program, null, minScalarVal, maxScalarVal);
		setFilterValues(minValue, maxValue);
		assertAllRowsGreaterThanMinAndLessThanMax(minValue, maxValue);
	}

	@Test
	public void testMinGreaterThanMax() throws Exception {
		int minValue = 5;
		int maxValue = 2;
		searchProgramAndDisplayResults(program, null, minScalarVal, maxScalarVal);
		setFilterValues(minValue, maxValue);
		assertNoRowsGiven(minValue, maxValue);
	}

	@Test
	public void testCompositeDataInTable() throws Exception {
		searchProgramAndDisplayResults(program, null, minScalarVal, maxScalarVal);
		assertScalarsFromCompositeDataInTable();
	}

	@Test
	public void testIntegerDataTypesInTable() throws Exception {

		String[] addressStrings = { BYTE_SCALAR_ADDRESS, DWORD_SCALAR_ADDRESS,
			INTEGER3_SCALAR_ADDRESS, LONG_SCALAR_ADDRESS, SHORT_SCALAR_ADDRESS,
			SIGNEDBYTE_SCALAR_ADDRESS, SIGNEDDWORD_SCALAR_ADDRESS, SIGNEDWORD_SCALAR_ADDRESS,
			UNSIGNEDINTEGER3_SCALAR_ADDRESS, UNSIGNEDLONG_SCALAR_ADDRESS,
			UNSIGNEDSHORT_SCALAR_ADDRESS, WORD_SCALAR_ADDRESS };

		searchProgramAndDisplayResults(program, null, minScalarVal, maxScalarVal);
		assertIntegerDataTypesInTable(addressStrings);
	}

	@Test
	public void testTableContainsNoStrings() throws Exception {
		searchProgramAndDisplayResults(program, null, minScalarVal, maxScalarVal);
		assertDataStringNotInScalarTable();
	}

	@Test
	public void testScalarsInNestedStructuresInTable() throws Exception {

		Program p = buildNestedStructureProgram();
		createCompositeStructure(p);
		searchProgramAndDisplayResults(p, null, minScalarVal, maxScalarVal);
		assertNestedScalarsInTable(p);
	}

	/**
	 * Tests that a signed scalar can be found using its decimal
	 * value. 
	 * <p>
	 * The instruction being targeted is at <b>00401090</b>:
	 *    <code>SUB ESP,-0x34</code>
	 * 
	 * @throws Exception
	 */
	@Test
	public void testSearchSpecificSignedScalarDecimal() throws Exception {
		searchProgramAndDisplayResults(program, null, -52, -52);
		List<ScalarRowObject> results = getTableData();
		assertTrue(results.size() == 1);
		assertAllRowsEqualTo(-52);
	}

	/**
	 * Tests that a signed scalar can be found using its hex
	 * value. 
	 * <p>
	 * The instruction being targeted is at <b>00401090</b>:
	 *    <code>SUB ESP,-0x34</code>
	 * 
	 * @throws Exception
	 */
	@Test
	public void testSearchSpecificSignedScalarHex() throws Exception {
		searchProgramAndDisplayResults(program, null, -0x34, -0x34);
		List<ScalarRowObject> results = getTableData();
		assertTrue(results.size() == 1);
		assertAllRowsEqualTo(-0x34);
	}

	/**
	 * Tests that an unsigned scalar can be found using its decimal
	 * value. 
	 * <p>
	 * The instruction being targeted is at <b>004010a0</b>:
	 *    <code>MOV EAX,0xcc</code>
	 * 
	 * @throws Exception
	 */
	@Test
	public void testSearchSpecificUnsignedScalarDecimal() throws Exception {
		searchProgramAndDisplayResults(program, null, 204, 204);
		List<ScalarRowObject> results = getTableData();
		assertTrue(results.size() == 1);
		assertAllRowsEqualTo(204);
	}

	/**
	 * Tests that an unsigned scalar can be found using its hex
	 * value. 
	 * <p>
	 * The instruction being targeted is at <b>004010a0</b>:
	 *    <code>MOV EAX,0xcc</code>
	 * 
	 * @throws Exception
	 */
	@Test
	public void testSearchSpecificUnsignedScalarHex() throws Exception {
		searchProgramAndDisplayResults(program, null, 0xcc, 0xcc);
		List<ScalarRowObject> results = getTableData();
		assertTrue(results.size() == 1);
		assertAllRowsEqualTo(0xcc);
	}

	private void assertAllRowsEqualTo(int value) {

		ScalarSearchModel model = provider.getScalarModel();
		waitForTableModel(model);

		List<ScalarRowObject> data = model.getModelData();

		for (ScalarRowObject rowObject : data) {
			Long signedScalar = rowObject.getScalar().getSignedValue();
			if (signedScalar != value) {
				fail("Table not filtered correctly: value exceeds max filter of " + value +
					"; found " + signedScalar);
			}
		}
	}

	private void assertOnlySelectedDataInTable(String scalarAddress) {

		ScalarSearchModel model = provider.getScalarModel();

		int tableLength = 0;
		Address codeUnitAddress = null;

		List<ScalarRowObject> data = model.getModelData();

		List<String> codeUnitAddressStrings = new ArrayList<>();
		for (ScalarRowObject rowObject : data) {
			codeUnitAddress = rowObject.getAddress();
			codeUnitAddressStrings.add(codeUnitAddress.toString());
			tableLength++;
		}

		if (tableLength != 1) {
			fail("Search did not work correcly: expected 1 table entry, got " + tableLength +
				" in table.");
		}

		if (!codeUnitAddress.toString().equals(scalarAddress)) {
			fail("Table not created correctly: expected to find scalar at address " +
				scalarAddress + "; got " + codeUnitAddress + ".");
		}
	}

	private void assertAllRowsLessThan(int value) {
		ScalarSearchModel model = provider.getScalarModel();
		waitForTableModel(model);

		List<ScalarRowObject> data = model.getModelData();

		for (ScalarRowObject rowObject : data) {
			Long signedScalar = rowObject.getScalar().getSignedValue();
			if (signedScalar > value) {
				fail("Table not filtered correctly: value exceeds max filter of " + value +
					"; found " + signedScalar);
			}
		}
	}

	private void assertAllRowsGreaterThan(int value) {

		ScalarSearchModel model = provider.getScalarModel();
		waitForTableModel(model);

		List<ScalarRowObject> data = model.getModelData();

		for (ScalarRowObject rowObject : data) {
			Long signedScalar = rowObject.getScalar().getValue();
			if (signedScalar < value) {
				fail("Table not filtered correctly: value is less than the min filter of " + value +
					"; found " + signedScalar + "\n\tat row " + rowObject);
			}
		}
	}

	private void assertAllRowsGreaterThanMinAndLessThanMax(int minValue, int maxValue) {

		ScalarSearchModel model = provider.getScalarModel();
		waitForTableModel(model);

		List<ScalarRowObject> data = model.getModelData();

		for (ScalarRowObject rowObject : data) {
			Long signedScalar = rowObject.getScalar().getSignedValue();
			if (signedScalar < minValue || signedScalar > maxValue) {
				fail("Table not filtered correctly: value does not fit the specified range of " +
					minValue + " to " + maxValue + "; found " + signedScalar);
			}
		}
	}

	/**
	 * Function for the case when the min is greater than the max.
	 * In this case, the program expects for there to be 0 entries in the scalar table.
	 */
	private void assertNoRowsGiven(int minValue, int maxValue) {

		ScalarSearchModel model = provider.getScalarModel();
		waitForTableModel(model);

		List<ScalarRowObject> data = model.getModelData();

		assertEquals(0, data.size());
	}

	private void assertScalarsFromCompositeDataInTable() {

		Listing listing = program.getListing();
		DataIterator compositeData = listing.getCompositeData(true);
		Data composite = compositeData.next();
		assertTrue("Expected array; found: " + composite, composite.getDataType() instanceof Array);

		//@formatter:off
		List<ScalarRowObject> data = getTableData();
		List<Address> addresses =
			data.stream()
				.map(rowObject -> rowObject.getAddress())
				.collect(Collectors.toList())
				;
		//@formatter:on

		int n = composite.getNumComponents();
		for (int i = 0; i < n; i++) {
			Data child = composite.getComponent(i);
			Address a = child.getAddress();
			assertTrue(addresses.contains(a));
		}
	}

	private List<ScalarRowObject> getTableData() {
		ScalarSearchModel model = provider.getScalarModel();
		waitForTableModel(model);
		return model.getModelData();
	}

	private void assertIntegerDataTypesInTable(String[] addressStrings) {

		ScalarSearchModel model = provider.getScalarModel();
		waitForTableModel(model);

		List<ScalarRowObject> data = model.getModelData();
		List<String> codeUnitAddressStrings = new ArrayList<>();

		for (ScalarRowObject rowObject : data) {
			Address codeUnitAddress = rowObject.getAddress();
			codeUnitAddressStrings.add(codeUnitAddress.toString());
		}

		for (String string : addressStrings) {
			if (!codeUnitAddressStrings.contains(string)) {
				fail("Table not created correctly: could not find the integer scalar address" +
					string + " in table.");
			}
		}
	}

	private void assertDataStringNotInScalarTable() {

		ScalarSearchModel model = provider.getScalarModel();
		waitForTableModel(model);

		List<ScalarRowObject> data = model.getModelData();

		for (ScalarRowObject rowObject : data) {
			Address codeUnitAddress = rowObject.getAddress();
			if (codeUnitAddress.toString().equals(DATA_STRING_ADDRESS)) {
				Data stringData = program.getListing().getDataAt(codeUnitAddress);
				fail("Table not created correctly: found the occurrence of data string " +
					stringData.getValue().toString() + " at address: " + codeUnitAddress);
			}
		}
	}

	private void assertNestedScalarsInTable(Program p) {

		ScalarSearchModel model = provider.getScalarModel();
		waitForTableModel(model);

		List<ScalarRowObject> data = model.getModelData();
		List<Address> tableAddress = new ArrayList<>();

		for (ScalarRowObject rowObject : data) {
			tableAddress.add(rowObject.getAddress());
		}

		DataIterator compositeData = p.getListing().getCompositeData(true);

		while (compositeData.hasNext()) {

			Data structureData = compositeData.next();
			Address address = structureData.getComponent(0).getAddress();

			if (!tableAddress.contains(address)) {
				fail("Table not created correctly: could not find address " + address +
					"in scalar table.");
			}
		}
	}

	private void setFilterValues(int min, int max) {

		RangeFilterTextField field = (RangeFilterTextField) getInstanceField("minField", provider);
		setFilterValue(field, min);
		waitForTableModel(provider.getScalarModel());

		field = (RangeFilterTextField) getInstanceField("maxField", provider);
		setFilterValue(field, max);
		waitForTableModel(provider.getScalarModel());
	}

	private void setFilterValue(RangeFilterTextField field, int value) {
		runSwing(() -> field.setValue(value));
	}

	/*
	 * Function that will build a testing program given a test file
	 * The function will initialize the program builder and then call
	 * {@link #createFunction(ProgramBuilder, String, String, String, int)}, {@link #createBytes(ProgramBuilder, String, String)}, and {@link #createDataStringVectorVbase()}
	 * to fill out the program in the builder
	 */
	private Program buildProgram() throws Exception {

		ProgramBuilder builder =
			new ProgramBuilder("Test_Program", (new LanguageID("x86:LE:32:default")).toString());
		builder.createMemory("test_program", "00400000", 7000);

		createFunction(builder, "004010b0", "55 8b ec 51 89 4d fc b8 01 00 00 00 8b e5 5d c3",
			"A_virt1@4010b0", 16);
		createFunction(builder, "004010c0", "55 8b ec 51 89 4d fc b8 02 00 00 00 8b e5 5d c3",
			"A_virt2@4010c0", 16);
		createFunction(builder, "004010d0", "55 8b ec b8 03 00 00 00 5d c3", "A_static1@4010d0",
			10);
		createFunction(builder, "004010e0",
			"55 8b ec 51 89 4d fc c7 05 60 52 42 00 04 00 00 00 8b e5 5d c3", "A_simple1@4010e0",
			21);
		createFunction(builder, "00401100", "55 8b ec 51 89 4d fc b8 05 00 00 00 8b e5 5d c3",
			"B_virt1@401100", 16);
		createFunction(builder, "00401110", "55 8b ec 51 89 4d fc b8 06 00 00 00 8b e5 5d c3",
			"B_virt2@401110", 16);
		createFunction(builder, "00401120", "55 8b ec 51 89 4d fc b8 07 00 00 00 8b e5 5d c3",
			"A_virt2@401120", 16);
		createFunction(builder, "00401130", "55 8b ec 51 89 4d fc b8 08 00 00 00 8b e5 5d c3",
			"B_virt2@401130", 16);
		createFunction(builder, "00401140", "48 83 ec cc",
			"C_virt2@401140", 4);
		createFunction(builder, "00401150", "55 8b ec 51 89 4d fc b8 cc 00 00 00 8b e5 5d c3",
			"C_virt2@401150", 16);

		createBytes(builder, COMPOSITE_DATA_ADDRESS,
			"0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 " +
				"72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e " +
				"20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 " + "00 00 00 00");
		createBytes(builder, BYTE_SCALAR_ADDRESS, "c4");
		createBytes(builder, CHAR_SCALAR_ADDRESS, "28");
		createBytes(builder, DWORD_SCALAR_ADDRESS, "08 34 23 cd");
		createBytes(builder, INTEGER3_SCALAR_ADDRESS, "08 34 48");
		createBytes(builder, INTEGER5_SCALAR_ADDRESS, "23 08 34 14 10");
		createBytes(builder, INTEGER6_SCALAR_ADDRESS, "25 79 21 43 08 34");
		createBytes(builder, INTEGER7_SCALAR_ADDRESS, "23 14 22 56 78 08 34");
		createBytes(builder, LONG_SCALAR_ADDRESS, "78 23 1c 34");
		createBytes(builder, LONGLONG_SCALAR_ADDRESS, "78 23 1c 34 08 34 cc fd");
		createBytes(builder, QWORD_SCALAR_ADDRESS, "08 34 23 cd 08 34 cd ef");
		createBytes(builder, SHORT_SCALAR_ADDRESS, "d8 34");
		createBytes(builder, SIGNEDBYTE_SCALAR_ADDRESS, "f8");
		createBytes(builder, SIGNEDDWORD_SCALAR_ADDRESS, "1c 34 89 de");
		createBytes(builder, SIGNEDWORD_SCALAR_ADDRESS, "08 f4");
		createBytes(builder, UNSIGNEDINTEGER3_SCALAR_ADDRESS, "08 34 4d");
		createBytes(builder, UNSIGNEDINTEGER5_SCALAR_ADDRESS, "23 08 34 14 10");
		createBytes(builder, UNSIGNEDINTEGER6_SCALAR_ADDRESS, "25 79 21 43 08 34");
		createBytes(builder, UNSIGNEDINTEGER7_SCALAR_ADDRESS, "25 79 21 43 08 34 ca");
		createBytes(builder, UNSIGNEDLONG_SCALAR_ADDRESS, "08 34 cd ef");
		createBytes(builder, UNSIGNEDLONGLONG_SCALAR_ADDRESS, "08 34 cd ef 08 34 cd ef");
		createBytes(builder, UNSIGNEDSHORT_SCALAR_ADDRESS,
			"d8 34 d8 34 d8 34 d8 34 d8 34 d8 34 d8 34 d8 34");
		createBytes(builder, WORD_SCALAR_ADDRESS, "08 34");

		createDataStringVectorVbase(builder);

		return builder.getProgram();

	}

	/*
	 * Program that will initialize a second program builder that will contain
	 * a structure with nested substructures.  This structure will be made by
	 * calling {@link #createBytes(ProgramBuilder, String, String)}
	 */
	private Program buildNestedStructureProgram() throws Exception {

		String bytesSpaces = "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 " +
			"00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
			"e8 00 00 00 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 " +
			"69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 " +
			"20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e 0d 0d 0a " +
			"24 00 00 00 00 00 00 00";

		nestedStructureLength = bytesSpaces.replace(" ", "").length();

		ProgramBuilder nestedStructureBuilder =
			new ProgramBuilder("Test_Program", new LanguageID("x86:LE:32:default").toString());
		nestedStructureBuilder.createMemory("test_program", "00400000", 256);

		createBytes(nestedStructureBuilder, NESTED_STRUCTURE_DATA_ADDRESS, bytesSpaces);

		return nestedStructureBuilder.getProgram();
	}

	private void createFunction(ProgramBuilder programBuilder, String address, String bytes,
			String functionLabel, int length) throws Exception {

		programBuilder.setBytes(address, bytes);
		programBuilder.createFunction(address);
		programBuilder.createLabel(address, functionLabel);
		programBuilder.disassemble(address, length, true);
	}

	private void createBytes(ProgramBuilder programBuilder, String address, String bytes)
			throws Exception {

		programBuilder.setBytes(address, bytes);
	}

	private void createDataStringVectorVbase(ProgramBuilder builder) throws Exception {

		builder.setBytes(DATA_STRING_ADDRESS,
			"60 65 68 20 76 65 63 74 6f 72 20 76 62 61 73 65 20 63 6f 70 " +
				"79 20 63 6f 6e 73 74 72 75 63 74 6f 72 20 69 74 65 72 61 74 " + "6f 72 27 00");
		builder.disassemble(DATA_STRING_ADDRESS, 44, true);
	}

	/**
	 * Opens the given program and the scalar search dialog, executing a search for scalars
	 * within the program. Optionally filters search results using the min/max values.
	 *
	 * @param customProgram the program to search
	 * @param selection address set to use for program selection; can be null
	 * @param min minimum filter value
	 * @param max maximum filter value
	 * @throws Exception
	 */
	private void searchProgramAndDisplayResults(Program customProgram, AddressSet selection,
			long min, long max) throws Exception {

		ScalarSearchDialog dialog = launchScalarSearchDialog(customProgram, selection);

		dialog.setFilterValues(min, max);

		pressButtonByText(dialog, "Search");
		provider = waitForComponentProvider(ScalarSearchProvider.class);
		waitForTableModel(provider.getScalarModel());
	}

	private ScalarSearchDialog launchScalarSearchDialog(Program customProgram, AddressSet selection)
			throws Exception {

		tool = env.launchDefaultTool(customProgram);
		tool.addPlugin(ScalarSearchPlugin.class.getName());
		plugin = env.getPlugin(ScalarSearchPlugin.class);

		if (selection != null) {
			makeSelection(tool, customProgram, selection);
		}

		DockingActionIf action = getAction(plugin, "Search for Scalars");
		waitForSwing();
		CodeBrowserPlugin cb = env.getPlugin(CodeBrowserPlugin.class);
		CodeViewerProvider cbp = cb.getProvider();
		performAction(action, cbp, false);

		ScalarSearchDialog dialog = waitForDialogComponent(ScalarSearchDialog.class);
		return dialog;
	}

	private void createCompositeDataType() throws Exception {
		ArrayDataType arrayDataType = new ArrayDataType(new ByteDataType(), 6, 2);
		createData(addr(Long.parseLong(COMPOSITE_DATA_ADDRESS, 16)), arrayDataType);
	}

	private void createByteDataType() throws Exception {
		ByteDataType byteDataType = new ByteDataType(dataTypeManager);
		createData(addr(Long.parseLong(BYTE_SCALAR_ADDRESS, 16)), byteDataType);
	}

	private void createCharDataType() throws Exception {
		CharDataType charDataType = new CharDataType(dataTypeManager);
		createData(addr(Long.parseLong(CHAR_SCALAR_ADDRESS, 16)), charDataType);
	}

	private void createDWordDataType() throws Exception {
		DWordDataType dWordDataType = new DWordDataType(dataTypeManager);
		createData(addr(Long.parseLong(DWORD_SCALAR_ADDRESS, 16)), dWordDataType);
	}

	private void createInteger3DataType() throws Exception {
		Integer3DataType integer3DataType = new Integer3DataType(dataTypeManager);
		createData(addr(Long.parseLong(INTEGER3_SCALAR_ADDRESS, 16)), integer3DataType);
	}

	private void createInteger5DataType() throws Exception {
		Integer5DataType integer5DataType = new Integer5DataType(dataTypeManager);
		createData(addr(Long.parseLong(INTEGER5_SCALAR_ADDRESS, 16)), integer5DataType);
	}

	private void createInteger6DataType() throws Exception {
		Integer6DataType integer6DataType = new Integer6DataType(dataTypeManager);
		createData(addr(Long.parseLong(INTEGER6_SCALAR_ADDRESS, 16)), integer6DataType);
	}

	private void createInteger7DataType() throws Exception {
		Integer7DataType integer7DataType = new Integer7DataType(dataTypeManager);
		createData(addr(Long.parseLong(INTEGER7_SCALAR_ADDRESS, 16)), integer7DataType);
	}

	private void createLongDataType() throws Exception {
		LongDataType longDataType = new LongDataType(dataTypeManager);
		createData(addr(Long.parseLong(LONG_SCALAR_ADDRESS, 16)), longDataType);
	}

	private void createLongLongDataType() throws Exception {
		LongLongDataType longLongDataType = new LongLongDataType(dataTypeManager);
		createData(addr(Long.parseLong(LONGLONG_SCALAR_ADDRESS, 16)), longLongDataType);
	}

	private void createQWordDataType() throws Exception {
		QWordDataType qWordDataType = new QWordDataType(dataTypeManager);
		createData(addr(Long.parseLong(QWORD_SCALAR_ADDRESS, 16)), qWordDataType);
	}

	private void createShortDataType() throws Exception {
		ShortDataType shortDataType = new ShortDataType(dataTypeManager);
		createData(addr(Long.parseLong(SHORT_SCALAR_ADDRESS, 16)), shortDataType);
	}

	private void createSignedByteDataType() throws Exception {
		SignedByteDataType signedByteDataType = new SignedByteDataType(dataTypeManager);
		createData(addr(Long.parseLong(SIGNEDBYTE_SCALAR_ADDRESS, 16)), signedByteDataType);
	}

	private void createSignedDWordDataType() throws Exception {
		SignedDWordDataType signedDWordDataType = new SignedDWordDataType(dataTypeManager);
		createData(addr(Long.parseLong(SIGNEDDWORD_SCALAR_ADDRESS, 16)), signedDWordDataType);
	}

	private void createSignedWordDataType() throws Exception {
		SignedWordDataType signedWordDataType = new SignedWordDataType(dataTypeManager);
		createData(addr(Long.parseLong(SIGNEDWORD_SCALAR_ADDRESS, 16)), signedWordDataType);
	}

	private void createUnsignedInteger3DataType() throws Exception {
		UnsignedInteger3DataType unsignedInteger3DataType =
			new UnsignedInteger3DataType(dataTypeManager);
		createData(addr(Long.parseLong(UNSIGNEDINTEGER3_SCALAR_ADDRESS, 16)),
			unsignedInteger3DataType);
	}

	private void createUnsignedInteger5DataType() throws Exception {
		UnsignedInteger5DataType unsignedInteger5DataType =
			new UnsignedInteger5DataType(dataTypeManager);
		createData(addr(Long.parseLong(UNSIGNEDINTEGER5_SCALAR_ADDRESS, 16)),
			unsignedInteger5DataType);
	}

	private void createUnsignedInteger6DataType() throws Exception {
		UnsignedInteger6DataType unsignedInteger6DataType =
			new UnsignedInteger6DataType(dataTypeManager);
		createData(addr(Long.parseLong(UNSIGNEDINTEGER6_SCALAR_ADDRESS, 16)),
			unsignedInteger6DataType);
	}

	private void createUnsignedInteger7DataType() throws Exception {
		UnsignedInteger7DataType unsignedInteger7DataType =
			new UnsignedInteger7DataType(dataTypeManager);
		createData(addr(Long.parseLong(UNSIGNEDINTEGER7_SCALAR_ADDRESS, 16)),
			unsignedInteger7DataType);
	}

	private void createUnsignedLongDataType() throws Exception {
		UnsignedLongDataType unsignedLongDataType = new UnsignedLongDataType(dataTypeManager);
		createData(addr(Long.parseLong(UNSIGNEDLONG_SCALAR_ADDRESS, 16)), unsignedLongDataType);
	}

	private void createUnsignedLongLongDataType() throws Exception {
		UnsignedLongLongDataType unsignedLongLongDataType =
			new UnsignedLongLongDataType(dataTypeManager);
		createData(addr(Long.parseLong(UNSIGNEDLONGLONG_SCALAR_ADDRESS, 16)),
			unsignedLongLongDataType);
	}

	private void createUnsignedShortDataType() throws Exception {
		UnsignedShortDataType unsignedShortDataType = new UnsignedShortDataType(dataTypeManager);
		createData(addr(Long.parseLong(UNSIGNEDSHORT_SCALAR_ADDRESS, 16)), unsignedShortDataType);
	}

	private void createWordDataType() throws Exception {
		WordDataType wordDataType = new WordDataType(dataTypeManager);
		createData(addr(Long.parseLong(WORD_SCALAR_ADDRESS, 16)), wordDataType);
	}

	private void createData(Address address, DataType dataType) {
		CreateDataCmd createDataCommand = new CreateDataCmd(address, dataType);
		assertTrue("Unable to apply data type at address: " + address, apply(createDataCommand));
	}

	private boolean apply(Command cmd) throws RollbackException {
		return cmd.applyTo(program);
	}

	/**
	 * Function that will create a composite structure that contains nested structures
	 * Once the function is made the function will call {@link #createNestedStructures(StructureDataType, int, int)}
	 */
	private void createCompositeStructure(Program p) throws Exception {
		StructureDataType structureDataType =
			new StructureDataType("NESTED_STRUCTURE", nestedStructureLength);
		createNestedStructures(p, structureDataType, 1, nestedStructureLength - 1);

		Address addr = addr(Long.parseLong(NESTED_STRUCTURE_DATA_ADDRESS, 16));
		CreateDataCmd createDataCommand = new CreateDataCmd(addr, structureDataType);
		assertTrue("Unable to apply data type at address: " + addr, applyCmd(p, createDataCommand));
	}

	/*
	 * Function will take an initial structure, and recursively nest structures to that structure
	 * For each possible component for the main structure, the function will continually call itself
	 * until every component of the structure is filled
	 */
	private void createNestedStructures(Program p, StructureDataType structureDataType, int offset,
			int length) {

		StructureDataType nestedStructureDataType =
			new StructureDataType("NESTED_STRUCTURE_" + offset, length);

		ByteDataType byteDataType = new ByteDataType(p.getDataTypeManager());
		structureDataType.replaceAtOffset(0, byteDataType, 1, "", "");
		structureDataType.replaceAtOffset(1, nestedStructureDataType, length,
			"NESTED_STRUCTURE_" + offset, "");

		length--;
		offset++;

		if (length > 0) {
			createNestedStructures(p, nestedStructureDataType, offset, length);
		}
	}

	private Address addr(long offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

}
