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
package ghidra.app.script;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import org.junit.*;

import docking.DialogComponentProvider;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.script.GhidraScriptMgrPlugin;
import ghidra.app.tablechooser.*;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;

public class GhidraScriptTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program;
	private GhidraState state;

	public GhidraScriptTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test1", "0x1001000", 0x1000);
		builder.createMemory("test2", "0x1006000", 0x4000);
		program = builder.getProgram();

		env = new TestEnv();
		PluginTool tool = env.showTool(program);
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(GhidraScriptMgrPlugin.class.getName());

		ProgramLocation loc = new ProgramLocation(program, program.getMinAddress());

		state = new GhidraState(env.getTool(), env.getProject(), program, loc, null, null);
		program.startTransaction(testName.getMethodName());
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testBookmarks() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x1006000);
		Bookmark bookmark1 = script.createBookmark(address, "category", "note");
		Bookmark[] bookmarks = script.getBookmarks(address);
		assertEquals(1, bookmarks.length);
		assertEquals(bookmark1, bookmarks[0]);
		assertEquals("category", bookmarks[0].getCategory());
		assertEquals("note", bookmarks[0].getComment());
		Bookmark bookmark2 = script.createBookmark(address, "category2", "note2");
		Bookmark[] bookmarks2 = script.getBookmarks(address);
		assertEquals(bookmark2, bookmarks2[0]);
		assertEquals("category2", bookmarks2[0].getCategory());
		assertEquals("note2", bookmarks2[0].getComment());
		script.removeBookmark(bookmark1);
		assertEquals(0, script.getBookmarks(address).length);
	}

	@Test
	public void testFunctions() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x1006420);
		Function function1 = script.createFunction(address, "reboot");
		List<Function> functions = script.getGlobalFunctions("reboot");
		assertEquals(1, functions.size());
		Function function2 = functions.get(0);
		Function function3 = script.getFunctionAt(address);
		assertEquals(function1, function2);
		assertEquals(function3, function2);
		script.removeFunction(function1);
		assertNull(script.getFunctionAt(address));
	}

	@Test
	public void testData() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x1008010);
		Data data1 = script.createData(address, new DWordDataType());
		Data data2 = script.getDataAt(address);
		assertEquals(data1, data2);
		script.removeData(data1);
		assertNull(script.getDataAt(address));
		script.createData(address, new DWordDataType());
		assertNotNull(script.getDataAt(address));
		script.removeDataAt(address);
		assertNull(script.getDataAt(address));
	}

	@Test
	public void testPREComments() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x1008010);
		script.setPreComment(address, "Four score and seven years ago...");
		String comment = script.getPreComment(address);
		assertEquals("Four score and seven years ago...", comment);
		script.setPreComment(address, null);
		assertNull(script.getPreComment(address));

		script.setPreComment(address, "Four score and {@url http://www.a.com 7} years ago...");
		comment = script.getPreCommentAsRendered(address);
		assertEquals("Four score and 7 years ago...", comment);
		comment = script.getPreComment(address);
		assertEquals("Four score and {@url http://www.a.com 7} years ago...", comment);
		script.setPreComment(address, null);
		assertNull(script.getPreComment(address));
	}

	@Test
	public void testPOSTComments() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x1008010);
		script.setPostComment(address, "Four score and seven years ago...");
		String comment = script.getPostComment(address);
		assertEquals("Four score and seven years ago...", comment);
		script.setPostComment(address, null);
		assertNull(script.getPostComment(address));

		script.setPostComment(address, "Four score and {@url http://www.a.com 7} years ago...");
		comment = script.getPostCommentAsRendered(address);
		assertEquals("Four score and 7 years ago...", comment);
		comment = script.getPostComment(address);
		assertEquals("Four score and {@url http://www.a.com 7} years ago...", comment);
		script.setPostComment(address, null);
		assertNull(script.getPostComment(address));
	}

	@Test
	public void testEOLComments() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x1008010);
		script.setEOLComment(address, "Four score and seven years ago...");
		String comment = script.getEOLComment(address);
		assertEquals("Four score and seven years ago...", comment);
		script.setEOLComment(address, null);
		assertNull(script.getEOLComment(address));

		script.setEOLComment(address, "Four score and {@url http://www.a.com 7} years ago...");
		comment = script.getEOLCommentAsRendered(address);
		assertEquals("Four score and 7 years ago...", comment);
		comment = script.getEOLComment(address);
		assertEquals("Four score and {@url http://www.a.com 7} years ago...", comment);
		script.setEOLComment(address, null);
		assertNull(script.getEOLComment(address));
	}

	@Test
	public void testPLATEComments() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x1008010);
		script.setPlateComment(address, "Four score and seven years ago...");
		String comment = script.getPlateComment(address);
		assertEquals("Four score and seven years ago...", comment);
		script.setPlateComment(address, null);
		assertNull(script.getPlateComment(address));

		script.setPlateComment(address, "Four score and {@url http://www.a.com 7} years ago...");
		comment = script.getPlateCommentAsRendered(address);
		assertEquals("Four score and 7 years ago...", comment);
		comment = script.getPlateComment(address);
		assertEquals("Four score and {@url http://www.a.com 7} years ago...", comment);
		script.setPlateComment(address, null);
		assertNull(script.getPlateComment(address));
	}

	@Test
	public void testByteInMemory() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x1008010);
		byte value1 = script.getByte(address);
		script.setByte(address, (byte) ~value1);
		byte value2 = script.getByte(address);
		assertEquals(~value1, value2);
	}

	@Test
	public void testBytesInMemory() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x1008010);
		byte[] values =
			new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, };
		script.setBytes(address, values);
		byte[] values2 = script.getBytes(address, values.length);
		assertEquals(values.length, values2.length);
		for (int i = 0; i < values2.length; i++) {
			assertEquals(values[i], values2[i]);
		}
	}

	@Test
	public void testShortInMemory() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x1008010);
		short value1 = script.getShort(address);
		script.setShort(address, (short) ~value1);
		short value2 = script.getShort(address);
		assertEquals(~value1, value2);
	}

	@Test
	public void testIntInMemory() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x1008010);
		int value1 = script.getInt(address);
		script.setInt(address, ~value1);
		int value2 = script.getInt(address);
		assertEquals(~value1, value2);
	}

	@Test
	public void testLongInMemory() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x1008010);
		long value1 = script.getLong(address);
		script.setLong(address, ~value1);
		long value2 = script.getLong(address);
		assertEquals(~value1, value2);
	}

	@Test
	public void testFloatInMemory() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x1008010);
		float value1 = (float) Math.PI;
		script.setInt(address, Float.floatToIntBits(value1));
		float value2 = Float.intBitsToFloat(script.getInt(address));
		assertEquals(value1, value2, .00001);
	}

	@Test
	public void testDoubleInMemory() throws Exception {
		GhidraScript script = getScript();
		Address address = script.toAddr(0x1008010);
		double value1 = Math.PI;
		script.setLong(address, Double.doubleToLongBits(value1));
		double value2 = Double.longBitsToDouble(script.getLong(address));
		assertEquals(value1, value2, .00001);
	}

	@Test
	public void testToHexStringByte() {
		GhidraScript script = getScript();

		assertEquals("0xab", script.toHexString((byte) 0xab, true, true));
		assertEquals("ab", script.toHexString((byte) 0xab, true, false));
		assertEquals("0xab", script.toHexString((byte) 0xab, false, true));
		assertEquals("ab", script.toHexString((byte) 0xab, false, false));

		assertEquals("0x0b", script.toHexString((byte) 0xb, true, true));
		assertEquals("0b", script.toHexString((byte) 0xb, true, false));
		assertEquals("0xb", script.toHexString((byte) 0xb, false, true));
		assertEquals("b", script.toHexString((byte) 0xb, false, false));

		assertEquals("0x05", script.toHexString((byte) 0x5, true, true));
		assertEquals("05", script.toHexString((byte) 0x5, true, false));
		assertEquals("0x5", script.toHexString((byte) 0x5, false, true));
		assertEquals("5", script.toHexString((byte) 0x5, false, false));
	}

	@Test
	public void testToHexStringShort() {
		GhidraScript script = getScript();

		assertEquals("0x00ab", script.toHexString((short) 0xab, true, true));
		assertEquals("00ab", script.toHexString((short) 0xab, true, false));
		assertEquals("0xab", script.toHexString((short) 0xab, false, true));
		assertEquals("ab", script.toHexString((short) 0xab, false, false));

		assertEquals("0xabab", script.toHexString((short) 0xabab, true, true));
		assertEquals("abab", script.toHexString((short) 0xabab, true, false));
		assertEquals("0xabab", script.toHexString((short) 0xabab, false, true));
		assertEquals("abab", script.toHexString((short) 0xabab, false, false));

		assertEquals("0x000b", script.toHexString((short) 0xb, true, true));
		assertEquals("000b", script.toHexString((short) 0xb, true, false));
		assertEquals("0xb", script.toHexString((short) 0xb, false, true));
		assertEquals("b", script.toHexString((short) 0xb, false, false));

		assertEquals("0x0005", script.toHexString((short) 0x5, true, true));
		assertEquals("0005", script.toHexString((short) 0x5, true, false));
		assertEquals("0x5", script.toHexString((short) 0x5, false, true));
		assertEquals("5", script.toHexString((short) 0x5, false, false));

		assertEquals("0x1234", script.toHexString((short) 0x1234, true, true));
		assertEquals("1234", script.toHexString((short) 0x1234, true, false));
		assertEquals("0x1234", script.toHexString((short) 0x1234, false, true));
		assertEquals("1234", script.toHexString((short) 0x1234, false, false));
	}

	@Test
	public void testToHexStringInt() {
		GhidraScript script = getScript();

		assertEquals("0x000000ab", script.toHexString(0xab, true, true));
		assertEquals("000000ab", script.toHexString(0xab, true, false));
		assertEquals("0xab", script.toHexString(0xab, false, true));
		assertEquals("ab", script.toHexString(0xab, false, false));

		assertEquals("0x0000abab", script.toHexString(0xabab, true, true));
		assertEquals("0000abab", script.toHexString(0xabab, true, false));
		assertEquals("0xabab", script.toHexString(0xabab, false, true));
		assertEquals("abab", script.toHexString(0xabab, false, false));

		assertEquals("0x0000000b", script.toHexString(0xb, true, true));
		assertEquals("0000000b", script.toHexString(0xb, true, false));
		assertEquals("0xb", script.toHexString(0xb, false, true));
		assertEquals("b", script.toHexString(0xb, false, false));

		assertEquals("0x00000005", script.toHexString(0x5, true, true));
		assertEquals("00000005", script.toHexString(0x5, true, false));
		assertEquals("0x5", script.toHexString(0x5, false, true));
		assertEquals("5", script.toHexString(0x5, false, false));

		assertEquals("0x00001234", script.toHexString(0x1234, true, true));
		assertEquals("00001234", script.toHexString(0x1234, true, false));
		assertEquals("0x1234", script.toHexString(0x1234, false, true));
		assertEquals("1234", script.toHexString(0x1234, false, false));

		assertEquals("0xeeeedddd", script.toHexString(0xeeeedddd, true, true));
		assertEquals("eeeedddd", script.toHexString(0xeeeedddd, true, false));
		assertEquals("0xeeeedddd", script.toHexString(0xeeeedddd, false, true));
		assertEquals("eeeedddd", script.toHexString(0xeeeedddd, false, false));

		assertEquals("0x00abc123", script.toHexString(0xabc123, true, true));
		assertEquals("00abc123", script.toHexString(0xabc123, true, false));
		assertEquals("0xabc123", script.toHexString(0xabc123, false, true));
		assertEquals("abc123", script.toHexString(0xabc123, false, false));
	}

	@Test
	public void testToHexStringLong() {
		GhidraScript script = getScript();

		assertEquals("0xaabbccddeeff0011", script.toHexString(0xaabbccddeeff0011L, true, true));
		assertEquals("aabbccddeeff0011", script.toHexString(0xaabbccddeeff0011L, true, false));
		assertEquals("0xaabbccddeeff0011", script.toHexString(0xaabbccddeeff0011L, false, true));
		assertEquals("aabbccddeeff0011", script.toHexString(0xaabbccddeeff0011L, false, false));
	}

	@Test
	public void testCreateTableChooserDialog() throws Exception {
		//
		// Basic test to show the chooser dialog, add some data, press the execute button
		// and add a column (bad test form to perform multiple tests in one test case, but
		// at least we are testing some stuff).
		//
		GhidraScript script = getScript();

		TestTableChooserExecutor executor = new TestTableChooserExecutor();

		TableChooserDialog dialog =
			script.createTableChooserDialog("Title " + testName.getMethodName(), executor);
		dialog.show();
		waitForSwing();
		assertTrue(dialog.isShowing());

		final List<TestAddressableRowObject> data = new ArrayList<>();
		data.add(new TestAddressableRowObject(addr("0x010085a7")));
		data.add(new TestAddressableRowObject(addr("0x010085a9")));
		data.add(new TestAddressableRowObject(addr("0x69676552")));

		dialog.add(data.get(0));
		dialog.add(data.get(1));
		dialog.add(data.get(2));
		waitForDialog(dialog);

		assertEquals(data.size(), dialog.getRowCount());

		//
		// Press the execute button on an item
		//
		JButton executeButton = (JButton) getInstanceField("okButton", dialog);
		assertTrue("Execute button enabled when no row selected", !executeButton.isEnabled());

		GTable table = (GTable) getInstanceField("table", dialog);
		ListSelectionModel selectionModel = table.getSelectionModel();
		runSwing(() -> selectionModel.setSelectionInterval(0, 0));

		Msg.debug(this, "preparing to execute...");
		runSwing(new Runnable() {
			@Override
			public void run() {
				int selectedRow = table.getSelectedRow();
				if (selectedRow < 0) {
					throw new AssertException(
						"Row not selected as expected--can't execute an item");
				}
				Msg.debug(this, "\tclicking execute button in the Swing thread...");
				executeButton.doClick();
			}
		});

		waitForTableChooserDialog(dialog);
		Msg.debug(this, "after executing and waiting for things to finish");

		assertEquals("Execute button did not execute", executor.getLastObjectExecuted(),
			data.get(0));

		//
		// Add a column
		//
		assertEquals(1, getColumnCount(table));

		runSwing(() -> dialog.addCustomColumn(new TestColumnDisplay()));
		waitForSwing();

		// we have to wait for the table to update it's columns after being loaded
		capture(dialog.getComponent(), "chooser.dialog.1");
		waitForConditionWithoutFailing(() -> getColumnCount(table) == 2);
		if (getColumnCount(table) != 2) {
			capture(dialog.getComponent(), "chooser.dialog.2");
			fail("Should only have 2 columns--the original and the newly added");
		}

		assertEquals("Bob", getColumnHeaderValue(table, 1));
	}

	@Test
	public void testSetAndResetAnalysisOptions() {
		//
		// Test analysis option-related methods in GhidraScript.
		// Emphasis on getting and setting/restoring options.
		//

		GhidraScript script = getScript();

		// Reset all analysis options to ensure they're set to default
		script.resetAllAnalysisOptions(program);

		Map<String, String> currOptions = script.getCurrentAnalysisOptionsAndValues(program);

		// Only one available option: "Decompiler Parameter ID.Prototype Evaluation"
		String testOption = "Decompiler Parameter ID.Prototype Evaluation";
		String defaultValue = script.getAnalysisOptionDefaultValue(program, testOption);
		String testValue = "__fastcall/__thiscall/__stdcall";
		String currentValue;

		// Test that reset value is indeed equal to expected default value
		currentValue = currOptions.get(testOption);
		assertEquals("Current Value: " + currentValue + " and Default Value: " + defaultValue +
			" are not equal.", currentValue, defaultValue);

		// Test that we are about to set an option that is not the default option
		assertFalse(script.isAnalysisOptionDefaultValue(program, testOption, testValue));

		// Set the option to testValue, verify that it was really set.
		script.setAnalysisOption(program, testOption, testValue);
		assertEquals(
			"Current value for option " + testOption + " and set value: " + testValue +
				" are not equal.",
			script.getCurrentAnalysisOptionsAndValues(program).get(testOption), testValue);

		// Reset to default again, verify value is equal to default value
		script.resetAnalysisOption(program, testOption);
		assertEquals(
			"Current value for option " + testOption + " and default value: " + defaultValue +
				" are not equal.",
			script.getCurrentAnalysisOptionsAndValues(program).get(testOption), defaultValue);
	}

	@Test
	public void testSetInvalidAnalysisOptionsAndValues() {

		//
		//  Try setting an analysis option with an invalid name or value, and
		//  ensure that the correct behavior occurs.
		//

		// create a enum test option

		int startTransaction = program.startTransaction("Test");
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		options.setEnum("bob", TestEnum.a);
		program.endTransaction(startTransaction, true);

		GhidraScript script = getScript();

		String validOptionName = "bob";

		// Try to set a valid option to an invalid value and verify that the invalid value was not stored.
		String invalidValue = "d";
		script.setAnalysisOption(program, validOptionName, invalidValue);
		assertFalse(script.getCurrentAnalysisOptionsAndValues(program).get(validOptionName).equals(
			invalidValue));

		// Try to set an invalid option and verify that the option is not successfully set.
		String invalidOption = "invalidOption";
		String validValue = "__stdcall";
		script.setAnalysisOption(program, invalidOption, validValue);
		assertNull(script.getCurrentAnalysisOptionsAndValues(program).get(invalidOption));

		// Set more than one invalid name/option at a time, verify that none are successfully set
		Map<String, String> invalidOptionsAndValues = new HashMap<>();

		invalidOptionsAndValues.put(validOptionName, "d");
		invalidOptionsAndValues.put(invalidOption, invalidValue);

		script.setAnalysisOptions(program, invalidOptionsAndValues);
		Map<String, String> currentOptions = script.getCurrentAnalysisOptionsAndValues(program);
		assertNotNull(currentOptions.get(validOptionName));
		assertNull(currentOptions.get(invalidOption));
	}

	@Test
	public void testAskChoiceDefaultValue_NullDefaultValue() throws Exception {
		final GhidraScript script = getScript();
		final String[] myChoice = new String[1];

		final String[] choices = new String[] { "one fish", "two fish", "red fish", "blue fish" };

		runSwing(() -> {
			try {
				myChoice[0] = script.askChoice("Ask Default Choice Test", "Pick",
					Arrays.asList(choices), null);
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.toString(), e);
			}
		}, false);

		@SuppressWarnings({ "rawtypes" })
		AskDialog askDialog = waitForDialogComponent(AskDialog.class);
		assertNotNull(askDialog);
		pressButtonByText(askDialog, "OK");

		waitForSwing();

		// The null passed-in means the first item will have been selected
		assertEquals(choices[0], myChoice[0]);
	}

	@Test
	public void testAskChoices_DifferentInterfaceImplementations_ChooseOne() throws Exception {

		GhidraScript script = getScript();

		List<TestInterface> values = Arrays.asList(new ATestInterface(), new BTestInterface());
		List<String> labels = Arrays.asList("A", "B");

		AtomicReference<List<TestInterface>> ref = new AtomicReference<>();
		runSwing(() -> {
			try {
				List<TestInterface> userChoices =
					script.askChoices("Ask Choices Test", "Pick", values, labels);
				ref.set(userChoices);
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.toString(), e);
			}
		}, false);

		MultipleOptionsDialog<?> dialog = waitForDialogComponent(MultipleOptionsDialog.class);
		assertNotNull(dialog);
		setToggleButtonSelected(dialog.getComponent(), "choice.check.box.1", true);

		pressButtonByText(dialog, "OK");

		waitForSwing();

		List<TestInterface> userChoices = ref.get();
		assertEquals(1, userChoices.size());
	}

	@Test
	public void testAskChoices_DifferentInterfaceImplementations_ChooseMultiple() throws Exception {

		GhidraScript script = getScript();

		List<TestInterface> values = Arrays.asList(new ATestInterface(), new BTestInterface());
		List<String> labels = Arrays.asList("A", "B");

		AtomicReference<List<TestInterface>> ref = new AtomicReference<>();
		runSwing(() -> {
			try {
				List<TestInterface> userChoices =
					script.askChoices("Ask Choices Test", "Pick", values, labels);
				ref.set(userChoices);
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.toString(), e);
			}
		}, false);

		MultipleOptionsDialog<?> dialog = waitForDialogComponent(MultipleOptionsDialog.class);
		assertNotNull(dialog);
		pressSelectAll(dialog);
		pressButtonByText(dialog, "OK");

		waitForSwing();

		List<TestInterface> userChoices = ref.get();
		assertEquals(values.size(), userChoices.size());
	}

	@Test
	public void testAskChoices_DifferentInterfaceImplementations_Complicated_ChooseMultiple()
			throws Exception {

		GhidraScript script = getScript();

		List<TestInterface> values = Arrays.asList(new CTestInterface(), new DTestInterface());
		List<String> labels = Arrays.asList("C", "D");

		AtomicReference<List<TestInterface>> ref = new AtomicReference<>();
		runSwing(() -> {
			try {
				List<TestInterface> userChoices =
					script.askChoices("Ask Choices Test", "Pick", values, labels);
				ref.set(userChoices);
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.toString(), e);
			}
		}, false);

		MultipleOptionsDialog<?> dialog = waitForDialogComponent(MultipleOptionsDialog.class);
		assertNotNull(dialog);
		pressSelectAll(dialog);
		pressButtonByText(dialog, "OK");

		waitForSwing();

		List<TestInterface> userChoices = ref.get();
		assertEquals(values.size(), userChoices.size());
	}

	@Test
	public void testAskChoices_NoSharedInterface_ChooseMultiple_Deprecated() throws Exception {

		// NOTE: this test can be deleted when the method it calls is deleted

		final GhidraScript script = getScript();

		List<Object> values = Arrays.asList(new JPanel(), new String());
		List<String> labels = Arrays.asList("Panel", "String");

		AtomicReference<List<Object>> ref = new AtomicReference<>();
		runSwing(() -> {
			try {
				List<Object> userChoices =
					script.askChoices("Ask Choices Test", "Pick", values, labels);
				ref.set(userChoices);
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.toString(), e);
			}
		}, false);

		MultipleOptionsDialog<?> dialog = waitForDialogComponent(MultipleOptionsDialog.class);
		assertNotNull(dialog);
		pressSelectAll(dialog);
		pressButtonByText(dialog, "OK");

		waitForSwing();

		List<Object> userChoices = ref.get();
		assertEquals(values.size(), userChoices.size());
	}

	@Test
	public void testAskChoices_JavaPrimitiveWrapper_ChooseMultiple() throws Exception {

		GhidraScript script = getScript();

		List<Double> values = Arrays.asList(1.1, 2.2, 3.3);
		List<String> labels = Arrays.asList("D1", "D2", "D3");

		AtomicReference<List<Double>> ref = new AtomicReference<>();
		runSwing(() -> {
			try {
				List<Double> userChoices =
					script.askChoices("Ask Choices Test", "Pick", values, labels);
				ref.set(userChoices);
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.toString(), e);
			}
		}, false);

		MultipleOptionsDialog<?> dialog = waitForDialogComponent(MultipleOptionsDialog.class);
		assertNotNull(dialog);
		pressSelectAll(dialog);
		pressButtonByText(dialog, "OK");

		waitForSwing();

		List<Double> userChoices = ref.get();
		assertEquals(values.size(), userChoices.size());
	}

	@Test
	public void testAskChoices_JavaPrimitiveWrapper_ChooseNone() throws Exception {

		GhidraScript script = getScript();

		List<Double> values = Arrays.asList(1.1, 2.2, 3.3);
		List<String> labels = Arrays.asList("D1", "D2", "D3");

		AtomicReference<List<Double>> ref = new AtomicReference<>();
		runSwing(() -> {
			try {
				List<Double> userChoices =
					script.askChoices("Ask Choices Test", "Pick", values, labels);
				ref.set(userChoices);
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.toString(), e);
			}
		}, false);

		MultipleOptionsDialog<?> dialog = waitForDialogComponent(MultipleOptionsDialog.class);
		assertNotNull(dialog);
		pressButtonByText(dialog, "OK");

		waitForSwing();

		List<Double> userChoices = ref.get();
		assertTrue(userChoices.isEmpty());
	}

//==================================================================================================
// Helper Code
//==================================================================================================

	private void pressSelectAll(DialogComponentProvider dialog) {
		setToggleButtonSelected(dialog.getComponent(), "select.all.check.box", true);
	}

	private GhidraScript getScript() {
		GhidraScript script = new GhidraScript() {
			@Override
			public void run() throws Exception {
				// test stub
			}
		};
		script.set(state, TaskMonitor.DUMMY, null);
		return script;
	}

	private int getColumnCount(GTable table) {

		AtomicInteger ref = new AtomicInteger();
		runSwing(() -> {
			TableColumnModel columnModel = table.getColumnModel();
			ref.set(columnModel.getColumnCount());
		});

		return ref.get();
	}

	private String getColumnHeaderValue(GTable table, int index) {
		AtomicReference<String> ref = new AtomicReference<>();
		runSwing(() -> {
			TableColumnModel columnModel = table.getColumnModel();
			TableColumn column = columnModel.getColumn(index);
			ref.set(column.getHeaderValue().toString());
		});

		return ref.get();
	}

	private void waitForTableChooserDialog(TableChooserDialog dialog) {
		int numWaits = 0;
		int sleepyTime = 100;
		while (dialog.isBusy() && numWaits < 20) {
			numWaits++;
			sleep(sleepyTime);
		}

		Msg.debug(this,
			"waitForTableChooserDialog(): waited a total of: " + (numWaits * sleepyTime));
		Assert.assertNotEquals(numWaits, 20);
	}

	private Address addr(String address) {
		return program.getAddressFactory().getAddress(address);
	}

	private void waitForDialog(TableChooserDialog dialog) {
		ThreadedTableModel<?, ?> model =
			(ThreadedTableModel<?, ?>) getInstanceField("model", dialog);
		waitForTableModel(model);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	public enum TestEnum {
		a, b, c
	}

	public interface TestInterface {
		// nope
	}

	private class ATestInterface implements TestInterface {
		// nope
	}

	private class BTestInterface implements TestInterface {
		// nope
	}

	private class CTestInterface extends ATestInterface {
		// nope
	}

	private class DTestInterface extends CTestInterface {
		// nope
	}

	private class TestColumnDisplay implements ColumnDisplay<String> {

		@Override
		public int compare(AddressableRowObject o1, AddressableRowObject o2) {
			return 0;// no sorting in test--not testing this
		}

		@Override
		public String getColumnValue(AddressableRowObject rowObject) {
			TestAddressableRowObject t = (TestAddressableRowObject) rowObject;
			return Long.toString(t.getAddress().getUnsignedOffset());
		}

		@Override
		public String getColumnName() {
			return "Bob";
		}

		@Override
		public Class<String> getColumnClass() {
			return String.class;
		}

	}

	private class TestTableChooserExecutor implements TableChooserExecutor {

		private String buttonName = "Press Me!";
		private volatile TestAddressableRowObject lastRowExecuted;

		@Override
		public String getButtonName() {
			return buttonName;
		}

		@Override
		public boolean execute(AddressableRowObject rowObject) {
			Msg.debug(this, "execute() called with rowObject: " + rowObject + "\n\tFrom Thread: " +
				Thread.currentThread().getName());
			lastRowExecuted = (TestAddressableRowObject) rowObject;
			return true;
		}

		TestAddressableRowObject getLastObjectExecuted() {
			return lastRowExecuted;
		}
	}

	private class TestAddressableRowObject implements AddressableRowObject {

		private final Address address;

		TestAddressableRowObject(Address address) {
			this.address = address;
		}

		@Override
		public Address getAddress() {
			return address;
		}

	}
}
