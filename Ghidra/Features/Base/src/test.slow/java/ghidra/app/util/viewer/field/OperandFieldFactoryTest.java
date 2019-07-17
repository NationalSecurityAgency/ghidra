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
package ghidra.app.util.viewer.field;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;

import javax.swing.SwingUtilities;

import org.junit.*;

import ghidra.GhidraOptions;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.cmd.data.CreateStructureCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.refs.AddMemRefCmd;
import ghidra.app.cmd.refs.RemoveAllReferencesCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.framework.cmd.Command;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class OperandFieldFactoryTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin cb;
	private Options fieldOptions;
	private Program program;

	@Before
	public void setUp() throws Exception {

		program = buildProgram();

		env = new TestEnv();
		tool = env.showTool(program);
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		cb = env.getPlugin(CodeBrowserPlugin.class);

		tool.addPlugin(GoToAddressLabelPlugin.class.getName());

		fieldOptions = cb.getFormatManager().getFieldOptions();
	}

	private ProgramDB buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._X86, this);
		builder.createMemory(".text", "0x1001000", 0x6600);

		// testOffcutReferencesToFunction_Indirect
		builder.createEmptyFunction(null, "1001f57", 40, null);
		builder.setBytes("01001f57", "ff 74 24 04", true);
		builder.setBytes("01001f62", "ff 15 d4 10 00 01", true);

		// testOffcutReferencesToFunction_Direct
		builder.setBytes("01001f5b", "e8 68ff ff ff", true);

		// testDefaultLabelMaxmimutStringLength
		builder.setBytes("1002b58", "68 78 16 00 01", true);
		builder.createEncodedString("1001678",
			"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", StandardCharsets.US_ASCII,
			false);

		// testDefaultLabelMaxmimutStringLength
		builder.setBytes("1001000", "68 37 12 00 01", true);  // make bytes point to string+3
		builder.createEncodedString("1001234", "abcdefgh", StandardCharsets.US_ASCII, false);

		return builder.getProgram();
	}

	/**
	 * Clear data and create char array of the same size as previous data
	 * @param addr data address
	 */
	private void createCharArray(Address addr) {
		Listing listing = program.getListing();
		Data d = listing.getDataAt(addr);
		assertNotNull("expected existing data", d);
		int length = d.getLength();
		int txId = program.startTransaction("create char array");
		try {
			listing.clearCodeUnits(addr, addr, true);
			listing.createData(addr, new ArrayDataType(CharDataType.dataType, length, 1));
		}
		catch (CodeUnitInsertionException e) {
			fail("failed to create char array at " + addr);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testOffcutReferenceToFunction_Indirect() throws Exception {
		//
		// This tests that code pointing to a function, offcut by 1 address, will have a mnemonic
		// that reads <function name> + 1.
		//

		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr("1001f57"));
		Address fromAddress = addr("1001f62");
		createOffcutFunctionReference(function, fromAddress);

		assertOperandText(fromAddress, "dword ptr [010010d4]=>FUN_01001f57+1");
	}

	@Test
	public void testOffcutReferenceToFunction_Direct() throws Exception {
		//
		// This tests that code pointing to a function, offcut by 1 address, will have a mnemonic
		// that reads <function name> + 1.
		//

		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr("1001f57"));
		Address fromAddress = addr("1001f5b");
		createOffcutFunctionReference(function, fromAddress);

		// offset FUN_01001f57
		assertOperandText(fromAddress, "offset FUN_01001f57+1");
	}

	/**
	 * Test to make sure that the option for restricting the maximum string length works.
	 */
	@Test
	public void testDefaultLabelMaximumStringLength() throws Exception {

		//
		// default option is to render the string in the default label
		//
		Address operandAddr = addr("01002b58");
		assertOperandText(operandAddr, "s_abcdefghijklmnopqrstuvwxyzABCDEF_01001678");

		//
		// change the option and make sure the rendering updates
		//
		setIntOption(OptionsBasedDataTypeDisplayOptions.MAXIMUM_DEFAULT_LABEL_LENGTH, 5);
		assertOperandText(operandAddr, "s_abcde_01001678");
	}

	/**
	 * Tests the option to not show strings in default labels.
	 */
	@Test
	public void testDefaultLabelRendering_StringOption() throws Exception {

		//
		// default option is to render the string in the default label
		//
		Address operandAddr = addr("01002b58");
		assertOperandText(operandAddr, "s_abcdefghijklmnopqrstuvwxyzABCDEF_01001678");

		//
		// change the option and make sure the rendering updates
		//
		setBooleanOption(OptionsBasedDataTypeDisplayOptions.DISPLAY_ABBREVIATED_DEFAULT_LABELS,
			true);
		assertOperandText(operandAddr, "STR_01001678");
	}

	/**
	 * Tests the option to not show strings in default labels.
	 */
	@Test
	public void testDefaultLabelRenderingCharArray_StringOption() throws Exception {

		createCharArray(addr("1001678")); // convert string to char array

		//
		// default option is to render the string in the default label
		//
		Address operandAddr = addr("01002b58");
		assertOperandText(operandAddr, "s_abcdefghijklmnopqrstuvwxyzABCDEF_01001678");

		//
		// change the option and make sure the rendering updates
		//
		setBooleanOption(OptionsBasedDataTypeDisplayOptions.DISPLAY_ABBREVIATED_DEFAULT_LABELS,
			true);
		assertOperandText(operandAddr, "STR_01001678");
	}

	@Test
	public void testOffcutStringDynamicLabelReference() throws Exception {

		// Note: for dynamic labels, we don't render the string based upon its offcut index, but
		//       rather we just show the entire string.  Alternatively, if there is a label there,
		//       we show that.  The label will show the string at its offcut location.
		Address operandAddr = addr("01001000");
		assertOperandText(operandAddr, "s_defgh_01001234+3");

		//
		// change the option and make sure the rendering updates
		//
		setBooleanOption(OptionsBasedDataTypeDisplayOptions.DISPLAY_ABBREVIATED_DEFAULT_LABELS,
			true);
		assertOperandText(operandAddr, "STR_01001234+3");
	}

	@Test
	public void testOffcutCharArrayDynamicLabelReference() throws Exception {

		createCharArray(addr("1001234")); // convert to string char array

		// Note: for dynamic labels, we don't render the string based upon its offcut index, but
		//       rather we just show the entire string.  Alternatively, if there is a label there,
		//       we show that.  The label will show the string at its offcut location.
		Address operandAddr = addr("01001000");
		assertOperandText(operandAddr, "s_defgh_01001234+3");

		//
		// change the option and make sure the rendering updates
		//
		setBooleanOption(OptionsBasedDataTypeDisplayOptions.DISPLAY_ABBREVIATED_DEFAULT_LABELS,
			true);
		assertOperandText(operandAddr, "STR_01001234+3");
	}

	@Test
	public void testOffcutStringNonDynamicLabelReference() throws Exception {
		String name = "Bob";
		createLabel("1001237", name);

		assertTrue(cb.goToField(addr("1001000"), OperandFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(name, tf.getText());
	}

	@Test
	public void testOffcutStringDynamicLabelReference_ShowOffcutInfoOptionOff() {
		//
		// Use options to hide the offcut info for a dynamic string reference.  By default the
		// option is on (unless we change that).  This tests the 'off' condition.
		//

		ToolOptions options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		options.setBoolean(
			GhidraOptions.OPERAND_GROUP_TITLE + Options.DELIMITER + "Show Offcut Information",
			false);

		assertTrue(cb.goToField(addr("1001000"), OperandFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		assertEquals("s_defgh", tf.getText());
	}

	/**
	 * Tests that offcut references into arrays are painted as offsets into the array and not
	 * as simply an offset from the min address.
	 */
	@Test
	public void testOffcutReferenceIntoArray() throws Exception {
//		openEmptyNotepad();

		StructureDataType structure = new StructureDataType("structure", 0);
		structure.add(IntegerDataType.dataType, "field1", "Comment 1");
		structure.add(IntegerDataType.dataType, "field2", "Comment 2");
		structure.add(IntegerDataType.dataType, "field3", "Comment 3");

		Address arrayAddr = addr("01001888");
		Command cmd = new CreateArrayCmd(arrayAddr, 3, structure, 12);
		applyCmd(program, cmd);

		String arrayName = "ArrayOfStructures";
		cmd = new AddLabelCmd(arrayAddr, arrayName, SourceType.USER_DEFINED);
		applyCmd(program, cmd);

		String operandAddressString = "1006440";
		Address operandAddr = addr(operandAddressString);
		cmd = new AddMemRefCmd(addr(operandAddressString), addr("010018a0"),
			SourceType.USER_DEFINED, 0, true);
		applyCmd(program, cmd);

		//
		// We should expect the operand field to use the dynamic label of the array, which is
		// generated by the reference.  It should look something like:
		//     ArrayOfStructures[2].field1
		//
		assertTrue(cb.goToField(operandAddr, OperandFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(arrayName + "[2].field1", tf.getText());
	}

	/**
	 * Similar test as {@link #testOffcutReferenceIntoArray()}.
	 */
	@Test
	public void testOffcutReferenceIntoStructure() throws Exception {
		//	openEmptyNotepad();

		StructureDataType structure = new StructureDataType("structure", 0);
		structure.add(IntegerDataType.dataType, "field1", "Comment 1");
		structure.add(IntegerDataType.dataType, "field2", "Comment 2");
		structure.add(IntegerDataType.dataType, "field3", "Comment 3");

		Address structAddr = addr("01001888");
		Command cmd = new CreateStructureCmd(structure, structAddr);
		applyCmd(program, cmd);

		String structName = "Structure";
		cmd = new AddLabelCmd(structAddr, structName, SourceType.USER_DEFINED);
		applyCmd(program, cmd);

		String operandAddressString = "1006440";
		Address operandAddr = addr(operandAddressString);
		cmd = new AddMemRefCmd(addr(operandAddressString), addr("100188c"), SourceType.USER_DEFINED,
			0, true);
		applyCmd(program, cmd);

		//
		// We should expect the operand field to use the dynamic label of the array, which is
		// generated by the reference.  It should look something like:
		//     ArrayOfStructures[2].field1
		//
		assertTrue(cb.goToField(operandAddr, OperandFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(structName + ".field2", tf.getText());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	protected void disassembleAt(Address addr) {
		Command cmd = new DisassembleCommand(addr, null, false);
		applyCmd(program, cmd);
		waitForSwing();
	}

	private void assertOperandText(Address address, String text) {
		assertTrue(cb.goToField(address, OperandFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(text, tf.getText());
	}

	private void createOffcutFunctionReference(Function function, Address fromAddress) {

		Address entryPoint = function.getEntryPoint();
		Address oneByteOff = entryPoint.add(1);

		AddMemRefCmd addRefCmd = new AddMemRefCmd(fromAddress, oneByteOff,
			RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);

		RemoveAllReferencesCmd removeRefsCmd = new RemoveAllReferencesCmd(fromAddress);

		int ID = program.startTransaction("Test - Create Reference");
		try {
			removeRefsCmd.applyTo(program);
			addRefCmd.applyTo(program);
		}
		finally {
			program.endTransaction(ID, true);
		}

		program.flushEvents();
		waitForPostedSwingRunnables();
	}

	private void createLabel(String addr, String name) {

		int transaction = program.startTransaction("Add Label");
		try {
			AddLabelCmd cmd = new AddLabelCmd(addr(addr), name, SourceType.USER_DEFINED);
			cmd.applyTo(program);
		}
		finally {
			program.endTransaction(transaction, true);
		}

		program.flushEvents();
		waitForPostedSwingRunnables();
	}

	private Address addr(String address) {
		AddressFactory addressFactory = program.getAddressFactory();
		return addressFactory.getAddress(address);
	}

	private void setBooleanOption(final String name, final boolean value) throws Exception {
		SwingUtilities.invokeAndWait(() -> fieldOptions.setBoolean(name, value));
		waitForPostedSwingRunnables();
		cb.updateNow();
	}

	private void setIntOption(final String name, final int value) throws Exception {
		SwingUtilities.invokeAndWait(() -> fieldOptions.setInt(name, value));
		waitForPostedSwingRunnables();
		cb.updateNow();
	}

}
