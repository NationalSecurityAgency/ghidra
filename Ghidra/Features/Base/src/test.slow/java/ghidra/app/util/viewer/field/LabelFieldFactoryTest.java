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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.*;

import ghidra.app.cmd.function.SetFunctionNameCmd;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.refs.AddMemRefCmd;
import ghidra.app.cmd.refs.RemoveAllReferencesCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.*;

public class LabelFieldFactoryTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin cb;
	private Program program;

	public LabelFieldFactoryTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		program = buildProgram();

		env = new TestEnv();
		tool = env.showTool(program);
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		cb = env.getPlugin(CodeBrowserPlugin.class);
	}

	private ProgramDB buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true);

		builder.createMemory(".text", "1001000", 0x4000);
		builder.addBytesNOP("1002000", 6);
		builder.disassemble("1002000", 6);
		builder.createEncodedString("1003000", "Kartika", StandardCharsets.UTF_16BE, true);
		builder.createLabel("1003000", "u_Kartika");
		builder.createEncodedString("1003100", "abcdef", StandardCharsets.UTF_16BE, true);

		builder.createEncodedString("1003200", "abcdef", StandardCharsets.US_ASCII, false);
		builder.createMemoryReadReference("1001000", "1003200");

		builder.addBytesNOP("1004000", 4);
		builder.disassemble("1004000", 4);
		builder.createEmptyFunction(null, "01004000", 10, null);

		return builder.getProgram();
	}

	private ProgramDB buildSegmentedProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("foo", ProgramBuilder._X86_16_REAL_MODE);

		builder.createMemory("seg_0", "1000:0000", 0x32c0);
		builder.createMemory("seg_1", "132c:0000", 0x100);

		builder.applyDataType("132c:0092", new WordDataType(), 1);
		builder.createEncodedString("132c:0004",
			"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", StandardCharsets.US_ASCII,
			false);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testOffcutLabelDynamic() {

		String offcutAddress = "1002001";
		String from = "1001000";
		createReference(from, offcutAddress);

		String minAddress = "1002000";
		Address address = addr(minAddress);
		assertTrue(cb.goToField(address, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		assertEquals("LAB_01002000+1", tf.getText());
	}

	@Test
	public void testMultipleOffcutLabelsDynamicDifferentAddresses() {

		String offcutAddress1 = "1003002";
		String from = "1001000";
		createReference(from, offcutAddress1);

		String offcutAddress2 = "1003004";
		from = "1001000";
		createReference(from, offcutAddress2);

		String minAddress = "1003000";
		Address address = addr(minAddress);
		assertTrue(cb.goToField(address, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		// expecting: u_artika and u_rtika
		// the rest is the text of the real label below the offcut label
		assertEquals("u_artika_01003002 u_rtika_01003004 u_Kartika", tf.getText());
	}

	@Test
	public void testMultipleOffcutLabelDynamicSameAddress() {

		String offcutAddress = "1003002";
		String from = "1001000";
		createReference(from, offcutAddress);

		from = "1001008";
		createReference(from, offcutAddress);

		String minAddress = "1003000";
		Address address = addr(minAddress);
		assertTrue(cb.goToField(address, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		// expecting: u_artika__+1
		// the rest is the text of the real label below the offcut label
		assertEquals("u_artika_01003002 u_Kartika", tf.getText());
	}

	@Test
	public void testMultipleBadOffcutReferencesIntoInstruction() {
		//
		// Multiple references to the same offcut address; bad/incorrect offcut
		//
		Address address = addr("1002000");
		createReference("1001004", "1002000");
		createReference("1001008", "1002001");
		createReference("100100c", "1002002");
		createReference("1001010", "1002003");
		createReference("1001014", "1002004");

		assertTrue(cb.goToField(address, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		// 4 offcut labels and one dynamic label
		assertEquals("LAB_01002000+1 LAB_01002000+2 LAB_01002000+3 LAB_01002000+4 LAB_01002000",
			tf.getText()); // bad offcut put on instruction

		assertEquals(5, tf.getNumRows());
	}

	@Test
	public void testOffcutLabelNonDynamic() {

		String offcutAddress = "1002002";
		String name = "Bob";
		createLabel(offcutAddress, name);

		String minAddress = "1002000";
		Address address = addr(minAddress);
		assertTrue(cb.goToField(address, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		// the rest is the text of the real label below the offcut label
		assertEquals("Bob (01002000+2)", tf.getText());
	}

	@Test
	public void testMultipleOffcutLabelsNonDynamic() {

		String offcutAddress = "1002002";
		String name = "Bob";
		createLabel(offcutAddress, name);

		offcutAddress = "1002003";
		name = "Joe";
		createLabel(offcutAddress, name);

		offcutAddress = "1002004";
		name = "Cat";
		createLabel(offcutAddress, name);

		String minAddress = "1002000";
		Address address = addr(minAddress);
		assertTrue(cb.goToField(address, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		// expecting: Bob (30a54bfb+2) Joe (30a54bfb+3) Cat (30a54bfb+4)
		// the rest is the text of the real label below the offcut label
		assertEquals("Bob (01002000+2) Joe (01002000+3) Cat (01002000+4)", tf.getText());
	}

	@Test
	public void testOffcutUnicodeStringLabelAtLastChar_SCR_9362() {

		//
		// The string at this address is 14 bytes; 6 characters and a null character
		// 
		// This tests a bug when we pointed to the null character in the string
		//

		String minAddress = "1003100";
		String offcutAddress = "100310c";
		String from = "1001000";
		createDataReference(from, offcutAddress);

		Address address = addr(minAddress);
		assertTrue(cb.goToField(address, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		assertEquals("u__0100310c", tf.getText());
	}

	@Test
	public void testOffcutStringLabelDynamic() {
		// format: s_text_address+n

		String minAddress = "1003200";
		String offcutAddress = "1003201";
		String from = "1001000";
		createDataReference(from, offcutAddress);

		Address address = addr(minAddress);
		assertTrue(cb.goToField(address, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		assertEquals("s_bcdef_01003201 s_abcdef_01003200", tf.getText());
	}

	@Test
	public void testOffcutStringLabelNonDynamic() {
		// format: Label Text (offcut address_offset)

		String minAddress = "1003200";
		String offcutAddress = "1003201";
		String from = "1001000";
		createDataReference(from, offcutAddress);

		String name = "Bob";
		createLabel(offcutAddress, name);

		Address address = addr(minAddress);
		assertTrue(cb.goToField(address, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		// expecting: Bob (30a54c14+1)
		// the rest is the text of the real label below the offcut label
		assertEquals("Bob (01003200+1) s_abcdef_01003200", tf.getText());
	}

	@Test
	public void testOffcutIntoDataInSegmentedAddressSpace() throws Exception {
		env.release(program);
		program = buildSegmentedProgram();
		env.open(program);

		String offcutAddress = "132c:0093";
		String from = "1000:00e2";
		createReference(from, offcutAddress);

		String minAddress = "132c:0092";
		Address address = addr(minAddress);
		assertTrue(cb.goToField(address, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		assertEquals("WORD_132c_0092+1", tf.getText());
	}

	@Test
	public void testOffcutIntoStringWhenOffcutIndexIsGreaterThanTheOptionsLength()
			throws Exception {
		//
		// This tests the odd condition when the offcut index into the string is greater than 
		// the options have specified for the length of the label.  The bug did not display any
		// of the string and instead only displayed the prefix and the address (like s_12345678).
		//
		env.release(program);
		program = buildSegmentedProgram();
		env.open(program);

		String minAddress = "132c:0004";
		createReference("1000:00e2", "132c:0026");
		Address address = addr(minAddress);
		assertTrue(cb.goToField(address, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		assertEquals("s_ijklmnopqrstuvwxyz_132c_0026", tf.getText());
	}

	@Test
	public void testOffcutStringWhenOffcutIsOnTheNullTerminatingCharacter() throws Exception {
		//
		// We can have a scenario where there is an offcut into a string where the offcut index
		// is the the last byte, which is the null terminator, which we do not render
		//
		env.close(program);
		program = buildSegmentedProgram();
		env.open(program);

		String minAddress = "132c:0004";
		createReference("1000:00e2", "132c:0038");

		Address address = addr(minAddress);
		assertTrue(cb.goToField(address, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		assertEquals("s__132c_0038", tf.getText());
	}

	@Test
	public void testOffcutReferenceToFunction_DefaultLabel() throws Exception {
		//
		// Test that a reference to one byte past a function entry point will add an offcut
		// label that has offcut information
		//

		FunctionManager functionManager = program.getFunctionManager();
		Address functionAddress = addr("1004000");
		Function function = functionManager.getFunctionAt(functionAddress);
		Address fromAddress = addr("1001000");
		createOffcutFunctionReference(function, fromAddress);

		assertTrue(cb.goToField(functionAddress, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		assertEquals("FUN_01004000+1 FUN_01004000", tf.getText());
	}

	@Test
	public void testOffcutReferenceToFunction_NonDefaultLabel() throws Exception {
		//
		// Test that a reference to one byte past a function entry point will add an offcut
		// label that has offcut information
		//

		FunctionManager functionManager = program.getFunctionManager();
		Address functionAddress = addr("1004000");
		Function function = functionManager.getFunctionAt(functionAddress);
		renameFunction(function, "bob");

		Address fromAddress = addr("1001000");
		createOffcutFunctionReference(function, fromAddress);

		assertTrue(cb.goToField(functionAddress, LabelFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();

		assertEquals("bob+1 bob", tf.getText());
	}

//==================================================================================================
// Tests designed to exercise various code paths in the CodeUnitFormat and BrowserCodeUnitFormat
// classes.	
//==================================================================================================	

	public void testOffcutIntoNonString_NoPrimarySymbol() {
		// ?
	}

	public void testOffcutIntoStructure_NoPrimarySymbolAtOffcutAddress_NoSymbolCodeUnitAddress() {
		// maybe an invalid offcut; may have to delete the symbol of the structure
	}

	public void testOffcutIntoStructure_AtStructureMember() {
		// 
	}

	public void testOffcutIntoStructure_NotAtStructureMember() {
		// ?
	}

	public void testOffcutIntoNonString_TypeHasPrefix() {
		// BrowserCodeUnitFormat
	}

	public void testOffcutIntoNonString_TypeHasNoPrefix() {
		// BrowserCodeUnitFormat
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void renameFunction(Function function, String name) {
		SetFunctionNameCmd cmd =
			new SetFunctionNameCmd(function.getEntryPoint(), name, SourceType.USER_DEFINED);

		int ID = program.startTransaction("Test - Create Reference");
		try {
			cmd.applyTo(program);
		}
		finally {
			program.endTransaction(ID, true);
		}

		program.flushEvents();
		waitForPostedSwingRunnables();
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

	private void createDataReference(String from, String to) {

		int transaction = program.startTransaction("Test - Add Reference");
		try {
			AddMemRefCmd cmd =
				new AddMemRefCmd(addr(from), addr(to), RefType.DATA, SourceType.USER_DEFINED, 0);
			cmd.applyTo(program);
			program.flushEvents();
			waitForPostedSwingRunnables();
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private void createReference(String from, String to) {

		int transaction = program.startTransaction("Test - Add Reference");
		try {
			AddMemRefCmd cmd =
				new AddMemRefCmd(addr(from), addr(to), RefType.READ, SourceType.USER_DEFINED, 0);
			cmd.applyTo(program);
			program.flushEvents();
			waitForPostedSwingRunnables();
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private void createLabel(String addr, String name) {

		int transaction = program.startTransaction("Add Label");
		try {
			AddLabelCmd cmd = new AddLabelCmd(addr(addr), name, SourceType.USER_DEFINED);
			cmd.applyTo(program);
			program.flushEvents();
			waitForPostedSwingRunnables();
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private Address addr(String address) {
		AddressFactory addressFactory = program.getAddressFactory();
		return addressFactory.getAddress(address);
	}

}
