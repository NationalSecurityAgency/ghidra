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

import javax.swing.SwingUtilities;

import org.junit.*;

import docking.widgets.fieldpanel.field.FieldElement;
import ghidra.app.plugin.core.blockmodel.BlockModelServicePlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.test.*;

public class PostCommentFieldFactoryTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin cb;
	private Options fieldOptions;
	private Program program;

	public PostCommentFieldFactoryTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		program = buildProgram();

		env = new TestEnv();
		tool = env.showTool(program);
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		cb = env.getPlugin(CodeBrowserPlugin.class);
		tool.addPlugin(BlockModelServicePlugin.class.getName());

		fieldOptions = cb.getFormatManager().getFieldOptions();
	}

	private ProgramDB buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createEmptyFunction(null, "1001000", 1000, null);
		builder.createReturnInstruction("1001000");
		builder.createJmpInstruction("1001010", "1001020");
		builder.createConditionalJmpInstruction("1001020", "1001030");

		builder.createJmpWithDelaySlot("1001030", "1001040");

		// create a return inside a delay slot
		builder.addBytesBranchWithDelaySlot("1001040", "1001050");
		builder.createReturnInstruction("1001042");
		builder.disassemble("1001040", 1);

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testFlagJumpReturn() throws Exception {

		assertTrue(!cb.goToField(addr("1001000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		assertTrue(!cb.goToField(addr("1001010"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		setBooleanOption(PostCommentFieldFactory.FLAG_TERMINATOR_OPTION, true);

		assertTrue(cb.goToField(addr("1001000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(PostCommentFieldFactory.DEFAULT_FLAG_COMMENT, tf.getText());

		assertTrue(cb.goToField(addr("1001010"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals(PostCommentFieldFactory.DEFAULT_FLAG_COMMENT, tf.getText());
	}

	@Test
	public void testLinesAfterBasicBlock() throws Exception {
		// ret
		assertTrue(!cb.goToField(addr("1001000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		// jmp
		assertTrue(!cb.goToField(addr("1001010"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		// conditional jmp
		assertTrue(!cb.goToField(addr("1001020"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		setIntOption(PostCommentFieldFactory.LINES_AFTER_BLOCKS_OPTION, 3);

		// ret
		assertTrue(cb.goToField(addr("1001000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(3, tf.getNumRows());

		// jmp
		assertTrue(cb.goToField(addr("1001010"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals(3, tf.getNumRows());

		// conditional jmp
		assertTrue(cb.goToField(addr("1001020"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals(3, tf.getNumRows());
	}

	@Test
	public void testLinesAfterBlocksWithDelaySlots() throws Exception {
		// inst at 1001032 is in delay slot of 1001030
		assertTrue(!cb.goToField(addr("1001032"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		setIntOption(PostCommentFieldFactory.LINES_AFTER_BLOCKS_OPTION, 3);

		// inst at 1001032 is in delay slot of 1001030
		assertTrue(cb.goToField(addr("1001032"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(3, tf.getNumRows());
	}

	@Test
	public void testFlagJmpReturnsWithDelaySlots() throws Exception {
		// inst at 1001032 is in delay slot of jmp at 1001030
		assertTrue(!cb.goToField(addr("1001032"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		setBooleanOption(PostCommentFieldFactory.FLAG_TERMINATOR_OPTION, true);

		// inst at 1001032 is in delay slot of jmp at 1001030
		assertTrue(cb.goToField(addr("1001032"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(PostCommentFieldFactory.DEFAULT_FLAG_COMMENT, tf.getText());
	}

	@Test
	public void testFlagFunctionExitsWithDelaySlots() throws Exception {
		// inst at 1001032 is in delay slot of jmp at 1001030
		assertTrue(!cb.goToField(addr("1001042"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		setBooleanOption(PostCommentFieldFactory.FLAG_FUNCTION_EXIT_OPTION, true);

		// inst at 1001032 is in delay slot of jmp at 1001030
		assertTrue(cb.goToField(addr("1001042"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(PostCommentFieldFactory.FUN_EXIT_FLAG_LEADER + "FUN_01001000" +
			PostCommentFieldFactory.FUN_EXIT_FLAG_TAIL, tf.getText());

	}

	@Test
	public void testFlagFunctionExitsWithDelaySlotsDoesNotTriggerWhenNotTerminator()
			throws Exception {
		// inst at 1001032 is in delay slot of jmp at 1001030
		assertTrue(!cb.goToField(addr("1001032"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		setBooleanOption(PostCommentFieldFactory.FLAG_FUNCTION_EXIT_OPTION, true);

		// inst at 1001032 is in delay slot of jmp at 1001030
		assertTrue(!cb.goToField(addr("1001032"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
	}

	@Test
	public void testExistingPostComment() throws Exception {
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(addr("1001000"));

		int transactionID = program.startTransaction("test");
		try {
			cu.setComment(CodeUnit.POST_COMMENT, "My post comment");
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		program.flushEvents();
		waitForPostedSwingRunnables();
		cb.updateNow();

		setBooleanOption(PostCommentFieldFactory.FLAG_FUNCTION_EXIT_OPTION, true);

		assertTrue(cb.goToField(addr("1001000"), PostCommentFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("My post comment", tf.getText());

	}

	@Test
	public void testFlagFunctionExit() throws Exception {
		assertTrue(!cb.goToField(addr("1001000"), PostCommentFieldFactory.FIELD_NAME, 1, 1));

		setBooleanOption(PostCommentFieldFactory.FLAG_FUNCTION_EXIT_OPTION, true);

		assertTrue(cb.goToField(addr("1001000"), PostCommentFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(PostCommentFieldFactory.FUN_EXIT_FLAG_LEADER + "FUN_01001000" +
			PostCommentFieldFactory.FUN_EXIT_FLAG_TAIL, tf.getText());
	}

	@Test
	public void testWordWrapping() throws Exception {
		Function function = findFirstFunction();

		setCommentInFunction(function, "comment line 1\ncomment line 2");

		changeFieldWidthToHalfCommentLength(function);

		ListingTextField tf = getFieldText(function);
		assertEquals(2, tf.getNumRows());

		setBooleanOption(PostCommentFieldFactory.ENABLE_WORD_WRAP_MSG, true);

		tf = getFieldText(function);
		assertEquals(4, tf.getNumRows());
	}

	private void setCommentInFunction(Function function, String comment) {
		CodeUnit cu = program.getListing().getCodeUnitAt(function.getEntryPoint());
		int transactionID = program.startTransaction("test");
		try {
			cu.setComment(CodeUnit.POST_COMMENT, comment);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	private Function findFirstFunction() {
		Listing listing = program.getListing();
		FunctionIterator iter = listing.getFunctions(true);
		Function function = iter.next();
		assertNotNull("Expected a function", function);
		return function;
	}

	private void changeFieldWidthToHalfCommentLength(Function function) throws Exception {
		ListingTextField tf = getFieldText(function);

		FieldElement fieldElement = tf.getFieldElement(0, 0);
		int stringWidth = fieldElement.getStringWidth();

		setFieldWidth(tf.getFieldFactory(), stringWidth / 2);
	}

	private ListingTextField getFieldText(Function function) {
		assertTrue(
			cb.goToField(function.getEntryPoint(), PostCommentFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		return tf;
	}

	private void setFieldWidth(final FieldFactory fieldFactory, final int width) throws Exception {
		SwingUtilities.invokeAndWait(() -> fieldFactory.setWidth(width));
		waitForPostedSwingRunnables();
		cb.updateNow();
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

	private Address addr(String address) {
		AddressFactory addressFactory = program.getAddressFactory();
		return addressFactory.getAddress(address);
	}

}
