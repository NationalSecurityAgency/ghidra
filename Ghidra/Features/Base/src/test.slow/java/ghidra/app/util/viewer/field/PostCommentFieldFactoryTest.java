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
import ghidra.program.model.symbol.*;
import ghidra.test.*;

public class PostCommentFieldFactoryTest extends AbstractGhidraHeadedIntegrationTest {

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

		//create a function for testing jump override comments
		builder.createEmptyFunction("jump_override", "1003000", 100, null);
		builder.createConditionalJmpInstruction("1003000", "1003006");
		builder.createNOPInstruction("1003002", 4);
		builder.createReturnInstruction("1003006");
		builder.createReturnInstruction("1003008");

		//create a function for testing indirect call override comments
		builder.createEmptyFunction("indirect_call_override", "1004000", 100, null);
		//call [r1]
		builder.setBytes("1004000", "f6 10");
		builder.disassemble("1004000", 2);
		builder.createReturnInstruction("1004002");

		//create function for testing direct call override comments
		builder.createEmptyFunction("direct_call_override_backward_compatibility", "1005000", 10,
			null);
		builder.createEmptyFunction("call_dest_1", "1005020", 10, null);
		builder.createCallInstruction("1005000", "1005020");
		builder.createReturnInstruction("1005002");

		//create function for testing that overrides only happen when there is exactly one
		//primary overriding reference (e.g., if there's a primary overriding ref on
		//both the mnemonic and an operand then no override
		builder.createEmptyFunction("only_one_primary_override_ref", "1006000", 10, null);
		builder.createEmptyFunction("call_dest_2", "1006020", 10, null);
		builder.createCallInstruction("1006000", "1006020");
		builder.createReturnInstruction("1006002");

		//create function for testing overrides that don't actually change the destination
		builder.createEmptyFunction("override_without_dest_change", "1007000", 10, null);
		builder.createEmptyFunction("call_dest_3", "1007020", 10, null);
		builder.createCallInstruction("1007000", "1007020");
		builder.createReturnInstruction("1007002");

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

	@Test
	public void testOverridingJumpComment() {
		//test overriding a conditional jump to an unconditional jump
		//using a RefType.JUMP_OVERRIDE_UNCONDITIONAL reference
		ReferenceManager refManager = program.getReferenceManager();
		Reference ref1 = null;
		int transactionID = program.startTransaction("add_primary_jump_ref");
		try {
			ref1 = refManager.addMemoryReference(addr("1003000"), addr("1003006"),
				RefType.JUMP_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref1, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		assertTrue(cb.goToField(addr("1003000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- Jump Destination Override: LAB_01003006 (01003006)", tf.getText());

		//test that making the reference non-primary removes the post comment
		ref1 = refManager.getPrimaryReferenceFrom(addr("1003000"), Reference.MNEMONIC);
		assertTrue(ref1.isPrimary());
		transactionID = program.startTransaction("set_ref_non_primary");
		try {
			refManager.setPrimary(ref1, false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1003000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		//test that adding a second ref of the same type and setting it to primary
		//yields a new post comment
		transactionID = program.startTransaction("add_second_jump_ref");
		Reference ref2 = null;
		try {
			ref2 = refManager.addMemoryReference(addr("1003000"), addr("1003008"),
				RefType.JUMP_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref2, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("1003000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- Jump Destination Override: LAB_01003008 (01003008)", tf.getText());

		//test the swapping which reference is primary changes the post comment
		transactionID = program.startTransaction("swap_primary");
		try {
			refManager.setPrimary(ref2, false);
			refManager.setPrimary(ref1, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("1003000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- Jump Destination Override: LAB_01003006 (01003006)", tf.getText());

		//test that making all references non-primary removes the post comment
		transactionID = program.startTransaction("no_primary_refs");
		try {
			refManager.setPrimary(ref2, false);
			refManager.setPrimary(ref1, false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1003000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		//test that the other overriding reference types don't add any post comments
		transactionID = program.startTransaction("add_overriding_call_ref");
		try {
			ref2 = refManager.addMemoryReference(addr("1003000"), addr("1004000"),
				RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref2, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1003000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		transactionID = program.startTransaction("add_overriding_callother_call_ref");
		try {
			ref2 = refManager.addMemoryReference(addr("1003000"), addr("1004000"),
				RefType.CALLOTHER_OVERRIDE_CALL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref2, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1003000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		transactionID = program.startTransaction("add_overriding_callother_jump_ref");
		try {
			ref2 = refManager.addMemoryReference(addr("1003000"), addr("1003006"),
				RefType.CALLOTHER_OVERRIDE_JUMP, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref2, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1003000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		//last test: test primary refs on mnemonic and operand 1
		//shouldn't work
	}

	@Test
	public void testOverridingIndirectCallComment() {
		//test that a primary RefType.CALL_OVERRIDE_UNCONDITIONAL reference on an indirect call
		//causes a post comment indicating that the call destination has been overridden
		ReferenceManager refManager = program.getReferenceManager();
		Reference ref1 = null;
		int transactionID = program.startTransaction("override indirect call");
		try {
			ref1 = refManager.addMemoryReference(addr("1004000"), addr("1003000"),
				RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref1, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("1004000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- Call Destination Override: jump_override (01003000)", tf.getText());

		//test that making the reference non-primary remove the post comment
		ref1 = refManager.getPrimaryReferenceFrom(addr("1004000"), Reference.MNEMONIC);
		assertTrue(ref1.isPrimary());
		transactionID = program.startTransaction("set_ref_non_primary");
		try {
			refManager.setPrimary(ref1, false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1004000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		//test that adding a second ref of the same type and setting it to primary
		//yields a new post comment
		transactionID = program.startTransaction("add_second_ref");
		Reference ref2 = null;
		try {
			ref2 = refManager.addMemoryReference(addr("1004000"), addr("1001000"),
				RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref2, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("1004000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- Call Destination Override: FUN_01001000 (01001000)", tf.getText());

		//test the swapping which reference is primary changes the post comment
		transactionID = program.startTransaction("swap_primary");
		try {
			refManager.setPrimary(ref2, false);
			refManager.setPrimary(ref1, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("1004000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- Call Destination Override: jump_override (01003000)", tf.getText());

		//test that making all references non-primary removes the post comment
		transactionID = program.startTransaction("no_primary_refs");
		try {
			refManager.setPrimary(ref2, false);
			refManager.setPrimary(ref1, false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1004000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		transactionID = program.startTransaction("add_overriding_jump_ref");
		try {
			ref2 = refManager.addMemoryReference(addr("1004000"), addr("1003008"),
				RefType.JUMP_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref2, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1004000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		transactionID = program.startTransaction("add_overriding_callother_call_ref");
		try {
			ref2 = refManager.addMemoryReference(addr("1004000"), addr("1003000"),
				RefType.CALLOTHER_OVERRIDE_CALL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref2, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1004000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		transactionID = program.startTransaction("add_overriding_callother_jump_ref");
		try {
			ref2 = refManager.addMemoryReference(addr("1004000"), addr("1003006"),
				RefType.CALLOTHER_OVERRIDE_JUMP, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref2, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1004000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

	}

	@Test
	public void testOverridingDirectCallAndBackwardCompatibility() {
		assertFalse(cb.goToField(addr("1005000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ReferenceManager refManager = program.getReferenceManager();
		Reference defaultRef = refManager.getPrimaryReferenceFrom(addr("1005000"), 0);
		assertNotNull(defaultRef);
		Reference callOverride = null;
		int transactionID = program.startTransaction("add_overriding_callother_jump_ref");
		try {
			callOverride = refManager.addMemoryReference(addr("1005000"), addr("1003000"),
				RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(callOverride, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		//there's a primary call-type reference on operand one, so the CALL_OVERRIDE_UNCONDITIONAL
		//override should *not* be active (this is testing backward compatibility)
		assertFalse(cb.goToField(addr("1005000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		//now make defaultRef non-primary and verify that the postcomment from callOverride
		//shows up
		transactionID = program.startTransaction("de-primary default ref");
		try {
			refManager.setPrimary(defaultRef, false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("1005000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- Call Destination Override: jump_override (01003000)", tf.getText());

		transactionID = program.startTransaction("set_ref_non_primary");
		try {
			refManager.setPrimary(callOverride, false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1005000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		//test that adding a second ref of the same type and setting it to primary
		//yields a new post comment
		transactionID = program.startTransaction("add_second_ref");
		Reference ref2 = null;
		try {
			ref2 = refManager.addMemoryReference(addr("1005000"), addr("1001000"),
				RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref2, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("1005000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- Call Destination Override: FUN_01001000 (01001000)", tf.getText());

		//test the swapping which reference is primary changes the post comment
		transactionID = program.startTransaction("swap_primary");
		try {
			refManager.setPrimary(ref2, false);
			refManager.setPrimary(callOverride, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("1005000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- Call Destination Override: jump_override (01003000)", tf.getText());

		//test that making all references non-primary removes the post comment
		transactionID = program.startTransaction("no_primary_refs");
		try {
			refManager.setPrimary(ref2, false);
			refManager.setPrimary(callOverride, false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1005000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		//verify that JUMP_OVERRIDE_UNCONDITIONAL references and 
		//CALLOTHER overriding references don't do anything
		transactionID = program.startTransaction("add_overriding_jump_ref");
		try {
			ref2 = refManager.addMemoryReference(addr("1005000"), addr("1003008"),
				RefType.JUMP_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref2, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1005000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		transactionID = program.startTransaction("add_overriding_callother_call_ref");
		try {
			ref2 = refManager.addMemoryReference(addr("1005000"), addr("1003000"),
				RefType.CALLOTHER_OVERRIDE_CALL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref2, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1005000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

		transactionID = program.startTransaction("add_overriding_callother_jump_ref");
		try {
			ref2 = refManager.addMemoryReference(addr("1005000"), addr("1003006"),
				RefType.CALLOTHER_OVERRIDE_JUMP, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref2, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1005000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
	}

	@Test
	public void testExactlyOnePrimaryOverridingRef() {
		assertFalse(cb.goToField(addr("1006000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ReferenceManager refManager = program.getReferenceManager();
		Reference defaultRef = refManager.getPrimaryReferenceFrom(addr("1006000"), 0);
		assertNotNull(defaultRef);
		Reference callOverrideMnemonic = null;
		int transactionID =
			program.startTransaction("turn_off_existing_primary_ref_and_create_override_ref");
		try {
			refManager.setPrimary(defaultRef, false);
			callOverrideMnemonic = refManager.addMemoryReference(addr("1006000"), addr("1003000"),
				RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(callOverrideMnemonic, true);

		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("1006000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- Call Destination Override: jump_override (01003000)", tf.getText());
		Reference callOverrideOperand0 = null;
		transactionID = program.startTransaction("set_operand_ref_primary");
		try {
			callOverrideOperand0 = refManager.addMemoryReference(addr("1006000"), addr("1005020"),
				RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, 0);
			refManager.setPrimary(callOverrideOperand0, true);

		}
		finally {
			program.endTransaction(transactionID, true);
		}
		//two primary override refs of same type, override should not take effect
		assertFalse(cb.goToField(addr("1006000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		transactionID = program.startTransaction("set_mnemonic_ref_non_primary");
		try {
			refManager.setPrimary(callOverrideMnemonic, false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		//now there's only one primary overriding ref, so the override comment should be there
		assertTrue(cb.goToField(addr("1006000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- Call Destination Override: call_dest_1 (01005020)", tf.getText());
		transactionID = program.startTransaction("set_operand_ref_non_primary");
		try {
			refManager.setPrimary(callOverrideOperand0, false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		//no primary overriding refs, no override post comment
		assertFalse(cb.goToField(addr("1006000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

	}

	@Test
	public void testOverridingWithChangingDestination() {
		assertFalse(cb.goToField(addr("1007000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ReferenceManager refManager = program.getReferenceManager();
		Reference defaultRef = refManager.getPrimaryReferenceFrom(addr("1007000"), 0);
		assertNotNull(defaultRef);
		Reference callOverrideMnemonic = null;
		int transactionID = program.startTransaction("override_without_changing_dest");
		try {
			refManager.setPrimary(defaultRef, false);
			callOverrideMnemonic = refManager.addMemoryReference(addr("1007000"), addr("1007020"),
				RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(callOverrideMnemonic, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("1007000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- Call Destination Override: call_dest_3 (01007020)", tf.getText());
		transactionID = program.startTransaction("turn_off_override");
		try {
			refManager.setPrimary(defaultRef, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1007000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
	}

	//TODO: test overriding CALLOTHER ops

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
