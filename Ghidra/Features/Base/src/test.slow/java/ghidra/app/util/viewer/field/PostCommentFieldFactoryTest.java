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

		builder.createMemory(".text", "0x1001000", 0x10000);
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

		//create a function for testing basic CALLOTHER override
		builder.createEmptyFunction("basic_callother_override", "1008000", 10, null);
		builder.createEmptyFunction("call_dest_4", "1008020", 10, null);
		builder.createEmptyFunction("call_dest_5", "1008040", 10, null);
		builder.setBytes("1008000", "a3 00");
		builder.disassemble("1008000", 2);
		builder.createCallInstruction("1008002", "1008020");
		builder.createCallInstruction("1008004", "1008040");
		builder.createReturnInstruction("1008006");

		//create a function for testing CALLOTHER_CALL_OVERRIDE having precedence
		//over CALLOTHER_JUMP_OVERRIDE
		builder.createEmptyFunction("precedence_test", "1009000", 10, null);
		builder.createEmptyFunction("call_dest_6", "1009020", 10, null);
		builder.setBytes("1009000", "a1 10");
		builder.disassemble("1009000", 2);
		builder.createCallInstruction("1009002", "1009020");
		builder.createReturnInstruction("1009004");

		//create a function for testing warning messages that there are additional
		builder.createEmptyFunction("warning_test", "100a000", 10, null);
		builder.createEmptyFunction("call_dest_7", "100a020", 10, null);
		builder.setBytes("100a000", "a2 10");
		builder.disassemble("100a000", 2);
		builder.createReturnInstruction("100a002");

		//add an overlay space
		builder.createOverlayMemory("overlay", "0x1001000", 0x10000);

		builder.createEmptyFunction("overlay_func", "overlay:100a020", 10, null);
		builder.createEmptyFunction("call_into_overlay", "100b000", 10, null);
		builder.createEmptyFunction("call_dest_8", "100b020", 10, null);
		//call [r1]
		builder.setBytes("100b000", "f6 10");
		builder.disassemble("100b000", 2);
		builder.createCallInstruction("100b002", "100b020");
		builder.setBytes("100b004", "a3 00");
		builder.disassemble("100b004", 2);
		builder.createReturnInstruction("100b006");

		builder.createEmptyFunction("multiple_ops1", "0x100c000", 10, null);
		builder.createEmptyFunction("call_dest_9", "0x100c020", 10, null);
		builder.setBytes("100c000", "a4 11");
		builder.disassemble("100c000", 2);
		builder.createReturnInstruction("100c002");

		builder.createEmptyFunction("multiple_ops2", "0x100d000", 10, null);
		builder.createEmptyFunction("call_dest_10", "0x100d020", 10, null);
		builder.createEmptyFunction("call_dest_11", "0x100d030", 10, null);
		builder.setBytes("100d000", "a5 20");
		builder.disassemble("100d000", 2);
		builder.createReturnInstruction("100d002");

		builder.createEmptyFunction("override_warning", "0x100e000", 10, null);
		builder.setBytes("100e000", "a6 00");
		builder.disassemble("100e000", 2);
		builder.createReturnInstruction("100e002");
		builder.createEmptyFunction("call_dest_12", "0x100e020", 10, null);


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
	public void testOverridingWithoutChangingDestination() {
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

	@Test
	public void testBasicCallOtherOverrides() {
		//initially no test comment
		assertFalse(cb.goToField(addr("1008000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ReferenceManager refManager = program.getReferenceManager();
		int transactionID = program.startTransaction("override_callother_with_call_ref");
		try {
			Reference callOverride = refManager.addMemoryReference(addr("1008000"), addr("1008020"),
				RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(callOverride, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		//CALL_OVERRIDE_UNCONDITIONAL references should not cause a post comment
		assertFalse(cb.goToField(addr("1008000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		transactionID = program.startTransaction("override_callother_with_unconditional_jump_ref");
		try {
			Reference jumpOverride = refManager.addMemoryReference(addr("1008000"), addr("1008020"),
				RefType.JUMP_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(jumpOverride, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		//JUMP_OVERRIDE_UNCONDITIONAL references should also not do anything
		assertFalse(cb.goToField(addr("1008000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		transactionID = program.startTransaction("override_callother_with_callother_override_call");
		try {
			Reference callOtherCallOverride =
				refManager.addMemoryReference(addr("1008000"), addr("1008020"),
					RefType.CALLOTHER_OVERRIDE_CALL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(callOtherCallOverride, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		//should now be a post comment about the CALLOTHER call override
		assertTrue(cb.goToField(addr("1008000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- CALLOTHER(pcodeop_three) Call Override: call_dest_4 (01008020)",
			tf.getText());
		transactionID = program.startTransaction("override_callother_with_callother_override_jump");
		try {
			Reference callOtherCallOverride =
				refManager.addMemoryReference(addr("1008000"), addr("1008004"),
					RefType.CALLOTHER_OVERRIDE_JUMP, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(callOtherCallOverride, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		//should now be a post comment about the CALLOTHER jump override
		assertTrue(cb.goToField(addr("1008000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- CALLOTHER(pcodeop_three) Jump Override: LAB_01008004 (01008004)",
			tf.getText());
	}

	//test: callother call overrides has precedence over callother jump overrides
	//test: only one override of each type on a given native instruction
	@Test
	public void testPrecedence() {
		assertFalse(cb.goToField(addr("1009000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ReferenceManager refManager = program.getReferenceManager();
		int transactionID = program.startTransaction("add_overriding_jump_ref");
		try {
			Reference callOtherJumpOverride =
				refManager.addMemoryReference(addr("1009000"), addr("1009004"),
					RefType.CALLOTHER_OVERRIDE_JUMP, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(callOtherJumpOverride, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		//normal CALLOTHER_OVERRIDE_JUMP comment
		assertTrue(cb.goToField(addr("1009000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- CALLOTHER(pcodeop_one) Jump Override: LAB_01009004 (01009004)",
			tf.getText());

		//now set another CALLOTHER_OVERRIDE_JUMP comment on operand 0, should no longer
		//be a post comment since overrides only take effect if there is exactly one
		transactionID = program.startTransaction("add_overriding_jump_ref2");
		try {
			Reference callOtherJumpOverride = refManager.addMemoryReference(addr("1009000"),
				addr("1009006"), RefType.CALLOTHER_OVERRIDE_JUMP, SourceType.ANALYSIS, 0);
			refManager.setPrimary(callOtherJumpOverride, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1009000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		//change the CALLOTHER_OVERRIDE_JUMP reference on operand 0 to a CALLOTHER_OVERRIDE_CALL
		//reference
		transactionID = program.startTransaction("add_callother_override_call_ref");
		try {
			Reference callOtherCallOverride = refManager.addMemoryReference(addr("1009000"),
				addr("1009020"), RefType.CALLOTHER_OVERRIDE_CALL, SourceType.ANALYSIS, 0);
			refManager.setPrimary(callOtherCallOverride, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("1009000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-- CALLOTHER(pcodeop_one) Call Override: call_dest_6 (01009020)",
			tf.getText());
		//now put a CALLOTHER_OVERRIDE_CALL ref on the mnemonic, should result in no post comment
		//since there now two CALLOTHER_OVERRIDE_CALL references
		transactionID = program.startTransaction("add_callother_override_call_ref2");
		try {
			Reference callOtherCallOverride =
				refManager.addMemoryReference(addr("1009000"), addr("1009020"),
					RefType.CALLOTHER_OVERRIDE_CALL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(callOtherCallOverride, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("1009000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
	}

	@Test
	public void testWarningMessage() {
		assertFalse(cb.goToField(addr("100a000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ReferenceManager refManager = program.getReferenceManager();
		int transactionID = program.startTransaction("add_callother_override_call_ref");
		try {
			Reference callOtherCallOverride = refManager.addMemoryReference(addr("100a000"),
				addr("100a020"), RefType.CALLOTHER_OVERRIDE_CALL, SourceType.ANALYSIS, 0);
			refManager.setPrimary(callOtherCallOverride, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("100a000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingField tf = cb.getCurrentField();
		assertEquals(
			"-- CALLOTHER(pcodeop_two) Call Override: call_dest_7 (0100a020) -- WARNING: additional CALLOTHER ops present",
			tf.getText());
	}

	@Test
	public void testOverridingCallIntoOverlay() {
		int transactionID = program.startTransaction("override_indirect_call");
		ReferenceManager refManager = program.getReferenceManager();
		try {
			Reference ref = refManager.addMemoryReference(addr("100b000"), addr("overlay:100a020"),
				RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, 0);
			refManager.setPrimary(ref, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("100b000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingField tf = cb.getCurrentField();
		assertEquals("-- Call Destination Override: overlay_func (overlay::0100a020)",
			tf.getText());
		transactionID = program.startTransaction("override_direct_call");
		try {
			Reference primaryRef = refManager.getPrimaryReferenceFrom(addr("100b002"), 0);
			refManager.setPrimary(primaryRef, false);
			Reference ref = refManager.addMemoryReference(addr("100b002"), addr("overlay:100a020"),
				RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, 0);
			refManager.setPrimary(ref, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("100b002"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = cb.getCurrentField();
		assertEquals("-- Call Destination Override: overlay_func (overlay::0100a020)",
			tf.getText());

		transactionID = program.startTransaction("override_callother");
		try {
			Reference ref = refManager.addMemoryReference(addr("100b004"), addr("overlay:100a020"),
				RefType.CALLOTHER_OVERRIDE_CALL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("100b004"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = cb.getCurrentField();
		assertEquals("-- CALLOTHER(pcodeop_three) Call Override: overlay_func (overlay::0100a020)",
			tf.getText());
	}

	@Test
	public void testMultipleOps1() {
		assertFalse(cb.goToField(addr("100c000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		int transactionID = program.startTransaction("override_indirect_call");
		ReferenceManager refManager = program.getReferenceManager();
		try {
			Reference ref = refManager.addMemoryReference(addr("100c000"), addr("100c020"),
				RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, 0);
			refManager.setPrimary(ref, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		transactionID = program.startTransaction("override_callother_call");
		try {
			Reference ref = refManager.addMemoryReference(addr("100c000"), addr("100c020"),
				RefType.CALLOTHER_OVERRIDE_CALL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("100c000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingField tf = cb.getCurrentField();
		assertEquals(
			"-- CALLOTHER(pcodeop_one) Call Override: call_dest_9 (0100c020) -- WARNING: additional CALLOTHER ops present -- Call Destination Override: call_dest_9 (0100c020)",
			tf.getText());
		transactionID = program.startTransaction("override_callother_jump");
		try {
			Reference ref = refManager.addMemoryReference(addr("100c000"), addr("100c002"),
				RefType.CALLOTHER_OVERRIDE_JUMP, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("100c000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		tf = cb.getCurrentField();
		assertEquals(
			"-- CALLOTHER(pcodeop_one) Jump Override: LAB_0100c002 (0100c002) -- WARNING: additional CALLOTHER ops present -- Call Destination Override: call_dest_9 (0100c020)",
			tf.getText());
	}

	@Test
	public void testMultipleOps2() {
		assertFalse(cb.goToField(addr("100d000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		int transactionID = program.startTransaction("override_call_with_primary_ref");
		ReferenceManager refManager = program.getReferenceManager();
		try {
			Reference primaryRef = refManager.getPrimaryReferenceFrom(addr("100d000"), 0);
			refManager.setPrimary(primaryRef, false);
			Reference ref = refManager.addMemoryReference(addr("100d000"), addr("100d030"),
				RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);
			refManager.setPrimary(ref, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		transactionID = program.startTransaction("override_callother_call");
		try {
			Reference ref = refManager.addMemoryReference(addr("100d000"), addr("100d020"),
				RefType.CALLOTHER_OVERRIDE_CALL, SourceType.ANALYSIS, Reference.MNEMONIC);
			refManager.setPrimary(ref, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("100d000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingField tf = cb.getCurrentField();
		//old way of overriding (With RefType.UNCONDITIONAL CALL) does not yield a post comment
		assertEquals(
			"-- CALLOTHER(pcodeop_three) Call Override: call_dest_10 (0100d020)",
			tf.getText());
	}

	@Test
	public void testOverrideWarnings() {
		assertFalse(cb.goToField(addr("100e000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		//verify CALLOTHER_OVERRIDE_CALL warning
		int transactionID = program.startTransaction("call_warning");
		ReferenceManager refManager = program.getReferenceManager();
		Reference ref = null;
		try {
			ref = refManager.addMemoryReference(addr("100e000"), addr("100e020"),
				RefType.CALLOTHER_OVERRIDE_CALL, SourceType.ANALYSIS, 0);
			refManager.setPrimary(ref, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("100e000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		ListingField tf = cb.getCurrentField();
		assertEquals("WARNING: Output of pcodeop_one destroyed by override!", tf.getText());
		//set ref non-primary, verify that warning goes away
		transactionID = program.startTransaction("turn_off_call_warning");
		try {
			refManager.setPrimary(ref, false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("100e000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		//verify CALLOTHER_OVERRIDE_JUMP warning
		transactionID = program.startTransaction("jump_warning");
		try {
			ref = refManager.addMemoryReference(addr("100e000"), addr("100e020"),
				RefType.CALLOTHER_OVERRIDE_JUMP, SourceType.ANALYSIS, 0);
			refManager.setPrimary(ref, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(addr("100e000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));
		assertEquals("WARNING: Output of pcodeop_one destroyed by override!", tf.getText());
		//set ref non-primary, verify that warning goes away
		transactionID = program.startTransaction("turn_off_jump_warning");
		try {
			refManager.setPrimary(ref, false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertFalse(cb.goToField(addr("100e000"), PostCommentFieldFactory.FIELD_NAME, 0, 1));

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
