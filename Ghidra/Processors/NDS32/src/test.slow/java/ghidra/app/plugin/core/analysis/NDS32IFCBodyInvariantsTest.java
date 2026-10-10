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
package ghidra.app.plugin.core.analysis;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Invariant tests for the IFC analyzer's per-body annotations on a
 * synthetic multi-caller-shared-body program.  After analysis the
 * shared body must:
 * <ul>
 * <li>carry an "ifcalled from: ..." repeatable listing comment at
 *     its entry, naming each caller (the original
 *     {@code CommentCheck.java} expectation);</li>
 * <li>have its {@code ifret} terminator marked with
 *     {@link FlowOverride#RETURN} so the listing renders the body
 *     standalone as a function (the original
 *     {@code CheckFlowOverride.java} expectation);</li>
 * <li>receive the {@code ifc_call} calling convention when it is
 *     exclusively reached via {@code ifcall} sites.</li>
 * </ul>
 */
public class NDS32IFCBodyInvariantsTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String LANGUAGE = "NDS32:LE:32:default";

	private TestEnv env;
	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		builder = new ProgramBuilder("ifc-body-invariants", LANGUAGE);
		builder.createMemory("ram", "0x0", 0x200);

		byte[] fill = new byte[0x200];
		java.util.Arrays.fill(fill, (byte) 0xff);
		builder.setBytes("0x0000", fill);

		// P_caller @ 0x000: ifcall9 BODY -- caller_next = 0x006.
		builder.setBytes("0x000",
			"44 00 00 01 f8 7e 44 10 00 02 48 00 00 eb");
		// Q_caller @ 0x040: ifcall9 BODY -- caller_next = 0x046.
		builder.setBytes("0x040",
			"44 00 00 02 f8 5e 44 10 00 03 48 00 00 9b");
		// Shared linear body @ 0x100.
		builder.setBytes("0x100", "44 20 00 10 83 ff");
		// _done @ 0x180.
		builder.setBytes("0x180", "48 00 00 00");

		program = builder.getProgram();

		// Anchor each region without flow-following so an earlier
		// region's flow doesn't drag instruction boundaries.  For the
		// body, anchor each instruction individually so the body's
		// fall-through past ifret16 (into the 0xff filler) is NOT
		// disassembled -- that is what makes the body "isolated" in
		// the eyes of the IFC analyzer's ifret-cleanup pass.
		int anchorTx = program.startTransaction("anchor-disasm");
		try {
			for (long off : new long[] { 0x000, 0x040, 0x100, 0x104,
				0x180 }) {
				new DisassembleCommand(addr(off), null, false)
						.applyTo(program, TaskMonitor.DUMMY);
			}
		}
		finally {
			program.endTransaction(anchorTx, true);
		}
		// Follow-flow pass for callers only -- the body is intentionally
		// left without follow-flow so its post-ifret fall-through stays
		// undecoded.
		for (long off : new long[] { 0x000, 0x040, 0x180 }) {
			builder.disassemble("0x" + Long.toHexString(off), 32, true);
		}

		// Create the body function first so caller-side flow analysis
		// stops at the ifcall edge.
		builder.createFunction("0x100");
		builder.createFunction("0x000");
		builder.createFunction("0x040");

		// Clear any instructions that auto-analysis decoded past the
		// body's ifret16 (into the 0xff filler).  The IFC analyzer's
		// ifret-cleanup pass only applies FlowOverride.RETURN when the
		// fall-through is NOT live in some function -- "live" meaning
		// both "is an instruction" and "is part of a function".
		// Removing the bogus filler instructions makes the body
		// "isolated" from the analyzer's point of view, which is how
		// hand-written IFC body shapes in real firmware appear.
		int clearTx = program.startTransaction("clear-filler");
		try {
			program.getListing().clearCodeUnits(addr(0x106), addr(0x17f),
				/*clearContext*/ false);
		}
		finally {
			program.endTransaction(clearTx, true);
		}

		// Run the IFC analyzer.
		int analysisTx = program.startTransaction("ifc-analysis");
		try {
			new NDS32IFCAnalyzer().added(program, program.getMemory(),
				TaskMonitor.DUMMY, new MessageLog());
		}
		finally {
			program.endTransaction(analysisTx, true);
		}
	}

	@After
	public void tearDown() throws Exception {
		if (env != null) {
			env.dispose();
		}
	}

	@Test
	public void bodyEntryHasRepeatableComment() {
		String comment = program.getListing()
				.getComment(CodeUnit.REPEATABLE_COMMENT, addr(0x100));
		assertNotNull("shared body should have a repeatable comment",
			comment);
		assertTrue("repeatable comment should be the IFC body annotation: " +
			comment, comment.toLowerCase().contains("ifc"));
		// Both callers should be named.
		assertTrue(
			"repeatable comment should mention both caller addresses: " +
				comment,
			comment.contains("00000000") && comment.contains("00000040"));
	}

	@Test
	public void ifretInIsolatedBodyHasReturnFlowOverride() {
		// ifret16 @ 0x104 is the body's terminator.  Its fall-through
		// (0x106) is filler not part of any function, so the analyzer
		// should clear the fall-through and apply FlowOverride.RETURN
		// so the body's standalone decompile renders as a function.
		Instruction ifret = program.getListing().getInstructionAt(addr(0x104));
		assertNotNull("ifret16 must exist at 0x104", ifret);
		assertEquals("ifret16 mnemonic", "ifret16",
			ifret.getMnemonicString().toLowerCase());
		assertEquals("ifret16 should have FlowOverride.RETURN",
			FlowOverride.RETURN, ifret.getFlowOverride());
		assertNull("ifret16's fall-through should be cleared",
			ifret.getFallThrough());
	}

	@Test
	public void bodyFunctionReceivesIfcCallConvention() {
		Function body = program.getFunctionManager().getFunctionAt(addr(0x100));
		assertNotNull("body function must exist", body);
		assertEquals(
			"body function reached exclusively via ifcall should get the " +
				"ifc_call calling convention",
			"ifc_call", body.getCallingConventionName());
	}

	private Address addr(long off) {
		return program.getAddressFactory().getDefaultAddressSpace()
				.getAddress(off);
	}
}
