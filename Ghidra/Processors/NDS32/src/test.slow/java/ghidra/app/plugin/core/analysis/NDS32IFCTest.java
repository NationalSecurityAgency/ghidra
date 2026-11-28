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
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Disassembler-level tests for the IFC (Inline Function Call) extension.
 *
 * <p>Builds a synthetic program in which six self-contained cases at
 * fixed offsets exercise the four IFC instructions ({@code ifcall},
 * {@code ifcall9}, {@code ifret}, {@code ifret16}) and their interaction
 * with regular branches:
 * <ul>
 * <li>Case A @ 0x000: simple {@code ifcall9 -> ifret16}.</li>
 * <li>Case B @ 0x080: thunk pattern ({@code ifcall9 -> jal -> far}).</li>
 * <li>Case C @ 0x280: nested {@code ifcall}.</li>
 * <li>Case D @ 0x400: {@code ifret16} in non-IFC context (no-op).</li>
 * <li>Case E @ 0x480: conditional branch inside an IFC body.</li>
 * <li>Case F @ 0x700: 32-bit {@code ifcall}/{@code ifret} forms.</li>
 * </ul>
 *
 * <p>Each instruction is checked for its mnemonic, its flow-type
 * classification, and (where the IFC semantics introduce runtime
 * branches) for the presence of the expected pcode ops.  No reliance
 * on the analyzer or decompiler -- those are exercised separately.
 *
 * <p>The source listing this byte map was assembled from is preserved
 * at the bottom of this file for reference.
 */
public class NDS32IFCTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String LANGUAGE = "NDS32:LE:32:default";

	private TestEnv env;
	private ProgramBuilder builder;
	private Program program;

	private static final long[] ENTRIES =
		{ 0x000L, 0x040L, 0x080L, 0x100L, 0x200L, 0x280L, 0x300L, 0x380L,
			0x400L, 0x480L, 0x500L, 0x600L, 0x700L, 0x780L };

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		builder = new ProgramBuilder("ifc", LANGUAGE);
		builder.createMemory("ram", "0x0", 0x800);

		// Pre-fill the whole RAM with 0xff so the padding between
		// regions decodes as invalid and disassembly cannot drift
		// from one region into the next.
		byte[] fill = new byte[0x800];
		java.util.Arrays.fill(fill, (byte) 0xff);
		builder.setBytes("0x000", fill);

		// Case A: A_caller @ 0x000, A_target @ 0x040.
		builder.setBytes("0x000", "44 00 00 01 f8 1e 44 10 00 02 48 00 02 fb");
		builder.setBytes("0x040", "44 20 00 a0 83 ff");

		// Case B: B_caller @ 0x080, B_thunk @ 0x100, B_far @ 0x200.
		builder.setBytes("0x080", "44 00 00 01 f8 3e 44 10 00 02 48 00 02 bb");
		builder.setBytes("0x100", "49 00 00 80");
		builder.setBytes("0x200", "44 20 00 b0 4a 00 78 20");

		// Case C: C_caller @ 0x280, C_t1 @ 0x300, C_t2 @ 0x380.
		builder.setBytes("0x280", "44 00 00 01 f8 3e 44 10 00 02 48 00 01 bb");
		builder.setBytes("0x300", "44 20 00 c1 f8 3e 44 30 00 cd 83 ff");
		builder.setBytes("0x380", "44 40 00 c2 83 ff");

		// Case D: D_caller @ 0x400 (ifret in non-IFC context).
		builder.setBytes("0x400", "44 00 00 01 83 ff 44 10 00 d1 48 00 00 fb");

		// Case E: E_caller @ 0x480, E_target @ 0x500 (conditional in body).
		builder.setBytes("0x480", "44 00 00 01 f8 3e 44 10 00 02 48 00 00 bb");
		builder.setBytes("0x500",
			"44 20 00 e0 4e 02 00 05 44 30 00 e1 83 ff 44 40 00 e2 83 ff");

		// Spin terminator @ 0x600.
		builder.setBytes("0x600", "48 00 00 00");

		// Case F: F_caller @ 0x700, F_target @ 0x780 (32-bit forms).
		builder.setBytes("0x700", "44 00 00 01 4e 00 00 3e 44 10 00 02 48 ff ff 7a");
		builder.setBytes("0x780", "44 20 00 f0 4a 00 00 60");

		program = builder.getProgram();

		// Two-pass disassembly: first anchor every region without
		// flow-following so flow from an earlier region cannot nudge
		// the instruction boundary in a later one; then a follow-flow
		// pass to fill in the bodies.
		int txId = program.startTransaction("disassemble");
		try {
			for (long off : ENTRIES) {
				new DisassembleCommand(addr(off), null, false)
						.applyTo(program, TaskMonitor.DUMMY);
			}
			for (long off : ENTRIES) {
				new DisassembleCommand(addr(off), null, true)
						.applyTo(program, TaskMonitor.DUMMY);
			}
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@After
	public void tearDown() throws Exception {
		if (env != null) {
			env.dispose();
		}
	}

	@Test
	public void caseA_simpleIfcall9() {
		assertMnemonic("movi", 0x000);
		assertMnemonic("ifcall9", 0x004);
		assertMnemonic("movi", 0x006); // post-ifcall fall-through
		assertMnemonic("movi", 0x040); // body
		assertMnemonic("ifret16", 0x044);

		// ifcall9 is modeled as a goto-with-fallthrough (pseudo-CBRANCH);
		// the IFC analyzer later annotates it as a CALL into the body.
		Instruction ifcall = insAt(0x004);
		assertTrue("ifcall9 flow is jump",
			ifcall.getFlowType().isJump());
		assertTrue("ifcall9 has fallthrough",
			ifcall.getFlowType().hasFallthrough());
		assertTrue("ifcall9 pcode contains CBRANCH",
			hasPcode(ifcall, PcodeOp.CBRANCH));

		// ifret16 is modeled as a conditional indirect branch (BRANCHIND)
		// guarded by IFC_ON; the fall-through path keeps non-IFC contexts
		// from being treated as a return.
		Instruction ifret = insAt(0x044);
		assertTrue("ifret16 pcode contains BRANCHIND",
			hasPcode(ifret, PcodeOp.BRANCHIND));
	}

	@Test
	public void caseB_thunk() {
		assertMnemonic("ifcall9", 0x084);
		assertMnemonic("jal", 0x100);
		assertMnemonic("ret", 0x204);

		// jal pcode is runtime-conditional on IFC_ON: it contains
		// BOTH a CALL (non-IFC path) and an unconditional BRANCH
		// (IFC tail-jump path), inside a single pcode block.
		Instruction jal = insAt(0x100);
		assertTrue("jal pcode contains CALL", hasPcode(jal, PcodeOp.CALL));
		assertTrue("jal pcode contains BRANCH",
			hasPcode(jal, PcodeOp.BRANCH));
	}

	@Test
	public void caseC_nestedIfcall() {
		assertMnemonic("ifcall9", 0x284); // outer ifcall
		assertMnemonic("ifcall9", 0x304); // nested ifcall (inside C_t1)
		assertMnemonic("ifret16", 0x384); // inner-most ifret

		// Both ifcall9 instances share the same flow shape regardless
		// of IFC nesting level -- the nesting distinction is purely
		// runtime (preserves the outer ifc_lp).
		Instruction outer = insAt(0x284);
		Instruction inner = insAt(0x304);
		assertTrue("outer ifcall9 is jump",
			outer.getFlowType().isJump());
		assertTrue("nested ifcall9 is jump",
			inner.getFlowType().isJump());
		assertTrue("nested ifcall9 pcode contains CBRANCH",
			hasPcode(inner, PcodeOp.CBRANCH));
	}

	@Test
	public void caseD_ifretInNonIfc() {
		assertMnemonic("ifret16", 0x404);
		Instruction ifret = insAt(0x404);
		assertTrue("ifret16 has fallthrough",
			ifret.getFlowType().hasFallthrough());
		// The instruction immediately after must be reached and decoded.
		assertMnemonic("movi", 0x406);
	}

	@Test
	public void caseE_conditionalInIfcBody() {
		assertMnemonic("beqz", 0x504);
		// Two ifret16 sites, one on each arm of the conditional.
		assertMnemonic("ifret16", 0x50c);
		assertMnemonic("ifret16", 0x512);

		Instruction notTaken = insAt(0x50c);
		Instruction taken = insAt(0x512);
		assertTrue("not-taken ifret16 has fallthrough",
			notTaken.getFlowType().hasFallthrough());
		assertTrue("taken ifret16 has fallthrough",
			taken.getFlowType().hasFallthrough());
	}

	@Test
	public void caseF_thirtyTwoBitForms() {
		assertMnemonic("ifcall", 0x704);
		assertMnemonic("ifret", 0x784);

		Instruction ifcall = insAt(0x704);
		assertTrue("32-bit ifcall is jump",
			ifcall.getFlowType().isJump());
		assertTrue("32-bit ifcall has fallthrough",
			ifcall.getFlowType().hasFallthrough());

		Instruction ifret = insAt(0x784);
		assertTrue("32-bit ifret pcode contains BRANCHIND",
			hasPcode(ifret, PcodeOp.BRANCHIND));
	}

	private Address addr(long off) {
		return program.getAddressFactory().getDefaultAddressSpace()
				.getAddress(off);
	}

	private Instruction insAt(long off) {
		return program.getListing().getInstructionAt(addr(off));
	}

	private void assertMnemonic(String expected, long off) {
		Instruction i = insAt(off);
		assertNotNull(
			String.format("no instruction at 0x%x (expected '%s')", off,
				expected),
			i);
		assertEquals(String.format("mnemonic at 0x%x", off), expected,
			i.getMnemonicString().toLowerCase());
	}

	private static boolean hasPcode(Instruction i, int opcode) {
		if (i == null) {
			return false;
		}
		for (PcodeOp op : i.getPcode()) {
			if (op.getOpcode() == opcode) {
				return true;
			}
		}
		return false;
	}

	/*
	 * Source reference -- the byte map above was assembled from this
	 * (NDS32 v3 toolchain, "-march=v3 -mall-ext", raw flat binary at
	 * base 0):
	 *
	 *     .text
	 *     .global _start
	 *
	 *     ! Case A: simple ifcall9 -> body -> ifret16
	 *     .org 0x000
	 * _start:
	 * A_caller:
	 *     movi  $r0, 0x1
	 *     ifcall9 A_target
	 * A_caller_resume:
	 *     movi  $r1, 0x2
	 *     j     _start_done
	 *
	 *     .org 0x040, 0xff
	 * A_target:
	 *     movi  $r2, 0xa0
	 *     ifret16
	 *
	 *     ! Case B: thunk pattern ifcall9 -> jal -> far
	 *     .org 0x080, 0xff
	 * B_caller:
	 *     movi  $r0, 0x1
	 *     ifcall9 B_thunk
	 * B_caller_resume:
	 *     movi  $r1, 0x2
	 *     j     _start_done
	 *
	 *     .org 0x100, 0xff
	 * B_thunk:
	 *     jal   B_far
	 *
	 *     .org 0x200, 0xff
	 * B_far:
	 *     movi  $r2, 0xb0
	 *     ret   $lp
	 *
	 *     ! Case C: nested ifcall
	 *     .org 0x280, 0xff
	 * C_caller:
	 *     movi  $r0, 0x1
	 *     ifcall9 C_t1
	 * C_caller_resume:
	 *     movi  $r1, 0x2
	 *     j     _start_done
	 *
	 *     .org 0x300, 0xff
	 * C_t1:
	 *     movi  $r2, 0xc1
	 *     ifcall9 C_t2
	 *     movi  $r3, 0xcd        ! unreachable: C_t2 returns to outer
	 *     ifret16
	 *
	 *     .org 0x380, 0xff
	 * C_t2:
	 *     movi  $r4, 0xc2
	 *     ifret16
	 *
	 *     ! Case D: ifret16 in non-IFC context (fall-through nop)
	 *     .org 0x400, 0xff
	 * D_caller:
	 *     movi  $r0, 0x1
	 *     ifret16
	 *     movi  $r1, 0xd1
	 *     j     _start_done
	 *
	 *     ! Case E: conditional branch inside IFC body
	 *     .org 0x480, 0xff
	 * E_caller:
	 *     movi  $r0, 0x1
	 *     ifcall9 E_target
	 * E_caller_resume:
	 *     movi  $r1, 0x2
	 *     j     _start_done
	 *
	 *     .org 0x500, 0xff
	 * E_target:
	 *     movi  $r2, 0xe0
	 *     beqz  $r0, E_skip
	 *     movi  $r3, 0xe1
	 *     ifret16
	 * E_skip:
	 *     movi  $r4, 0xe2
	 *     ifret16
	 *
	 *     .org 0x600, 0xff
	 * _start_done:
	 *     j     _start_done
	 *
	 *     ! Case F: 32-bit ifcall + ifret pair
	 *     .org 0x700, 0xff
	 * F_caller:
	 *     movi  $r0, 0x1
	 *     ifcall F_target
	 * F_caller_resume:
	 *     movi  $r1, 0x2
	 *     j     _start_done
	 *
	 *     .org 0x780, 0xff
	 * F_target:
	 *     movi  $r2, 0xf0
	 *     ifret
	 */
}
