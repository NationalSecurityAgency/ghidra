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
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Regression test for the "shared ifret" shape: an {@code ifret16}
 * whose fall-through is live code in the same function (i.e. the
 * sequential next instruction is reachable from somewhere other
 * than this ifret's IFC dispatch).  The IFC analyzer's ifret
 * cleanup pass must NOT clear the fall-through or apply
 * {@link FlowOverride#RETURN} -- doing so orphans the post-ifret
 * block and breaks stack-depth propagation.
 *
 * <p>The shape lifted here is the synthetic minimum that
 * reproduces the bug originally diagnosed in ROM (the
 * {@code C7eFlowCheck} scenario): a function {@code F} contains an
 * {@code ifcall9} whose target body's {@code ifret16} fall-through
 * lands on instructions that are part of {@code F}'s own body
 * (because the disassembler followed the {@code ifcall9} JUMP edge
 * during function-body discovery).
 */
public class NDS32IFCSharedIfretTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String LANGUAGE = "NDS32:LE:32:default";

	private TestEnv env;
	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		builder = new ProgramBuilder("ifc-shared-ifret", LANGUAGE);
		builder.createMemory("ram", "0x0", 0x200);

		byte[] fill = new byte[0x200];
		java.util.Arrays.fill(fill, (byte) 0xff);
		builder.setBytes("0x0000", fill);

		// F @ 0x000: ifcall9 BODY @ 0x100, then post-ifcall straight-line.
		builder.setBytes("0x000",
			"44 00 00 01 f8 7e 44 10 00 02 48 00 00 eb");

		// BODY @ 0x100: shared with F's own body via the ifcall9
		// JUMP edge.  ifret16 at 0x104 must keep its fall-through to
		// 0x106 alive because 0x106 is live code in F.
		builder.setBytes("0x100",
			"44 20 00 10 83 ff 44 30 00 20 48 00 00 3b");

		// _done @ 0x180: spin.
		builder.setBytes("0x180", "48 00 00 00");

		program = builder.getProgram();

		int anchorTx = program.startTransaction("anchor-disasm");
		try {
			for (long off : new long[] { 0x000, 0x100, 0x180 }) {
				new DisassembleCommand(addr(off), null, false)
						.applyTo(program, TaskMonitor.DUMMY);
			}
		}
		finally {
			program.endTransaction(anchorTx, true);
		}
		for (long off : new long[] { 0x000, 0x100, 0x180 }) {
			builder.disassemble("0x" + Long.toHexString(off), 32, true);
		}

		builder.createFunction("0x000");

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
	public void ifretWithLiveFallthrough_preservesFallthrough() {
		Instruction ifret = program.getListing()
				.getInstructionAt(addr(0x104));
		assertNotNull("ifret16 must exist at 0x104", ifret);
		assertEquals("ifret16", ifret.getMnemonicString().toLowerCase());
		Address fall = ifret.getFallThrough();
		assertNotNull(
			"ifret16 with live post-ifret code must retain its fall-through",
			fall);
		assertEquals("fall-through must point at the next sequential insn",
			addr(0x106), fall);
	}

	@Test
	public void ifretWithLiveFallthrough_noFlowOverride() {
		Instruction ifret = program.getListing()
				.getInstructionAt(addr(0x104));
		assertNotNull("ifret16 must exist at 0x104", ifret);
		assertEquals(
			"ifret16 with live post-ifret code must NOT be marked as a return",
			FlowOverride.NONE, ifret.getFlowOverride());
	}

	@Test
	public void postIfretInstructionIsReachable() {
		// The instruction immediately after ifret16 is reached via
		// fall-through; it must be disassembled and exist in the
		// listing.  Without the bug fix the post-ifret block becomes
		// orphaned from the function's flow graph.
		Instruction post = program.getListing()
				.getInstructionAt(addr(0x106));
		assertNotNull("post-ifret code at 0x106 must exist", post);
		assertEquals("movi", post.getMnemonicString().toLowerCase());
	}

	private Address addr(long off) {
		return program.getAddressFactory().getDefaultAddressSpace()
				.getAddress(off);
	}
}
