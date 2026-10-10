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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Mixed-call test: a body B reached BOTH via {@code ifcall} (from
 * P_caller) AND via a direct {@code jal} (from Q_caller).  The
 * analyzer's IFC-exclusivity heuristic must NOT classify B as
 * IFC-only -- otherwise B would receive the {@code ifc_call}
 * calling convention and be decompiled assuming
 * {@code IFC_ON = 1} on entry, which is wrong for the {@code jal}
 * caller's flow.  The non-IFC entry path must continue to work.
 */
public class NDS32IFCMixedCallTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String LANGUAGE = "NDS32:LE:32:default";

	private TestEnv env;
	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		builder = new ProgramBuilder("ifc-mixed", LANGUAGE);
		builder.createMemory("ram", "0x0", 0x200);

		byte[] fill = new byte[0x200];
		java.util.Arrays.fill(fill, (byte) 0xff);
		builder.setBytes("0x0000", fill);

		// P_caller @ 0x000: reaches B via ifcall9.
		// imm9 for ifcall9 @ 0x004 -> 0x100 = (0x100-0x4)>>1 = 0x7e.
		builder.setBytes("0x000",
			"44 00 00 01 f8 7e 44 10 00 02 48 00 00 eb");

		// Q_caller @ 0x040: reaches B via direct jal.
		// imm24 for jal @ 0x044 -> 0x100 = (0x100-0x44)>>1 = 0x5e.
		// Encoding: OpSz=0, Opc=0b100100, JIt=1 -> high byte 0x49.
		builder.setBytes("0x040",
			"44 00 00 02 49 00 00 5e 44 10 00 03 48 00 00 9a");

		// B @ 0x100: movi r2, 0x10; ret lp.
		// ret lp encoded as in test_basic's B_far.
		builder.setBytes("0x100", "44 20 00 10 4a 00 78 20");

		// _done @ 0x180.
		builder.setBytes("0x180", "48 00 00 00");

		program = builder.getProgram();

		int anchorTx = program.startTransaction("anchor-disasm");
		try {
			for (long off : new long[] { 0x000, 0x040, 0x100, 0x180 }) {
				new DisassembleCommand(addr(off), null, false)
						.applyTo(program, TaskMonitor.DUMMY);
			}
		}
		finally {
			program.endTransaction(anchorTx, true);
		}
		for (long off : new long[] { 0x000, 0x040, 0x100, 0x180 }) {
			builder.disassemble("0x" + Long.toHexString(off), 32, true);
		}

		builder.createFunction("0x100");
		builder.createFunction("0x000");
		builder.createFunction("0x040");

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
	public void mixedCallBody_doesNotGetIfcCallConvention() {
		Function b = program.getFunctionManager().getFunctionAt(addr(0x100));
		assertNotNull("body function must exist", b);
		assertNotEquals(
			"B reached by BOTH ifcall and direct jal must NOT receive the " +
				"ifc_call calling convention (the analyzer's IFC-exclusivity " +
				"heuristic must reject this shape)",
			"ifc_call", b.getCallingConventionName());
	}

	@Test
	public void mixedCallBody_isNotMarkedInline() {
		Function b = program.getFunctionManager().getFunctionAt(addr(0x100));
		assertNotNull("body function must exist", b);
		assertFalse(
			"B reached by BOTH ifcall and direct jal must NOT be marked " +
				"inline -- the standalone decompile is needed for the " +
				"non-IFC caller (the direct jal)",
			b.isInline());
	}

	private Address addr(long off) {
		return program.getAddressFactory().getDefaultAddressSpace()
				.getAddress(off);
	}
}
