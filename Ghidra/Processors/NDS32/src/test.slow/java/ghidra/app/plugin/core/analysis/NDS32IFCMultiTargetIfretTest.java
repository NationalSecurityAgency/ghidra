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

import java.util.HashSet;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.util.LongPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Multi-caller multi-target ifret test: a body shared by two
 * callers, where the body's shape does not qualify for the
 * inline-body fast path (the conditional branch inside the body
 * targets an undecoded address, so {@code qualifiesForInlineBody}
 * rejects on the null-instruction check and the analyzer falls
 * through to {@code accumulateReachableBody}).
 *
 * <p>Under that fallback the analyzer is expected to:
 * <ul>
 * <li>Populate a {@code FunctionBodyExt:<caller>} property map for
 *     each caller, so the body's addresses are reachable via
 *     {@code FunctionManager.getFunctionsContaining(addr)} from
 *     every caller (multi-owner -- the original
 *     {@code MultiOwnerCheck.java} expectation).</li>
 * <li>Add a {@link RefType#COMPUTED_JUMP} reference from the
 *     body's {@code ifret16} to each caller-next address (the
 *     original {@code MultiRefsCheck.java} expectation).</li>
 * </ul>
 */
public class NDS32IFCMultiTargetIfretTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String LANGUAGE = "NDS32:LE:32:default";

	private TestEnv env;
	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		builder = new ProgramBuilder("ifc-multi-target", LANGUAGE);
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

		// BODY @ 0x100: linear movi + beqz to undecoded address + ifret16.
		// 0x100: movi r2, 0x10        (4 bytes)
		// 0x104: beqz r0, +0x10       (4 bytes; target 0x114 left undecoded)
		// 0x108: ifret16              (2 bytes)
		builder.setBytes("0x100",
			"44 20 00 10 4e 02 00 08 83 ff");

		// _done @ 0x180.
		builder.setBytes("0x180", "48 00 00 00");

		program = builder.getProgram();

		// Use restricted-set disassembly so flow-following inside one
		// region cannot extend into another region's filler (in
		// particular, beqz's target at 0x114 must stay undecoded so
		// the analyzer's inline-body qualification check rejects this
		// body and falls through to the per-caller body walker).
		disassembleRange(0x000, 0x00e);
		disassembleRange(0x040, 0x04e);
		disassembleRange(0x100, 0x10a);
		disassembleRange(0x180, 0x184);

		// Create the body function first so caller-side flow analysis
		// stops at the ifcall edge.
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

	private void disassembleRange(long lo, long hi) {
		int tx = program.startTransaction("disasm-range");
		try {
			AddressSet restricted = new AddressSet(addr(lo), addr(hi - 1));
			new DisassembleCommand(restricted, restricted, true)
					.applyTo(program, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	@After
	public void tearDown() throws Exception {
		if (env != null) {
			env.dispose();
		}
	}

	@Test
	public void bodyExtensionsPublishedForEachCaller() {
		// FunctionBodyExt:<caller> -- analyzer's accumulateReachableBody
		// records the body addresses into each caller's extension.
		assertNotNull("P_caller must have FunctionBodyExt",
			program.getAddressSetPropertyMap("FunctionBodyExt:0"));
		assertNotNull("Q_caller must have FunctionBodyExt",
			program.getAddressSetPropertyMap("FunctionBodyExt:40"));
	}

	@Test
	public void multiOwnerLookupReturnsAllCallers() {
		// getFunctionsContaining(body_addr) should return BOTH P and Q
		// (and the body's own function if it has one) because each
		// caller's FunctionBodyExt covers the body's instructions.
		FunctionManager fm = program.getFunctionManager();
		Set<Function> owners = fm.getFunctionsContaining(addr(0x100));
		Set<Long> ownerEntries = new HashSet<>();
		for (Function f : owners) {
			ownerEntries.add(f.getEntryPoint().getOffset());
		}
		assertTrue(
			"body addr 0x100 should appear in P_caller's extension: " +
				ownerEntries,
			ownerEntries.contains(0x000L));
		assertTrue(
			"body addr 0x100 should appear in Q_caller's extension: " +
				ownerEntries,
			ownerEntries.contains(0x040L));
	}

	@Test
	public void multiTargetIfretHasReferencesToAllCallerNexts() {
		// The ifret16 instruction at 0x108 must end up with
		// COMPUTED_JUMP references to BOTH caller-next addresses
		// (0x006 and 0x046).  These refs are what MultiRefsCheck.java
		// verified on real ROMs.
		Instruction ifret = program.getListing().getInstructionAt(addr(0x108));
		assertNotNull("ifret16 must exist at 0x108", ifret);
		assertEquals("ifret16", ifret.getMnemonicString().toLowerCase());

		Set<Long> targets = new HashSet<>();
		for (Reference r : ifret.getReferencesFrom()) {
			if (r.getReferenceType() == RefType.COMPUTED_JUMP) {
				targets.add(r.getToAddress().getOffset());
			}
		}
		assertTrue(
			"ifret16 must have a COMPUTED_JUMP ref to P_caller's caller-next 0x006: " +
				targets,
			targets.contains(0x006L));
		assertTrue(
			"ifret16 must have a COMPUTED_JUMP ref to Q_caller's caller-next 0x046: " +
				targets,
			targets.contains(0x046L));
	}

	@Test
	public void multiBranchbackMapPublished() {
		// MultiBranchback maps an ifret address (key) to a CSV string
		// of resolved branch-back targets.  For a body called once
		// from each of two callers, EACH caller's MultiBranchback
		// could contain the ifret with a single-target string, OR
		// the single-target ifretTargetMap could be used.  Verify
		// at least the Branchback or MultiBranchback map is present.
		PropertyMapManager pmm = program.getUsrPropertyManager();
		boolean anyMapHasEntry = false;
		for (long caller : new long[] { 0x000L, 0x040L }) {
			String fnHex = Long.toHexString(caller);
			LongPropertyMap bb = pmm.getLongPropertyMap("Branchback:" + fnHex);
			if (bb != null && bb.getSize() > 0) {
				anyMapHasEntry = true;
				break;
			}
			if (pmm.getStringPropertyMap("MultiBranchback:" + fnHex) != null) {
				anyMapHasEntry = true;
				break;
			}
		}
		assertTrue(
			"Either Branchback or MultiBranchback must be published " +
				"for at least one caller of the multi-target body",
			anyMapHasEntry);
	}

	private Address addr(long off) {
		return program.getAddressFactory().getDefaultAddressSpace()
				.getAddress(off);
	}
}
