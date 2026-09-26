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
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Tests reference rewriting at {@code ex9.it} sites for IT entries
 * of various flow types.  Once {@link NDS32ITBAnalyzer} decodes an
 * IT entry, the ex9.it dispatch site should reflect that entry's
 * actual flow: a {@code j} entry gives the dispatch a
 * {@link RefType#UNCONDITIONAL_JUMP} reference (and clears the
 * fall-through); a {@code jal} entry gives an
 * {@link RefType#UNCONDITIONAL_CALL} reference; an ALU/load entry
 * gives no flow reference but still receives an EOL comment.
 *
 * <p>The bytes for the {@code j} / {@code jal} entries are lifted
 * from the same encoding the NDS32 assembler emits in the existing
 * synthetic test bench, so this test does not require the
 * toolchain to be rebuilt.
 */
public class NDS32EX9ITDispatchTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String LANGUAGE = "NDS32:LE:32:default";

	private TestEnv env;
	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		builder = new ProgramBuilder("ex9it-dispatch", LANGUAGE);
		builder.createMemory("ram", "0x0", 0x2000);

		byte[] fill = new byte[0x2000];
		java.util.Arrays.fill(fill, (byte) 0xff);
		builder.setBytes("0x0000", fill);

		// Code: r0 = 0x1000, mtusr r0,itb, ex9.it 0..3, j .
		builder.setBytes("0x0000",
			"46 00 00 01 58 00 00 00 42 0e 00 21");
		builder.setBytes("0x000c",
			"dd 40 dd 41 dd 42 dd 43 48 00 00 00");

		// L_target @ 0x0100: just a spin so the disassembler creates an
		// instruction at the address (so refs from ex9.it sites resolve
		// to a known code location).
		builder.setBytes("0x0100", "48 00 00 00");

		// IT[0] @ 0x1000: `add r0, r1, r2`  (32-bit ALU; no flow ref).
		// IT[1] @ 0x1004: `j 0x100`         (32-bit jump).
		// IT[2] @ 0x1008: `lwi a0,[a1+4]`   (32-bit load; no flow ref).
		// IT[3] @ 0x100c: `jal 0x100`       (32-bit call).
		//
		// Branch IT entries are decoded against PC=0 per the NDS32
		// manual (the imm24 holds the target shifted right by one,
		// not a PC-relative displacement).  For target=0x100 the
		// imm24 field is 0x80.
		builder.setBytes("0x1000",
			"40 00 88 00 48 00 00 80 04 00 80 01 49 00 00 80");

		program = builder.getProgram();

		int txId = program.startTransaction("disassemble");
		try {
			new DisassembleCommand(addr(0x0000), null, true).applyTo(program,
				TaskMonitor.DUMMY);
			new DisassembleCommand(addr(0x0100), null, true).applyTo(program,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		int analysisTx = program.startTransaction("itb-analysis");
		try {
			new NDS32ITBAnalyzer().added(program, program.getMemory(),
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
	public void aluEntry_eolCommentOnly() {
		// ex9.it 0 -> IT[0] = add: no jump/call ref, EOL comment present.
		String eol = program.getListing()
				.getComment(CodeUnit.EOL_COMMENT, addr(0x000c));
		assertNotNull("ex9.it 0 should have an EOL comment", eol);
		assertTrue("ex9.it 0 EOL should mention `add`: " + eol,
			eol.toLowerCase().contains("add"));
		assertFalse("ex9.it 0 should NOT have a flow reference",
			anyFlowRefAt(0x000c));
	}

	@Test
	public void jumpEntry_jumpReferenceCreated() {
		// ex9.it 1 -> IT[1] = j 0x100: dispatch gets an
		// UNCONDITIONAL_JUMP reference to 0x100.
		Reference jr = findRef(0x000e, RefType.UNCONDITIONAL_JUMP);
		assertNotNull("ex9.it 1 should have an UNCONDITIONAL_JUMP reference",
			jr);
		assertEquals("ex9.it 1 jump target should be 0x100",
			addr(0x0100), jr.getToAddress());
	}

	@Test
	public void loadEntry_noFlowReference() {
		// ex9.it 2 -> IT[2] = lwi: no flow reference.
		String eol = program.getListing()
				.getComment(CodeUnit.EOL_COMMENT, addr(0x0010));
		assertNotNull("ex9.it 2 should have an EOL comment", eol);
		assertTrue("ex9.it 2 EOL should mention `lwi`: " + eol,
			eol.toLowerCase().contains("lwi"));
		assertFalse("ex9.it 2 should NOT have a flow reference",
			anyFlowRefAt(0x0010));
	}

	@Test
	public void callEntry_callReferenceCreated() {
		// ex9.it 3 -> IT[3] = jal 0x100: dispatch gets an
		// UNCONDITIONAL_CALL reference to 0x100.
		Reference cr = findRef(0x0012, RefType.UNCONDITIONAL_CALL);
		assertNotNull("ex9.it 3 should have an UNCONDITIONAL_CALL reference",
			cr);
		assertEquals("ex9.it 3 call target should be 0x100",
			addr(0x0100), cr.getToAddress());
	}

	private Reference findRef(long off, RefType expectedType) {
		for (Reference r : program.getReferenceManager()
				.getReferencesFrom(addr(off))) {
			if (r.getReferenceType().equals(expectedType)) {
				return r;
			}
		}
		return null;
	}

	private boolean anyFlowRefAt(long off) {
		for (Reference r : program.getReferenceManager()
				.getReferencesFrom(addr(off))) {
			RefType rt = r.getReferenceType();
			if (rt.isJump() || rt.isCall()) {
				return true;
			}
		}
		return false;
	}

	private Address addr(long off) {
		return program.getAddressFactory().getDefaultAddressSpace()
				.getAddress(off);
	}
}
