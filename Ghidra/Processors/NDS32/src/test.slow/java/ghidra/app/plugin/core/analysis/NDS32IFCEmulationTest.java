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

import java.math.BigInteger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Emulator semantics tests for the IFC (Inline Function Call)
 * extension.  Each case spins up a fresh emulator and steps through
 * the instruction sequence, asserting the architectural state
 * ({@code pc}, {@code ifc_lp}, {@code IFC_ON}, GPRs) after every
 * step.  This pins down the runtime behavior of the four IFC
 * instructions and the IFC-aware variants of {@code jal}/{@code ret}.
 *
 * <p>The byte map is the same synthetic test bench used by
 * {@link NDS32IFCTest} (see that class for the full assembly
 * listing).
 */
public class NDS32IFCEmulationTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String LANGUAGE = "NDS32:LE:32:default";

	private TestEnv env;
	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		builder = new ProgramBuilder("ifc-emu", LANGUAGE);
		builder.createMemory("ram", "0x0", 0x800);

		byte[] fill = new byte[0x800];
		java.util.Arrays.fill(fill, (byte) 0xff);
		builder.setBytes("0x000", fill);

		// Case A
		builder.setBytes("0x000", "44 00 00 01 f8 1e 44 10 00 02 48 00 02 fb");
		builder.setBytes("0x040", "44 20 00 a0 83 ff");
		// Case B
		builder.setBytes("0x080", "44 00 00 01 f8 3e 44 10 00 02 48 00 02 bb");
		builder.setBytes("0x100", "49 00 00 80");
		builder.setBytes("0x200", "44 20 00 b0 4a 00 78 20");
		// Case C
		builder.setBytes("0x280", "44 00 00 01 f8 3e 44 10 00 02 48 00 01 bb");
		builder.setBytes("0x300", "44 20 00 c1 f8 3e 44 30 00 cd 83 ff");
		builder.setBytes("0x380", "44 40 00 c2 83 ff");
		// Case D
		builder.setBytes("0x400", "44 00 00 01 83 ff 44 10 00 d1 48 00 00 fb");
		// Case F
		builder.setBytes("0x700", "44 00 00 01 4e 00 00 3e 44 10 00 02 48 ff ff 7a");
		builder.setBytes("0x780", "44 20 00 f0 4a 00 00 60");

		program = builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		if (env != null) {
			env.dispose();
		}
	}

	@Test
	public void caseA_ifcall9ThenIfret16() throws Exception {
		PcodeThread<byte[]> t = freshThread(0x000);
		t.stepInstruction(); // movi r0, 1
		assertRegEquals(t, "a0", 1L, "after movi: r0=1");

		t.stepInstruction(); // ifcall9 -> A_target
		assertRegEquals(t, "pc", 0x40L, "ifcall9 -> A_target");
		assertRegEquals(t, "ifc_lp", 0x6L, "ifc_lp = inst_next (0x6)");
		assertRegEquals(t, "IFC_ON", 1L, "IFC_ON set");

		t.stepInstruction(); // movi r2, 0xa0
		assertRegEquals(t, "a2", 0xa0L, "A_target body: r2=0xa0");

		t.stepInstruction(); // ifret16
		assertRegEquals(t, "pc", 0x6L, "ifret16 returns to ifc_lp (0x6)");
		assertRegEquals(t, "IFC_ON", 0L, "ifret16 clears IFC_ON");
	}

	@Test
	public void caseB_ifcallThenJalTailCall() throws Exception {
		PcodeThread<byte[]> t = freshThread(0x080);
		t.stepInstruction(); // movi r0, 1
		t.stepInstruction(); // ifcall9 -> B_thunk
		assertRegEquals(t, "pc", 0x100L, "ifcall9 -> B_thunk");
		assertRegEquals(t, "ifc_lp", 0x86L, "ifc_lp = 0x86");
		assertRegEquals(t, "IFC_ON", 1L, "IFC_ON set");

		t.stepInstruction(); // jal B_far  (in IFC mode -> tail-jump)
		assertRegEquals(t, "pc", 0x200L, "thunk's jal -> B_far");
		assertRegEquals(t, "lp", 0x86L,
			"jal in IFC mode: lp = ifc_lp (not inst_next)");
		assertRegEquals(t, "IFC_ON", 0L, "jal clears IFC_ON");

		t.stepInstruction(); // movi r2, 0xb0
		t.stepInstruction(); // ret $lp
		assertRegEquals(t, "pc", 0x86L,
			"B_far ret -> caller's resume (via re-used lp)");
	}

	@Test
	public void caseC_nestedIfcall() throws Exception {
		PcodeThread<byte[]> t = freshThread(0x280);
		t.stepInstruction(); // movi r0, 1
		t.stepInstruction(); // ifcall9 -> C_t1
		assertRegEquals(t, "pc", 0x300L, "outer ifcall9 -> C_t1");
		assertRegEquals(t, "ifc_lp", 0x286L, "ifc_lp captured outer next");

		t.stepInstruction(); // movi r2, 0xc1
		t.stepInstruction(); // ifcall9 -> C_t2 (nested)
		assertRegEquals(t, "pc", 0x380L, "nested ifcall9 -> C_t2");
		assertRegEquals(t, "ifc_lp", 0x286L,
			"nested ifcall preserves outer ifc_lp");
		assertRegEquals(t, "IFC_ON", 1L, "IFC_ON still set");

		t.stepInstruction(); // movi r4, 0xc2
		t.stepInstruction(); // ifret16
		assertRegEquals(t, "pc", 0x286L,
			"ifret16 returns to outer caller's resume");
		assertRegEquals(t, "IFC_ON", 0L, "ifret16 clears IFC_ON");
	}

	@Test
	public void caseD_ifretIsNopInNonIfc() throws Exception {
		PcodeThread<byte[]> t = freshThread(0x400);
		t.stepInstruction(); // movi r0, 1
		assertRegEquals(t, "pc", 0x404L, "advanced to ifret16");

		t.stepInstruction(); // ifret16 with IFC_ON=0
		assertRegEquals(t, "pc", 0x406L,
			"ifret16 in non-IFC: fall-through, not return");
		assertRegEquals(t, "IFC_ON", 0L, "IFC_ON remains 0");
	}

	@Test
	public void caseF_thirtyTwoBitForms() throws Exception {
		PcodeThread<byte[]> t = freshThread(0x700);
		t.stepInstruction(); // movi r0, 1
		t.stepInstruction(); // ifcall F_target  (32-bit)
		assertRegEquals(t, "pc", 0x780L, "32-bit ifcall -> F_target");
		assertRegEquals(t, "ifc_lp", 0x708L,
			"ifc_lp = inst_next after 32-bit ifcall");
		assertRegEquals(t, "IFC_ON", 1L, "IFC_ON set");

		t.stepInstruction(); // movi r2, 0xf0
		t.stepInstruction(); // ifret  (32-bit)
		assertRegEquals(t, "pc", 0x708L,
			"32-bit ifret returns to ifc_lp");
		assertRegEquals(t, "IFC_ON", 0L, "32-bit ifret clears IFC_ON");
	}

	private PcodeThread<byte[]> freshThread(long entry) throws Exception {
		PcodeEmulator emu = new PcodeEmulator(program.getLanguage());
		for (MemoryBlock blk : program.getMemory().getBlocks()) {
			if (!blk.isInitialized()) {
				continue;
			}
			byte[] buf = new byte[(int) blk.getSize()];
			blk.getBytes(blk.getStart(), buf);
			emu.getSharedState().setVar(blk.getStart(), buf.length, true,
				buf);
		}
		PcodeThread<byte[]> thread = emu.newThread("t");
		writeReg(thread, "sp", 0x10000);
		writeReg(thread, "IFC_ON", 0);
		thread.overrideCounter(addr(entry));
		return thread;
	}

	private Address addr(long off) {
		return program.getAddressFactory().getDefaultAddressSpace()
				.getAddress(off);
	}

	private long readReg(PcodeThread<byte[]> thread, String name) {
		Register r = program.getLanguage().getRegister(name);
		assertNotNull("unknown register " + name, r);
		byte[] bytes =
			thread.getState().getVar(r, PcodeExecutorStatePiece.Reason.INSPECT);
		byte[] beBytes;
		if (program.getLanguage().isBigEndian()) {
			beBytes = bytes;
		}
		else {
			beBytes = new byte[bytes.length];
			for (int i = 0; i < bytes.length; i++) {
				beBytes[i] = bytes[bytes.length - 1 - i];
			}
		}
		return new BigInteger(1, beBytes).longValue();
	}

	private void writeReg(PcodeThread<byte[]> thread, String name,
			long value) {
		Register r = program.getLanguage().getRegister(name);
		assertNotNull("unknown register " + name, r);
		int size = r.getMinimumByteSize();
		byte[] padded = new byte[size];
		if (program.getLanguage().isBigEndian()) {
			for (int i = 0; i < size; i++) {
				padded[size - 1 - i] = (byte) ((value >> (i * 8)) & 0xff);
			}
		}
		else {
			for (int i = 0; i < size; i++) {
				padded[i] = (byte) ((value >> (i * 8)) & 0xff);
			}
		}
		thread.getState().setVar(r, padded);
	}

	private void assertRegEquals(PcodeThread<byte[]> thread, String name,
			long expected, String msg) {
		long got = readReg(thread, name);
		assertEquals(
			String.format("%s: %s=0x%x (got 0x%x)", msg, name, expected,
				got),
			expected, got);
	}
}
