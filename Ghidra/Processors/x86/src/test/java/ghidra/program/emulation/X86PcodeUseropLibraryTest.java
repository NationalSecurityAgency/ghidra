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
package ghidra.program.emulation;

import static org.junit.Assert.*;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;

import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.jit.JitConfiguration;
import ghidra.pcode.emu.jit.JitPcodeEmulator;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.program.util.DefaultLanguageService;

public class X86PcodeUseropLibraryTest extends AbstractEmulationEquivalenceTest {
	static final LanguageID LANG_ID_REAL = new LanguageID("x86:LE:16:Real Mode");
	static final LanguageID LANG_ID_PROTECTED = new LanguageID("x86:LE:16:Protected Mode");
	static final LanguageID LANG_ID_32 = new LanguageID("x86:LE:32:default");

	static final int CODE_SEG = 0x1000;
	static final int STACK_SEG = 0x2000;
	static final int FAR_SEG = 0x3000;
	static final int DATA_SEG = 0x4000;
	static final int ENTRY = 0x0100;
	static final int STACK_TOP = 0x0100;
	static final int FAR_TARGET = 0x0234;

	static SleighLanguage getLanguage(LanguageID id) throws Exception {
		return (SleighLanguage) DefaultLanguageService.getLanguageService().getLanguage(id);
	}

	/**
	 * Every instruction test runs on both the interpreting and the JIT-compiling emulator
	 */
	static final boolean[] JIT_MODES = { false, true };

	/**
	 * A 16-bit machine that places code at {@code CODE_SEG:ENTRY} and the stack at
	 * {@code STACK_SEG:STACK_TOP}
	 */
	static class Machine16 {
		final SleighLanguage language;
		final SegmentedAddressSpace space;
		final PcodeEmulator emu;
		final PcodeThread<byte[]> thread;
		final PcodeArithmetic<byte[]> arithmetic;

		Machine16(LanguageID id, boolean jit, int... code) throws Exception {
			language = getLanguage(id);
			space = (SegmentedAddressSpace) language.getDefaultSpace();
			emu = jit
					? new JitPcodeEmulator(language, new JitConfiguration(), MethodHandles.lookup())
					: new PcodeEmulator(language);
			thread = emu.newThread();
			arithmetic = thread.getArithmetic();

			byte[] bytes = new byte[code.length];
			for (int i = 0; i < code.length; i++) {
				bytes[i] = (byte) code[i];
			}
			emu.getSharedState().setVar(addr(CODE_SEG, ENTRY), bytes.length, false, bytes);

			setReg("CS", CODE_SEG);
			setReg("SS", STACK_SEG);
			setReg("DS", DATA_SEG);
			setReg("SP", STACK_TOP);
		}

		Address addr(int segment, int offset) {
			return space.getAddress(segment, offset);
		}

		void setReg(String name, long value) {
			Register reg = language.getRegister(name);
			thread.getState()
					.setVar(reg, arithmetic.fromConst(BigInteger.valueOf(value), reg.getNumBytes()));
		}

		long getReg(String name) {
			Register reg = language.getRegister(name);
			return arithmetic.toLong(thread.getState().getVar(reg, Reason.INSPECT),
				Purpose.INSPECT);
		}

		void writeWord(int segment, int offset, int value) {
			emu.getSharedState()
					.setVar(addr(segment, offset), 2, false,
						new byte[] { (byte) value, (byte) (value >> 8) });
		}

		int readWord(int segment, int offset) {
			byte[] bytes = emu.getSharedState().getVar(addr(segment, offset), 2, false,
				Reason.INSPECT);
			return (bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8);
		}

		void step() {
			thread.setCounter(addr(CODE_SEG, ENTRY));
			thread.overrideContextWithDefault();
			thread.stepInstruction();
		}

		void assertAtFarTarget() {
			assertEquals(addr(FAR_SEG, FAR_TARGET).getOffset(), thread.getCounter().getOffset());
			assertEquals(FAR_SEG, getReg("CS"));
		}
	}

	@Test
	public void testSegmentFoundByLang() throws Exception {
		for (LanguageID id : new LanguageID[] { LANG_ID_REAL, LANG_ID_PROTECTED }) {
			SleighLanguage language = getLanguage(id);
			PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory
					.createUseropLibraryForLanguage(language,
						BytesPcodeArithmetic.forLanguage(language));
			assertNotNull(id.toString(), lib.getUserops().get("segment"));
		}
	}

	@Test
	public void testSegmentAbsentFor32Bit() throws Exception {
		SleighLanguage language = getLanguage(LANG_ID_32);
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory
				.createUseropLibraryForLanguage(language,
					BytesPcodeArithmetic.forLanguage(language));
		assertNull(lib.getUserops().get("segment"));
	}

	protected void doTestMovFromDataSegment(LanguageID id) throws Exception {
		for (boolean jit : JIT_MODES) {
			Machine16 m = new Machine16(id, jit, 0x8b, 0x07); // MOV AX,word ptr [BX]
			m.setReg("BX", 0x0010);
			m.writeWord(DATA_SEG, 0x0010, 0xbeef);
			m.step();
			assertEquals(0xbeef, m.getReg("AX"));
		}
	}

	@Test
	public void testMovFromDataSegmentReal() throws Exception {
		doTestMovFromDataSegment(LANG_ID_REAL);
	}

	@Test
	public void testMovFromDataSegmentProtected() throws Exception {
		doTestMovFromDataSegment(LANG_ID_PROTECTED);
	}

	protected void doTestRetImm16(LanguageID id) throws Exception {
		for (boolean jit : JIT_MODES) {
			Machine16 m = new Machine16(id, jit, 0xc2, 0x04, 0x00); // RET 0x4
			m.writeWord(STACK_SEG, STACK_TOP, FAR_TARGET);
			m.step();
			assertEquals(m.addr(CODE_SEG, FAR_TARGET).getOffset(), m.thread.getCounter().getOffset());
			assertEquals(CODE_SEG, m.getReg("CS"));
			assertEquals(STACK_TOP + 2 + 4, m.getReg("SP"));
		}
	}

	@Test
	public void testRetImm16Real() throws Exception {
		doTestRetImm16(LANG_ID_REAL);
	}

	@Test
	public void testRetImm16Protected() throws Exception {
		doTestRetImm16(LANG_ID_PROTECTED);
	}

	protected void doTestRetfImm16(LanguageID id) throws Exception {
		for (boolean jit : JIT_MODES) {
			Machine16 m = new Machine16(id, jit, 0xca, 0x04, 0x00); // RETF 0x4
			m.writeWord(STACK_SEG, STACK_TOP, FAR_TARGET);
			m.writeWord(STACK_SEG, STACK_TOP + 2, FAR_SEG);
			m.step();
			m.assertAtFarTarget();
			assertEquals(STACK_TOP + 4 + 4, m.getReg("SP"));
		}
	}

	@Test
	public void testRetfImm16Real() throws Exception {
		doTestRetfImm16(LANG_ID_REAL);
	}

	@Test
	public void testRetfImm16Protected() throws Exception {
		doTestRetfImm16(LANG_ID_PROTECTED);
	}

	protected void doTestIret(LanguageID id) throws Exception {
		for (boolean jit : JIT_MODES) {
			Machine16 m = new Machine16(id, jit, 0xcf); // IRET
			m.writeWord(STACK_SEG, STACK_TOP, FAR_TARGET);
			m.writeWord(STACK_SEG, STACK_TOP + 2, FAR_SEG);
			m.writeWord(STACK_SEG, STACK_TOP + 4, 0x0002);
			m.step();
			m.assertAtFarTarget();
			assertEquals(STACK_TOP + 6, m.getReg("SP"));
		}
	}

	@Test
	public void testIretReal() throws Exception {
		doTestIret(LANG_ID_REAL);
	}

	@Test
	public void testIretProtected() throws Exception {
		doTestIret(LANG_ID_PROTECTED);
	}

	protected void doTestCallfIndirect(LanguageID id) throws Exception {
		for (boolean jit : JIT_MODES) {
			Machine16 m = new Machine16(id, jit, 0xff, 0x1e, 0x00, 0x05); // CALLF [0x500]
			m.writeWord(DATA_SEG, 0x0500, FAR_TARGET);
			m.writeWord(DATA_SEG, 0x0502, FAR_SEG);
			m.step();
			m.assertAtFarTarget();
			assertEquals(STACK_TOP - 4, m.getReg("SP"));
			assertEquals(ENTRY + 4, m.readWord(STACK_SEG, STACK_TOP - 4));
			assertEquals(CODE_SEG, m.readWord(STACK_SEG, STACK_TOP - 2));
		}
	}

	@Test
	public void testCallfIndirectReal() throws Exception {
		doTestCallfIndirect(LANG_ID_REAL);
	}

	@Test
	public void testCallfIndirectProtected() throws Exception {
		doTestCallfIndirect(LANG_ID_PROTECTED);
	}

	protected void doTestJmpfIndirect(LanguageID id) throws Exception {
		for (boolean jit : JIT_MODES) {
			Machine16 m = new Machine16(id, jit, 0xff, 0x2e, 0x00, 0x05); // JMPF [0x500]
			m.writeWord(DATA_SEG, 0x0500, FAR_TARGET);
			m.writeWord(DATA_SEG, 0x0502, FAR_SEG);
			m.step();
			m.assertAtFarTarget();
			assertEquals(STACK_TOP, m.getReg("SP"));
		}
	}

	@Test
	public void testJmpfIndirectReal() throws Exception {
		doTestJmpfIndirect(LANG_ID_REAL);
	}

	@Test
	public void testJmpfIndirectProtected() throws Exception {
		doTestJmpfIndirect(LANG_ID_PROTECTED);
	}
}
