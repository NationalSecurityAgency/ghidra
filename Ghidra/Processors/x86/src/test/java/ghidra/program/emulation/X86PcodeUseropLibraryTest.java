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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.*;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;

import org.hamcrest.Matchers;
import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.jit.JitConfiguration;
import ghidra.pcode.emu.jit.JitPcodeEmulator;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.SegmentopPcodeUseropLibraryFactory.SegmentopPcodeUseropDefinition;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.NumericUtilities;

public class X86PcodeUseropLibraryTest extends AbstractEmulationEquivalenceTest {
	static final LanguageID LANG_ID_REAL = new LanguageID("x86:LE:16:Real Mode");
	static final LanguageID LANG_ID_PROTECTED = new LanguageID("x86:LE:16:Protected Mode");
	static final LanguageID LANG_ID_32 = new LanguageID("x86:LE:32:default");

	/**
	 * Segment values that are not multiples of 0x1000, so a real-mode offset differs from the low
	 * 16 bits of its linear address
	 */
	static final int CODE_SEG = 0x1234;
	static final int STACK_SEG = 0x2345;
	static final int FAR_SEG = 0x3456;
	static final int DATA_SEG = 0x4567;
	static final int EXTRA_SEG = 0x5678;

	static final int ENTRY = 0x0100;
	static final int STACK_TOP = 0x0100;
	static final int FAR_TARGET = 0x0234;

	/**
	 * Every instruction test runs on both the interpreting and the JIT-compiling emulator
	 */
	static final boolean[] JIT_MODES = { false, true };

	static SleighLanguage getLanguage(LanguageID id) throws Exception {
		return (SleighLanguage) DefaultLanguageService.getLanguageService().getLanguage(id);
	}

	/**
	 * An x86 machine for a single thread
	 *
	 * <p>
	 * For the 16-bit languages, {@link #addr(int, int)} takes a segment and an offset. The 32-bit
	 * language ignores the segment.
	 */
	static class Machine {
		final SleighLanguage language;
		final AddressSpace space;
		final PcodeEmulator emu;
		final PcodeThread<byte[]> thread;
		final PcodeArithmetic<byte[]> arithmetic;

		Machine(LanguageID id, boolean jit) throws Exception {
			language = getLanguage(id);
			space = language.getDefaultSpace();
			emu = jit
					? new JitPcodeEmulator(language, new JitConfiguration(), MethodHandles.lookup())
					: new PcodeEmulator(language);
			thread = emu.newThread();
			arithmetic = thread.getArithmetic();
		}

		Address addr(int segment, int offset) {
			if (space instanceof SegmentedAddressSpace seg) {
				return seg.getAddress(segment, offset);
			}
			return space.getAddress(offset);
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

		/**
		 * Write bytes given as hex, e.g., {@code "ff 1e 00 05"}
		 */
		void write(int segment, int offset, String hex) {
			byte[] bytes = NumericUtilities.convertStringToBytes(hex.replace(" ", ""));
			emu.getSharedState().setVar(addr(segment, offset), bytes.length, false, bytes);
		}

		void writeWord(int segment, int offset, int value) {
			emu.getSharedState()
					.setVar(addr(segment, offset), 2, false,
						new byte[] { (byte) value, (byte) (value >> 8) });
		}

		int readWord(int segment, int offset) {
			byte[] bytes =
				emu.getSharedState().getVar(addr(segment, offset), 2, false, Reason.INSPECT);
			return (bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8);
		}

		void start(int segment, int offset) {
			thread.setCounter(addr(segment, offset));
			thread.overrideContextWithDefault();
		}

		void step() {
			thread.stepInstruction();
		}

		void assertCounter(int segment, int offset) {
			assertEquals(addr(segment, offset).getOffset(), thread.getCounter().getOffset());
		}
	}

	/**
	 * A 16-bit machine with its code at {@code CODE_SEG:ENTRY} and its stack at
	 * {@code STACK_SEG:STACK_TOP}
	 */
	static class Machine16 extends Machine {
		Machine16(LanguageID id, boolean jit, String code) throws Exception {
			super(id, jit);
			write(CODE_SEG, ENTRY, code);
			setReg("CS", CODE_SEG);
			setReg("SS", STACK_SEG);
			setReg("DS", DATA_SEG);
			setReg("ES", EXTRA_SEG);
			setReg("SP", STACK_TOP);
			start(CODE_SEG, ENTRY);
		}

		void assertAtFarTarget() {
			assertCounter(FAR_SEG, FAR_TARGET);
			assertEquals(FAR_SEG, getReg("CS"));
		}

		/**
		 * Assert a far call pushed the caller's CS and the offset of the next instruction
		 */
		void assertFarReturnPushed(int stackSeg, int top, int nextOffset) {
			assertEquals(nextOffset, readWord(stackSeg, top - 4));
			assertEquals(CODE_SEG, readWord(stackSeg, top - 2));
		}
	}

	interface TestBody {
		void run(LanguageID id, boolean jit) throws Exception;
	}

	static void on16BitModes(TestBody body) throws Exception {
		for (LanguageID id : new LanguageID[] { LANG_ID_REAL, LANG_ID_PROTECTED }) {
			for (boolean jit : JIT_MODES) {
				body.run(id, jit);
			}
		}
	}

	@Test
	public void testSegmentFromSegmentop() throws Exception {
		for (LanguageID id : new LanguageID[] { LANG_ID_REAL, LANG_ID_PROTECTED }) {
			SleighLanguage language = getLanguage(id);
			PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory
					.createUseropLibraryForLanguage(language,
						BytesPcodeArithmetic.forLanguage(language));
			assertThat(id.toString(), lib.getUserops().get("segment"),
				Matchers.instanceOf(SegmentopPcodeUseropDefinition.class));
		}
	}

	@Test
	public void testSegmentFlatFor32Bit() throws Exception {
		SleighLanguage language = getLanguage(LANG_ID_32);
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory
				.createUseropLibraryForLanguage(language,
					BytesPcodeArithmetic.forLanguage(language));
		assertThat(lib.getUserops().get("segment"),
			Matchers.instanceOf(SleighPcodeUseropDefinition.class));
	}

	@Test
	public void testMovFromDataSegment() throws Exception {
		on16BitModes((id, jit) -> {
			Machine16 m = new Machine16(id, jit, "8b 07"); // MOV AX,word ptr [BX]
			m.setReg("BX", 0x0010);
			m.writeWord(DATA_SEG, 0x0010, 0xbeef);
			m.step();
			assertEquals(0xbeef, m.getReg("AX"));
		});
	}

	@Test
	public void testRetImm16() throws Exception {
		on16BitModes((id, jit) -> {
			Machine16 m = new Machine16(id, jit, "c2 04 00"); // RET 0x4
			m.writeWord(STACK_SEG, STACK_TOP, FAR_TARGET);
			m.step();
			m.assertCounter(CODE_SEG, FAR_TARGET);
			assertEquals(CODE_SEG, m.getReg("CS"));
			assertEquals(STACK_TOP + 2 + 4, m.getReg("SP"));
		});
	}

	@Test
	public void testRetfImm16() throws Exception {
		on16BitModes((id, jit) -> {
			Machine16 m = new Machine16(id, jit, "ca 04 00"); // RETF 0x4
			m.writeWord(STACK_SEG, STACK_TOP, FAR_TARGET);
			m.writeWord(STACK_SEG, STACK_TOP + 2, FAR_SEG);
			m.step();
			m.assertAtFarTarget();
			assertEquals(STACK_TOP + 4 + 4, m.getReg("SP"));
		});
	}

	@Test
	public void testIret() throws Exception {
		on16BitModes((id, jit) -> {
			Machine16 m = new Machine16(id, jit, "cf"); // IRET
			m.writeWord(STACK_SEG, STACK_TOP, FAR_TARGET);
			m.writeWord(STACK_SEG, STACK_TOP + 2, FAR_SEG);
			m.writeWord(STACK_SEG, STACK_TOP + 4, 0x0002);
			m.step();
			m.assertAtFarTarget();
			assertEquals(STACK_TOP + 6, m.getReg("SP"));
		});
	}

	@Test
	public void testCallRetRoundTrip() throws Exception {
		on16BitModes((id, jit) -> {
			Machine16 m = new Machine16(id, jit, "e8 0d 00"); // CALL ENTRY+0x10
			m.write(CODE_SEG, ENTRY + 0x10, "c2 00 00"); // RET 0x0
			m.step();
			m.assertCounter(CODE_SEG, ENTRY + 0x10);
			assertEquals(ENTRY + 3, m.readWord(STACK_SEG, STACK_TOP - 2));
			m.step();
			m.assertCounter(CODE_SEG, ENTRY + 3);
			assertEquals(STACK_TOP, m.getReg("SP"));
		});
	}

	@Test
	public void testCallfDirectRetfRoundTrip() throws Exception {
		on16BitModes((id, jit) -> {
			// CALLF FAR_SEG:FAR_TARGET
			Machine16 m = new Machine16(id, jit, "9a 34 02 56 34");
			m.write(FAR_SEG, FAR_TARGET, "cb"); // RETF
			m.step();
			m.assertAtFarTarget();
			m.assertFarReturnPushed(STACK_SEG, STACK_TOP, ENTRY + 5);
			m.step();
			m.assertCounter(CODE_SEG, ENTRY + 5);
			assertEquals(CODE_SEG, m.getReg("CS"));
			assertEquals(STACK_TOP, m.getReg("SP"));
		});
	}

	@Test
	public void testCallfIndirectRetfRoundTrip() throws Exception {
		on16BitModes((id, jit) -> {
			Machine16 m = new Machine16(id, jit, "ff 1e 00 05"); // CALLF [0x500]
			m.writeWord(DATA_SEG, 0x0500, FAR_TARGET);
			m.writeWord(DATA_SEG, 0x0502, FAR_SEG);
			m.write(FAR_SEG, FAR_TARGET, "cb"); // RETF
			m.step();
			m.assertAtFarTarget();
			assertEquals(STACK_TOP - 4, m.getReg("SP"));
			m.assertFarReturnPushed(STACK_SEG, STACK_TOP, ENTRY + 4);
			m.step();
			m.assertCounter(CODE_SEG, ENTRY + 4);
			assertEquals(CODE_SEG, m.getReg("CS"));
		});
	}

	@Test
	public void testCallfIndirectSegmentOverride() throws Exception {
		on16BitModes((id, jit) -> {
			Machine16 m = new Machine16(id, jit, "26 ff 1f"); // CALLF ES:[BX]
			m.setReg("BX", 0x0010);
			m.writeWord(EXTRA_SEG, 0x0010, FAR_TARGET);
			m.writeWord(EXTRA_SEG, 0x0012, FAR_SEG);
			m.step();
			m.assertAtFarTarget();
			m.assertFarReturnPushed(STACK_SEG, STACK_TOP, ENTRY + 3);
		});
	}

	@Test
	public void testCallfIndirectBpUsesStackSegment() throws Exception {
		on16BitModes((id, jit) -> {
			Machine16 m = new Machine16(id, jit, "ff 5e 06"); // CALLF [BP + 0x6]
			m.setReg("BP", 0x0020);
			m.writeWord(STACK_SEG, 0x0026, FAR_TARGET);
			m.writeWord(STACK_SEG, 0x0028, FAR_SEG);
			m.step();
			m.assertAtFarTarget();
			m.assertFarReturnPushed(STACK_SEG, STACK_TOP, ENTRY + 3);
		});
	}

	@Test
	public void testCallfIndirect32BitOffset() throws Exception {
		on16BitModes((id, jit) -> {
			// CALLF [0x500] with a 0x66 prefix, through an m16:32 pointer
			Machine16 m = new Machine16(id, jit, "66 ff 1e 00 05");
			m.writeWord(DATA_SEG, 0x0500, FAR_TARGET);
			m.writeWord(DATA_SEG, 0x0502, 0);
			m.writeWord(DATA_SEG, 0x0504, FAR_SEG);
			m.step();
			m.assertAtFarTarget();
		});
	}

	@Test
	public void testJmpfIndirect() throws Exception {
		on16BitModes((id, jit) -> {
			Machine16 m = new Machine16(id, jit, "ff 2e 00 05"); // JMPF [0x500]
			m.writeWord(DATA_SEG, 0x0500, FAR_TARGET);
			m.writeWord(DATA_SEG, 0x0502, FAR_SEG);
			m.step();
			m.assertAtFarTarget();
			assertEquals(STACK_TOP, m.getReg("SP"));
		});
	}

	/*
	 * With a 0x67 prefix, 16-bit code addresses memory and the stack through 32-bit registers,
	 * which ia.sinc does not offset by a segment base. These tests place the data at linear
	 * addresses to match.
	 */

	@Test
	public void testRetfImm16AddrPrefix() throws Exception {
		on16BitModes((id, jit) -> {
			Machine16 m = new Machine16(id, jit, "67 ca 04 00"); // RETF 0x4
			m.setReg("ESP", 0x0600);
			m.writeWord(0, 0x0600, FAR_TARGET);
			m.writeWord(0, 0x0602, FAR_SEG);
			m.step();
			m.assertAtFarTarget();
			assertEquals(0x0600 + 4 + 4, m.getReg("ESP"));
		});
	}

	@Test
	public void testIretAddrPrefix() throws Exception {
		on16BitModes((id, jit) -> {
			Machine16 m = new Machine16(id, jit, "67 cf"); // IRET
			m.setReg("ESP", 0x0600);
			m.writeWord(0, 0x0600, FAR_TARGET);
			m.writeWord(0, 0x0602, FAR_SEG);
			m.writeWord(0, 0x0604, 0x0002);
			m.step();
			m.assertAtFarTarget();
		});
	}

	@Test
	public void testCallfIndirectAddrPrefix() throws Exception {
		on16BitModes((id, jit) -> {
			Machine16 m = new Machine16(id, jit, "67 ff 1f"); // CALLF [EDI]
			m.setReg("EDI", 0x0500);
			m.setReg("ESP", 0x0600);
			m.writeWord(0, 0x0500, FAR_TARGET);
			m.writeWord(0, 0x0502, FAR_SEG);
			m.step();
			m.assertAtFarTarget();
			m.assertFarReturnPushed(0, 0x0600, ENTRY + 3);
		});
	}

	@Test
	public void testJmpfIndirectAddrPrefix() throws Exception {
		on16BitModes((id, jit) -> {
			Machine16 m = new Machine16(id, jit, "67 ff 2f"); // JMPF [EDI]
			m.setReg("EDI", 0x0500);
			m.writeWord(0, 0x0500, FAR_TARGET);
			m.writeWord(0, 0x0502, FAR_SEG);
			m.step();
			m.assertAtFarTarget();
		});
	}

	@Test
	public void testRetImm16With16BitPrefixesIn32BitCode() throws Exception {
		for (boolean jit : JIT_MODES) {
			Machine m = new Machine(LANG_ID_32, jit);
			m.write(0, 0x00400000, "66 67 c2 04 00"); // RET 0x4
			m.setReg("ESP", 0x0600);
			m.writeWord(0, 0x0600, 0x1234);
			m.start(0, 0x00400000);
			m.step();
			m.assertCounter(0, 0x1234);
			assertEquals(0x0600 + 2 + 4, m.getReg("ESP"));
		}
	}
}
