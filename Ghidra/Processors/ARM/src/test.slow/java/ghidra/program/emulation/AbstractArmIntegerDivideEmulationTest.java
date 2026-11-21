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

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.InterruptPcodeExecutionException;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.NumericUtilities;

/**
 * Emulation tests for the ARM and Thumb {@code SDIV} and {@code UDIV} instructions.
 *
 * <p>
 * Per the ARM Architecture Reference Manual, a division by zero must write {@code 0} to the
 * destination register (when divide-by-zero trapping is not enabled). P-code does not define
 * division by zero, so the language must handle it before dividing. See GitHub issue #10139.
 */
public abstract class AbstractArmIntegerDivideEmulationTest
		extends AbstractGhidraHeadlessIntegrationTest {
	private static final LanguageID LANG_ID_ARM_V8 = new LanguageID("ARM:LE:32:v8");
	private static final long ENTRY = 0x00400000L;

	// Little-endian encodings, all with Rd=r0, Rn=r1, Rm=r2 unless noted otherwise
	private static final String A32_SDIV = "11 f2 10 e7"; // sdiv r0,r1,r2
	private static final String A32_UDIV = "11 f2 30 e7"; // udiv r0,r1,r2
	private static final String A32_SDIVNE = "11 f2 10 17"; // sdivne r0,r1,r2
	private static final String A32_SDIV_RD_IS_RM = "11 f2 12 e7"; // sdiv r2,r1,r2
	private static final String A32_UDIV_RD_IS_RM = "11 f2 32 e7"; // udiv r2,r1,r2
	private static final String T32_SDIV = "91 fb f2 f0"; // sdiv r0,r1,r2
	private static final String T32_UDIV = "b1 fb f2 f0"; // udiv r0,r1,r2
	private static final String T32_SDIV_RD_IS_RM = "91 fb f2 f2"; // sdiv r2,r1,r2
	private static final String T32_UDIV_RD_IS_RM = "b1 fb f2 f2"; // udiv r2,r1,r2

	private enum Isa {
		A32, T32
	}

	private SleighLanguage language;
	private PcodeArithmetic<byte[]> arithmetic;

	/**
	 * Create the emulator under test
	 *
	 * @param lang the ARM language
	 * @return the emulator
	 */
	protected abstract PcodeEmulator createEmulator(SleighLanguage lang);

	@Before
	public void setUp() throws Exception {
		language = (SleighLanguage) DefaultLanguageService.getLanguageService()
				.getLanguage(LANG_ID_ARM_V8);
	}

	private PcodeThread<byte[]> newThread(PcodeEmulator emulator, Isa isa, String bytes) {
		Address entry = language.getDefaultSpace().getAddress(ENTRY);
		byte[] code = NumericUtilities.convertStringToBytes(bytes.replace(" ", ""));
		emulator.getSharedState().setVar(entry, code.length, false, code);

		PcodeThread<byte[]> thread = emulator.newThread();
		thread.overrideCounter(entry);
		Register tMode = language.getRegister("TMode");
		thread.overrideContext(
			new RegisterValue(tMode, isa == Isa.T32 ? BigInteger.ONE : BigInteger.ZERO));
		return thread;
	}

	/**
	 * Verify the given bytes decode to the expected instruction, guarding against a wrong
	 * encoding silently testing a different instruction
	 */
	private void assertDecodesTo(Isa isa, String bytes, String expectedInstruction) {
		PcodeThread<byte[]> thread = newThread(new PcodeEmulator(language), isa, bytes);
		thread.stepPcodeOp(); // decodes the instruction and sets up its p-code frame
		assertEquals(expectedInstruction, thread.getInstruction().toString());
		thread.dropInstruction();
	}

	/**
	 * Verify the given bytes decode to the expected instruction, then set the given registers and
	 * execute that single instruction on the emulator under test.
	 *
	 * @param isa the instruction set to decode with
	 * @param bytes the little-endian instruction bytes, as hex
	 * @param expectedInstruction the expected disassembly
	 * @param registerValues alternating register names and values
	 * @return the thread, after executing the instruction
	 */
	private PcodeThread<byte[]> execute(Isa isa, String bytes, String expectedInstruction,
			Object... registerValues) {
		assertDecodesTo(isa, bytes, expectedInstruction);

		PcodeEmulator emulator = createEmulator(language);
		arithmetic = emulator.getArithmetic();
		PcodeThread<byte[]> thread = newThread(emulator, isa, bytes);
		for (int i = 0; i < registerValues.length; i += 2) {
			Register register = language.getRegister((String) registerValues[i]);
			long value = ((Number) registerValues[i + 1]).longValue();
			thread.getState()
					.setVar(register, arithmetic.fromConst(value, register.getMinimumByteSize()));
		}

		// Stop before the (all zero) bytes following the single 4-byte instruction
		emulator.addBreakpoint(thread.getCounter().add(4), "1:1");
		try {
			thread.run();
		}
		catch (InterruptPcodeExecutionException e) {
			// expected: hit the breakpoint
		}
		assertEquals(ENTRY + 4, thread.getCounter().getOffset());
		return thread;
	}

	private long register(PcodeThread<byte[]> thread, String name) {
		Register register = language.getRegister(name);
		byte[] value = thread.getState().getVar(register, Reason.INSPECT);
		return arithmetic.toLong(value, Purpose.INSPECT) & 0xffffffffL;
	}

	/*
	 * S1: Given a zero divisor, when SDIV/UDIV executes, then Rd is 0 and emulation does not fault
	 */

	@Test
	public void testGivenZeroDivisor_WhenSdivA32_ThenResultIsZero() {
		// given / when
		PcodeThread<byte[]> thread = execute(Isa.A32, A32_SDIV, "sdiv r0,r1,r2", "r1", 42, "r2", 0);
		// then
		assertEquals(0, register(thread, "r0"));
	}

	@Test
	public void testGivenZeroDivisor_WhenUdivA32_ThenResultIsZero() {
		PcodeThread<byte[]> thread = execute(Isa.A32, A32_UDIV, "udiv r0,r1,r2", "r1", 42, "r2", 0);
		assertEquals(0, register(thread, "r0"));
	}

	@Test
	public void testGivenZeroDivisor_WhenSdivT32_ThenResultIsZero() {
		PcodeThread<byte[]> thread = execute(Isa.T32, T32_SDIV, "sdiv r0,r1,r2", "r1", 42, "r2", 0);
		assertEquals(0, register(thread, "r0"));
	}

	@Test
	public void testGivenZeroDivisor_WhenUdivT32_ThenResultIsZero() {
		PcodeThread<byte[]> thread = execute(Isa.T32, T32_UDIV, "udiv r0,r1,r2", "r1", 42, "r2", 0);
		assertEquals(0, register(thread, "r0"));
	}

	/*
	 * S2: Given a stale Rd and a zero divisor, then Rd is overwritten with 0
	 */

	@Test
	public void testGivenStaleDestinationAndZeroDivisor_WhenSdivA32_ThenDestinationIsZero() {
		PcodeThread<byte[]> thread = execute(Isa.A32, A32_SDIV, "sdiv r0,r1,r2",
			"r0", 0xdeadbeefL, "r1", 42, "r2", 0);
		assertEquals(0, register(thread, "r0"));
	}

	@Test
	public void testGivenStaleDestinationAndZeroDivisor_WhenUdivT32_ThenDestinationIsZero() {
		PcodeThread<byte[]> thread = execute(Isa.T32, T32_UDIV, "udiv r0,r1,r2",
			"r0", 0xdeadbeefL, "r1", 42, "r2", 0);
		assertEquals(0, register(thread, "r0"));
	}

	/*
	 * S3: Given a non-zero divisor, then the quotient is computed (regression)
	 */

	@Test
	public void testGivenNonZeroDivisor_WhenSdivA32_ThenQuotient() {
		PcodeThread<byte[]> thread = execute(Isa.A32, A32_SDIV, "sdiv r0,r1,r2", "r1", 42, "r2", 5);
		assertEquals(8, register(thread, "r0"));
	}

	@Test
	public void testGivenNonZeroDivisor_WhenUdivA32_ThenQuotient() {
		PcodeThread<byte[]> thread = execute(Isa.A32, A32_UDIV, "udiv r0,r1,r2", "r1", 42, "r2", 5);
		assertEquals(8, register(thread, "r0"));
	}

	@Test
	public void testGivenNonZeroDivisor_WhenSdivT32_ThenQuotient() {
		PcodeThread<byte[]> thread = execute(Isa.T32, T32_SDIV, "sdiv r0,r1,r2", "r1", 42, "r2", 5);
		assertEquals(8, register(thread, "r0"));
	}

	@Test
	public void testGivenNonZeroDivisor_WhenUdivT32_ThenQuotient() {
		PcodeThread<byte[]> thread = execute(Isa.T32, T32_UDIV, "udiv r0,r1,r2", "r1", 42, "r2", 5);
		assertEquals(8, register(thread, "r0"));
	}

	/*
	 * S4: SDIV rounds toward zero
	 */

	@Test
	public void testGivenNegativeDividend_WhenSdivA32_ThenRoundsTowardZero() {
		PcodeThread<byte[]> thread = execute(Isa.A32, A32_SDIV, "sdiv r0,r1,r2", "r1", -7, "r2", 2);
		assertEquals(-3 & 0xffffffffL, register(thread, "r0"));
	}

	@Test
	public void testGivenNegativeDivisor_WhenSdivT32_ThenRoundsTowardZero() {
		PcodeThread<byte[]> thread = execute(Isa.T32, T32_SDIV, "sdiv r0,r1,r2", "r1", 7, "r2", -2);
		assertEquals(-3 & 0xffffffffL, register(thread, "r0"));
	}

	/*
	 * S5: SDIV of INT_MIN by -1 wraps to INT_MIN (result<31:0>) instead of faulting
	 */

	@Test
	public void testGivenIntMinByMinusOne_WhenSdivA32_ThenWrapsToIntMin() {
		PcodeThread<byte[]> thread = execute(Isa.A32, A32_SDIV, "sdiv r0,r1,r2",
			"r1", 0x80000000L, "r2", 0xffffffffL);
		assertEquals(0x80000000L, register(thread, "r0"));
	}

	@Test
	public void testGivenIntMinByMinusOne_WhenSdivT32_ThenWrapsToIntMin() {
		PcodeThread<byte[]> thread = execute(Isa.T32, T32_SDIV, "sdiv r0,r1,r2",
			"r1", 0x80000000L, "r2", 0xffffffffL);
		assertEquals(0x80000000L, register(thread, "r0"));
	}

	/*
	 * S6: UDIV treats operands as unsigned
	 */

	@Test
	public void testGivenLargeUnsignedDividend_WhenUdivA32_ThenUnsignedQuotient() {
		PcodeThread<byte[]> thread = execute(Isa.A32, A32_UDIV, "udiv r0,r1,r2",
			"r1", 0xffffffffL, "r2", 2);
		assertEquals(0x7fffffffL, register(thread, "r0"));
	}

	@Test
	public void testGivenLargeUnsignedDivisor_WhenUdivT32_ThenUnsignedQuotient() {
		PcodeThread<byte[]> thread = execute(Isa.T32, T32_UDIV, "udiv r0,r1,r2",
			"r1", 0xfffffffeL, "r2", 0xffffffffL);
		assertEquals(0, register(thread, "r0"));
	}

	/*
	 * S7: Given Rd aliases the divisor register, then Rd receives the result
	 */

	@Test
	public void testGivenDestinationIsZeroDivisor_WhenSdivA32_ThenResultIsZero() {
		PcodeThread<byte[]> thread =
			execute(Isa.A32, A32_SDIV_RD_IS_RM, "sdiv r2,r1,r2", "r1", 42, "r2", 0);
		assertEquals(0, register(thread, "r2"));
	}

	@Test
	public void testGivenDestinationIsZeroDivisor_WhenUdivA32_ThenResultIsZero() {
		PcodeThread<byte[]> thread =
			execute(Isa.A32, A32_UDIV_RD_IS_RM, "udiv r2,r1,r2", "r1", 42, "r2", 0);
		assertEquals(0, register(thread, "r2"));
	}

	@Test
	public void testGivenDestinationIsZeroDivisor_WhenSdivT32_ThenResultIsZero() {
		PcodeThread<byte[]> thread =
			execute(Isa.T32, T32_SDIV_RD_IS_RM, "sdiv r2,r1,r2", "r1", 42, "r2", 0);
		assertEquals(0, register(thread, "r2"));
	}

	@Test
	public void testGivenDestinationIsNonZeroDivisor_WhenUdivT32_ThenQuotient() {
		PcodeThread<byte[]> thread =
			execute(Isa.T32, T32_UDIV_RD_IS_RM, "udiv r2,r1,r2", "r1", 42, "r2", 5);
		assertEquals(8, register(thread, "r2"));
	}

	/*
	 * S8: Given a false condition, then the destination is left unchanged
	 */

	@Test
	public void testGivenConditionFalseAndZeroDivisor_WhenSdivneA32_ThenDestinationUnchanged() {
		// given Z set, so NE is false
		PcodeThread<byte[]> thread = execute(Isa.A32, A32_SDIVNE, "sdivne r0,r1,r2",
			"ZR", 1, "r0", 0x1234, "r1", 42, "r2", 0);
		assertEquals(0x1234, register(thread, "r0"));
	}

	@Test
	public void testGivenConditionTrueAndZeroDivisor_WhenSdivneA32_ThenResultIsZero() {
		// given Z clear, so NE is true
		PcodeThread<byte[]> thread = execute(Isa.A32, A32_SDIVNE, "sdivne r0,r1,r2",
			"ZR", 0, "r0", 0x1234, "r1", 42, "r2", 0);
		assertEquals(0, register(thread, "r0"));
	}

	@Test
	public void testGivenConditionFalse_WhenSdivneA32_ThenDestinationUnchanged() {
		PcodeThread<byte[]> thread = execute(Isa.A32, A32_SDIVNE, "sdivne r0,r1,r2",
			"ZR", 1, "r0", 0x1234, "r1", 42, "r2", 5);
		assertEquals(0x1234, register(thread, "r0"));
	}
}
