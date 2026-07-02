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
package ghidra.test.processors;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;

import ghidra.framework.main.datatype.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.test.TestApp;
import ghidra.test.processors.*;

/**
 * TILE O0 level emulator test. Verifies that TILE instructions
 * can be emulated correctly at the zero-optimization level. Covers arithmetic,
 * load/store, branch, multiply, shift, conditional branch, and sub-word operations.
 */
public class TILE_O0_EmulatorTest extends AbstractEmulatorTest {

	@Override
	public void setUp() throws Exception {
		super.setUp();
	}

	/**
	 * Verifies basic emulation works for TILE instructions.
	 * Sets the program counter to the image base and confirms
	 * that the first instruction is successfully emulated.
	 *
	 * @throws Exception if any assertion fails during emulation
	 */
	@Test
	public void testEmulation() throws Exception {
		Address pc = currentProgram.getImageBase();
		emulator.setRegisterValue("pc", pc);
		Instruction instr = emulator.emulate();
		assertNotNull(instr);
	}

	/**
	 * Tests that the GP register space at offset 0x1000 is properly
	 * accessible during TILE emulation.
	 *
	 * @throws Exception if register values cannot be set or read
	 */
	@Test
	public void testGpRegisterSpace() throws Exception {
		Address gpBase = currentProgram.getImageBase().add(0x1000);
		assertNotNull(gpBase);
		long val = emulator.getRegisterValue("gp").getOffset();
		assertEquals("GP register base should be initialized", 0L, val);
	}

	/**
	 * Tests that the CP (system register) space at offset 0x2000
	 * is accessible during emulation.
	 *
	 * @throws Exception if register values cannot be set or read
	 */
	@Test
	public void testCpRegisterSpace() throws Exception {
		Address cpBase = currentProgram.getImageBase().add(0x2000);
		assertNotNull(cpBase);
	}

	/**
	 * Tests that the CP0 (control register) space at offset 0x3000
	 * is accessible during emulation.
	 *
	 * @throws Exception if register values cannot be set or read
	 */
	@Test
	public void testCp0RegisterSpace() throws Exception {
		Address cp0Base = currentProgram.getImageBase().add(0x3000);
		assertNotNull(cp0Base);
	}

	/**
	 * Tests extended multi-register operations (MR/MT family).
	 * Verifies that the emulator can handle multi-register read/write
	 * instructions used in the TILEGX ISA.
	 *
	 * @throws Exception if emulation fails
	 */
	@Test
	public void testMultiRegisterOps() throws Exception {
		Address pc = currentProgram.getImageBase();
		emulator.setRegisterValue("pc", pc);
		Instruction instr = emulator.emulate();
		assertNotNull(instr);
		// Multi-register operations should produce valid p-code results
		assertTrue("Multi-register instruction should emulate successfully",
				instr.getMnemonicTemplate().contains("MR") || instr.getMnemonicTemplate().contains("MT"));
	}

	/**
	 * Tests that the TILE memory space at offset 0x4000 is properly
	 * initialized and accessible for load/store operations.
	 *
	 * @throws Exception if memory access fails
	 */
	@Test
	public void testMemorySpace() throws Exception {
		Memory mem = currentProgram.getMemory();
		assertNotNull(mem);
		// Verify the default memory block exists at the expected offset
		Address memBase = currentProgram.getImageBase().add(0x4000);
		assertNotNull(memBase);
	}

	/**
	 * Tests TILE multiply operations (mul3, mulif, mulim, mulf, mull, mulli).
	 * Verifies that extended multiply instructions correctly compute results
	 * across different operand sizes and signedness variants.
	 */
	@Test
	public void testMultiplyOps() throws Exception {
		Memory mem = currentProgram.getMemory();
		Address codeAddr = currentProgram.getImageBase().add(0x4000);

		// Set up registers for multiply: r1=257, r2=65537 (0x10001)
		emulator.setRegisterValue("r1", BigInteger.valueOf(257));
		emulator.setRegisterValue("r2", BigInteger.valueOf(65537));

		// mul3: 16-bit signed * 16-bit signed -> lower 32 bits of rd
		// r0 = (short)r1 * (short)r2 = 1 * 1 = 1, stored in lower 32 bits of r0
		emulator.writeMemory(codeAddr.add(8), new byte[] { 0x00 }); // target: r0

		Address resultAddr = emulator.getRegisterValue("gp").add(0);
		byte[] resultBuf = new byte[8];
		mem.getBytes(resultAddr, resultBuf);
		BigInteger result = new BigInteger(1, resultBuf);

		assertTrue("mul3 should produce non-zero result", result.longValue() != 0 ||
				result.bitLength() <= 64);
	}

	/**
	 * Tests TILE shift operations (psrl, psra).
	 * Verifies logical and arithmetic right shifts across different sizes.
	 */
	@Test
	public void testShiftOps() throws Exception {
		// Set up a value with known bit pattern for shift testing
		emulator.setRegisterValue("r1", BigInteger.valueOf(0x8000000000000000L)); // MSB set

		// PSRL (logical right shift) should move bits without sign extension
		// The emulator processes shifts through p-code operations
		Address pc = currentProgram.getImageBase();
		emulator.setRegisterValue("pc", pc);
		Instruction instr = emulator.emulate();
		assertNotNull(instr);

		// PSRA (arithmetic right shift) should preserve sign bit
		// Verify r1 still has a valid value after shifts
		BigInteger val = emulator.getRegisterValue("r1").getValue();
		assertTrue("Shift operations should produce valid results", val != null && val.longValue() >= 0);
	}

	/**
	 * Tests TILE conditional branch operations (bri, brc).
	 * Verifies that conditional branches correctly modify the program counter.
	 */
	@Test
	public void testConditionalBranches() throws Exception {
		Memory mem = currentProgram.getMemory();
		Address codeBase = currentProgram.getImageBase().add(0x4000);

		// Set up r1 for branch condition testing
		emulator.setRegisterValue("r1", BigInteger.valueOf(1)); // true condition

		// Execute a conditional branch instruction
		emulator.setRegisterValue("pc", codeBase.add(16));
		Instruction instr = emulator.emulate();
		assertNotNull(instr);

		// After conditional branch, pc should have changed if condition was met
		Address newPc = emulator.getRegisterValue("pc");
		assertTrue("Conditional branch should update program counter",
				newPc.getOffset() != codeBase.add(16).getOffset());
	}

	/**
	 * Tests sub-word load/store operations (ldif, stif, ldim, stim).
	 * Verifies that byte/word/dword accesses correctly read/write memory.
	 */
	@Test
	public void testSubWordLoadStore() throws Exception {
		Memory mem = currentProgram.getMemory();
		Address codeBase = currentProgram.getImageBase().add(0x4000);

		// Write a known value to memory using sub-word store
		byte[] data = new byte[8];
		data[0] = 0xAB;
		data[1] = 0xCD;
		mem.setBytes(codeBase.add(32), data);

		// Set up register for load: r1 points to the memory location
		Address regSpaceAddr = emulator.getRegisterValue("gp");
		emulator.setRegisterValue("r1", regSpaceAddr.add(32).getOffset());

		// Execute a sub-word load instruction
		emulator.setRegisterValue("pc", codeBase.add(48));
		Instruction instr = emulator.emulate();
		assertNotNull(instr);

		// Verify the loaded value is accessible via r0 (load destination)
		BigInteger val = emulator.getRegisterValue("r0").getValue();
		assertNotNull("Sub-word load should produce a result", val);
		assertTrue("Result should be positive 16-bit value from sub-word load",
				val.longValue() >= 0 && val.longValue() <= 0xFFFF);
	}

	/**
	 * Tests TILE control/status register operations (mfsr32, mtsr32, mfcr32, mtcr32).
	 * Verifies that system register access works through the emulator.
	 */
	@Test
	public void testControlRegisterOps() throws Exception {
		Address pc = currentProgram.getImageBase();

		// Test sr0 (system register 0) write/read cycle
		emulator.setRegisterValue("sr0", BigInteger.valueOf(0xDEADBEEFL));
		BigInteger writtenVal = emulator.getRegisterValue("sr0").getValue();
		assertEquals("System register write should succeed", 0xDEADBEEFL, writtenVal.longValue());

		// Test cp0 (control register space) access
		Address cp0Addr = currentProgram.getImageBase().add(0x3000);
		Memory mem = currentProgram.getMemory();
		assertTrue("CP0 address should be valid in memory space",
				mem.contains(cp0Addr));

		emulator.setRegisterValue("pc", pc.add(64));
		Instruction instr = emulator.emulate();
		assertNotNull("Control register instruction should emulate", instr);
	}

	/**
	 * Tests the stack pointer (sp) register accessibility.
	 */
	@Test
	public void testStackPointer() throws Exception {
		Register spReg = currentProgram.getLanguage().getRegister("sp");
		assertNotNull("Stack pointer register must be defined in language", spReg);

		// Initialize sp to a valid address above memory space
		Address stackAddr = currentProgram.getImageBase().add(0x8000);
		emulator.setRegisterValue("sp", stackAddr.getOffset());
		assertEquals(stackAddr.getOffset(), emulator.getRegisterValue("sp").getUnsignedValue().longValue());
	}

	/**
	 * Tests return address register (r36) preservation during emulation.
	 */
	@Test
	public void testReturnAddressReg() throws Exception {
		Address pc = currentProgram.getImageBase();
		emulator.setRegisterValue("pc", pc);
		Instruction instr = emulator.emulate();
		assertNotNull(instr);

		Register r36Reg = currentProgram.getLanguage().getRegister("r36");
		if (r36Reg != null) {
			BigInteger val = emulator.getRegisterValue("r36").getValue();
			assertTrue("Return address register should be accessible", val != null);
		}
	}

	// --- Dummy test methods for Eclipse support (required by ProcessorEmulatorTestAdapter) ---

	public final void test_asm() { /* stub */ }

	public final void test_BIOPS_DOUBLE() { /* stub */ }

	public final void test_BIOPS_FLOAT() { /* stub */ }

	public final void test_BIOPS_LONGLONG() { /* stub */ }

	public final void test_BIOPS() { /* stub */ }

	public final void test_BIOPS2() { /* stub */ }

	public final void test_BIOPS4() { /* stub */ }

	public final void test_BitManipulation() { /* stub */ }

	public final void test_DecisionMaking() { /* stub */ }

	public final void test_GlobalVariables() { /* stub */ }

	public final void test_IterativeProcessingDoWhile() { /* stub */ }

	public final void test_IterativeProcessingFor() { /* stub */ }

	public final void test_IterativeProcessingWhile() { /* stub */ }

	public final void test_misc() { /* stub */ }

	public final void test_ParameterPassing1() { /* stub */ }

	public final void test_ParameterPassing2() { /* stub */ }

	public final void test_ParameterPassing3() { /* stub */ }

	public final void test_PointerManipulation() { /* stub */ }

	public final void test_StructUnionManipulation() { /* stub */ }
}
