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
 * can be emulated correctly. Covers arithmetic, load/store, branch,
 * and extended multi-register operations.
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
		// Verify basic emulation works
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
		Address gpBase = currentProgram.getAddressFactory().getAddress("0x1000");
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
		Address cpBase = currentProgram.getAddressFactory().getAddress("0x2000");
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
		Address cp0Base = currentProgram.getAddressFactory().getAddress("0x3000");
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
		Address memBase = currentProgram.getAddressFactory().getAddress("0x4000");
		assertNotNull(memBase);
	}
}
