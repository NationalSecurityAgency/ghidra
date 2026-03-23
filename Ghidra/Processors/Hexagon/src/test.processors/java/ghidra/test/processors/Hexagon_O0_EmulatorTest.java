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

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.test.processors.support.EmulatorTestRunner;
import ghidra.test.processors.support.ProcessorEmulatorTestAdapter;
import junit.framework.Test;

public class Hexagon_O0_EmulatorTest extends ProcessorEmulatorTestAdapter {

	/**
	 * Known Failures:
	 * - All nalign_i2,4,8 tests are known to fail since the llvm compiler for Hexagon
	 *   produces code which handles reads and writes inconsistently and does not
	 *   attempt to force use of byte read/write for non-aligned accesses.  The processor
	 *   H/W will throw an exception for unaligned accesses.
	 */

	private static final String LANGUAGE_ID = "Hexagon:LE:32:default";
	private static final String COMPILER_SPEC_ID = "default";

	private static final String[] REG_DUMP_SET = new String[] {};

	public Hexagon_O0_EmulatorTest(String name) throws Exception {
		super(name, LANGUAGE_ID, COMPILER_SPEC_ID, REG_DUMP_SET);

		// Ignore known issues with alignment tests
		addIgnoredTests(
			// Alignment tests need to declare the char array with proper alignment
			// since Hexagon will access char array in a char-aligned fashion for
			// the various size.
			"nalign_i2_Main",
			"nalign_i4_Main",
			"nalign_i8_Main");
	}

	@Override
	protected void initializeState(EmulatorTestRunner testRunner, Program program)
			throws Exception {
		super.initializeState(testRunner, program);
		testRunner.setRegister("SP", 0x40000000L);  // stack, unused location		
		Symbol globalDataSym = SymbolUtilities.getLabelOrFunctionSymbol(program, "GLOBAL",
			m -> {
				/* ignore */ });
		assertNotNull("GLOBAL data symbol not found", globalDataSym);
		testRunner.setRegister("GP", globalDataSym.getAddress().getOffset());
	}

	@Override
	protected String getProcessorDesignator() {
		return "Hexagon_CLANG_LLVM_O0";
	}

	public static Test suite() {
		return ProcessorEmulatorTestAdapter
				.buildEmulatorTestSuite(Hexagon_O0_EmulatorTest.class);
	}
}
