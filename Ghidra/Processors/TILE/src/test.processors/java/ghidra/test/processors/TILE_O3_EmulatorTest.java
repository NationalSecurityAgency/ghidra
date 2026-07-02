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

import ghidra.test.processors.support.ProcessorEmulatorTestAdapter;
import junit.framework.Test;

/**
 * TILE O3 level emulator test (high optimization). Verifies that TILE instructions
 * can be emulated correctly with GCC -O3 optimized binaries. This includes testing:
 * <ul>
 *   <li>Multiply operations (mul3, mulif, mulim, mulf, mull, mulli)</li>
 *   <li>Floating-point divide (divfp) and conversions (cvtif, cvtfi)</li>
 *   <li>Multi-register read/write (mr6, mt6, mr12, mt12)</li>
 *   <li>System register access (mfsr32, mtsr32, mfcr32, mtcr32)</li>
 *   <li>Control operations (rfe, wfi, halt, yield, barrier, flush)</li>
 * </ul>
 */
public class TILE_O3_EmulatorTest extends ProcessorEmulatorTestAdapter {

	private static final String LANGUAGE_ID = "TILE:BE:64:default";
	private static final String COMPILER_SPEC_ID = "gcc";

	// Register dump set for trace output (empty = all registers)
	private static final String[] REG_DUMP_SET = new String[] {};

	public TILE_O3_EmulatorTest(String name) throws Exception {
		super(name, LANGUAGE_ID, COMPILER_SPEC_ID, REG_DUMP_SET);
	}

	@Override
	protected String getProcessorDesignator() {
		return "TILE_GCC_O3";
	}

	public static Test suite() {
		return ProcessorEmulatorTestAdapter.buildEmulatorTestSuite(TILE_O3_EmulatorTest.class);
	}
}
