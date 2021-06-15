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

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.test.processors.support.EmulatorTestRunner;
import ghidra.test.processors.support.ProcessorEmulatorTestAdapter;
import junit.framework.Test;

public class AVR8_51_GCC_O3_EmulatorTest extends ProcessorEmulatorTestAdapter {

	private static final String LANGUAGE_ID = "avr8:LE:16:extended";
	private static final String COMPILER_SPEC_ID = "gcc";

	private static final String[] REG_DUMP_SET = new String[] {};

	public AVR8_51_GCC_O3_EmulatorTest(String name) throws Exception {
		super(name, LANGUAGE_ID, COMPILER_SPEC_ID, REG_DUMP_SET);
	}

	@Override
	protected String getProcessorDesignator() {
		return "AVR8_51_GCC_O3";
	}

	@Override
	protected void initializeState(EmulatorTestRunner testRunner, Program program)
			throws Exception {
		// These eliminate "uninitialized register" errors. Not strictly needed, but helps find actual problems.
		testRunner.setRegister("SP", 0x0);
		testRunner.setRegister("R1", 0x0);
		testRunner.setRegister("Y", 0x0);
		testRunner.setRegister("W", 0x0);
	}

	@Override
	protected void setAnalysisOptions(Options analysisOptions) {
		super.setAnalysisOptions(analysisOptions);
		analysisOptions.setBoolean("Reference", false); // too many bad disassemblies
		analysisOptions.setBoolean("Data Reference", false);
	}

	public static Test suite() {
		return ProcessorEmulatorTestAdapter.buildEmulatorTestSuite(
			AVR8_51_GCC_O3_EmulatorTest.class);
	}
}
