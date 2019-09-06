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

public class TRICORE_BE_O0_EmulatorTest extends ProcessorEmulatorTestAdapter {
	private static final String LANGUAGE_ID = "tricore:LE:32:default";
	private static final String COMPILER_SPEC_ID = "default";
	private static final String[] REG_DUMP_SET = new String[] {};

	public TRICORE_BE_O0_EmulatorTest(String name) throws Exception {
		super(name, LANGUAGE_ID, COMPILER_SPEC_ID, REG_DUMP_SET);
	}

	protected String getProcessorDesignator() { return "tricore_GCC_O0"; }

	protected void initializeState(EmulatorTestRunner testRunner, Program program) throws Exception {
		testRunner.setRegister("a10", 0x40000000L);  // stack, unused location		
		testRunner.setRegister("FCX", 0x00020000L);  // free context list start, unused location
		testRunner.setRegister("LCX", 0x00030000L);  // free context list max		
		testRunner.setRegister("PCXI", 0x0L);        // current thread context list
	}
	
	public static Test suite() {
		return ProcessorEmulatorTestAdapter.buildEmulatorTestSuite(TRICORE_BE_O0_EmulatorTest.class);
	}
	
	protected void setAnalysisOptions(Options analysisOptions) {
		super.setAnalysisOptions(analysisOptions);
		analysisOptions.setBoolean("Reference", false); // too many bad disassemblies
	}
}
