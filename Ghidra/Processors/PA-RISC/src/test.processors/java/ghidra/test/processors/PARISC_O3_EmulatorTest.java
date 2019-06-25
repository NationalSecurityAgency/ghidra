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

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.processors.support.ProcessorEmulatorTestAdapter;
import junit.framework.Test;

public class PARISC_O3_EmulatorTest extends ProcessorEmulatorTestAdapter {

	private static final String LANGUAGE_ID = "pa-risc:BE:32:default";
	private static final String COMPILER_SPEC_ID = "default";

	private static final String[] REG_DUMP_SET = new String[] {};

	public PARISC_O3_EmulatorTest(String name) throws Exception {
		super(name, LANGUAGE_ID, COMPILER_SPEC_ID, REG_DUMP_SET);
	}

	@Override
	protected String getProcessorDesignator() {
		return "HPPA1.1_GCC_O3";
	}

	@Override
	protected void preAnalyze(Program program) throws Exception {
		MemoryBlock block = program.getMemory().getBlock(".data");
		if (block != null) {
			Register dpReg = program.getRegister("dp");
			RegisterValue value =
				new RegisterValue(dpReg, block.getStart().getOffsetAsBigInteger());
			AddressSetView loadedMemory = program.getMemory().getLoadedAndInitializedAddressSet();
			program.getProgramContext().setRegisterValue(loadedMemory.getMinAddress(),
				loadedMemory.getMaxAddress(), value);
		}
		super.preAnalyze(program);
	}

	public static Test suite() {
		return ProcessorEmulatorTestAdapter.buildEmulatorTestSuite(PARISC_O3_EmulatorTest.class);
	}

	@Override
	public boolean failOnDisassemblyErrors() {
		return false;
	}
}
