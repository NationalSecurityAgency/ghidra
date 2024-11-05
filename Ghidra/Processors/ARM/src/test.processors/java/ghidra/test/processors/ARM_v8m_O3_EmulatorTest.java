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

public class ARM_v8m_O3_EmulatorTest extends ProcessorEmulatorTestAdapter {

	private static final String LANGUAGE_ID = "ARM:LE:32:v8-m";
	private static final String COMPILER_SPEC_ID = "default";

	private static final String[] REG_DUMP_SET = new String[] {};

	public ARM_v8m_O3_EmulatorTest(String name) throws Exception {
		super(name, LANGUAGE_ID, COMPILER_SPEC_ID, REG_DUMP_SET);
	}

	@Override
	protected String getProcessorDesignator() {
		return "ARM_v8m_GCC_O3";
	}

	public static Test suite() {
		return ProcessorEmulatorTestAdapter.buildEmulatorTestSuite(ARM_v8m_O3_EmulatorTest.class);
	}
}
