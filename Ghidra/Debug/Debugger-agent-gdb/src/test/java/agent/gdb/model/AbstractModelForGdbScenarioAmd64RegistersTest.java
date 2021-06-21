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
package agent.gdb.model;

import static org.junit.Assert.assertEquals;

import java.util.Map;

import agent.gdb.model.impl.GdbModelTargetInferior;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.test.AbstractDebuggerModelScenarioRegistersTest;

public abstract class AbstractModelForGdbScenarioAmd64RegistersTest
		extends AbstractDebuggerModelScenarioRegistersTest {

	@Override
	protected GdbLinuxSpecimen getSpecimen() {
		return GdbLinuxSpecimen.REGISTERS;
	}

	protected String getBinModuleName() {
		return getSpecimen().getCommandLine();
	}

	@Override
	protected String getBreakpointExpression() {
		return "*break_here"; // Don't decode prologue, GDB!
	}

	@Override
	protected Map<String, byte[]> getRegisterWrites() {
		// RDI is first parameter `val` of break_here(int val)
		return Map.of("rdi", arr("0000000000000041"));
	}

	@Override
	protected void verifyExpectedEffect(TargetProcess process) throws Throwable {
		long status = process.getTypedAttributeNowByName(
			GdbModelTargetInferior.EXIT_CODE_ATTRIBUTE_NAME, Long.class, 0L);
		assertEquals(0x41, status);
	}
}
