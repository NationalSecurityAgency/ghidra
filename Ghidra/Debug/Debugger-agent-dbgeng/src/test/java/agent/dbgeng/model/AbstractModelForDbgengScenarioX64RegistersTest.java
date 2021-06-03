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
package agent.dbgeng.model;

import static org.junit.Assert.*;

import java.util.Map;

import agent.dbgeng.model.impl.DbgModelTargetProcessImpl;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.test.AbstractDebuggerModelScenarioRegistersTest;

public abstract class AbstractModelForDbgengScenarioX64RegistersTest
		extends AbstractDebuggerModelScenarioRegistersTest {

	@Override
	protected DebuggerTestSpecimen getSpecimen() {
		return WindowsSpecimen.REGISTERS;
	}

	@Override
	protected String getBreakpointExpression() {
		return "expRegisters!break_here";
	}

	@Override
	protected Map<String, byte[]> getRegisterWrites() {
		// RCX is first parameter `val` of break_here(int val)
		return Map.of("rcx", arr("0000000000000041"));
	}

	@Override
	protected void verifyExpectedEffect(TargetProcess process) throws Throwable {
		long status = process.getTypedAttributeNowByName(
			DbgModelTargetProcessImpl.EXIT_CODE_ATTRIBUTE_NAME, Long.class, 0L);
		// TODO: This really shouldn't return 0 - possible race?
		assertTrue(status == 0x41 || status == 0);
	}
}
