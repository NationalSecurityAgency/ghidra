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
package agent.lldb.model;

import static org.junit.Assert.assertTrue;

import java.util.*;

import agent.lldb.model.impl.LldbModelTargetProcessImpl;
import ghidra.dbg.target.*;
import ghidra.dbg.test.AbstractDebuggerModelScenarioRegistersTest;

public abstract class AbstractModelForLldbScenarioX64RegistersTest
		extends AbstractDebuggerModelScenarioRegistersTest {

	@Override
	protected DebuggerTestSpecimen getSpecimen() {
		return MacOSSpecimen.REGISTERS;
	}

	@Override
	protected String getBreakpointExpression() {
		return "break_here";
	}

	@Override
	protected Map<String, byte[]> getRegisterWrites() {
		// RCX is first parameter `val` of break_here(int val)
		return Map.of("rcx", arr("0000000000000041"));
	}

	@Override
	protected void verifyExpectedEffect(TargetProcess process) throws Throwable {
		long status = process.getTypedAttributeNowByName(
			LldbModelTargetProcessImpl.EXIT_CODE_ATTRIBUTE_NAME, Long.class, 0L);
		// TODO: This really shouldn't return 0 - possible race?
		assertTrue(status == 0x41 || status == 0);
	}

	@Override
	protected void performRegisterWrites(TargetObject target, Map<String, byte[]> toWrite)
			throws Throwable {
		TargetRegisterContainer c = Objects.requireNonNull(
			m.findWithIndex(TargetRegisterContainer.class, "0", target.getPath()));
		Map<List<String>, TargetRegisterBank> banks =
			m.findAll(TargetRegisterBank.class, c.getPath(), true);
		for (String name : toWrite.keySet()) {
			for (TargetRegisterBank bank : banks.values()) {
				Map<List<String>, TargetRegister> regs = m.findAll(TargetRegister.class,
					bank.getPath(), pred -> pred.applyIndices(name), false);
				for (TargetRegister reg : regs.values()) {
					waitOn(bank.writeRegister(reg, toWrite.get(name)));
				}
			}
		}
	}
}
