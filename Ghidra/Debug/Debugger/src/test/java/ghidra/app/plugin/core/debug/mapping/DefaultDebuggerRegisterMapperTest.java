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
package ghidra.app.plugin.core.debug.mapping;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.Objects;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.dbg.model.TestTargetRegister;
import ghidra.dbg.model.TestTargetRegisterValue;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegister;
import ghidra.debug.api.action.ActionSource;
import ghidra.debug.api.model.DebuggerRegisterMapper;
import ghidra.debug.api.model.TraceRecorder;
import ghidra.program.model.lang.*;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.model.thread.TraceThread;

public class DefaultDebuggerRegisterMapperTest extends AbstractGhidraHeadedDebuggerTest {

	static class TestTargetMapper extends DefaultDebuggerTargetTraceMapper {
		public TestTargetMapper(TargetObject target)
				throws LanguageNotFoundException, CompilerSpecNotFoundException {
			super(target, new LanguageID(ToyProgramBuilder._TOY64_BE),
				new CompilerSpecID("default"), Set.of());
		}
	}

	protected static void assertSameRegister(TargetRegister expected, TargetObject actual) {
		if (actual instanceof TestTargetRegister tr) {
			assertEquals(expected, tr);
		}
		else if (actual instanceof TestTargetRegisterValue rv) {
			assertEquals(expected, rv.desc);
		}
		else {
			fail();
		}
	}

	@Before
	public void setUpMapperTest() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		mb.createTestThreadRegisterBanks();
	}

	protected DebuggerRegisterMapper doGetRegisterMapper(String toConfirm)
			throws Throwable {
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestTargetMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		TraceThread thread1 = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		DebuggerRegisterMapper rm = waitForValue(() -> recorder.getRegisterMapper(thread1));
		waitForValue(() -> rm.getTargetRegister(toConfirm));
		return rm;
	}

	protected DebuggerRegisterMapper getRegisterMapper() throws Throwable {
		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(), r -> true);
		return doGetRegisterMapper("r0");
	}

	protected DebuggerRegisterMapper getRegisterMapperAliased() throws Throwable {
		Register r0 = getToyBE64Language().getRegister("r0");
		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(), r -> r != r0);
		mb.testProcess1.regs.addRegister("a0", r0);
		return doGetRegisterMapper("r1");
	}

	@Test
	public void testTraceToTargetRegCanonical() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapper();
		TestTargetRegister tR0 =
			Objects.requireNonNull(mb.testProcess1.regs.getCachedElements().get("r0"));
		Register lR0 = Objects.requireNonNull(getToyBE64Language().getRegister("r0"));

		TargetRegister tReg = waitForValue(() -> rm.traceToTarget(lR0));
		assertSameRegister(tR0, tReg);
	}

	@Test
	public void testTargetToTraceRegCanonical() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapper();
		TestTargetRegister tR0 =
			Objects.requireNonNull(mb.testProcess1.regs.getCachedElements().get("r0"));
		Register lR0 = Objects.requireNonNull(getToyBE64Language().getRegister("r0"));

		Register lReg = waitForValue(() -> rm.targetToTrace(tR0));
		assertEquals(lR0, lReg);
	}

	@Test
	public void testTraceToTargetRegAlias() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperAliased();
		TestTargetRegister tA0 =
			Objects.requireNonNull(mb.testProcess1.regs.getCachedElements().get("a0"));
		Register lR0 = Objects.requireNonNull(getToyBE64Language().getRegister("r0"));

		TargetRegister tReg = waitForValue(() -> rm.traceToTarget(lR0));
		assertSameRegister(tA0, tReg);
	}

	@Test
	public void testTargetToTraceRegAlias() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperAliased();
		TestTargetRegister tA0 =
			Objects.requireNonNull(mb.testProcess1.regs.getCachedElements().get("a0"));
		Register lR0 = Objects.requireNonNull(getToyBE64Language().getRegister("r0"));

		Register lReg = waitForValue(() -> rm.targetToTrace(tA0));
		assertEquals(lR0, lReg);
	}
}
