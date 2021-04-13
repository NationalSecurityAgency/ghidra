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

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.model.TestTargetRegister;
import ghidra.dbg.target.*;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.program.model.lang.*;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.model.thread.TraceThread;

public class LargestSubDebuggerRegisterMapperTest extends AbstractGhidraHeadedDebuggerGUITest {

	static class TestTargetMapper extends AbstractDebuggerTargetTraceMapper {
		public TestTargetMapper(TargetObject target)
				throws LanguageNotFoundException, CompilerSpecNotFoundException {
			super(target, new LanguageID(ToyProgramBuilder._X64), new CompilerSpecID("gcc"),
				Set.of());
		}

		@Override
		protected DebuggerRegisterMapper createRegisterMapper(
				TargetRegisterContainer registers) {
			return new LargestSubDebuggerRegisterMapper(cSpec, registers, false);
		}

		@Override
		protected DebuggerMemoryMapper createMemoryMapper(TargetMemory memory) {
			return new DefaultDebuggerMemoryMapper(language, memory.getModel());
		}
	}

	@Before
	public void setUpMapperTest() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		mb.createTestThreadRegisterBanks();
	}

	protected DebuggerRegisterMapper getRegisterMapperBase() throws Throwable {
		mb.testProcess1.regs.addRegistersFromLanguage(getSLEIGH_X86_64_LANGUAGE(), r -> true);

		TraceRecorder recorder =
			modelService.recordTarget(mb.testProcess1, new TestTargetMapper(mb.testProcess1));
		TraceThread thread1 = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		DebuggerRegisterMapper rm = waitForValue(() -> recorder.getRegisterMapper(thread1));
		waitForValue(() -> rm.getTargetRegister("rax"));
		return rm;
	}

	// This simulates mapping 32-bit x86 into 64-bit x86, as required for WoW64
	protected DebuggerRegisterMapper getRegisterMapperSub() throws Throwable {
		mb.testProcess1.regs.addRegistersFromLanguage(getSLEIGH_X86_LANGUAGE(), r -> true);

		TraceRecorder recorder =
			modelService.recordTarget(mb.testProcess1, new TestTargetMapper(mb.testProcess1));
		TraceThread thread1 = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		DebuggerRegisterMapper rm = waitForValue(() -> recorder.getRegisterMapper(thread1));
		waitForValue(() -> rm.getTargetRegister("eax"));
		return rm;
	}

	protected static byte[] genBytes8() {
		return new byte[] {
			(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
			(byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef };
	}

	@Test
	public void testGetTargetRegisterNameBase() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperBase();
		TestTargetRegister tRAX =
			Objects.requireNonNull(mb.testProcess1.regs.getCachedElements().get("RAX"));
		TestTargetRegister tEAX =
			Objects.requireNonNull(mb.testProcess1.regs.getCachedElements().get("EAX"));

		assertEquals(tRAX, waitForValue(() -> rm.getTargetRegister("rax")));
		assertEquals(tEAX, waitForValue(() -> rm.getTargetRegister("eax"))); // Seems reasonable
	}

	@Test
	public void testGetTraceRegisterNameBase() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperBase();
		Register lRAX = Objects.requireNonNull(getSLEIGH_X86_64_LANGUAGE().getRegister("RAX"));

		assertEquals(lRAX, waitForValue(() -> rm.getTraceRegister("rax")));
		assertNull(rm.getTraceRegister("eax"));
	}

	@Test
	public void testTraceToTargetValueBase() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperBase();
		Register lRAX = Objects.requireNonNull(getSLEIGH_X86_64_LANGUAGE().getRegister("RAX"));
		RegisterValue rv = new RegisterValue(lRAX, new BigInteger("0123456789abcdef", 16));

		Map.Entry<String, byte[]> ent = rm.traceToTarget(rv);
		assertEquals("RAX", ent.getKey());
		assertArrayEquals(genBytes8(), ent.getValue());
	}

	@Test
	public void testTraceToTargetRegBase() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperBase();
		TestTargetRegister tRAX =
			Objects.requireNonNull(mb.testProcess1.regs.getCachedElements().get("RAX"));
		Register lRAX = Objects.requireNonNull(getSLEIGH_X86_64_LANGUAGE().getRegister("RAX"));

		TargetRegister tReg = waitForValue(() -> rm.traceToTarget(lRAX));
		assertEquals(tRAX, tReg);
	}

	@Test
	public void testTargetToTraceNameValueBase() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperBase();
		Register lRAX = Objects.requireNonNull(getSLEIGH_X86_64_LANGUAGE().getRegister("RAX"));

		RegisterValue rv = waitForValue(() -> rm.targetToTrace("rax", genBytes8()));
		assertEquals(new RegisterValue(lRAX, new BigInteger("0123456789abcdef", 16)), rv);
	}

	@Test
	public void testTargetToTraceRegValueBase() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperBase();
		Register lRAX = Objects.requireNonNull(getSLEIGH_X86_64_LANGUAGE().getRegister("RAX"));
		TestTargetRegister tRAX =
			Objects.requireNonNull(mb.testProcess1.regs.getCachedElements().get("RAX"));

		RegisterValue rv = waitForValue(() -> rm.targetToTrace(tRAX, genBytes8()));
		assertEquals(new RegisterValue(lRAX, new BigInteger("0123456789abcdef", 16)), rv);
	}

	@Test
	public void testTargetToTraceRegBase() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperBase();
		Register lRAX = getSLEIGH_X86_64_LANGUAGE().getRegister("RAX");
		TestTargetRegister tRAX =
			Objects.requireNonNull(mb.testProcess1.regs.getCachedElements().get("RAX"));

		Register lReg = waitForValue(() -> rm.targetToTrace(tRAX));
		assertEquals(lRAX, lReg);
	}

	protected static byte[] genBytes4() {
		return new byte[] {
			(byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef };
	}

	@Test
	public void testGetTargetRegisterNameSub() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperSub();
		TestTargetRegister tEAX =
			Objects.requireNonNull(mb.testProcess1.regs.getCachedElements().get("EAX"));

		assertEquals(tEAX, waitForValue(() -> rm.getTargetRegister("eax")));
		assertNull(rm.getTargetRegister("rax"));
	}

	@Test
	public void testGetTraceRegisterNameSub() throws Throwable {
		/**
		 * Seems counter-intuitive, but trace side should be base registers only, and the trace is
		 * still 64-bit.
		 */
		DebuggerRegisterMapper rm = getRegisterMapperSub();
		Register lRAX = Objects.requireNonNull(getSLEIGH_X86_64_LANGUAGE().getRegister("RAX"));

		assertEquals(lRAX, waitForValue(() -> rm.getTraceRegister("rax")));
		assertNull(rm.getTraceRegister("eax"));
	}

	@Test
	public void testTraceToTargetValueSub() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperSub();
		Register lRAX = Objects.requireNonNull(getSLEIGH_X86_64_LANGUAGE().getRegister("RAX"));
		RegisterValue rv = new RegisterValue(lRAX, new BigInteger("0123456789abcdef", 16));

		Map.Entry<String, byte[]> ent = waitForValue(() -> rm.traceToTarget(rv));
		assertEquals("EAX", ent.getKey());
		assertArrayEquals(genBytes4(), ent.getValue());
	}

	@Test
	public void testTraceToTargetRegSub() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperSub();
		TestTargetRegister tEAX =
			Objects.requireNonNull(mb.testProcess1.regs.getCachedElements().get("EAX"));
		Register lRAX = Objects.requireNonNull(getSLEIGH_X86_64_LANGUAGE().getRegister("RAX"));

		TargetRegister tReg = waitForValue(() -> rm.traceToTarget(lRAX));
		assertEquals(tEAX, tReg);
	}

	@Test
	public void testTargetToTraceNameValueSub() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperSub();
		Register lRAX = Objects.requireNonNull(getSLEIGH_X86_64_LANGUAGE().getRegister("RAX"));

		RegisterValue rv = waitForValue(() -> rm.targetToTrace("eax", genBytes4()));
		assertEquals(new RegisterValue(lRAX, new BigInteger("0000000089abcdef", 16)), rv);
	}

	@Test
	public void testTargetToTraceRegValueSub() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperSub();
		Register lRAX = Objects.requireNonNull(getSLEIGH_X86_64_LANGUAGE().getRegister("RAX"));
		TestTargetRegister tEAX =
			Objects.requireNonNull(mb.testProcess1.regs.getCachedElements().get("EAX"));

		RegisterValue rv = waitForValue(() -> rm.targetToTrace(tEAX, genBytes4()));
		assertEquals(new RegisterValue(lRAX, new BigInteger("0000000089abcdef", 16)), rv);
	}

	@Test
	public void testTargetToTraceRegSub() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperSub();
		Register lRAX = getSLEIGH_X86_64_LANGUAGE().getRegister("RAX");
		TestTargetRegister tEAX =
			Objects.requireNonNull(mb.testProcess1.regs.getCachedElements().get("EAX"));

		Register lReg = waitForValue(() -> rm.targetToTrace(tEAX));
		assertEquals(lRAX, lReg);
	}

	@Test
	public void testTargetToTraceAmidChanges() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperBase();
		Register lRAX = Objects.requireNonNull(getSLEIGH_X86_64_LANGUAGE().getRegister("RAX"));
		RegisterValue rv;

		rv = waitForValue(() -> rm.targetToTrace("rax", genBytes8()));
		assertEquals(new RegisterValue(lRAX, new BigInteger("0123456789abcdef", 16)), rv);
		// NOTE: This is not allowed, but still generates a courtesy warning
		assertNull(rm.targetToTrace("eax", genBytes4()));

		Delta<?, ?> delta = mb.testProcess1.regs.changeElements(List.of("RAX"), List.of(), "WoW64");
		assertFalse(delta.removed.isEmpty());
		waitForPass(() -> assertNull(rm.getTargetRegister("rax")));

		rv = waitForValue(() -> rm.targetToTrace("eax", genBytes4()));
		assertEquals(new RegisterValue(lRAX, new BigInteger("0000000089abcdef", 16)), rv);
		/**
		 * Should this be kept? I favoring a more accepting model makes sense, but I worry about
		 * erroneous cases we might not be catching, by re-generating missing registers on the fly.
		 */
		// assertNull(rm.targetToTrace("rax", genBytes8())); // Should no longer understand this one

		// This might be quite kick, back to 64-bit
		mb.testProcess1.regs.addRegistersFromLanguage(getSLEIGH_X86_64_LANGUAGE(), r -> true);
		waitForValue(() -> rm.getTargetRegister("rax"));

		rv = waitForValue(() -> rm.targetToTrace("rax", genBytes8()));
		assertEquals(new RegisterValue(lRAX, new BigInteger("0123456789abcdef", 16)), rv);
	}

	@Test
	public void testTraceToTargetAmidChanges() throws Throwable {
		DebuggerRegisterMapper rm = getRegisterMapperBase();
		Register lRAX = Objects.requireNonNull(getSLEIGH_X86_64_LANGUAGE().getRegister("RAX"));
		RegisterValue rv = new RegisterValue(lRAX, new BigInteger("0123456789abcdef", 16));
		Map.Entry<String, byte[]> ent;

		ent = waitForValue(() -> rm.traceToTarget(rv));
		assertEquals("RAX", ent.getKey());
		assertArrayEquals(genBytes8(), ent.getValue());

		Delta<?, ?> delta = mb.testProcess1.regs.changeElements(List.of("RAX"), List.of(), "WoW64");
		assertFalse(delta.removed.isEmpty());
		waitForPass(() -> assertNull(rm.getTargetRegister("rax")));

		ent = waitForValue(() -> rm.traceToTarget(rv));
		assertEquals("EAX", ent.getKey());
		assertArrayEquals(genBytes4(), ent.getValue());

		// This might be quite kick, back to 64-bit
		mb.testProcess1.regs.addRegistersFromLanguage(getSLEIGH_X86_64_LANGUAGE(), r -> true);
		waitForValue(() -> rm.getTargetRegister("rax"));

		ent = waitForValue(() -> rm.traceToTarget(rv));
		assertEquals("RAX", ent.getKey());
		assertArrayEquals(genBytes8(), ent.getValue());
	}
}
