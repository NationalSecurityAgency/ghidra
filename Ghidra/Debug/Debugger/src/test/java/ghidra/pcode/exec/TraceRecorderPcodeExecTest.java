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
package ghidra.pcode.exec;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.Map;

import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.mapping.DebuggerRegisterMapper;
import ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerAccess;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.services.ActionSource;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.model.TestTargetRegisterBankInThread;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.trace.DirectBytesTracePcodeExecutorState;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.TraceSchedule;

/**
 * Test the {@link DirectBytesTracePcodeExecutorState} in combination with
 * {@link PcodeDebuggerAccess} to ensure it read and writes the target when appropriate.
 */
public class TraceRecorderPcodeExecTest extends AbstractGhidraHeadedDebuggerGUITest {

	@Test
	public void testExecutorEval() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();

		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(),
			Register::isBaseRegister);
		TestTargetRegisterBankInThread regs = mb.testThread1.addRegisterBank();
		waitOn(regs.writeRegistersNamed(Map.of(
			"r0", new byte[] { 5 },
			"r1", new byte[] { 6 })));

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);

		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		Trace trace = recorder.getTrace();
		SleighLanguage language = (SleighLanguage) trace.getBaseLanguage();

		PcodeExpression expr = SleighProgramCompiler
				.compileExpression(language, "r0 + r1");

		Register r0 = language.getRegister("r0");
		Register r1 = language.getRegister("r1");
		waitForPass(() -> {
			// TODO: A little brittle: Depends on a specific snap advancement strategy
			assertEquals(3, trace.getTimeManager().getSnapshotCount());
			DebuggerRegisterMapper rm = recorder.getRegisterMapper(thread);
			assertNotNull(rm);
			assertNotNull(rm.getTargetRegister("r0"));
			assertNotNull(rm.getTargetRegister("r1"));
			assertTrue(rm.getRegistersOnTarget().contains(r0));
			assertTrue(rm.getRegistersOnTarget().contains(r1));
		});

		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool,
			DebuggerCoordinates.NOWHERE.recorder(recorder).thread(thread));

		// In practice, this should be backgrounded, but we're in a test thread
		byte[] result = expr.evaluate(executor);
		assertEquals(11, Utils.bytesToLong(result, result.length, language.isBigEndian()));
	}

	@Test
	public void testExecutorEvalInScratchReadsLive() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();

		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(),
			Register::isBaseRegister);
		TestTargetRegisterBankInThread regs = mb.testThread1.addRegisterBank();
		waitOn(regs.writeRegistersNamed(Map.of(
			"r0", new byte[] { 5 },
			"r1", new byte[] { 6 })));

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);

		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		Trace trace = recorder.getTrace();
		SleighLanguage language = (SleighLanguage) trace.getBaseLanguage();

		PcodeExpression expr = SleighProgramCompiler
				.compileExpression(language, "r0 + r1");

		Register r0 = language.getRegister("r0");
		Register r1 = language.getRegister("r1");
		waitForPass(() -> {
			// TODO: A little brittle: Depends on a specific snap advancement strategy
			assertEquals(3, trace.getTimeManager().getSnapshotCount());
			DebuggerRegisterMapper rm = recorder.getRegisterMapper(thread);
			assertNotNull(rm);
			assertNotNull(rm.getTargetRegister("r0"));
			assertNotNull(rm.getTargetRegister("r1"));
			assertTrue(rm.getRegistersOnTarget().contains(r0));
			assertTrue(rm.getRegistersOnTarget().contains(r1));
		});

		TraceSchedule oneTick = TraceSchedule.snap(recorder.getSnap()).steppedForward(thread, 1);
		try (Transaction tx = trace.openTransaction("Scratch")) {
			TraceSnapshot scratch = trace.getTimeManager().getSnapshot(Long.MIN_VALUE, true);
			scratch.setSchedule(oneTick);
			scratch.setDescription("Faked");

			TraceMemorySpace space = trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
			space.setValue(scratch.getKey(), new RegisterValue(r0, BigInteger.valueOf(10)));
		}

		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool,
			DebuggerCoordinates.NOWHERE.recorder(recorder).thread(thread).time(oneTick));

		// In practice, this should be backgrounded, but we're in a test thread
		byte[] result = expr.evaluate(executor);
		assertEquals(16, Utils.bytesToLong(result, result.length, language.isBigEndian()));
	}

	@Test
	public void testExecutorWrite() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();

		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(),
			Register::isBaseRegister);
		TestTargetRegisterBankInThread regs = mb.testThread1.addRegisterBank();
		waitOn(regs.writeRegistersNamed(Map.of(
			"r0", new byte[] { 5 },
			"r1", new byte[] { 6 })));

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		waitRecorder(recorder);

		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		Trace trace = recorder.getTrace();
		SleighLanguage language = (SleighLanguage) trace.getBaseLanguage();

		PcodeProgram prog = SleighProgramCompiler.compileProgram(language, "test",
			"r2 = r0 + r1;", PcodeUseropLibrary.NIL);

		Register r0 = language.getRegister("r0");
		Register r1 = language.getRegister("r1");
		waitForPass(() -> {
			// TODO: A little brittle: Depends on a specific snap advancement strategy
			assertEquals(3, trace.getTimeManager().getSnapshotCount());
			DebuggerRegisterMapper rm = recorder.getRegisterMapper(thread);
			assertNotNull(rm);
			assertNotNull(rm.getTargetRegister("r0"));
			assertNotNull(rm.getTargetRegister("r1"));
			assertTrue(rm.getRegistersOnTarget().contains(r0));
			assertTrue(rm.getRegistersOnTarget().contains(r1));
		});

		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool,
			DebuggerCoordinates.NOWHERE.recorder(recorder).thread(thread));

		executor.execute(prog, PcodeUseropLibrary.nil());
		// Ignore return value. We'll assert that it got written to the trace
		executor.state.getVar(language.getRegister("r2"), Reason.INSPECT);

		assertEquals(BigInteger.valueOf(11), new BigInteger(1, regs.regVals.get("r2")));
	}
}
