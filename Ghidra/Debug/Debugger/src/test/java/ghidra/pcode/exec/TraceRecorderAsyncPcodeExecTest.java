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

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServiceTest;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.model.TestTargetRegisterBankInThread;
import ghidra.dbg.testutil.DebuggerModelTestUtils;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;

public class TraceRecorderAsyncPcodeExecTest extends AbstractGhidraHeadedDebuggerGUITest
		implements DebuggerModelTestUtils {
	static {
		DebuggerModelServiceTest.addTestModelPathPatterns();
	}

	@Test
	public void testExecutorEval() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();

		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(),
			Register::isBaseRegister);
		TestTargetRegisterBankInThread regs = mb.testThread1.addRegisterBank();
		regs.writeRegistersNamed(Map.of(
			"r0", new byte[] { 5 },
			"r1", new byte[] { 6 }));

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));

		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		Trace trace = recorder.getTrace();
		Language language = trace.getBaseLanguage();

		SleighExpression expr = SleighProgramCompiler
				.compileExpression((SleighLanguage) language, "r0 + r1");

		AsyncPcodeExecutor<byte[]> executor =
			new AsyncPcodeExecutor<>(language, AsyncWrappedPcodeArithmetic.forLanguage(language),
				new TraceRecorderAsyncPcodeExecutorState(recorder, recorder.getSnap(), thread, 0));
		byte[] result = waitOn(expr.evaluate(executor));

		assertEquals(11, Utils.bytesToLong(result, result.length, language.isBigEndian()));
	}

	@Test
	public void testExecutorWrite() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();

		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(),
			Register::isBaseRegister);
		TestTargetRegisterBankInThread regs = mb.testThread1.addRegisterBank();
		regs.writeRegistersNamed(Map.of(
			"r0", new byte[] { 5 },
			"r1", new byte[] { 6 }));

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));

		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		Trace trace = recorder.getTrace();
		Language language = trace.getBaseLanguage();

		PcodeProgram prog = SleighProgramCompiler.compileProgram((SleighLanguage) language, "test",
			List.of("r2 = r0 + r1;"), SleighUseropLibrary.NIL);

		TraceRecorderAsyncPcodeExecutorState asyncState =
			new TraceRecorderAsyncPcodeExecutorState(recorder, recorder.getSnap(), thread, 0);
		AsyncPcodeExecutor<byte[]> executor = new AsyncPcodeExecutor<>(
			language, AsyncWrappedPcodeArithmetic.forLanguage(language), asyncState);
		waitOn(executor.executeAsync(prog, SleighUseropLibrary.nil()));
		waitOn(asyncState.getVar(language.getRegister("r2")));

		assertEquals(BigInteger.valueOf(11), new BigInteger(1, regs.regVals.get("r2")));
	}
}
