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
import java.util.concurrent.CompletableFuture;

import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerIntegrationTest;
import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.SleighUtils.LitIdMode;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.database.symbol.DBTraceSymbolManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.TraceSchedule;

public class TraceRmiPcodeExecTest extends AbstractGhidraHeadedDebuggerIntegrationTest {

	Target target;
	TraceThread thread;
	SleighLanguage language;

	protected void setupExecTest() throws Throwable {
		createRmiConnection();
		addRegisterMethods();
		createTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();
			thread = tb.obj("Processes[1].Threads[1]").queryInterface(TraceThread.class);
			tb.createObjectsFramesAndRegs(thread, Lifespan.nowOn(0), tb.host, 1);

			DBTraceSymbolManager syms = tb.trace.getSymbolManager();
			syms.labels()
					.create(0, tb.addr(0x1234), "abba", syms.getGlobalNamespace(),
						SourceType.IMPORTED);
		}
		target = rmiCx.publishTarget(tool, tb.trace);
		language = (SleighLanguage) tb.trace.getBaseLanguage();
	}

	@Test
	public void testExecutorEval() throws Throwable {
		setupExecTest();

		PcodeExpression expr = SleighProgramCompiler.compileExpression(language, "r0 + r1");
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool,
			DebuggerCoordinates.NOWHERE.target(target).thread(thread));

		CompletableFuture<byte[]> futResult =
			CompletableFuture.supplyAsync(() -> expr.evaluate(executor));

		long snap = target.getSnap();
		handleReadRegsInvocation(tb.obj("Processes[1].Threads[1].Stack[0].Registers"), () -> {
			try (Transaction tx = tb.startTransaction()) {
				TraceMemorySpace regs =
					tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
				regs.setValue(snap, new RegisterValue(tb.reg("r0"), new BigInteger("5")));
				regs.setValue(snap, new RegisterValue(tb.reg("r1"), new BigInteger("6")));
			}
			return null;
		});

		byte[] result = waitOn(futResult);
		assertEquals(new BigInteger("11"),
			executor.getArithmetic().toBigInteger(result, Purpose.INSPECT));
	}

	@Test
	public void testExecutorEvalBinLit() throws Throwable {
		setupExecTest();

		DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.target(target).thread(thread);
		PcodeExpression expr = DebuggerPcodeUtils.compileExpression(tool, coords, tb.addr(0x1000),
			".+0b10", LitIdMode.NORMAL);
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool, coords);
		byte[] result = expr.evaluate(executor);
		assertEquals(new BigInteger("1002", 16),
			executor.getArithmetic().toBigInteger(result, Purpose.INSPECT));
	}

	@Test
	public void testExecutorEvalWithDot() throws Throwable {
		setupExecTest();

		DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.target(target).thread(thread);
		PcodeExpression expr =
			DebuggerPcodeUtils.compileExpression(tool, coords, tb.addr(0x1000), ".+4");
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool, coords);
		byte[] result = expr.evaluate(executor);
		assertEquals(new BigInteger("1004", 16),
			executor.getArithmetic().toBigInteger(result, Purpose.INSPECT));
	}

	@Test
	public void testExecutorEvalWithLabel() throws Throwable {
		setupExecTest();

		DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.target(target).thread(thread);
		PcodeExpression expr =
			DebuggerPcodeUtils.compileExpression(tool, coords, tb.addr(0x1000), "abba+4");
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool, coords);
		byte[] result = expr.evaluate(executor);
		assertEquals(new BigInteger("1238", 16),
			executor.getArithmetic().toBigInteger(result, Purpose.INSPECT));
	}

	@Test
	public void testExecutorEvalHexMode() throws Throwable {
		setupExecTest();

		DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.target(target).thread(thread);
		PcodeExpression expr = DebuggerPcodeUtils.compileExpression(tool, coords, tb.addr(0x1000),
			".+4c", LitIdMode.HEX);
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool, coords);
		byte[] result = expr.evaluate(executor);
		assertEquals(new BigInteger("104c", 16),
			executor.getArithmetic().toBigInteger(result, Purpose.INSPECT));
	}

	@Test
	public void testExecutorEvalHexMode0nPrefix() throws Throwable {
		setupExecTest();

		DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.target(target).thread(thread);
		PcodeExpression expr = DebuggerPcodeUtils.compileExpression(tool, coords, tb.addr(0x1000),
			".+0n100", LitIdMode.HEX);
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool, coords);
		byte[] result = expr.evaluate(executor);
		assertEquals(new BigInteger("1064", 16),
			executor.getArithmetic().toBigInteger(result, Purpose.INSPECT));
	}

	@Test
	public void testExecutorEvalHexModeWithSize() throws Throwable {
		setupExecTest();

		DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.target(target).thread(thread);
		PcodeExpression expr = DebuggerPcodeUtils.compileExpression(tool, coords, tb.addr(0x1000),
			".+4c:8", LitIdMode.HEX);
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool, coords);
		byte[] result = expr.evaluate(executor);
		assertEquals(new BigInteger("104c", 16),
			executor.getArithmetic().toBigInteger(result, Purpose.INSPECT));
	}

	@Test(expected = SleighException.class)
	public void testExecutorEvalHexModeWithHexSizeErr() throws Throwable {
		setupExecTest();

		DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.target(target).thread(thread);
		PcodeExpression expr = DebuggerPcodeUtils.compileExpression(tool, coords, tb.addr(0x1000),
			".+4c:a", LitIdMode.HEX);
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool, coords);
		byte[] result = expr.evaluate(executor);
		assertEquals(new BigInteger("104c", 16),
			executor.getArithmetic().toBigInteger(result, Purpose.INSPECT));
	}

	@Test
	public void testExecutorEvalHexModeLooksBinPrefix() throws Throwable {
		setupExecTest();

		DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.target(target).thread(thread);
		PcodeExpression expr = DebuggerPcodeUtils.compileExpression(tool, coords, tb.addr(0x1000),
			".+0b12", LitIdMode.HEX);
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool, coords);
		byte[] result = expr.evaluate(executor);
		assertEquals(new BigInteger("1b12", 16),
			executor.getArithmetic().toBigInteger(result, Purpose.INSPECT));
	}

	@Test
	public void testExecutorEvalHexModeLooksBin() throws Throwable {
		setupExecTest();

		DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.target(target).thread(thread);
		PcodeExpression expr = DebuggerPcodeUtils.compileExpression(tool, coords, tb.addr(0x1000),
			".+0b10", LitIdMode.HEX);
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool, coords);
		byte[] result = expr.evaluate(executor);
		assertEquals(new BigInteger("1b10", 16),
			executor.getArithmetic().toBigInteger(result, Purpose.INSPECT));
	}

	@Test
	public void testExecutorEvalHexModeWithLabel() throws Throwable {
		setupExecTest();

		DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.target(target).thread(thread);
		PcodeExpression expr = DebuggerPcodeUtils.compileExpression(tool, coords, tb.addr(0x1000),
			"abba+4", LitIdMode.HEX);
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool, coords);
		byte[] result = expr.evaluate(executor);
		// This should prefer to interpret abba as an int (hex) literal
		assertEquals(new BigInteger("abbe", 16),
			executor.getArithmetic().toBigInteger(result, Purpose.INSPECT));
	}

	@Test
	public void testExecutorEvalIdHexModeWithLabel() throws Throwable {
		setupExecTest();

		DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.target(target).thread(thread);
		PcodeExpression expr = DebuggerPcodeUtils.compileExpression(tool, coords, tb.addr(0x1000),
			"abba+4", LitIdMode.ID_HEX);
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool, coords);
		byte[] result = expr.evaluate(executor);
		// This should prefer to interpret abba as an id (with value 0x1234)
		assertEquals(new BigInteger("1238", 16),
			executor.getArithmetic().toBigInteger(result, Purpose.INSPECT));
	}

	@Test
	public void testExecutorEvalIdHexModeWithHexLooksLabel() throws Throwable {
		setupExecTest();

		DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.target(target).thread(thread);
		PcodeExpression expr = DebuggerPcodeUtils.compileExpression(tool, coords, tb.addr(0x1000),
			"abbb+4", LitIdMode.ID_HEX);
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool, coords);
		byte[] result = expr.evaluate(executor);
		// Even though abbb may be parsed as an id, we fall back to an int, if hex.
		assertEquals(new BigInteger("abbf", 16),
			executor.getArithmetic().toBigInteger(result, Purpose.INSPECT));
	}

	@Test(expected = SleighException.class)
	public void testExecutorEvalNormalModeHexErr() throws Throwable {
		setupExecTest();

		DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.target(target).thread(thread);
		DebuggerPcodeUtils.compileExpression(tool, coords, tb.addr(0x1000),
			".+4c", LitIdMode.NORMAL);
	}

	@Test
	public void testExecutorEvalInScratchModeReadsLive() throws Throwable {
		setupExecTest();

		TraceSchedule oneTick = TraceSchedule.snap(target.getSnap()).steppedForward(thread, 1);
		try (Transaction tx = tb.trace.openTransaction("Scratch")) {
			TraceSnapshot scratch = tb.trace.getTimeManager().getSnapshot(Long.MIN_VALUE, true);
			scratch.setSchedule(oneTick);
			scratch.setDescription("Faked");
		}

		PcodeExpression expr = SleighProgramCompiler.compileExpression(language, "r0 + r1");
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool,
			DebuggerCoordinates.NOWHERE.target(target).thread(thread).time(oneTick));

		CompletableFuture<byte[]> futResult =
			CompletableFuture.supplyAsync(() -> expr.evaluate(executor));

		long snap = target.getSnap(); // should be 0, not the scratch
		TraceObject objRegs = tb.obj("Processes[1].Threads[1].Stack[0].Registers");
		handleReadRegsInvocation(objRegs, () -> {
			try (Transaction tx = tb.startTransaction()) {
				TraceMemorySpace regs =
					tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
				regs.setValue(snap, new RegisterValue(tb.reg("r0"), new BigInteger("5")));
				regs.setValue(snap, new RegisterValue(tb.reg("r1"), new BigInteger("6")));
			}
			return null;
		});

		byte[] result = waitOn(futResult);
		assertEquals(new BigInteger("11"),
			executor.getArithmetic().toBigInteger(result, Purpose.INSPECT));
	}

	@Test
	public void testExecutorWrite() throws Throwable {
		setupExecTest();

		PcodeProgram prog = SleighProgramCompiler.compileProgram(language, "test",
			"r2 = r0 + r1;", PcodeUseropLibrary.NIL);
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool,
			DebuggerCoordinates.NOWHERE.target(target).thread(thread));

		CompletableFuture<Void> futResult =
			CompletableFuture.runAsync(() -> executor.execute(prog, PcodeUseropLibrary.nil()));

		long snap = target.getSnap();
		handleReadRegsInvocation(tb.obj("Processes[1].Threads[1].Stack[0].Registers"), () -> {
			try (Transaction tx = tb.startTransaction()) {
				TraceMemorySpace regs =
					tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
				regs.setValue(snap, new RegisterValue(tb.reg("r0"), new BigInteger("5")));
				regs.setValue(snap, new RegisterValue(tb.reg("r1"), new BigInteger("6")));
			}
			return null;
		});

		handleWriteRegInvocation(
			tb.obj("Processes[1].Threads[1].Stack[0]").queryInterface(TraceStackFrame.class),
			"r2", 11);

		waitOn(futResult);
	}
}
