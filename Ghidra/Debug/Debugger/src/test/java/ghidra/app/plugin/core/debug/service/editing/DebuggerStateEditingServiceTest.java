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
package ghidra.app.plugin.core.debug.service.editing;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.services.DebuggerStateEditingService;
import ghidra.app.services.DebuggerStateEditingService.StateEditingMode;
import ghidra.app.services.DebuggerStateEditingService.StateEditor;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.pcode.exec.AsyncPcodeExecutor;
import ghidra.pcode.exec.DebuggerPcodeUtils;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.database.UndoableTransaction;

public class DebuggerStateEditingServiceTest extends AbstractGhidraHeadedDebuggerGUITest {
	private DebuggerStateEditingService editingService;

	private Register r0;
	private Register r0h;
	private RegisterValue rv1234;
	private RegisterValue rv5678;
	private RegisterValue rvHigh1234;

	@Before
	public void setUpEditorTest() throws Exception {
		editingService = addPlugin(tool, DebuggerStateEditingServicePlugin.class);
		Language toy = getToyBE64Language();
		r0 = toy.getRegister("r0");
		r0h = toy.getRegister("r0h");
		rv1234 = new RegisterValue(r0, BigInteger.valueOf(1234));
		rv5678 = new RegisterValue(r0, BigInteger.valueOf(5678));
		rvHigh1234 = new RegisterValue(r0h, BigInteger.valueOf(1234));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testWriteEmuMemoryNoThreadErr() throws Throwable {
		/**
		 * TODO: It'd be nice if this worked, since memory edits don't really require a thread
		 * context. That would require some changes in the TraceSchedule and its execution. IINM,
		 * each step currently requires a thread. We'd have to relax that for patch steps, and it'd
		 * only work if they don't refer to any register.
		 */
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_EMULATOR);

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testWriteEmuRegisterNoThreadErr() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_EMULATOR);

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setRegister(rv1234));
	}

	@Test
	public void testWriteEmuMemory() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_EMULATOR);

		try (UndoableTransaction tid = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			tb.getOrAddThread("Threads[0]", 0);
		}
		waitForSwing();

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		long snap = current.getViewSnap();
		assertTrue(DBTraceUtils.isScratch(snap));

		ByteBuffer buf = ByteBuffer.allocate(4);
		tb.trace.getMemoryManager().getBytes(snap, tb.addr(0x00400000), buf);
		assertArrayEquals(tb.arr(1, 2, 3, 4), buf.array());
	}

	@Test
	public void testWriteEmuRegister() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_EMULATOR);

		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			thread = tb.getOrAddThread("Threads[0]", 0);
		}
		waitForSwing();

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setRegister(rv1234));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		long snap = current.getViewSnap();
		assertTrue(DBTraceUtils.isScratch(snap));

		RegisterValue value =
			tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, false).getValue(snap, r0);
		assertEquals(rv1234, value);
	}

	@Test
	public void testWriteEmuMemoryAfterStep() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_TRACE);

		try (UndoableTransaction tid = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			TraceThread thread = tb.getOrAddThread("Threads[0]", 0);
			AsyncPcodeExecutor<byte[]> executor = DebuggerPcodeUtils
					.executorForCoordinates(DebuggerCoordinates.NOWHERE.thread(thread));

			Assembler asm = Assemblers.getAssembler(tb.trace.getFixedProgramView(0));
			asm.assemble(tb.addr(0x00400000), "imm r0,#123");
			executor.executeSleighLine("pc = 0x00400000");
		}
		traceManager.activateTrace(tb.trace);
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_EMULATOR);
		waitForSwing();

		TraceSchedule step1 = TraceSchedule.parse("0:t0-1");
		traceManager.activateTime(step1);
		waitForPass(() -> assertEquals(step1, traceManager.getCurrent().getTime()));

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setVariable(tb.addr(0x00600000), tb.arr(1, 2, 3, 4)));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		assertEquals(0, current.getSnap()); // Chain edits, don't source from scratch
		long snap = current.getViewSnap();
		assertTrue(DBTraceUtils.isScratch(snap));

		ByteBuffer buf = ByteBuffer.allocate(4);
		tb.trace.getMemoryManager().getBytes(snap, tb.addr(0x00600000), buf);
		assertArrayEquals(tb.arr(1, 2, 3, 4), buf.array());
	}

	@Test
	public void testWriteEmuRegisterAfterStep() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_TRACE);

		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			thread = tb.getOrAddThread("Threads[0]", 0);
			AsyncPcodeExecutor<byte[]> executor = DebuggerPcodeUtils
					.executorForCoordinates(DebuggerCoordinates.NOWHERE.thread(thread));

			Assembler asm = Assemblers.getAssembler(tb.trace.getFixedProgramView(0));
			asm.assemble(tb.addr(0x00400000), "imm r0,#123");
			executor.executeSleighLine("pc = 0x00400000");
		}
		traceManager.activateTrace(tb.trace);
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_EMULATOR);
		waitForSwing();

		TraceSchedule step1 = TraceSchedule.parse("0:t0-1");
		traceManager.activateTime(step1);
		waitForPass(() -> assertEquals(step1, traceManager.getCurrent().getTime()));

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setRegister(rv1234));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		assertEquals(0, current.getSnap()); // Chain edits, don't source from scratch
		long snap = current.getViewSnap();
		assertTrue(DBTraceUtils.isScratch(snap));

		RegisterValue value =
			tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, false).getValue(snap, r0);
		assertEquals(rv1234, value);
	}

	@Test
	public void testWriteEmuMemoryTwice() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_EMULATOR);

		try (UndoableTransaction tid = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			tb.getOrAddThread("Threads[0]", 0);
		}
		waitForSwing();

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));
		waitOn(editor.setVariable(tb.addr(0x00400002), tb.arr(5, 6, 7, 8)));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		long snap = current.getViewSnap();
		assertTrue(DBTraceUtils.isScratch(snap));
		assertEquals(1, current.getTime().patchCount()); // Check coalesced

		ByteBuffer buf = ByteBuffer.allocate(6);
		tb.trace.getMemoryManager().getBytes(snap, tb.addr(0x00400000), buf);
		assertArrayEquals(tb.arr(1, 2, 5, 6, 7, 8), buf.array());
	}

	@Test
	public void testWriteEmuRegisterTwice() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_EMULATOR);

		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			thread = tb.getOrAddThread("Threads[0]", 0);
		}
		waitForSwing();

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setRegister(rv1234));
		waitOn(editor.setRegister(rv5678));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		long snap = current.getViewSnap();
		assertTrue(DBTraceUtils.isScratch(snap));
		assertEquals(1, current.getTime().patchCount()); // Check coalesced

		RegisterValue value =
			tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, false).getValue(snap, r0);
		assertEquals(rv5678, value);
	}

	@Test
	public void testWriteTraceMemory() throws Throwable {
		// NB. Definitely no thread required
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_TRACE);

		StateEditor editor = editingService.createStateEditor(tb.trace);
		// NB. Editor creates its own transaction
		waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		long snap = current.getViewSnap();
		assertEquals(0, snap);

		ByteBuffer buf = ByteBuffer.allocate(4);
		tb.trace.getMemoryManager().getBytes(snap, tb.addr(0x00400000), buf);
		assertArrayEquals(tb.arr(1, 2, 3, 4), buf.array());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testWriteTraceRegisterNoThreadErr() throws Throwable {
		// NB. Definitely no thread required
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_TRACE);

		StateEditor editor = editingService.createStateEditor(tb.trace);
		// NB. Editor creates its own transaction
		waitOn(editor.setRegister(rv1234));
	}

	@Test
	public void testWriteTraceRegister() throws Throwable {
		// NB. Definitely no thread required
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_TRACE);

		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			thread = tb.getOrAddThread("Threads[0]", 0);
		}
		waitForSwing();

		StateEditor editor = editingService.createStateEditor(tb.trace);
		// NB. Editor creates its own transaction
		waitOn(editor.setRegister(rv1234));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		long snap = current.getViewSnap();
		assertEquals(0, snap);

		RegisterValue value =
			tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, false).getValue(snap, r0);
		assertEquals(rv1234, value);
	}

	@Test
	public void testWriteTargetMemory() throws Throwable {
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(recorder.getTrace());
		traceManager.activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();
		editingService.setCurrentMode(recorder.getTrace(), StateEditingMode.WRITE_TARGET);

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));

		assertArrayEquals(mb.arr(1, 2, 3, 4),
			waitOn(mb.testProcess1.memory.readMemory(mb.addr(0x00400000), 4)));
	}

	@Test
	public void testWriteTargetRegister() throws Throwable {
		TraceRecorder recorder = recordAndWaitSync();
		TargetRegisterBank bank =
			(TargetRegisterBank) mb.testThread1.getCachedAttribute("RegisterBank");
		traceManager.openTrace(recorder.getTrace());
		traceManager.activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();
		editingService.setCurrentMode(recorder.getTrace(), StateEditingMode.WRITE_TARGET);

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setRegister(rv1234));

		assertArrayEquals(mb.arr(0, 0, 0, 0, 0, 0, 4, 0xd2), waitOn(bank.readRegister("r0")));
	}

	@Test
	public void testWriteTargetSubRegister() throws Throwable {
		TraceRecorder recorder = recordAndWaitSync();
		TargetRegisterBank bank =
			(TargetRegisterBank) mb.testThread1.getCachedAttribute("RegisterBank");
		traceManager.openTrace(recorder.getTrace());
		TraceThread thread = recorder.getTraceThread(mb.testThread1);
		traceManager.activateThread(thread);
		waitForSwing();
		editingService.setCurrentMode(recorder.getTrace(), StateEditingMode.WRITE_TARGET);

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setRegister(rv1234));
		waitForPass(() -> {
			TraceMemorySpace regs =
				tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
			assertNotNull(regs);
			RegisterValue value = regs.getValue(traceManager.getCurrentSnap(), r0);
			assertEquals(rv1234, value);
		});
		waitOn(editor.setRegister(rvHigh1234));

		assertArrayEquals(mb.arr(0, 0, 4, 0xd2, 0, 0, 4, 0xd2), waitOn(bank.readRegister("r0")));
	}

	@Test(expected = MemoryAccessException.class)
	public void testWriteTargetMemoryNotPresentErr() throws Throwable {
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(recorder.getTrace());
		traceManager.activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();
		editingService.setCurrentMode(recorder.getTrace(), StateEditingMode.WRITE_TARGET);

		traceManager.activateSnap(traceManager.getCurrentSnap() - 1);

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));
	}

	@Test(expected = MemoryAccessException.class)
	public void testWriteTargetRegisterNotPresentErr() throws Throwable {
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(recorder.getTrace());
		traceManager.activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();
		editingService.setCurrentMode(recorder.getTrace(), StateEditingMode.WRITE_TARGET);

		traceManager.activateSnap(traceManager.getCurrentSnap() - 1);

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setRegister(rv1234));
	}

	@Test(expected = MemoryAccessException.class)
	public void testWriteTargetMemoryNotAliveErr() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_TARGET);

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));
	}

	@Test(expected = MemoryAccessException.class)
	public void testWriteTargetRegisterNotAliveErr() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_TARGET);

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setRegister(rv1234));
	}

	@Test(expected = MemoryAccessException.class)
	public void testWriteReadOnlyMemoryErr() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.READ_ONLY);

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));
	}

	@Test(expected = MemoryAccessException.class)
	public void testWriteReadOnlyRegisterErr() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, StateEditingMode.READ_ONLY);

		StateEditor editor = editingService.createStateEditor(tb.trace);
		waitOn(editor.setRegister(rv1234));
	}
}
