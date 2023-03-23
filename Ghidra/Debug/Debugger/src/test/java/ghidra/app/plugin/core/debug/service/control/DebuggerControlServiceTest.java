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
package ghidra.app.plugin.core.debug.service.control;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.async.AsyncUtils.TemperamentalRunnable;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.TraceSchedule;

public class DebuggerControlServiceTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected DebuggerControlService editingService;

	protected Register r0;
	protected Register r0h;
	protected RegisterValue rv1234;
	protected RegisterValue rv5678;
	protected RegisterValue rvHigh1234;

	protected StateEditor createStateEditor() {
		return editingService.createStateEditor(tb.trace);
	}

	protected void activateTrace() {
		traceManager.activateTrace(tb.trace);
		waitForSwing();
	}

	protected TracePlatform getPlatform() {
		return tb.trace.getPlatformManager().getHostPlatform();
	}

	/**
	 * Verify that the given action (usually a lambda) throws an exception
	 * 
	 * <p>
	 * This fulfills the same use case as the {@link Test#expected()} attribute, but allows more
	 * precise verification of which code in the test causes the exception.
	 */
	<E extends Throwable> E expecting(Class<E> cls, TemperamentalRunnable action) {
		try {
			action.run();
			fail("Expected exception type " + cls + ", but got no error.");
		}
		catch (Throwable e) {
			if (cls.isInstance(e)) {
				return cls.cast(e);
			}
			fail("Expection exception type " + cls + ", but got " + e);
		}
		throw new AssertionError();
	}

	@Before
	public void setUpEditorTest() throws Exception {
		editingService = addPlugin(tool, DebuggerControlServicePlugin.class);
		Language toy = getToyBE64Language();
		r0 = toy.getRegister("r0");
		r0h = toy.getRegister("r0h");
		rv1234 = new RegisterValue(r0, BigInteger.valueOf(1234));
		rv5678 = new RegisterValue(r0, BigInteger.valueOf(5678));
		rvHigh1234 = new RegisterValue(r0h, BigInteger.valueOf(1234));
	}

	@Test
	public void testWriteEmuMemoryNoThreadErr() throws Throwable {
		/**
		 * TODO: It'd be nice if this worked, since memory edits don't really require a thread
		 * context. That would require some changes in the TraceSchedule and its execution. IINM,
		 * each step currently requires a thread. We'd have to relax that for patch steps, and it'd
		 * only work if they don't refer to any register.
		 */
		createAndOpenTrace();
		activateTrace();

		editingService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		StateEditor editor = createStateEditor();
		assertFalse(editor.isVariableEditable(tb.addr(0x00400000), 4));
		expecting(IllegalArgumentException.class, () -> {
			waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));
		});
	}

	@Test
	public void testWriteEmuRegisterNoThreadErr() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		activateTrace();
		waitForSwing();

		StateEditor editor = createStateEditor();
		assertFalse(editor.isRegisterEditable(r0));
		expecting(IllegalArgumentException.class, () -> {
			waitOn(editor.setRegister(rv1234));
		});
	}

	@Test
	public void testWriteEmuMemory() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		try (Transaction tx = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			tb.getOrAddThread("Threads[0]", 0);
		}
		activateTrace();
		waitForSwing();

		StateEditor editor = createStateEditor();
		assertTrue(editor.isVariableEditable(tb.addr(0x00400000), 4));
		waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		long snap = current.getViewSnap();
		assertTrue(Lifespan.isScratch(snap));

		ByteBuffer buf = ByteBuffer.allocate(4);
		tb.trace.getMemoryManager().getBytes(snap, tb.addr(0x00400000), buf);
		assertArrayEquals(tb.arr(1, 2, 3, 4), buf.array());
	}

	@Test
	public void testWriteEmuRegister() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			thread = tb.getOrAddThread("Threads[0]", 0);
		}
		activateTrace();
		waitForSwing();

		StateEditor editor = createStateEditor();
		assertTrue(editor.isRegisterEditable(r0));
		waitOn(editor.setRegister(rv1234));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		long snap = current.getViewSnap();
		assertTrue(Lifespan.isScratch(snap));

		RegisterValue value =
			tb.trace.getMemoryManager()
					.getMemoryRegisterSpace(thread, false)
					.getValue(getPlatform(), snap, r0);
		assertEquals(rv1234, value);
	}

	@Test
	public void testWriteEmuMemoryAfterStep() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		try (Transaction tx = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			TraceThread thread = tb.getOrAddThread("Threads[0]", 0);
			Assembler asm = Assemblers.getAssembler(getPlatform().getLanguage());
			AssemblyBuffer buf = new AssemblyBuffer(asm, tb.addr(getPlatform(), 0x00400000));
			buf.assemble("imm r0,#123");
			tb.trace.getMemoryManager()
					.putBytes(0, tb.addr(0x00400000), ByteBuffer.wrap(buf.getBytes()));
			tb.exec(getPlatform(), 0, thread, 0, "pc = 0x00400000;");
		}
		activateTrace();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);
		waitForSwing();

		TraceSchedule step1 = TraceSchedule.parse("0:t0-1");
		traceManager.activateTime(step1);
		waitForPass(() -> assertEquals(step1, traceManager.getCurrent().getTime()));

		StateEditor editor = createStateEditor();
		assertTrue(editor.isVariableEditable(tb.addr(0x00600000), 4));
		waitOn(editor.setVariable(tb.addr(0x00600000), tb.arr(1, 2, 3, 4)));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		assertEquals(0, current.getSnap()); // Chain edits, don't source from scratch
		long snap = current.getViewSnap();
		assertTrue(Lifespan.isScratch(snap));

		ByteBuffer buf = ByteBuffer.allocate(4);
		tb.trace.getMemoryManager().getBytes(snap, tb.addr(0x00600000), buf);
		assertArrayEquals(tb.arr(1, 2, 3, 4), buf.array());
	}

	@Test
	public void testWriteEmuRegisterAfterStep() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			thread = tb.getOrAddThread("Threads[0]", 0);
			Assembler asm = Assemblers.getAssembler(getPlatform().getLanguage());
			AssemblyBuffer buf = new AssemblyBuffer(asm, tb.addr(getPlatform(), 0x00400000));
			buf.assemble("imm r0,#123");
			tb.trace.getMemoryManager()
					.putBytes(0, tb.addr(0x00400000), ByteBuffer.wrap(buf.getBytes()));
			tb.exec(getPlatform(), 0, thread, 0, "pc = 0x00400000;");
		}
		activateTrace();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);
		waitForSwing();

		TraceSchedule step1 = TraceSchedule.parse("0:t0-1");
		traceManager.activateTime(step1);
		waitForPass(() -> assertEquals(step1, traceManager.getCurrent().getTime()));

		StateEditor editor = createStateEditor();
		assertTrue(editor.isRegisterEditable(r0));
		waitOn(editor.setRegister(rv1234));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		assertEquals(0, current.getSnap()); // Chain edits, don't source from scratch
		long snap = current.getViewSnap();
		assertTrue(Lifespan.isScratch(snap));

		RegisterValue value = tb.trace.getMemoryManager()
				.getMemoryRegisterSpace(thread, false)
				.getValue(getPlatform(), snap, r0);
		assertEquals(rv1234, value);
	}

	@Test
	public void testWriteEmuMemoryTwice() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		try (Transaction tx = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			tb.getOrAddThread("Threads[0]", 0);
		}
		activateTrace();
		waitForSwing();

		StateEditor editor = createStateEditor();
		assertTrue(editor.isVariableEditable(tb.addr(0x00400000), 4));
		waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));
		assertTrue(editor.isVariableEditable(tb.addr(0x00400002), 4));
		waitOn(editor.setVariable(tb.addr(0x00400002), tb.arr(5, 6, 7, 8)));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		long snap = current.getViewSnap();
		assertTrue(Lifespan.isScratch(snap));
		assertEquals(1, current.getTime().patchCount()); // Check coalesced

		ByteBuffer buf = ByteBuffer.allocate(6);
		tb.trace.getMemoryManager().getBytes(snap, tb.addr(0x00400000), buf);
		assertArrayEquals(tb.arr(1, 2, 5, 6, 7, 8), buf.array());
	}

	@Test
	public void testWriteEmuRegisterTwice() throws Throwable {
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			thread = tb.getOrAddThread("Threads[0]", 0);
		}
		activateTrace();
		waitForSwing();

		StateEditor editor = createStateEditor();
		assertTrue(editor.isRegisterEditable(r0));
		waitOn(editor.setRegister(rv1234));
		waitOn(editor.setRegister(rv5678));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		long snap = current.getViewSnap();
		assertTrue(Lifespan.isScratch(snap));
		assertEquals(1, current.getTime().patchCount()); // Check coalesced

		RegisterValue value = tb.trace.getMemoryManager()
				.getMemoryRegisterSpace(thread, false)
				.getValue(getPlatform(), snap, r0);
		assertEquals(rv5678, value);
	}

	@Test
	public void testWriteTraceMemory() throws Throwable {
		// NB. Definitely no thread required
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
		activateTrace();
		waitForSwing();

		StateEditor editor = createStateEditor();
		assertTrue(editor.isVariableEditable(tb.addr(0x00400000), 4));
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

	@Test
	public void testWriteTraceRegisterNoThreadErr() throws Throwable {
		// NB. Definitely no thread required
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
		activateTrace();
		waitForSwing();

		StateEditor editor = createStateEditor();
		assertFalse(editor.isRegisterEditable(r0));
		// NB. Editor creates its own transaction
		expecting(IllegalArgumentException.class, () -> {
			waitOn(editor.setRegister(rv1234));
		});
	}

	@Test
	public void testWriteTraceRegister() throws Throwable {
		// NB. Definitely no thread required
		createAndOpenTrace();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			thread = tb.getOrAddThread("Threads[0]", 0);
		}
		activateTrace();
		waitForSwing();

		StateEditor editor = createStateEditor();
		assertTrue(editor.isRegisterEditable(r0));
		// NB. Editor creates its own transaction
		waitOn(editor.setRegister(rv1234));
		waitForSwing();

		DebuggerCoordinates current = traceManager.getCurrent();
		long snap = current.getViewSnap();
		assertEquals(0, snap);

		RegisterValue value = tb.trace.getMemoryManager()
				.getMemoryRegisterSpace(thread, false)
				.getValue(getPlatform(), snap, r0);
		assertEquals(rv1234, value);
	}

	@Test
	public void testWriteTargetMemory() throws Throwable {
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(tb.trace);
		activateTrace();
		traceManager.activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();
		editingService.setCurrentMode(recorder.getTrace(), ControlMode.RW_TARGET);

		StateEditor editor = createStateEditor();
		assertTrue(editor.isVariableEditable(tb.addr(0x00400000), 4));
		waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));

		assertArrayEquals(mb.arr(1, 2, 3, 4),
			waitOn(mb.testProcess1.memory.readMemory(mb.addr(0x00400000), 4)));
	}

	@Test
	public void testWriteTargetRegister() throws Throwable {
		TraceRecorder recorder = recordAndWaitSync();
		TargetRegisterBank bank =
			(TargetRegisterBank) mb.testThread1.getCachedAttribute("RegisterBank");
		traceManager.openTrace(tb.trace);
		activateTrace();
		waitForSwing();
		traceManager.activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();
		editingService.setCurrentMode(recorder.getTrace(), ControlMode.RW_TARGET);

		StateEditor editor = createStateEditor();
		assertTrue(editor.isRegisterEditable(r0));
		waitOn(editor.setRegister(rv1234));

		assertArrayEquals(mb.arr(0, 0, 0, 0, 0, 0, 4, 0xd2), waitOn(bank.readRegister("r0")));
	}

	@Test
	public void testWriteTargetSubRegister() throws Throwable {
		TraceRecorder recorder = recordAndWaitSync();
		TargetRegisterBank bank =
			(TargetRegisterBank) mb.testThread1.getCachedAttribute("RegisterBank");
		traceManager.openTrace(tb.trace);
		activateTrace();
		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		traceManager.activateThread(thread);
		waitForSwing();
		editingService.setCurrentMode(recorder.getTrace(), ControlMode.RW_TARGET);

		StateEditor editor = createStateEditor();
		waitForPass(() -> assertTrue(editor.isRegisterEditable(r0)));
		waitOn(editor.setRegister(rv1234));
		waitForPass(() -> {
			TraceMemorySpace regs =
				tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
			assertNotNull(regs);
			RegisterValue value = regs.getValue(getPlatform(), traceManager.getCurrentSnap(), r0);
			assertEquals(rv1234, value);
		});
		waitForPass(() -> assertTrue(editor.isRegisterEditable(r0h)));
		waitOn(editor.setRegister(rvHigh1234));

		assertArrayEquals(mb.arr(0, 0, 4, 0xd2, 0, 0, 4, 0xd2), waitOn(bank.readRegister("r0")));
	}

	@Test
	public void testWriteTargetRequiresPresent() throws Throwable {
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(tb.trace);
		activateTrace();
		traceManager.activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();

		editingService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);
		waitForSwing();
		assertEquals(recorder.getSnap(), traceManager.getCurrentSnap());

		traceManager.activateSnap(traceManager.getCurrentSnap() - 1);
		waitForSwing();
		assertEquals(ControlMode.RW_EMULATOR, editingService.getCurrentMode(tb.trace));

		editingService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);
		waitForSwing();
		assertEquals(recorder.getSnap(), traceManager.getCurrentSnap());
	}

	@Test
	public void testWriteTargetMemoryNotAliveErr() throws Throwable {
		createAndOpenTrace();
		activateTrace();
		waitForSwing();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);
		waitForSwing();

		StateEditor editor = createStateEditor();
		assertFalse(editor.isVariableEditable(tb.addr(0x00400000), 4));
		expecting(MemoryAccessException.class, () -> {
			waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));
		});
	}

	@Test
	public void testWriteTargetRegisterNotAliveErr() throws Throwable {
		createAndOpenTrace();
		activateTrace();
		waitForSwing();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);
		waitForSwing();

		StateEditor editor = createStateEditor();
		assertFalse(editor.isRegisterEditable(r0));
		expecting(MemoryAccessException.class, () -> {
			waitOn(editor.setRegister(rv1234));
		});
	}

	@Test
	public void testWriteReadOnlyMemoryErr() throws Throwable {
		createAndOpenTrace();
		activateTrace();
		editingService.setCurrentMode(tb.trace, ControlMode.RO_TARGET);

		StateEditor editor = createStateEditor();
		assertFalse(editor.isVariableEditable(tb.addr(0x00400000), 4));
		expecting(MemoryAccessException.class, () -> {
			waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));
		});
	}

	@Test
	public void testWriteReadOnlyRegisterErr() throws Throwable {
		createAndOpenTrace();
		activateTrace();
		editingService.setCurrentMode(tb.trace, ControlMode.RO_TARGET);

		StateEditor editor = createStateEditor();
		assertFalse(editor.isRegisterEditable(r0));
		expecting(MemoryAccessException.class, () -> {
			waitOn(editor.setRegister(rv1234));
		});
	}
}
