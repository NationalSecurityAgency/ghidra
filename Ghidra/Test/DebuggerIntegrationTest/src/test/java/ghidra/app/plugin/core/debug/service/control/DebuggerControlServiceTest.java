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

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerIntegrationTest;
import ghidra.app.plugin.core.debug.service.MockTarget;
import ghidra.app.services.DebuggerControlService;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.async.AsyncUtils.TemperamentalRunnable;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.stack.TraceObjectStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.TraceSchedule;

public class DebuggerControlServiceTest extends AbstractGhidraHeadedDebuggerIntegrationTest {
	protected DebuggerControlService controlService;

	protected Register r0;
	protected Register r0h;
	protected RegisterValue rv1234;
	protected RegisterValue rv5678;
	protected RegisterValue rvHigh1234;

	protected StateEditor createStateEditor() {
		return controlService.createStateEditor(tb.trace);
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
		}
		catch (Throwable e) {
			if (cls.isInstance(e)) {
				return cls.cast(e);
			}
			throw new AssertionError("Expection exception type " + cls + ", but got " + e, e);
		}
		throw new AssertionError("Expected exception type " + cls + ", but got no error.");
	}

	@Before
	public void setUpEditorTest() throws Exception {
		controlService = addPlugin(tool, DebuggerControlServicePlugin.class);
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

		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		StateEditor editor = createStateEditor();
		assertFalse(editor.isVariableEditable(tb.addr(0x00400000), 4));
		expecting(IllegalArgumentException.class, () -> {
			waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));
		});
	}

	@Test
	public void testWriteEmuRegisterNoThreadErr() throws Throwable {
		createAndOpenTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		activateTrace();
		waitForSwing();

		StateEditor editor = createStateEditor();
		assertFalse(editor.isRegisterEditable(r0));
		expecting(IllegalArgumentException.class, () -> {
			waitOn(editor.setRegister(rv1234));
		});
	}

	@Override
	protected void createAndOpenTrace(String langID) throws IOException {
		super.createAndOpenTrace(langID);
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
		}
	}

	@Test
	public void testWriteEmuMemory() throws Throwable {
		createAndOpenTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		try (Transaction tx = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			tb.createObjectsProcessAndThreads();
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
		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		TraceObjectThread thread;
		try (Transaction tx = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			thread = tb.createObjectsProcessAndThreads();
			tb.createObjectsFramesAndRegs(thread, Lifespan.nowOn(0), getPlatform(), 1);
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
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		TraceObjectThread thread;
		try (Transaction tx = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			thread = tb.createObjectsProcessAndThreads();
			tb.createObjectsFramesAndRegs(thread, Lifespan.nowOn(0), getPlatform(), 1);
			Assembler asm = Assemblers.getAssembler(getPlatform().getLanguage());
			AssemblyBuffer buf = new AssemblyBuffer(asm, tb.addr(getPlatform(), 0x00400000));
			buf.assemble("imm r0,#123");
			tb.trace.getMemoryManager()
					.putBytes(0, tb.addr(0x00400000), ByteBuffer.wrap(buf.getBytes()));
			tb.exec(getPlatform(), 0, thread, 0, "pc = 0x00400000;");
		}
		activateTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);
		waitForSwing();

		TraceSchedule step1 = TraceSchedule.snap(0).steppedForward(thread, 1);
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
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		TraceObjectThread thread;
		try (Transaction tx = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			thread = tb.createObjectsProcessAndThreads();
			tb.createObjectsFramesAndRegs(thread, Lifespan.nowOn(0), getPlatform(), 1);
			Assembler asm = Assemblers.getAssembler(getPlatform().getLanguage());
			AssemblyBuffer buf = new AssemblyBuffer(asm, tb.addr(getPlatform(), 0x00400000));
			buf.assemble("imm r0,#123");
			tb.trace.getMemoryManager()
					.putBytes(0, tb.addr(0x00400000), ByteBuffer.wrap(buf.getBytes()));
			tb.exec(getPlatform(), 0, thread, 0, "pc = 0x00400000;");
		}
		activateTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);
		waitForSwing();

		TraceSchedule step1 = TraceSchedule.snap(0).steppedForward(thread, 1);
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
		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		try (Transaction tx = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			TraceObjectThread thread = tb.createObjectsProcessAndThreads();
			tb.createObjectsFramesAndRegs(thread, Lifespan.nowOn(0), getPlatform(), 1);
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
		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		TraceObjectThread thread;
		try (Transaction tx = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			thread = tb.createObjectsProcessAndThreads();
			tb.createObjectsFramesAndRegs(thread, Lifespan.nowOn(0), getPlatform(), 1);
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
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
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
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
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
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		TraceObjectThread thread;
		try (Transaction tx = tb.startTransaction()) {
			// NB. TraceManager should automatically activate the first thread
			thread = tb.createObjectsProcessAndThreads();
			tb.createObjectsFramesAndRegs(thread, Lifespan.nowOn(0), getPlatform(), 1);
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

	protected Target addTarget() throws Throwable {
		createRmiConnection();
		addRegisterMethods();
		addMemoryMethods();

		try (Transaction tx = tb.startTransaction()) {
			tb.createObjectsProcessAndThreads();
			TraceObjectThread thread =
				tb.obj("Processes[1].Threads[1]").queryInterface(TraceObjectThread.class);
			tb.createObjectsFramesAndRegs(thread, Lifespan.nowOn(0), getPlatform(), 1);
			tb.trace.getMemoryManager()
					.addRegion("Processes[1].Memory[exe:.text]", Lifespan.nowOn(0),
						tb.range(0x00400000, 00401000),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		return rmiCx.publishTarget(tool, tb.trace);
	}

	@Test
	public void testWriteTargetMemory() throws Throwable {
		createAndOpenTrace();
		addTarget();

		TraceObject process = tb.obj("Processes[1]");
		TraceThread thread =
			tb.obj("Processes[1].Threads[1]").queryInterface(TraceObjectThread.class);
		activateTrace(); // platform
		traceManager.activateThread(thread);
		waitForSwing();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);

		StateEditor editor = createStateEditor();
		assertTrue(editor.isVariableEditable(tb.addr(0x00400000), 4));
		CompletableFuture<Void> future =
			editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4));
		handleWriteMemInvocation(process, tb.addr(0x00400000), new Bytes(1, 2, 3, 4));
		waitOn(future);
	}

	@Test
	public void testWriteTargetRegister() throws Throwable {
		createAndOpenTrace();
		addTarget();

		TraceThread thread =
			tb.obj("Processes[1].Threads[1]").queryInterface(TraceObjectThread.class);
		activateTrace(); // platform
		traceManager.activateThread(thread);
		waitForSwing();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);

		StateEditor editor = createStateEditor();
		assertTrue(editor.isRegisterEditable(r0));
		CompletableFuture<Void> future = editor.setRegister(rv1234);
		handleWriteRegInvocation(
			tb.obj("Processes[1].Threads[1].Stack[0]").queryInterface(TraceObjectStackFrame.class),
			"r0", 1234);
		waitOn(future);
	}

	@Test
	public void testWriteTargetSubRegister() throws Throwable {
		createAndOpenTrace();
		addTarget();

		TraceThread thread =
			tb.obj("Processes[1].Threads[1]").queryInterface(TraceObjectThread.class);
		activateTrace(); // platform
		traceManager.activateThread(thread);
		waitForSwing();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);

		StateEditor editor = createStateEditor();
		assertTrue(editor.isRegisterEditable(r0));
		CompletableFuture<Void> future = editor.setRegister(rv1234);
		handleWriteRegInvocation(
			tb.obj("Processes[1].Threads[1].Stack[0]").queryInterface(TraceObjectStackFrame.class),
			"r0", 1234);
		waitOn(future);

		assertTrue(editor.isRegisterEditable(r0h));
		CompletableFuture<Void> future2 = editor.setRegister(rvHigh1234);
		handleWriteRegInvocation(
			tb.obj("Processes[1].Threads[1].Stack[0]").queryInterface(TraceObjectStackFrame.class),
			"r0h", 1234);
		waitOn(future2);
	}

	@Test
	public void testWriteTargetRequiresPresent() throws Throwable {
		createAndOpenTrace();
		Target target = addTarget();

		TraceThread thread =
			tb.obj("Processes[1].Threads[1]").queryInterface(TraceObjectThread.class);
		activateTrace(); // platform
		traceManager.activateThread(thread);
		waitForSwing();

		controlService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);
		waitForSwing();
		assertEquals(target.getSnap(), traceManager.getCurrentSnap());

		traceManager.activateSnap(traceManager.getCurrentSnap() - 1);
		waitForSwing();
		assertEquals(
			"Cannot navigate time in Control Target mode. Switch to Trace or Emulate mode first.",
			tool.getStatusInfo());
		assertEquals(target.getSnap(), traceManager.getCurrentSnap());

		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);
		waitForSwing();
		traceManager.activateSnap(traceManager.getCurrentSnap() - 1);
		waitForSwing();
		assertEquals(ControlMode.RW_EMULATOR, controlService.getCurrentMode(tb.trace));

		controlService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);
		waitForSwing();
		assertEquals(target.getSnap(), traceManager.getCurrentSnap());
	}

	@Test
	public void testWriteTargetMemoryNotAliveErr() throws Throwable {
		createAndOpenTrace();
		activateTrace();
		waitForSwing();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);
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
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);
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
		targetService.publishTarget(new MockTarget(tb.trace));
		activateTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RO_TARGET);

		StateEditor editor = createStateEditor();
		assertFalse(editor.isVariableEditable(tb.addr(0x00400000), 4));
		expecting(MemoryAccessException.class, () -> {
			waitOn(editor.setVariable(tb.addr(0x00400000), tb.arr(1, 2, 3, 4)));
		});
	}

	@Test
	public void testWriteReadOnlyRegisterErr() throws Throwable {
		createAndOpenTrace();
		targetService.publishTarget(new MockTarget(tb.trace));
		activateTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RO_TARGET);

		StateEditor editor = createStateEditor();
		assertFalse(editor.isRegisterEditable(r0));
		expecting(MemoryAccessException.class, () -> {
			waitOn(editor.setRegister(rv1234));
		});
	}
}
