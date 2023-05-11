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
package ghidra.app.plugin.core.debug.gui.control;

import static org.junit.Assert.*;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.dnd.GClipboard;
import docking.widgets.OptionDialog;
import generic.Unique;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.core.assembler.AssemblerPlugin;
import ghidra.app.plugin.core.assembler.AssemblerPluginTestHelper;
import ghidra.app.plugin.core.clipboard.ClipboardPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.disassemble.DebuggerDisassemblerPlugin;
import ghidra.app.plugin.core.debug.disassemble.DebuggerDisassemblerPluginTestHelper;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.mapping.DebuggerTargetTraceMapper;
import ghidra.app.plugin.core.debug.mapping.ObjectBasedDebuggerTargetTraceMapper;
import ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerEmulationService.CachedEmulator;
import ghidra.app.services.DebuggerEmulationService.EmulationResult;
import ghidra.dbg.model.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.pcode.exec.SuspendedPcodeExecutionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Instruction;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.program.TraceVariableSnapProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.Scheduler;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.Swing;

/**
 * Tests for target control and state editing
 * 
 * <p>
 * In these and other control service integration tests, we use {@link ControlMode#RW_EMULATOR} as a
 * stand-in for any mode. We also use {@link ControlMode#RO_TARGET} just to verify the mode is
 * heeded. Other modes may be tested if bugs crop up in various combinations.
 */
public class DebuggerControlPluginTest extends AbstractGhidraHeadedDebuggerGUITest {

	DebuggerListingPlugin listingPlugin;
	DebuggerControlService controlService;
	DebuggerEmulationService emulationService;
	DebuggerControlPlugin controlPlugin;

	List<String> commands = Collections.synchronizedList(new ArrayList<>());

	@Before
	public void setUpControlTest() throws Exception {
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		controlService = addPlugin(tool, DebuggerControlServicePlugin.class);
		emulationService = addPlugin(tool, DebuggerEmulationServicePlugin.class);
		controlPlugin = addPlugin(tool, DebuggerControlPlugin.class);

		mb = new TestDebuggerModelBuilder() {
			@Override
			protected TestDebuggerObjectModel newModel(String typeHint) {
				commands.clear();
				return new TestDebuggerObjectModel(typeHint) {
					@Override
					protected TestTargetThread newTestTargetThread(
							TestTargetThreadContainer container, int tid) {
						return new TestTargetThread(container, tid) {
							{
								setState(TargetExecutionState.STOPPED);
							}

							@Override
							public CompletableFuture<Void> resume() {
								commands.add("resume");
								setState(TargetExecutionState.RUNNING);
								return super.resume();
							}

							@Override
							public CompletableFuture<Void> interrupt() {
								commands.add("interrupt");
								setState(TargetExecutionState.STOPPED);
								return super.interrupt();
							}

							@Override
							public CompletableFuture<Void> kill() {
								commands.add("kill");
								setState(TargetExecutionState.TERMINATED);
								return super.kill();
							}

							@Override
							public CompletableFuture<Void> step(TargetStepKind kind) {
								commands.add("step(" + kind + ")");
								setState(TargetExecutionState.RUNNING);
								setState(TargetExecutionState.STOPPED);
								return super.step(kind);
							}
						};
					}

					@Override
					public CompletableFuture<Void> close() {
						commands.add("close");
						return super.close();
					}
				};
			}
		};
	}

	@Override
	protected DebuggerTargetTraceMapper createTargetTraceMapper(TargetObject target)
			throws Exception {
		return new ObjectBasedDebuggerTargetTraceMapper(target,
			new LanguageID("DATA:BE:64:default"), new CompilerSpecID("pointer64"), Set.of());
	}

	@Override
	protected TraceRecorder recordAndWaitSync() throws Throwable {
		TraceRecorder recorder = super.recordAndWaitSync();
		useTrace(recorder.getTrace());
		return recorder;
	}

	@Override
	protected TargetObject chooseTarget() {
		return mb.testModel.session;
	}

	@Test
	public void testTargetResumeAction() throws Throwable {
		createTestModel();
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		waitOn(recorder.requestFocus(mb.testThread1));
		waitRecorder(recorder);
		waitForSwing();

		performEnabledAction(null, controlPlugin.actionTargetResume, true);
		waitRecorder(recorder);
		assertEquals(List.of("resume"), commands);
		waitForSwing();
		assertFalse(controlPlugin.actionTargetResume.isEnabled());
	}

	@Test
	public void testTargetInterruptAction() throws Throwable {
		createTestModel();
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		waitOn(recorder.requestFocus(mb.testThread1));
		waitRecorder(recorder);
		waitForSwing();

		assertFalse(controlPlugin.actionTargetInterrupt.isEnabled());
		waitOn(mb.testThread1.resume());
		waitRecorder(recorder);
		commands.clear();
		waitForSwing();

		performEnabledAction(null, controlPlugin.actionTargetInterrupt, true);
		waitRecorder(recorder);
		assertEquals(List.of("interrupt"), commands);
		waitForSwing();
		assertFalse(controlPlugin.actionTargetInterrupt.isEnabled());
	}

	@Test
	public void testTargetKillAction() throws Throwable {
		createTestModel();
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		waitOn(recorder.requestFocus(mb.testThread1));
		waitRecorder(recorder);
		waitForSwing();

		performEnabledAction(null, controlPlugin.actionTargetKill, true);
		waitRecorder(recorder);
		assertEquals(List.of("kill"), commands);
		waitForSwing();
		assertFalse(controlPlugin.actionTargetKill.isEnabled());
	}

	@Test
	public void testTargetDisconnectAction() throws Throwable {
		createTestModel();
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		performEnabledAction(null, controlPlugin.actionTargetDisconnect, true);
		waitRecorder(recorder);
		assertEquals(List.of("close"), commands);
		waitForSwing();
		waitForPass(() -> assertFalse(controlPlugin.actionTargetDisconnect.isEnabled()));
	}

	protected void runTestTargetStepAction(DockingAction action, TargetStepKind expected)
			throws Throwable {
		createTestModel();
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		waitOn(recorder.requestFocus(mb.testThread1));
		waitRecorder(recorder);
		waitForSwing();

		performEnabledAction(null, action, true);
		waitRecorder(recorder);
		assertEquals(List.of("step(" + expected + ")"), commands);
		waitForSwing();
		assertTrue(action.isEnabled());
	}

	@Test
	public void testTargetStepIntoAction() throws Throwable {
		runTestTargetStepAction(controlPlugin.actionTargetStepInto, TargetStepKind.INTO);
	}

	@Test
	public void testTargetStepOverAction() throws Throwable {
		runTestTargetStepAction(controlPlugin.actionTargetStepOver, TargetStepKind.OVER);
	}

	@Test
	public void testTargetStepFinishAction() throws Throwable {
		runTestTargetStepAction(controlPlugin.actionTargetStepFinish, TargetStepKind.FINISH);
	}

	TraceThread createToyLoopTrace() throws Throwable {
		createAndOpenTrace();

		Address start = tb.addr(0x00400000);
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			Assembler asm = Assemblers.getAssembler(tb.language);
			AssemblyBuffer buf = new AssemblyBuffer(asm, start);
			buf.assemble("br 0x" + start);

			thread = tb.getOrAddThread("Threads[0]", 0);
			tb.exec(0, thread, 0, "pc = 0x" + start + ";");
			tb.trace.getMemoryManager().putBytes(0, start, ByteBuffer.wrap(buf.getBytes()));
		}
		return thread;
	}

	@Test
	public void testEmulateResumeAction() throws Throwable {
		TraceThread thread = createToyLoopTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		traceManager.activateThread(thread);
		waitForSwing();

		performEnabledAction(null, controlPlugin.actionEmulateResume, true);
		waitForPass(() -> assertFalse(controlPlugin.actionEmulateResume.isEnabled()));

		CachedEmulator ce = Unique.assertOne(emulationService.getBusyEmulators());
		ce.emulator().setSuspended(true);
		waitForTasks();
		assertTrue(controlPlugin.actionEmulateResume.isEnabled());
	}

	@Test
	public void testEmulateInterruptAction() throws Throwable {
		TraceThread thread = createToyLoopTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		traceManager.activateThread(thread);
		waitForSwing();

		assertFalse(controlPlugin.actionEmulateInterrupt.isEnabled());

		CompletableFuture<EmulationResult> future = emulationService.backgroundRun(tb.host,
			TraceSchedule.snap(0), Scheduler.oneThread(thread));
		waitForPass(() -> assertTrue(controlPlugin.actionEmulateInterrupt.isEnabled()));

		performEnabledAction(null, controlPlugin.actionEmulateInterrupt, true);
		EmulationResult result = waitOn(future);
		assertTrue(result.error() instanceof SuspendedPcodeExecutionException);
		waitForTasks();

		assertFalse(controlPlugin.actionEmulateInterrupt.isEnabled());
	}

	@Test
	public void testEmulateStepBackAction() throws Throwable {
		TraceThread thread = createToyLoopTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		traceManager.activateThread(thread);
		waitForSwing();

		assertFalse(controlPlugin.actionEmulateStepBack.isEnabled());

		traceManager.activateTime(TraceSchedule.parse("0:t0-1"));
		waitForSwing();

		performEnabledAction(null, controlPlugin.actionEmulateStepBack, true);

		assertEquals(TraceSchedule.snap(0), traceManager.getCurrent().getTime());
		assertFalse(controlPlugin.actionEmulateStepBack.isEnabled());
	}

	@Test
	public void testEmulateStepIntoAction() throws Throwable {
		TraceThread thread = createToyLoopTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		traceManager.activateThread(thread);
		waitForSwing();

		performEnabledAction(null, controlPlugin.actionEmulateStepInto, true);

		assertEquals(TraceSchedule.parse("0:t0-1"), traceManager.getCurrent().getTime());
	}

	@Test
	public void testEmulateSkipOverAction() throws Throwable {
		TraceThread thread = createToyLoopTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		traceManager.activateThread(thread);
		waitForSwing();

		performEnabledAction(null, controlPlugin.actionEmulateSkipOver, true);

		assertEquals(TraceSchedule.parse("0:t0-s1"), traceManager.getCurrent().getTime());
	}

	protected void create2SnapTrace() throws Throwable {
		createAndOpenTrace();

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getTimeManager().getSnapshot(1, true);
		}
	}

	@Test
	public void testTraceSnapBackwardAction() throws Throwable {
		create2SnapTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertFalse(controlPlugin.actionTraceSnapBackward.isEnabled());

		traceManager.activateTime(TraceSchedule.snap(1));
		performEnabledAction(null, controlPlugin.actionTraceSnapBackward, true);

		assertEquals(TraceSchedule.snap(0), traceManager.getCurrent().getTime());
		assertFalse(controlPlugin.actionTraceSnapBackward.isEnabled());
	}

	@Test
	public void testTraceSnapForwardAction() throws Throwable {
		create2SnapTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		performEnabledAction(null, controlPlugin.actionTraceSnapForward, true);

		assertEquals(TraceSchedule.snap(1), traceManager.getCurrent().getTime());
		assertFalse(controlPlugin.actionTraceSnapForward.isEnabled());
	}

	@Test
	public void testPatchInstructionActionInDynamicListingEmu() throws Throwable {
		DebuggerDisassemblerPlugin disassemblerPlugin =
			addPlugin(tool, DebuggerDisassemblerPlugin.class);

		assertFalse(controlPlugin.actionControlMode.isEnabled());

		createAndOpenTrace();
		TraceVariableSnapProgramView view = tb.trace.getProgramView();
		try (Transaction tx = tb.startTransaction()) {
			tb.getOrAddThread("Threads[0]", 0);
			tb.trace.getMemoryManager()
					.createRegion("Memory[bin:.text]", 0, tb.range(0x00400000, 0x00401000),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			// Dynamic Patch Instruction requires existing code unit for context
			tb.addInstruction(0, tb.addr(0x00400123), tb.host);
		}

		CodeViewerProvider listingProvider = listingPlugin.getProvider();
		DebuggerDisassemblerPluginTestHelper helper =
			new DebuggerDisassemblerPluginTestHelper(disassemblerPlugin, listingProvider, view);

		traceManager.activateTrace(tb.trace);
		Swing.runNow(
			() -> listingProvider.goTo(view, new ProgramLocation(view, tb.addr(0x00400123))));
		waitForSwing();

		assertTrue(controlPlugin.actionControlMode.isEnabled());

		runSwing(() -> controlPlugin.actionControlMode
				.setCurrentActionStateByUserData(ControlMode.RO_TARGET));
		assertEquals(ControlMode.RO_TARGET, controlService.getCurrentMode(tb.trace));
		assertFalse(
			helper.patchInstructionAction.isAddToPopup(listingProvider.getActionContext(null)));

		runSwing(() -> controlPlugin.actionControlMode
				.setCurrentActionStateByUserData(ControlMode.RW_EMULATOR));
		assertEquals(ControlMode.RW_EMULATOR, controlService.getCurrentMode(tb.trace));

		assertTrue(
			helper.patchInstructionAction.isAddToPopup(listingProvider.getActionContext(null)));
		Instruction ins =
			helper.patchInstructionAt(tb.addr(0x00400123), "imm r0,#0x0", "imm r0,#0x3d2");
		assertEquals(2, ins.getLength());

		long snap = traceManager.getCurrent().getViewSnap();
		assertTrue(Lifespan.isScratch(snap));
		byte[] bytes = new byte[2];
		view.getMemory().getBytes(tb.addr(0x00400123), bytes);
		assertArrayEquals(tb.arr(0x30, 0xd2), bytes);
	}

	@Test
	public void testPatchDataActionInDynamicListingEmu() throws Throwable {
		AssemblerPlugin assemblerPlugin = addPlugin(tool, AssemblerPlugin.class);

		assertFalse(controlPlugin.actionControlMode.isEnabled());

		createAndOpenTrace();
		TraceVariableSnapProgramView view = tb.trace.getProgramView();
		try (Transaction tx = tb.startTransaction()) {
			tb.getOrAddThread("Threads[0]", 0);
			tb.trace.getMemoryManager()
					.createRegion("Memory[bin:.text]", 0, tb.range(0x00400000, 0x00401000),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			tb.trace.getCodeManager()
					.definedData()
					.create(Lifespan.nowOn(0), tb.addr(0x00400123), ShortDataType.dataType);
		}

		CodeViewerProvider listingProvider = listingPlugin.getProvider();
		AssemblerPluginTestHelper helper =
			new AssemblerPluginTestHelper(assemblerPlugin, listingProvider, view);

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertTrue(controlPlugin.actionControlMode.isEnabled());

		runSwing(() -> controlPlugin.actionControlMode
				.setCurrentActionStateByUserData(ControlMode.RO_TARGET));
		assertEquals(ControlMode.RO_TARGET, controlService.getCurrentMode(tb.trace));
		assertFalse(helper.patchDataAction.isAddToPopup(listingProvider.getActionContext(null)));

		runSwing(() -> controlPlugin.actionControlMode
				.setCurrentActionStateByUserData(ControlMode.RW_EMULATOR));
		assertEquals(ControlMode.RW_EMULATOR, controlService.getCurrentMode(tb.trace));

		goTo(listingProvider.getListingPanel(), new ProgramLocation(view, tb.addr(0x00400123)));
		assertTrue(helper.patchDataAction.isAddToPopup(listingProvider.getActionContext(null)));

		/**
		 * TODO: There's a bug in the trace forking: Data units are not replaced when bytes changed.
		 * Thus, we'll make no assertions about the data unit.
		 */
		/*Data data =*/ helper.patchDataAt(tb.addr(0x00400123), "0h", "5h");
		// assertEquals(2, data.getLength());

		long snap = traceManager.getCurrent().getViewSnap();
		assertTrue(Lifespan.isScratch(snap));
		byte[] bytes = new byte[2];
		view.getMemory().getBytes(tb.addr(0x00400123), bytes);
		assertArrayEquals(tb.arr(0, 5), bytes);
	}

	@Test
	public void testPasteActionInDynamicListingEmu() throws Throwable {
		addPlugin(tool, ClipboardPlugin.class);

		CodeViewerProvider listingProvider = listingPlugin.getProvider();
		DockingActionIf pasteAction = getLocalAction(listingProvider, "Paste");

		assertFalse(controlPlugin.actionControlMode.isEnabled());

		createAndOpenTrace();
		TraceVariableSnapProgramView view = tb.trace.getProgramView();
		try (Transaction tx = tb.startTransaction()) {
			tb.getOrAddThread("Threads[0]", 0);
			tb.trace.getMemoryManager()
					.createRegion("Memory[bin:.text]", 0, tb.range(0x00400000, 0x00401000),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		ActionContext ctx;

		assertTrue(controlPlugin.actionControlMode.isEnabled());

		runSwing(() -> controlPlugin.actionControlMode
				.setCurrentActionStateByUserData(ControlMode.RO_TARGET));
		assertEquals(ControlMode.RO_TARGET, controlService.getCurrentMode(tb.trace));
		ctx = listingProvider.getActionContext(null);
		assertTrue(pasteAction.isAddToPopup(ctx));
		assertFalse(pasteAction.isEnabledForContext(ctx));

		runSwing(() -> controlPlugin.actionControlMode
				.setCurrentActionStateByUserData(ControlMode.RW_EMULATOR));
		assertEquals(ControlMode.RW_EMULATOR, controlService.getCurrentMode(tb.trace));

		goTo(listingPlugin.getListingPanel(), new ProgramLocation(view, tb.addr(0x00400123)));
		ctx = listingProvider.getActionContext(null);
		assertTrue(pasteAction.isAddToPopup(ctx));
		assertFalse(pasteAction.isEnabledForContext(ctx));

		Clipboard clipboard = GClipboard.getSystemClipboard();
		clipboard.setContents(new StringSelection("12 34 56 78"), null);
		ctx = listingProvider.getActionContext(null);
		assertTrue(pasteAction.isAddToPopup(ctx));
		assertTrue(pasteAction.isEnabledForContext(ctx));

		performAction(pasteAction, listingProvider, false);
		OptionDialog confirm = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(confirm, "Yes");

		byte[] bytes = new byte[4];
		waitForPass(noExc(() -> {
			long snap = traceManager.getCurrent().getViewSnap();
			assertTrue(Lifespan.isScratch(snap));
			view.getMemory().getBytes(tb.addr(0x00400123), bytes);
			assertArrayEquals(tb.arr(0x12, 0x34, 0x56, 0x78), bytes);
		}));
	}
}
