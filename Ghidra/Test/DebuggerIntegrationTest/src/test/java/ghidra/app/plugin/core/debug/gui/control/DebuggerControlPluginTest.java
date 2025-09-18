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
import java.util.function.Supplier;

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
import ghidra.app.plugin.core.clipboard.ClipboardPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.disassemble.DebuggerDisassemblerPlugin;
import ghidra.app.plugin.core.debug.disassemble.DebuggerDisassemblerPluginTestHelper;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerIntegrationTest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin;
import ghidra.app.plugin.core.debug.service.tracermi.TestTraceRmiConnection.TestRemoteMethod;
import ghidra.app.services.DebuggerControlService;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.app.services.DebuggerEmulationService.CachedEmulator;
import ghidra.app.services.DebuggerEmulationService.EmulationResult;
import ghidra.debug.api.control.ControlMode;
import ghidra.pcode.exec.SuspendedPcodeExecutionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.ToyDBTraceBuilder.ToySchemaBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.TraceExecutionState;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.program.TraceVariableSnapProgramView;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.schema.SchemaContext;
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
public class DebuggerControlPluginTest extends AbstractGhidraHeadedDebuggerIntegrationTest {

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
	}

	protected TraceObject setUpRmiTarget() throws Throwable {
		createRmiConnection();
		addControlMethods();
		createTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();
		}
		rmiCx.publishTarget(tool, tb.trace);
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		return Objects.requireNonNull(tb.obj("Processes[1]"));
	}

	protected void assertInTool(DockingAction action) {
		assertNotNull(action);
		assertTrue(tool.getDockingActionsByOwnerName(controlPlugin.getName()).contains(action));
	}

	@Test
	public void testRmiTargetResumeAction() throws Throwable {
		TraceObject proc1 = setUpRmiTarget();
		traceManager.activateObject(proc1);
		waitForSwing();

		DockingAction actionTargetResume = controlPlugin.actionTargetResume;
		assertInTool(actionTargetResume);
		performEnabledAction(null, actionTargetResume, true);

		Map<String, Object> args = rmiMethodResume.expect();
		try (Transaction tx = tb.startTransaction()) {
			proc1.setAttribute(Lifespan.nowOn(0), "_state", TraceExecutionState.RUNNING.name());
		}
		rmiMethodResume.result(null);
		assertEquals(Map.ofEntries(
			Map.entry("process", proc1)),
			args);
		waitForTasks();
		waitForDomainObject(tb.trace);

		assertFalse(actionTargetResume.isEnabled());
	}

	@Test
	public void testRmiTargetInterruptAction() throws Throwable {
		TraceObject proc1 = setUpRmiTarget();
		traceManager.activateObject(proc1);
		waitForSwing();

		DockingAction actionTargetInterrupt = controlPlugin.actionTargetInterrupt;
		assertInTool(actionTargetInterrupt);
		assertFalse(actionTargetInterrupt.isEnabled());

		try (Transaction tx = tb.startTransaction()) {
			proc1.setAttribute(Lifespan.nowOn(0), "_state", TraceExecutionState.RUNNING.name());
		}
		waitForDomainObject(tb.trace);

		performEnabledAction(null, actionTargetInterrupt, true);

		Map<String, Object> args = rmiMethodInterrupt.expect();
		try (Transaction tx = tb.startTransaction()) {
			proc1.setAttribute(Lifespan.nowOn(0), "_state", TraceExecutionState.STOPPED.name());
		}
		rmiMethodInterrupt.result(null);
		assertEquals(Map.ofEntries(
			Map.entry("process", proc1)),
			args);
		waitForTasks();
		waitForDomainObject(tb.trace);

		assertFalse(actionTargetInterrupt.isEnabled());
	}

	@Test
	public void testRmiTargetKillAction() throws Throwable {
		TraceObject proc1 = setUpRmiTarget();
		traceManager.activateObject(proc1);
		waitForSwing();

		DockingAction actionTargetKill = controlPlugin.actionTargetKill;
		assertInTool(actionTargetKill);
		performEnabledAction(null, actionTargetKill, true);

		Map<String, Object> args = rmiMethodKill.expect();
		try (Transaction tx = tb.startTransaction()) {
			proc1.setAttribute(Lifespan.nowOn(0), "_state", TraceExecutionState.TERMINATED.name());
		}
		rmiMethodKill.result(null);
		assertEquals(Map.ofEntries(
			Map.entry("process", proc1)),
			args);
		waitForTasks();
		waitForDomainObject(tb.trace);

		assertFalse(actionTargetKill.isEnabled());
	}

	@Test
	public void testRmiTargetDisconnectAction() throws Throwable {
		TraceObject proc1 = setUpRmiTarget();
		traceManager.activateObject(proc1);
		waitForSwing();
		assertFalse(rmiCx.isClosed());

		DockingAction actionTargetDisconnect = controlPlugin.actionTargetDisconnect;
		assertInTool(actionTargetDisconnect);
		performEnabledAction(null, actionTargetDisconnect, true);
		waitForTasks();

		assertTrue(rmiCx.isClosed());

		waitForPass(() -> assertFalse(actionTargetDisconnect.isEnabled()));
	}

	protected void runTestRmiTargetStepAction(Supplier<DockingAction> actionSupplier,
			Supplier<TestRemoteMethod> methodSupplier) throws Throwable {
		setUpRmiTarget(); // method is created here, so we accept a supplier
		TraceObject thread1 = tb.obj("Processes[1].Threads[1]");
		traceManager.activateObject(thread1);
		waitForSwing();

		DockingAction action = actionSupplier.get();
		assertInTool(action);
		performEnabledAction(null, action, true);

		TestRemoteMethod method = methodSupplier.get();
		// NB. Provide a result before asserting
		Map<String, Object> args = method.expect();
		// No state change, or brief state change
		method.result(null);
		assertEquals(Map.ofEntries(
			Map.entry("thread", thread1)),
			args);
		waitForTasks();
		waitForDomainObject(tb.trace);

		assertTrue(action.isEnabled());
	}

	@Test
	public void testRmiTargetStepIntoAction() throws Throwable {
		runTestRmiTargetStepAction(() -> controlPlugin.actionTargetStepInto,
			() -> rmiMethodStepInto);
	}

	@Test
	public void testRmiTargetStepOverAction() throws Throwable {
		runTestRmiTargetStepAction(() -> controlPlugin.actionTargetStepOver,
			() -> rmiMethodStepOver);
	}

	@Test
	public void testRmiTargetStepOutAction() throws Throwable {
		runTestRmiTargetStepAction(() -> controlPlugin.actionTargetStepOut,
			() -> rmiMethodStepOut);
	}

	SchemaContext buildContext() {
		return new ToySchemaBuilder()
				.noRegisterGroups()
				.useRegistersPerFrame()
				.build();
	}

	TraceThread createToyLoopTrace() throws Throwable {
		createAndOpenTrace();

		Address start = tb.addr(0x00400000);
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			tb.createRootObject(buildContext(), "Target");
			Assembler asm = Assemblers.getAssembler(tb.language);
			AssemblyBuffer buf = new AssemblyBuffer(asm, start);
			buf.assemble("br 0x" + start);

			thread = tb.getOrAddThread("Threads[0]", 0);
			tb.createObjectsFramesAndRegs(thread, Lifespan.nowOn(0), tb.host, 1);
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

	/**
	 * Tests the UI so it does not error when the user presses resume after already stepping into a
	 * p-code instruction.
	 * 
	 * @throws Throwable because
	 */
	@Test
	public void testEmulateResumeActionAfterPcodeStep() throws Throwable {
		TraceThread thread = createToyLoopTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		traceManager.activateThread(thread);
		traceManager.activateTime(TraceSchedule.parse("0:.t%d-2".formatted(thread.getKey())));
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

		traceManager.activateTime(TraceSchedule.parse("0:t%d-1".formatted(thread.getKey())));
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

		assertEquals(TraceSchedule.parse("0:t%d-1".formatted(thread.getKey())),
			traceManager.getCurrent().getTime());
	}

	@Test
	public void testEmulateSkipOverAction() throws Throwable {
		TraceThread thread = createToyLoopTrace();
		controlService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);

		traceManager.activateThread(thread);
		waitForSwing();

		performEnabledAction(null, controlPlugin.actionEmulateSkipOver, true);

		assertEquals(TraceSchedule.parse("0:t%d-s1".formatted(thread.getKey())),
			traceManager.getCurrent().getTime());
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
			tb.createRootObject("Target");
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
		DebuggerDisassemblerPlugin disassemblerPlugin =
			addPlugin(tool, DebuggerDisassemblerPlugin.class);

		assertFalse(controlPlugin.actionControlMode.isEnabled());

		createAndOpenTrace();
		TraceVariableSnapProgramView view = tb.trace.getProgramView();
		try (Transaction tx = tb.startTransaction()) {
			tb.createRootObject("Target");
			tb.getOrAddThread("Threads[0]", 0);
			tb.trace.getMemoryManager()
					.createRegion("Memory[bin:.text]", 0, tb.range(0x00400000, 0x00401000),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			tb.trace.getCodeManager()
					.definedData()
					.create(Lifespan.nowOn(0), tb.addr(0x00400123), ShortDataType.dataType);
		}

		CodeViewerProvider listingProvider = listingPlugin.getProvider();
		DebuggerDisassemblerPluginTestHelper helper =
			new DebuggerDisassemblerPluginTestHelper(disassemblerPlugin, listingProvider, view);

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
			tb.createRootObject("Target");
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
