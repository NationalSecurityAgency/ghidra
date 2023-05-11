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
package ghidra.app.plugin.core.debug.gui.breakpoint;

import static org.junit.Assert.*;

import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import db.Transaction;
import docking.widgets.table.RowWrappedEnumeratedColumnTableModel;
import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsProvider.LogicalBreakpointTableModel;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsolePlugin;
import ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.services.*;
import ghidra.app.services.LogicalBreakpoint.State;
import ghidra.dbg.model.TestTargetProcess;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class DebuggerBreakpointsProviderTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected static final long TIMEOUT_MILLIS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

	protected DebuggerBreakpointsPlugin breakpointsPlugin;
	protected DebuggerBreakpointsProvider breakpointsProvider;
	protected DebuggerStaticMappingService mappingService;
	protected DebuggerLogicalBreakpointService breakpointService;

	@Before
	public void setUpBreakpointsProviderTest() throws Exception {
		breakpointsPlugin = addPlugin(tool, DebuggerBreakpointsPlugin.class);
		breakpointsProvider = waitForComponentProvider(DebuggerBreakpointsProvider.class);
		mappingService = tool.getService(DebuggerStaticMappingService.class);
		breakpointService = tool.getService(DebuggerLogicalBreakpointService.class);
	}

	protected void waitAndFlush(TraceRecorder recorder) throws Throwable {
		waitOn(recorder.getTarget().getModel().flushEvents());
		waitOn(recorder.flushTransactions());
		waitForDomainObject(recorder.getTrace());
	}

	protected void addMapping(Trace trace, Program prog) throws Exception {
		try (Transaction tx = trace.openTransaction("Add mapping")) {
			DebuggerStaticMappingUtils.addMapping(
				new DefaultTraceLocation(trace, null, Lifespan.nowOn(0), addr(trace, 0x55550000)),
				new ProgramLocation(prog, addr(prog, 0x00400000)), 0x1000, false);
		}
	}

	protected void addLiveMemoryAndBreakpoint(TestTargetProcess process, TraceRecorder recorder)
			throws Exception {
		process.addRegion("bin:.text", mb.rng(0x55550000, 0x55550fff), "rx");
		addLiveBreakpoint(recorder, 0x55550123);
	}

	protected void addLiveBreakpoint(TraceRecorder recorder, long offset) throws Exception {
		TargetBreakpointSpecContainer cont = getBreakpointContainer(recorder);
		cont.placeBreakpoint(mb.addr(offset), Set.of(TargetBreakpointKind.SW_EXECUTE))
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
	}

	protected void addStaticMemoryAndBreakpoint() throws LockException, DuplicateNameException,
			MemoryConflictException, AddressOverflowException, CancelledException {
		try (Transaction tx = program.openTransaction("Add bookmark break")) {
			program.getMemory()
					.createInitializedBlock(".text", addr(program, 0x00400000), 0x1000, (byte) 0,
						TaskMonitor.DUMMY, false);
			program.getBookmarkManager()
					.setBookmark(addr(program, 0x00400123),
						LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE, "SW_EXECUTE;1", "");
		}
	}

	protected void assertProviderEmpty() {
		assertTrue(breakpointsProvider.breakpointTableModel.getModelData().isEmpty());
	}

	@Test
	public void testEmpty() throws Exception {
		waitForSwing();
		assertProviderEmpty();
	}

	@Test
	public void testAddLiveOpenTracePopulatesProvider() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		Trace trace = recorder.getTrace();

		addLiveMemoryAndBreakpoint(mb.testProcess1, recorder);
		waitOn(mb.testModel.flushEvents());
		waitForDomainObject(trace);

		// NB, optionally open trace. Mapping only works if open...
		traceManager.openTrace(trace);
		waitForSwing();

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		assertEquals("55550123", row.getAddress().toString());
		assertEquals(trace, row.getDomainObject());
		assertEquals("SW_EXECUTE", row.getKinds());
		assertEquals(State.INCONSISTENT_ENABLED, row.getState());
	}

	@Test
	public void testToggleLiveViaTable() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		Trace trace = recorder.getTrace();

		addLiveMemoryAndBreakpoint(mb.testProcess1, recorder);
		waitForDomainObject(trace);

		traceManager.openTrace(trace);
		waitForSwing();

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		assertEquals(State.INCONSISTENT_ENABLED, row.getState());

		// NB, the row does not take the value immediately, but via async callbacks
		row.setEnabled(false);

		waitForPass(() -> assertEquals(State.INCONSISTENT_DISABLED, row.getState()));

		row.setEnabled(true);

		waitForPass(() -> assertEquals(State.INCONSISTENT_ENABLED, row.getState()));
	}

	@Test
	public void testOpenProgramAddBookmarkPopulatesProvider() throws Exception {
		createProgram();
		programManager.openProgram(program);
		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		assertEquals("00400123", row.getAddress().toString());
		assertEquals(program, row.getDomainObject());
		assertEquals("SW_EXECUTE", row.getKinds());
		assertEquals(State.INEFFECTIVE_ENABLED, row.getState());
	}

	@Test
	public void testToggleStaticViaTable() throws Exception {
		createProgram();
		programManager.openProgram(program);
		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		assertEquals(State.INEFFECTIVE_ENABLED, row.getState());

		row.setEnabled(false); // Synchronous, but on swing thread
		waitForDomainObject(program);

		assertEquals(State.INEFFECTIVE_DISABLED, row.getState());

		row.setEnabled(true);
		waitForDomainObject(program);

		assertEquals(State.INEFFECTIVE_ENABLED, row.getState());
	}

	@Test
	public void testEnablementColumnMapped() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		Trace trace = recorder.getTrace();
		createProgramFromTrace(trace);
		intoProject(trace);
		intoProject(program);

		addMapping(trace, program);
		addLiveMemoryAndBreakpoint(mb.testProcess1, recorder);
		addStaticMemoryAndBreakpoint();
		programManager.openProgram(program);
		traceManager.openTrace(trace);
		// Because mapping service debounces, wait for breakpoints to be reconciled
		waitForPass(() -> {
			LogicalBreakpointRow row =
				Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
			LogicalBreakpoint lb = row.getLogicalBreakpoint();
			assertEquals(program, lb.getProgram());
			assertEquals(Set.of(trace), lb.getParticipatingTraces());
			assertEquals(State.ENABLED, row.getState());
		});

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		LogicalBreakpoint lb = row.getLogicalBreakpoint();

		lb.disableForProgram();
		waitForDomainObject(program);

		waitForPass(() -> assertEquals(State.INCONSISTENT_DISABLED, row.getState()));

		// NOTE: This acts on the corresponding target, not directly on trace
		waitOn(lb.disableForTrace(trace));
		waitAndFlush(recorder);

		waitForPass(() -> assertEquals(State.DISABLED, row.getState()));

		lb.enableForProgram();
		waitForDomainObject(program);

		waitForPass(() -> assertEquals(State.INCONSISTENT_ENABLED, row.getState()));

		// This duplicates the initial case, but without it, I just feel incomplete
		waitOn(lb.enableForTrace(trace));
		waitAndFlush(recorder);

		waitForPass(() -> assertEquals(State.ENABLED, row.getState()));
	}

	@Test
	public void testRenameStaticViaTable() throws Exception {
		createProgram();
		programManager.openProgram(program);
		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		assertEquals("", row.getName());

		row.setName("Test name");
		waitForDomainObject(program);

		assertEquals("Test name", row.getName());

		// Check that name persists, since bookmark is swapped
		row.setEnabled(false);
		waitForDomainObject(program);

		assertEquals("Test name", row.getName());
	}

	// TODO: Test a scenario where one spec manifests two breaks, select both, and perform actions

	// TODO: Test a scenario where one spec manifests the same mapped breakpoint in two traces

	@Test
	public void testActionEnableSelectedBreakpoints() throws Throwable {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		assertFalse(breakpointsProvider.actionEnableSelectedBreakpoints.isEnabled());

		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		assertFalse(breakpointsProvider.actionEnableSelectedBreakpoints.isEnabled());

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		row.setEnabled(false);
		breakpointsProvider.breakpointFilterPanel.setSelectedItem(row);
		waitForSwing();

		assertEquals(State.INEFFECTIVE_DISABLED, row.getState());
		assertTrue(breakpointsProvider.actionEnableSelectedBreakpoints.isEnabled());

		performAction(breakpointsProvider.actionEnableSelectedBreakpoints);

		assertEquals(State.INEFFECTIVE_ENABLED, row.getState());
		assertTrue(breakpointsProvider.actionEnableSelectedBreakpoints.isEnabled());

		breakpointsProvider.breakpointTable.clearSelection();
		waitForSwing();

		assertFalse(breakpointsProvider.actionEnableSelectedBreakpoints.isEnabled());

		breakpointsProvider.breakpointFilterPanel.setSelectedItem(row);
		waitForSwing();

		assertTrue(breakpointsProvider.actionEnableSelectedBreakpoints.isEnabled());

		// Bookmark part should actually be synchronous.
		waitOn(row.getLogicalBreakpoint().delete());
		waitForDomainObject(program);

		assertFalse(breakpointsProvider.actionEnableSelectedBreakpoints.isEnabled());
	}

	@Test
	public void testActionEnableAllBreakpoints() throws Exception {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		assertFalse(breakpointsProvider.actionEnableAllBreakpoints.isEnabled());

		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		assertTrue(breakpointsProvider.actionEnableAllBreakpoints.isEnabled());

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		row.setEnabled(false);
		waitForSwing();

		assertEquals(State.INEFFECTIVE_DISABLED, row.getState());
		assertTrue(breakpointsProvider.actionEnableAllBreakpoints.isEnabled());

		performAction(breakpointsProvider.actionEnableAllBreakpoints);

		assertEquals(State.INEFFECTIVE_ENABLED, row.getState());
		assertTrue(breakpointsProvider.actionEnableAllBreakpoints.isEnabled());

		// Bookmark part should actually be synchronous.
		row.getLogicalBreakpoint().delete().get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		waitForDomainObject(program);

		assertFalse(breakpointsProvider.actionEnableAllBreakpoints.isEnabled());
	}

	@Test
	public void testActionDisableSelectedBreakpoints() throws Throwable {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		assertFalse(breakpointsProvider.actionDisableSelectedBreakpoints.isEnabled());

		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		assertFalse(breakpointsProvider.actionDisableSelectedBreakpoints.isEnabled());

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		breakpointsProvider.breakpointFilterPanel.setSelectedItem(row);
		waitForSwing();

		waitForPass(() -> assertEquals(State.INEFFECTIVE_ENABLED, row.getState()));
		assertTrue(breakpointsProvider.actionDisableSelectedBreakpoints.isEnabled());

		performAction(breakpointsProvider.actionDisableSelectedBreakpoints);

		waitForPass(() -> assertEquals(State.INEFFECTIVE_DISABLED, row.getState()));
		assertTrue(breakpointsProvider.actionDisableSelectedBreakpoints.isEnabled());

		breakpointsProvider.breakpointTable.clearSelection();
		waitForSwing();

		assertFalse(breakpointsProvider.actionDisableSelectedBreakpoints.isEnabled());

		breakpointsProvider.breakpointFilterPanel.setSelectedItem(row);
		waitForSwing();

		assertTrue(breakpointsProvider.actionDisableSelectedBreakpoints.isEnabled());

		// Bookmark part should actually be synchronous.
		waitOn(row.getLogicalBreakpoint().delete());
		waitForDomainObject(program);

		assertFalse(breakpointsProvider.actionDisableSelectedBreakpoints.isEnabled());
	}

	@Test
	public void testActionDisableAllBreakpoints() throws Exception {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		assertFalse(breakpointsProvider.actionDisableAllBreakpoints.isEnabled());

		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		assertTrue(breakpointsProvider.actionDisableAllBreakpoints.isEnabled());
		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		assertEquals(State.INEFFECTIVE_ENABLED, row.getState());
		assertTrue(breakpointsProvider.actionDisableAllBreakpoints.isEnabled());

		performAction(breakpointsProvider.actionDisableAllBreakpoints);

		assertEquals(State.INEFFECTIVE_DISABLED, row.getState());
		assertTrue(breakpointsProvider.actionDisableAllBreakpoints.isEnabled());

		// Bookmark part should actually be synchronous.
		row.getLogicalBreakpoint().delete().get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		waitForDomainObject(program);

		assertFalse(breakpointsProvider.actionDisableAllBreakpoints.isEnabled());
	}

	@Test
	public void testActionClearSelectedBreakpoints() throws Exception {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		assertFalse(breakpointsProvider.actionClearSelectedBreakpoints.isEnabled());

		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		assertFalse(breakpointsProvider.actionClearSelectedBreakpoints.isEnabled());

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		breakpointsProvider.breakpointFilterPanel.setSelectedItem(row);
		waitForSwing();

		assertTrue(breakpointsProvider.actionClearSelectedBreakpoints.isEnabled());

		breakpointsProvider.breakpointTable.clearSelection();
		waitForSwing();

		assertFalse(breakpointsProvider.actionClearSelectedBreakpoints.isEnabled());

		breakpointsProvider.breakpointFilterPanel.setSelectedItem(row);
		waitForSwing();

		assertTrue(breakpointsProvider.actionClearSelectedBreakpoints.isEnabled());

		performAction(breakpointsProvider.actionClearSelectedBreakpoints);

		assertProviderEmpty();
		assertFalse(breakpointsProvider.actionClearSelectedBreakpoints.isEnabled());
	}

	@Test
	public void testActionClearAllBreakpoints() throws Exception {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		assertFalse(breakpointsProvider.actionClearAllBreakpoints.isEnabled());

		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		assertTrue(breakpointsProvider.actionClearAllBreakpoints.isEnabled());

		performAction(breakpointsProvider.actionClearAllBreakpoints);

		assertProviderEmpty();
		assertFalse(breakpointsProvider.actionClearAllBreakpoints.isEnabled());
	}

	@Test
	public void testActionMakeBreakpointsEffective() throws Exception {
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		Trace trace = recorder.getTrace();
		createProgramFromTrace(trace);
		intoProject(trace);
		intoProject(program);

		assertFalse(breakpointsProvider.actionMakeBreakpointsEffective.isEnabled());
		programManager.openProgram(program);
		assertFalse(breakpointsProvider.actionMakeBreakpointsEffective.isEnabled());
		traceManager.openTrace(trace);
		assertFalse(breakpointsProvider.actionMakeBreakpointsEffective.isEnabled());
		addStaticMemoryAndBreakpoint();
		assertFalse(breakpointsProvider.actionMakeBreakpointsEffective.isEnabled());

		addMapping(trace, program);
		waitForPass(() -> {
			assertTrue(breakpointsProvider.actionMakeBreakpointsEffective.isEnabled());
			assertEquals(1,
				consolePlugin.getRowCount(DebuggerMakeBreakpointsEffectiveActionContext.class));
		});

		performAction(breakpointsProvider.actionMakeBreakpointsEffective);

		waitForPass(() -> {
			assertFalse(breakpointsProvider.actionMakeBreakpointsEffective.isEnabled());
			assertEquals(0,
				consolePlugin.getRowCount(DebuggerMakeBreakpointsEffectiveActionContext.class));
		});
	}

	protected static <R> List<R> copyModelData(
			RowWrappedEnumeratedColumnTableModel<?, ?, R, ?> model) {
		synchronized (model) {
			return List.copyOf(model.getModelData());
		}
	}

	@Test
	public void testActionFilters() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder1 = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		Trace trace1 = recorder1.getTrace();

		TraceRecorder recorder3 = modelService.recordTarget(mb.testProcess3,
			createTargetTraceMapper(mb.testProcess3), ActionSource.AUTOMATIC);
		Trace trace3 = recorder3.getTrace();

		createProgramFromTrace(trace1);
		intoProject(trace1);
		intoProject(trace3);
		intoProject(program);

		addMapping(trace1, program);
		addMapping(trace3, program);
		addLiveMemoryAndBreakpoint(mb.testProcess1, recorder1);
		addLiveBreakpoint(recorder1, 0x55550321);
		addLiveMemoryAndBreakpoint(mb.testProcess3, recorder3);
		addLiveBreakpoint(recorder3, 0x55550321);
		waitRecorder(recorder1);
		waitRecorder(recorder3);
		addStaticMemoryAndBreakpoint();
		// Note, no program breakpoint for 0321...

		programManager.openProgram(program);
		traceManager.openTrace(trace1);
		CompletableFuture<Void> mappingsSettled = mappingService.changesSettled();
		CompletableFuture<Void> breakpointsSettled = breakpointService.changesSettled();
		traceManager.openTrace(trace3);
		waitForSwing();
		waitOn(mappingsSettled);
		waitOn(breakpointsSettled);
		waitForSwing();

		LogicalBreakpointTableModel bptModel = breakpointsProvider.breakpointTableModel;

		List<LogicalBreakpointRow> data = copyModelData(bptModel);
		assertEquals(2, data.size());
		LogicalBreakpointRow row1 = data.get(0);
		LogicalBreakpointRow row2 = data.get(1);
		LogicalBreakpoint lb1 = row1.getLogicalBreakpoint();
		LogicalBreakpoint lb2 = row2.getLogicalBreakpoint();
		assertEquals(program, lb1.getProgram());
		assertEquals(program, lb2.getProgram());
		assertEquals(addr(program, 0x00400123), lb1.getAddress());
		assertEquals(addr(program, 0x00400321), lb2.getAddress());
		assertEquals(Set.of(trace1, trace3), lb1.getParticipatingTraces());
		assertEquals(Set.of(trace1, trace3), lb2.getParticipatingTraces());

		// Sanity check / experiment: Equal fields, but from different traces
		TraceBreakpoint bl1t1 = Unique.assertOne(lb1.getTraceBreakpoints(trace1));
		TraceBreakpoint bl1t3 = Unique.assertOne(lb1.getTraceBreakpoints(trace3));
		assertNotEquals(bl1t1, bl1t3);

		// OK, back to work
		assertEquals(2, lb1.getTraceBreakpoints().size());
		assertEquals(2, lb2.getTraceBreakpoints().size());

		List<BreakpointLocationRow> filtLocs =
			breakpointsProvider.locationFilterPanel.getTableFilterModel().getModelData();

		for (LogicalBreakpointRow breakRow : data) {
			assertEquals(2, breakRow.getLocationCount());
		}
		assertEquals(4, filtLocs.size());

		assertTrue(breakpointsProvider.actionFilterByCurrentTrace.isEnabled());
		performAction(breakpointsProvider.actionFilterByCurrentTrace);

		// No trace active, so empty :)
		data = copyModelData(bptModel);
		filtLocs = breakpointsProvider.locationFilterPanel.getTableFilterModel().getModelData();
		for (LogicalBreakpointRow breakRow : data) {
			assertEquals(0, breakRow.getLocationCount());
		}
		assertEquals(0, filtLocs.size());

		traceManager.activateTrace(trace1);
		waitForSwing();

		data = copyModelData(bptModel);
		filtLocs = breakpointsProvider.locationFilterPanel.getTableFilterModel().getModelData();
		for (LogicalBreakpointRow breakRow : data) {
			assertEquals(1, breakRow.getLocationCount());
		}
		assertEquals(2, filtLocs.size());

		assertTrue(breakpointsProvider.actionFilterLocationsByBreakpoints.isEnabled());
		performAction(breakpointsProvider.actionFilterLocationsByBreakpoints);

		// No breakpoint selected, so no change, yet.
		data = copyModelData(bptModel);
		filtLocs = breakpointsProvider.locationFilterPanel.getTableFilterModel().getModelData();
		for (LogicalBreakpointRow breakRow : data) {
			assertEquals(1, breakRow.getLocationCount());
		}
		assertEquals(2, filtLocs.size());

		LogicalBreakpointRow bpRow = data.get(0);
		runSwing(() -> breakpointsProvider
				.setSelectedBreakpoints(Set.of(bpRow.getLogicalBreakpoint())));
		waitForSwing();

		filtLocs = breakpointsProvider.locationFilterPanel.getTableFilterModel().getModelData();
		assertEquals(1, filtLocs.size());

		assertTrue(breakpointsProvider.actionFilterByCurrentTrace.isEnabled());
		performAction(breakpointsProvider.actionFilterByCurrentTrace);

		data = copyModelData(bptModel);
		filtLocs = breakpointsProvider.locationFilterPanel.getTableFilterModel().getModelData();
		for (LogicalBreakpointRow breakRow : data) {
			assertEquals(2, breakRow.getLocationCount());
		}
		assertEquals(2, filtLocs.size());
	}

	public static final Set<String> POPUP_ACTIONS = Set.of(
		AbstractEnableSelectedBreakpointsAction.NAME, AbstractDisableSelectedBreakpointsAction.NAME,
		AbstractClearSelectedBreakpointsAction.NAME);

	@Test
	public void testPopupActionsOnBreakpointSelections() throws Exception {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		addStaticMemoryAndBreakpoint();
		waitForProgram(program);

		// NOTE: the row becomes selected by right-click
		clickTableCellWithButton(breakpointsProvider.breakpointTable, 0, 0, MouseEvent.BUTTON3);
		waitForSwing();
		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractEnableSelectedBreakpointsAction.NAME,
				AbstractDisableSelectedBreakpointsAction.NAME,
				AbstractClearSelectedBreakpointsAction.NAME));

		// NOTE: With no selection, no actions (even table built-in) apply, so no menu
	}

	@Test
	public void testEmuBreakpointState() throws Throwable {
		addPlugin(tool, DebuggerControlServicePlugin.class);

		createProgram();
		intoProject(program);
		programManager.openProgram(program);
		waitForSwing();

		addStaticMemoryAndBreakpoint();
		waitForProgram(program);

		LogicalBreakpointRow row = waitForValue(
			() -> Unique.assertAtMostOne(breakpointsProvider.breakpointTableModel.getModelData()));
		assertEquals(State.INEFFECTIVE_ENABLED, row.getState());

		// Do our own launch, so that object mode is enabled during load (region creation)
		createTrace(program.getLanguageID().getIdAsString());
		try (Transaction startTransaction = tb.startTransaction()) {
			TraceSnapshot initial = tb.trace.getTimeManager().getSnapshot(0, true);
			ProgramEmulationUtils.loadExecutable(initial, program);
			Address pc = program.getMinAddress();
			ProgramEmulationUtils.doLaunchEmulationThread(tb.trace, 0, program, pc, pc);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		waitOn(mappingService.changesSettled());
		waitOn(breakpointService.changesSettled());
		waitForSwing();

		row = waitForValue(
			() -> Unique.assertAtMostOne(breakpointsProvider.breakpointTableModel.getModelData()));
		assertEquals(State.INEFFECTIVE_ENABLED, row.getState());

		row.setEnabled(true);
		waitForSwing();

		row = waitForValue(
			() -> Unique.assertAtMostOne(breakpointsProvider.breakpointTableModel.getModelData()));
		assertEquals(State.ENABLED, row.getState());
	}

	@Test
	public void testTablesAndStatesWhenhModeChanges() throws Throwable {
		DebuggerControlService controlService =
			addPlugin(tool, DebuggerControlServicePlugin.class);

		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		Trace trace = recorder.getTrace();
		createProgramFromTrace(trace);
		intoProject(trace);
		intoProject(program);

		mb.testProcess1.addRegion("bin:.text", mb.rng(0x55550000, 0x55550fff), "rx");
		waitRecorder(recorder);
		addMapping(trace, program);
		addStaticMemoryAndBreakpoint();
		programManager.openProgram(program);
		traceManager.openTrace(trace);
		waitForSwing();

		LogicalBreakpointRow lbRow1 = waitForPass(() -> {
			LogicalBreakpointRow newRow =
				Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
			LogicalBreakpoint lb = newRow.getLogicalBreakpoint();
			assertEquals(program, lb.getProgram());
			assertEquals(Set.of(trace), lb.getMappedTraces());
			assertEquals(Set.of(), lb.getParticipatingTraces());
			assertEquals(State.INEFFECTIVE_ENABLED, newRow.getState());
			return newRow;
		});

		controlService.setCurrentMode(trace, ControlMode.RW_EMULATOR);
		lbRow1.setEnabled(true);
		TraceBreakpoint emuBpt = waitForValue(
			() -> Unique.assertAtMostOne(trace.getBreakpointManager().getAllBreakpoints()));
		assertNull(recorder.getTargetBreakpoint(emuBpt));

		LogicalBreakpointRow lbRow2 =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		waitForPass(() -> assertEquals(State.ENABLED, lbRow2.getState()));

		waitForPass(() -> {
			BreakpointLocationRow newRow =
				Unique.assertOne(breakpointsProvider.locationTableModel.getModelData());
			assertEquals(State.ENABLED, newRow.getState());
		});

		for (int i = 0; i < 3; i++) {
			controlService.setCurrentMode(trace, ControlMode.RO_TARGET);
			waitOn(breakpointService.changesSettled());
			waitForSwing();
			assertEquals(0, breakpointsProvider.locationTableModel.getModelData().size());

			controlService.setCurrentMode(trace, ControlMode.RW_EMULATOR);
			waitOn(breakpointService.changesSettled());
			waitForSwing();
			assertEquals(1, breakpointsProvider.locationTableModel.getModelData().size());
		}
	}
}
