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
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;

import com.google.common.collect.Range;

import generic.Unique;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsProvider.LogicalBreakpointTableModel;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServiceTest;
import ghidra.app.services.*;
import ghidra.async.AsyncTestUtils;
import ghidra.dbg.model.TestTargetProcess;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.util.SystemUtilities;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class DebuggerBreakpointsProviderTest extends AbstractGhidraHeadedDebuggerGUITest
		implements AsyncTestUtils {
	protected static final long TIMEOUT_MILLIS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

	static {
		DebuggerModelServiceTest.addTestModelPathPatterns();
	}

	protected DebuggerBreakpointsPlugin breakpointsPlugin;
	protected DebuggerBreakpointsProvider breakpointsProvider;
	protected DebuggerStaticMappingService mappingService;

	@Before
	public void setUpBreakpointsProviderTest() throws Exception {
		breakpointsPlugin = addPlugin(tool, DebuggerBreakpointsPlugin.class);
		breakpointsProvider = waitForComponentProvider(DebuggerBreakpointsProvider.class);
		mappingService = tool.getService(DebuggerStaticMappingService.class);
	}

	protected void addMapping(Trace trace, Program prog) throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Add mapping", true)) {
			mappingService.addMapping(
				new DefaultTraceLocation(trace, null, Range.atLeast(0L), addr(trace, 0x55550000)),
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
		try (UndoableTransaction tid =
			UndoableTransaction.start(program, "Add bookmark break", true)) {
			program.getMemory()
					.createInitializedBlock(".text", addr(program, 0x00400000), 0x1000, (byte) 0,
						TaskMonitor.DUMMY, false);
			program.getBookmarkManager()
					.setBookmark(addr(program, 0x00400123),
						LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE, "SOFTWARE;1", "");
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
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
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
		assertEquals("SOFTWARE", row.getKinds());
		assertTrue(row.isEnabled());
	}

	@Test
	public void testToggleLiveViaTable() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		addLiveMemoryAndBreakpoint(mb.testProcess1, recorder);
		waitForDomainObject(trace);

		traceManager.openTrace(trace);
		waitForSwing();

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		assertTrue(row.isEnabled());

		// NB, the row does not take the value immediately, but via async callbacks
		row.setEnabled(false);

		waitForPass(() -> assertEquals(Boolean.FALSE, row.isEnabled()));

		row.setEnabled(true);

		waitForPass(() -> assertEquals(Boolean.TRUE, row.isEnabled()));
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
		assertEquals("SOFTWARE", row.getKinds());
		assertTrue(row.isEnabled());
	}

	@Test
	public void testToggleStaticViaTable() throws Exception {
		createProgram();
		programManager.openProgram(program);
		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		assertTrue(row.isEnabled());

		row.setEnabled(false); // Synchronous, but on swing thread
		waitForDomainObject(program);

		assertEquals(Boolean.FALSE, row.isEnabled());

		row.setEnabled(true);
		waitForDomainObject(program);

		assertEquals(Boolean.TRUE, row.isEnabled());
	}

	@Test
	public void testEnablementColumnMapped() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
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
			assertEquals(Boolean.TRUE, row.isEnabled());
		});

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		LogicalBreakpoint lb = row.getLogicalBreakpoint();

		lb.disableForProgram();
		waitForDomainObject(program);

		// TODO: As of now, the table displays "N/A", which is not ideal
		// Would be nicer to have icons, but still want click to toggle.
		assertNull(row.isEnabled());

		// NOTE: This acts on the corresponding target, not directly on trace
		lb.disableForTrace(trace);

		waitForPass(() -> assertEquals(Boolean.FALSE, row.isEnabled()));

		lb.enableForProgram();
		waitForDomainObject(program);

		assertNull(row.isEnabled());

		// This duplicates the initial case, but without it, I just feel incomplete
		lb.enableForTrace(trace);

		waitForPass(() -> assertEquals(Boolean.TRUE, row.isEnabled()));
	}

	// TODO: Test a scenario where one spec manifests two breaks, select both, and perform actions

	// TODO: Test a scenario where one spec manifests the same mapped breakpoint in two traces

	@Test
	public void testActionEnableSelectedBreakpoints() throws Exception {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		assertFalse(breakpointsProvider.actionEnableSelectedBreakpointsAction.isEnabled());

		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		assertFalse(breakpointsProvider.actionEnableSelectedBreakpointsAction.isEnabled());

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		row.setEnabled(false);
		breakpointsProvider.breakpointFilterPanel.setSelectedItem(row);
		waitForSwing();

		assertEquals(Boolean.FALSE, row.isEnabled());
		assertTrue(breakpointsProvider.actionEnableSelectedBreakpointsAction.isEnabled());

		performAction(breakpointsProvider.actionEnableSelectedBreakpointsAction);

		assertEquals(Boolean.TRUE, row.isEnabled());
		assertTrue(breakpointsProvider.actionEnableSelectedBreakpointsAction.isEnabled());

		breakpointsProvider.breakpointTable.clearSelection();
		waitForSwing();

		assertFalse(breakpointsProvider.actionEnableSelectedBreakpointsAction.isEnabled());

		breakpointsProvider.breakpointFilterPanel.setSelectedItem(row);
		waitForSwing();

		assertTrue(breakpointsProvider.actionEnableSelectedBreakpointsAction.isEnabled());

		// Bookmark part should actually be synchronous.
		row.getLogicalBreakpoint().delete().get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		waitForDomainObject(program);

		assertFalse(breakpointsProvider.actionEnableSelectedBreakpointsAction.isEnabled());
	}

	@Test
	public void testActionEnableAllBreakpoints() throws Exception {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		assertFalse(breakpointsProvider.actionEnableAllBreakpointsAction.isEnabled());

		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		assertTrue(breakpointsProvider.actionEnableAllBreakpointsAction.isEnabled());

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		row.setEnabled(false);
		waitForSwing();

		assertEquals(Boolean.FALSE, row.isEnabled());
		assertTrue(breakpointsProvider.actionEnableAllBreakpointsAction.isEnabled());

		performAction(breakpointsProvider.actionEnableAllBreakpointsAction);

		assertEquals(Boolean.TRUE, row.isEnabled());
		assertTrue(breakpointsProvider.actionEnableAllBreakpointsAction.isEnabled());

		// Bookmark part should actually be synchronous.
		row.getLogicalBreakpoint().delete().get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		waitForDomainObject(program);

		assertFalse(breakpointsProvider.actionEnableAllBreakpointsAction.isEnabled());
	}

	@Test
	public void testActionDisableSelectedBreakpoints() throws Exception {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		assertFalse(breakpointsProvider.actionDisableSelectedBreakpointsAction.isEnabled());

		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		assertFalse(breakpointsProvider.actionDisableSelectedBreakpointsAction.isEnabled());

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		breakpointsProvider.breakpointFilterPanel.setSelectedItem(row);
		waitForSwing();

		assertEquals(Boolean.TRUE, row.isEnabled());
		assertTrue(breakpointsProvider.actionDisableSelectedBreakpointsAction.isEnabled());

		performAction(breakpointsProvider.actionDisableSelectedBreakpointsAction);

		assertEquals(Boolean.FALSE, row.isEnabled());
		assertTrue(breakpointsProvider.actionDisableSelectedBreakpointsAction.isEnabled());

		breakpointsProvider.breakpointTable.clearSelection();
		waitForSwing();

		assertFalse(breakpointsProvider.actionDisableSelectedBreakpointsAction.isEnabled());

		breakpointsProvider.breakpointFilterPanel.setSelectedItem(row);
		waitForSwing();

		assertTrue(breakpointsProvider.actionDisableSelectedBreakpointsAction.isEnabled());

		// Bookmark part should actually be synchronous.
		row.getLogicalBreakpoint().delete().get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		waitForDomainObject(program);

		assertFalse(breakpointsProvider.actionDisableSelectedBreakpointsAction.isEnabled());
	}

	@Test
	public void testActionDisableAllBreakpoints() throws Exception {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		assertFalse(breakpointsProvider.actionDisableAllBreakpointsAction.isEnabled());

		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		assertTrue(breakpointsProvider.actionDisableAllBreakpointsAction.isEnabled());
		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		assertEquals(Boolean.TRUE, row.isEnabled());
		assertTrue(breakpointsProvider.actionDisableAllBreakpointsAction.isEnabled());

		performAction(breakpointsProvider.actionDisableAllBreakpointsAction);

		assertEquals(Boolean.FALSE, row.isEnabled());
		assertTrue(breakpointsProvider.actionDisableAllBreakpointsAction.isEnabled());

		// Bookmark part should actually be synchronous.
		row.getLogicalBreakpoint().delete().get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		waitForDomainObject(program);

		assertFalse(breakpointsProvider.actionDisableAllBreakpointsAction.isEnabled());
	}

	@Test
	public void testActionClearSelectedBreakpoints() throws Exception {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		assertFalse(breakpointsProvider.actionClearSelectedBreakpointsAction.isEnabled());

		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		assertFalse(breakpointsProvider.actionClearSelectedBreakpointsAction.isEnabled());

		LogicalBreakpointRow row =
			Unique.assertOne(breakpointsProvider.breakpointTableModel.getModelData());
		breakpointsProvider.breakpointFilterPanel.setSelectedItem(row);
		waitForSwing();

		assertTrue(breakpointsProvider.actionClearSelectedBreakpointsAction.isEnabled());

		breakpointsProvider.breakpointTable.clearSelection();
		waitForSwing();

		assertFalse(breakpointsProvider.actionClearSelectedBreakpointsAction.isEnabled());

		breakpointsProvider.breakpointFilterPanel.setSelectedItem(row);
		waitForSwing();

		assertTrue(breakpointsProvider.actionClearSelectedBreakpointsAction.isEnabled());

		performAction(breakpointsProvider.actionClearSelectedBreakpointsAction);

		assertProviderEmpty();
		assertFalse(breakpointsProvider.actionClearSelectedBreakpointsAction.isEnabled());
	}

	@Test
	public void testActionClearAllBreakpoints() throws Exception {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		assertFalse(breakpointsProvider.actionClearAllBreakpointsAction.isEnabled());

		addStaticMemoryAndBreakpoint();
		waitForDomainObject(program);

		assertTrue(breakpointsProvider.actionClearAllBreakpointsAction.isEnabled());

		performAction(breakpointsProvider.actionClearAllBreakpointsAction);

		assertProviderEmpty();
		assertFalse(breakpointsProvider.actionClearAllBreakpointsAction.isEnabled());
	}

	@Test
	public void testActionFilters() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder1 = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace1 = recorder1.getTrace();
		TraceRecorder recorder3 = modelService.recordTarget(mb.testProcess3,
			new TestDebuggerTargetTraceMapper(mb.testProcess3));
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
		addStaticMemoryAndBreakpoint();
		// Note, no program breakpoint for 0321...
		programManager.openProgram(program);
		traceManager.openTrace(trace1);
		traceManager.openTrace(trace3);
		// Because mapping service debounces, wait for breakpoints to be reconciled
		LogicalBreakpointTableModel bptModel = breakpointsProvider.breakpointTableModel;
		waitForPass(() -> {
			List<LogicalBreakpointRow> data = bptModel.getModelData();
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
		});

		List<LogicalBreakpointRow> breakData = bptModel.getModelData();
		List<BreakpointLocationRow> filtLocs =
			breakpointsProvider.locationFilterPanel.getTableFilterModel().getModelData();

		for (LogicalBreakpointRow breakRow : breakData) {
			assertEquals(2, breakRow.getLocationCount());
		}
		assertEquals(4, filtLocs.size());

		assertTrue(breakpointsProvider.actionFilterByCurrentTrace.isEnabled());
		performAction(breakpointsProvider.actionFilterByCurrentTrace);

		// No trace active, so empty :)
		breakData = bptModel.getModelData();
		filtLocs = breakpointsProvider.locationFilterPanel.getTableFilterModel().getModelData();
		for (LogicalBreakpointRow breakRow : breakData) {
			assertEquals(0, breakRow.getLocationCount());
		}
		assertEquals(0, filtLocs.size());

		traceManager.activateTrace(trace1);
		waitForSwing();

		breakData = bptModel.getModelData();
		filtLocs = breakpointsProvider.locationFilterPanel.getTableFilterModel().getModelData();
		for (LogicalBreakpointRow breakRow : breakData) {
			assertEquals(1, breakRow.getLocationCount());
		}
		assertEquals(2, filtLocs.size());

		assertTrue(breakpointsProvider.actionFilterLocationsByBreakpoints.isEnabled());
		performAction(breakpointsProvider.actionFilterLocationsByBreakpoints);

		// No breakpoint selected, so no change, yet.
		breakData = bptModel.getModelData();
		filtLocs = breakpointsProvider.locationFilterPanel.getTableFilterModel().getModelData();
		for (LogicalBreakpointRow breakRow : breakData) {
			assertEquals(1, breakRow.getLocationCount());
		}
		assertEquals(2, filtLocs.size());

		breakpointsProvider.setSelectedBreakpoints(Set.of(breakData.get(0).getLogicalBreakpoint()));
		waitForSwing();

		filtLocs = breakpointsProvider.locationFilterPanel.getTableFilterModel().getModelData();
		assertEquals(1, filtLocs.size());

		assertTrue(breakpointsProvider.actionFilterByCurrentTrace.isEnabled());
		performAction(breakpointsProvider.actionFilterByCurrentTrace);

		breakData = bptModel.getModelData();
		filtLocs = breakpointsProvider.locationFilterPanel.getTableFilterModel().getModelData();
		for (LogicalBreakpointRow breakRow : breakData) {
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
}
