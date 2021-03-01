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
package ghidra.app.plugin.core.debug.service.breakpoint;

import static ghidra.lifecycle.Unfinished.TODO;
import static org.junit.Assert.*;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.*;

import org.junit.*;

import generic.Unique;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServiceTest;
import ghidra.app.services.*;
import ghidra.app.services.LogicalBreakpoint.Enablement;
import ghidra.async.AsyncReference;
import ghidra.dbg.model.TestTargetMemoryRegion;
import ghidra.dbg.model.TestTargetProcess;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.util.DebuggerModelTestUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.TraceStaticMapping;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.datastruct.ListenerMap;

public class DebuggerLogicalBreakpointServiceTest extends AbstractGhidraHeadedDebuggerGUITest
		implements DebuggerModelTestUtils {
	protected static final long TIMEOUT_MILLIS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

	static {
		DebuggerModelServiceTest.addTestModelPathPatterns();
	}

	/**
	 * Tracks the current set of logical breakpoints.
	 * 
	 * <p>
	 * Its assertions require perfection in the sequence of events: 1) No double-adds. 2) No
	 * double-removes. 3) No extraneous updates. At the end of each test, the current set of
	 * breakpoints in this listener should be verified against those reported by the service.
	 */
	protected class NoDuplicatesTrackingChangeListener
			implements LogicalBreakpointsChangeListener {
		private Set<LogicalBreakpoint> current = new HashSet<>();

		@Override
		public synchronized void breakpointAdded(LogicalBreakpoint lb) {
			Msg.debug(this, "LogicalBreakpoint added: (" + System.identityHashCode(lb) + ")" + lb);
			assertTrue(current.add(lb));
		}

		@Override
		public synchronized void breakpointUpdated(LogicalBreakpoint lb) {
			Msg.debug(this, "LogicalBreakpoint updated: " + lb);
			assertTrue(current.contains(lb));
		}

		@Override
		public synchronized void breakpointRemoved(LogicalBreakpoint lb) {
			Msg.debug(this,
				"LogicalBreakpoint removed: (" + System.identityHashCode(lb) + ")" + lb);
			assertTrue(current.remove(lb));
		}

		public synchronized void assertAccurate() {
			assertEquals(breakpointService.getAllBreakpoints(), changeListener.current);
		}
	}

	protected class ForTimingMappingChangeListener implements DebuggerStaticMappingChangeListener {
		protected final AsyncReference<Boolean, Void> ar = new AsyncReference<>(false);

		@Override
		public void mappingsChanged(Set<Trace> affectedTraces, Set<Program> affectedPrograms) {
			ar.set(true, null);
		}
	}

	protected interface ExceptionalSupplier<T, E extends Throwable> {
		T get() throws E;
	}

	protected interface ExceptionalRunnable<E extends Throwable> {
		void run() throws E;
	}

	protected <T, E extends Throwable> T expectMappingChange(ExceptionalSupplier<T, E> supplier)
			throws E, InterruptedException, ExecutionException, TimeoutException {
		mappingChangeListener.ar.set(false, null);
		T result = supplier.get();
		mappingChangeListener.ar.waitValue(true).get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		return result;
	}

	protected <E extends Throwable> void expectMappingChange(ExceptionalRunnable<E> runnable)
			throws E, InterruptedException, ExecutionException, TimeoutException {
		expectMappingChange(() -> {
			runnable.run();
			return null;
		});
	}

	protected DebuggerStaticMappingService mappingService;
	protected DebuggerLogicalBreakpointService breakpointService;

	protected TraceRecorder recorder1;
	protected TraceRecorder recorder3;

	protected Bookmark enBm;
	protected Bookmark disBm;

	protected LogicalBreakpoint foundRead = null;
	protected LogicalBreakpoint foundWrite = null;

	protected TraceBreakpointManager breakpointManager;

	protected NoDuplicatesTrackingChangeListener changeListener =
		new NoDuplicatesTrackingChangeListener();
	protected ForTimingMappingChangeListener mappingChangeListener =
		new ForTimingMappingChangeListener();

	@Before
	public void setUpBreakpointServiceTest() throws Exception {
		ListenerMap.clearErr();

		addPlugin(tool, DebuggerLogicalBreakpointServicePlugin.class);
		breakpointService = tool.getService(DebuggerLogicalBreakpointService.class);
		mappingService = tool.getService(DebuggerStaticMappingService.class);

		breakpointService.addChangeListener(changeListener);
		mappingService.addChangeListener(mappingChangeListener);

		// NOTE: Traces derive from recordings, not toy builder
		// NOTE: Program must be saved into project so it has a URL for mappings
		createTestModel();
		mb.createTestProcessesAndThreads();

		// Unfinished.ignoreTODO();
	}

	public void startRecorder1() throws Exception {
		recorder1 = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
	}

	public void startRecorder3() throws Exception {
		recorder3 = modelService.recordTarget(mb.testProcess3,
			new TestDebuggerTargetTraceMapper(mb.testProcess3));
	}

	@After
	public void tearDownBreakpointServiceTest() {
		assertConsistent();
		changeListener.assertAccurate();
		if (recorder1 != null && recorder1.isRecording()) {
			recorder1.stopRecording();
		}
		if (recorder3 != null && recorder3.isRecording()) {
			recorder3.stopRecording();
		}
		ListenerMap.checkErr();
	}

	protected void assertConsistent() {
		Map<Trace, Set<LogicalBreakpoint>> breaksByTraceViaPer = new HashMap<>();
		for (Trace trace : traceManager.getOpenTraces()) {
			Set<LogicalBreakpoint> breaks = new HashSet<>();
			for (Entry<Address, Set<LogicalBreakpoint>> ent : breakpointService
					.getBreakpoints(trace)
					.entrySet()) {
				for (LogicalBreakpoint lb : ent.getValue()) {
					Address traceAddress = lb.getTraceAddress(trace);
					assertEquals(ent.getKey(), traceAddress);
					assertTrue(breaks.add(lb)); // All are unique within a trace
				}
			}
			if (!breaks.isEmpty()) {
				assertNull(breaksByTraceViaPer.put(trace, breaks));
			}
		}

		Map<Program, Set<LogicalBreakpoint>> breaksByProgramViaPer = new HashMap<>();
		for (Program prog : programManager.getAllOpenPrograms()) {
			Set<LogicalBreakpoint> breaks = new HashSet<>();
			for (Entry<Address, Set<LogicalBreakpoint>> ent : breakpointService
					.getBreakpoints(prog)
					.entrySet()) {
				for (LogicalBreakpoint lb : ent.getValue()) {
					ProgramLocation loc = lb.getProgramLocation();
					assertEquals(prog, loc.getProgram());
					assertEquals(ent.getKey(), loc.getAddress());
					assertTrue(breaks.add(lb)); // All are unique within a program
				}
			}
			if (!breaks.isEmpty()) {
				assertNull(breaksByProgramViaPer.put(prog, breaks));
			}
		}

		Map<Trace, Set<LogicalBreakpoint>> breaksByTraceViaAll = new HashMap<>();
		Map<Program, Set<LogicalBreakpoint>> breaksByProgramViaAll = new HashMap<>();
		for (LogicalBreakpoint lb : breakpointService.getAllBreakpoints()) {
			ProgramLocation loc = lb.getProgramLocation();
			if (loc != null) {
				Set<LogicalBreakpoint> breaks =
					breaksByProgramViaAll.computeIfAbsent(loc.getProgram(), __ -> new HashSet<>());
				assertTrue(breaks.add(lb));
			}
			for (Trace t : lb.getMappedTraces()) {
				Set<LogicalBreakpoint> breaks =
					breaksByTraceViaAll.computeIfAbsent(t, __ -> new HashSet<>());
				assertTrue(breaks.add(lb));
			}
		}

		assertEquals(breaksByProgramViaPer, breaksByProgramViaAll);
		assertEquals(breaksByTraceViaPer, breaksByTraceViaAll);

		changeListener.assertAccurate();
	}

	protected void addProgramTextBlock(Program p) throws Exception {
		try (UndoableTransaction tid =
			UndoableTransaction.start(program, "Add .text block", true)) {
			p.getMemory()
					.createInitializedBlock(".text", addr(p, 0x00400000), 0x1000, (byte) 0,
						monitor, false);
		}
	}

	protected TestTargetMemoryRegion addTargetDataRegion(TestTargetProcess p) {
		return p.addRegion("bin:.data", mb.rng(0x56550000, 0x5655ffff), "rw");
	}

	protected TestTargetMemoryRegion addTargetTextRegion(TestTargetProcess p) {
		return addTargetTextRegion(p, 0x55550000);
	}

	protected TestTargetMemoryRegion addTargetTextRegion(TestTargetProcess p, long offset) {
		return p.addRegion("bin:.text", mb.rng(offset, offset + 0x0fff), "rx");
	}

	protected void addTextMapping(TraceRecorder r, TestTargetMemoryRegion region, Program p)
			throws Exception {
		Trace t = r.getTrace();
		TraceMemoryRegion textRegion =
			waitFor(() -> r.getTraceMemoryRegion(region), "Recorder missed region: " + region);
		try (UndoableTransaction tid =
			UndoableTransaction.start(t, "Add .text mapping", true)) {
			mappingService.addMapping(new DefaultTraceLocation(t, null, textRegion.getLifespan(),
				textRegion.getMinAddress()), new ProgramLocation(p, addr(p, 0x00400000)), 0x1000,
				false);
		}
	}

	protected void removeTextMapping(TraceRecorder r, Program p) throws Exception {
		Trace t = r.getTrace();
		try (UndoableTransaction tid = UndoableTransaction.start(t, "Remove .text mapping", true)) {
			TraceStaticMapping mapping =
				t.getStaticMappingManager().findContaining(addr(t, 0x55550000), r.getSnap());
			mapping.delete();
		}
	}

	protected void addTargetAccessBreakpoint(TraceRecorder r) throws Exception {
		TargetBreakpointContainer cont = getBreakpointContainer(r);
		cont.placeBreakpoint(mb.testModel.getAddress("ram", 0x56550123),
			Set.of(TargetBreakpointKind.READ, TargetBreakpointKind.WRITE))
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
	}

	protected void addTargetSoftwareBreakpoint(TraceRecorder r, TestTargetMemoryRegion region)
			throws Exception {
		TraceMemoryRegion textRegion =
			waitFor(() -> r.getTraceMemoryRegion(region), "Recorder missed region: " + region);
		long offset = textRegion.getMinAddress().getOffset() + 0x0123;
		TargetBreakpointContainer cont = getBreakpointContainer(r);
		cont.placeBreakpoint(mb.addr(offset), Set.of(TargetBreakpointKind.SOFTWARE))
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
	}

	protected void removeTargetSoftwareBreakpoint(TraceRecorder r) throws Exception {
		TargetBreakpointContainer cont = getBreakpointContainer(r);
		cont.fetchElements().thenAccept(elements -> {
			for (TargetObject obj : elements.values()) {
				if (!(obj instanceof TargetBreakpointSpec) ||
					!(obj instanceof TargetDeletable)) {
					continue;
				}
				TargetBreakpointSpec spec = (TargetBreakpointSpec) obj;
				if (!spec.getKinds().contains(TargetBreakpointKind.SOFTWARE)) {
					continue;
				}
				TargetDeletable del = (TargetDeletable) obj;
				del.delete();
				return;
			}
			fail("No deletable software breakpoint spec found");
		}).get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
	}

	protected void addProgramBreakpoints(Program p) throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(p, "Create bookmarks", true)) {
			enBm = p.getBookmarkManager()
					.setBookmark(addr(p, 0x00400123),
						LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE, "SOFTWARE", "");
			disBm = p.getBookmarkManager()
					.setBookmark(addr(p, 0x00400321),
						LogicalBreakpoint.BREAKPOINT_DISABLED_BOOKMARK_TYPE, "SOFTWARE", "");
		}
	}

	protected void refetchProgramBreakpoints(Program p) throws Exception {
		// After a redo
		enBm = p.getBookmarkManager()
				.getBookmark(addr(p, 0x00400123),
					LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE, "SOFTWARE");
		disBm = p.getBookmarkManager()
				.getBookmark(addr(p, 0x00400321),
					LogicalBreakpoint.BREAKPOINT_DISABLED_BOOKMARK_TYPE, "SOFTWARE");
	}

	protected void removeProgramBreakpoints(Program p) throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(p, "Remove breakpoints", true)) {
			p.getBookmarkManager().removeBookmark(enBm);
			p.getBookmarkManager().removeBookmark(disBm);
		}
	}

	protected void assertLogicalBreakpointForLoneAccessBreakpoint(Trace trace) {
		LogicalBreakpoint enLb = Unique.assertOne(breakpointService.getAllBreakpoints());
		assertNull(enLb.getProgramLocation());
		assertEquals(Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE), enLb.getKinds());

		TraceBreakpoint bpt = Unique.assertOne(trace.getBreakpointManager().getAllBreakpoints());
		assertEquals(Set.of(trace), enLb.getMappedTraces());
		assertEquals(addr(trace, 0x56550123), enLb.getTraceAddress(trace));
		assertEquals(Set.of(bpt), enLb.getTraceBreakpoints(trace));
		assertEquals(Set.of(bpt), enLb.getTraceBreakpoints());
		assertEquals(Enablement.ENABLED, enLb.computeEnablementForTrace(trace));
	}

	protected void assertLogicalBreakpointForLoneSoftwareBreakpoint(Trace trace) {
		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace, 0x55550123, 1);
	}

	protected void assertLogicalBreakpointForLoneSoftwareBreakpoint(Trace trace, long offset,
			int total) {
		assertEquals(total, breakpointService.getAllBreakpoints().size());

		LogicalBreakpoint enLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(trace, addr(trace, offset)));
		assertNull(enLb.getProgramLocation());
		assertEquals(Set.of(TraceBreakpointKind.SOFTWARE), enLb.getKinds());

		TraceBreakpoint bpt = Unique.assertOne(trace.getBreakpointManager().getAllBreakpoints());
		assertEquals(Set.of(trace), enLb.getMappedTraces());
		assertEquals(addr(trace, offset), enLb.getTraceAddress(trace));
		assertEquals(Set.of(bpt), enLb.getTraceBreakpoints(trace));
		assertEquals(Set.of(bpt), enLb.getTraceBreakpoints());
		assertEquals(Enablement.ENABLED, enLb.computeEnablementForTrace(trace));
	}

	protected void assertLogicalBreakpointForMappedSoftwareBreakpoint(Trace trace) {
		assertEquals(1, breakpointService.getAllBreakpoints().size());

		LogicalBreakpoint enLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400123)));
		assertNull(enLb.getProgramBookmark());
		assertEquals(Enablement.DISABLED_ENABLED, enLb.computeEnablementForProgram(program));
		assertEquals(Set.of(TraceBreakpointKind.SOFTWARE), enLb.getKinds());

		TraceBreakpoint bpt = Unique.assertOne(trace.getBreakpointManager().getAllBreakpoints());
		assertEquals(Set.of(trace), enLb.getMappedTraces());
		assertEquals(addr(trace, 0x55550123), enLb.getTraceAddress(trace));
		assertEquals(Set.of(bpt), enLb.getTraceBreakpoints(trace));
		assertEquals(Set.of(bpt), enLb.getTraceBreakpoints());
		assertEquals(Enablement.ENABLED_DISABLED, enLb.computeEnablementForTrace(trace));
	}

	protected void assertLogicalBreakpointsForUnmappedBookmarks() {
		assertEquals(2, breakpointService.getAllBreakpoints().size());

		LogicalBreakpoint enLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400123)));
		assertEquals(program, enLb.getProgram());
		assertEquals(addr(program, 0x00400123), enLb.getProgramLocation().getAddress());
		assertEquals(enBm, enLb.getProgramBookmark());
		assertTrue(enLb.getMappedTraces().isEmpty());
		assertEquals(Enablement.ENABLED, enLb.computeEnablementForProgram(program));
		assertEquals(Set.of(TraceBreakpointKind.SOFTWARE), enLb.getKinds());

		LogicalBreakpoint disLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400321)));
		assertEquals(program, disLb.getProgram());
		assertEquals(addr(program, 0x00400321), disLb.getProgramLocation().getAddress());
		assertEquals(disBm, disLb.getProgramBookmark());
		assertTrue(disLb.getMappedTraces().isEmpty());
		assertEquals(Enablement.DISABLED, disLb.computeEnablementForProgram(program));
		assertEquals(Set.of(TraceBreakpointKind.SOFTWARE), disLb.getKinds());
	}

	protected void assertLogicalBreakpointsForMappedBookmarks(Trace trace) {
		assertEquals(2, breakpointService.getAllBreakpoints().size());

		LogicalBreakpoint enLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400123)));
		assertEquals(program, enLb.getProgram());
		assertEquals(addr(program, 0x00400123), enLb.getProgramLocation().getAddress());
		assertEquals(enBm, enLb.getProgramBookmark());
		assertEquals(Set.of(trace), enLb.getMappedTraces());
		assertEquals(addr(trace, 0x55550123), enLb.getTraceAddress(trace));
		assertEquals(Set.of(), enLb.getTraceBreakpoints(trace));
		assertEquals(Set.of(), enLb.getTraceBreakpoints());
		assertEquals(Enablement.ENABLED_DISABLED, enLb.computeEnablementForProgram(program));
		assertEquals(Enablement.DISABLED_ENABLED, enLb.computeEnablementForTrace(trace));

		LogicalBreakpoint disLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400321)));
		assertEquals(program, disLb.getProgram());
		assertEquals(addr(program, 0x00400321), disLb.getProgramLocation().getAddress());
		assertEquals(disBm, disLb.getProgramBookmark());
		assertEquals(Set.of(trace), disLb.getMappedTraces());
		assertEquals(addr(trace, 0x55550321), disLb.getTraceAddress(trace));
		assertEquals(Set.of(), disLb.getTraceBreakpoints(trace));
		assertEquals(Set.of(), disLb.getTraceBreakpoints());
		assertEquals(Enablement.DISABLED, disLb.computeEnablementForProgram(program));
		assertEquals(Enablement.DISABLED, disLb.computeEnablementForTrace(trace));
	}

	protected void assertLogicalBreakpointForMappedBookmarkAnd2TraceBreakpoints(Trace trace1,
			Trace trace2) {
		assertEquals(2, breakpointService.getAllBreakpoints().size());

		LogicalBreakpoint enLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400123)));
		assertEquals(program, enLb.getProgram());
		assertEquals(addr(program, 0x00400123), enLb.getProgramLocation().getAddress());
		assertEquals(enBm, enLb.getProgramBookmark());
		assertEquals(Set.of(trace1, trace2), enLb.getMappedTraces());
		assertEquals(addr(trace1, 0x55550123), enLb.getTraceAddress(trace1));
		assertEquals(addr(trace2, 0x55551123), enLb.getTraceAddress(trace2));

		TraceBreakpoint bpt1 = Unique.assertOne(trace1.getBreakpointManager().getAllBreakpoints());
		TraceBreakpoint bpt2 = Unique.assertOne(trace2.getBreakpointManager().getAllBreakpoints());
		assertEquals(Set.of(bpt1), enLb.getTraceBreakpoints(trace1));
		assertEquals(Set.of(bpt2), enLb.getTraceBreakpoints(trace2));
		assertNotEquals(Set.of(bpt2), enLb.getTraceBreakpoints(trace1)); // Sanity check
		assertNotEquals(Set.of(bpt1), enLb.getTraceBreakpoints(trace2)); // Sanity check
		assertEquals(Set.of(bpt1, bpt2), enLb.getTraceBreakpoints());

		assertEquals(Enablement.ENABLED, enLb.computeEnablementForProgram(program));
		assertEquals(Enablement.ENABLED, enLb.computeEnablementForTrace(trace1));
		assertEquals(Enablement.ENABLED, enLb.computeEnablementForTrace(trace2));

		LogicalBreakpoint disLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400321)));
		assertEquals(program, disLb.getProgram());
		assertEquals(addr(program, 0x00400321), disLb.getProgramLocation().getAddress());
		assertEquals(disBm, disLb.getProgramBookmark());
		assertEquals(Set.of(trace1, trace2), disLb.getMappedTraces());
		assertEquals(addr(trace1, 0x55550321), disLb.getTraceAddress(trace1));
		assertEquals(addr(trace2, 0x55551321), disLb.getTraceAddress(trace2));
		assertEquals(Set.of(), disLb.getTraceBreakpoints(trace1));
		assertEquals(Set.of(), disLb.getTraceBreakpoints(trace2));
		assertEquals(Set.of(), disLb.getTraceBreakpoints());
		assertEquals(Enablement.DISABLED, disLb.computeEnablementForProgram(program));
		assertEquals(Enablement.DISABLED, disLb.computeEnablementForTrace(trace1));
		assertEquals(Enablement.DISABLED, disLb.computeEnablementForTrace(trace2));
	}

	protected void assertLogicalBreakpointForMappedBookmarkAnd1TraceBreakpoint(Trace trace) {
		assertEquals(2, breakpointService.getAllBreakpoints().size());

		LogicalBreakpoint enLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400123)));
		assertEquals(program, enLb.getProgram());
		assertEquals(addr(program, 0x00400123), enLb.getProgramLocation().getAddress());
		assertEquals(enBm, enLb.getProgramBookmark());
		assertEquals(Set.of(trace), enLb.getMappedTraces());
		assertEquals(addr(trace, 0x55550123), enLb.getTraceAddress(trace));

		TraceBreakpoint bpt = Unique.assertOne(trace.getBreakpointManager().getAllBreakpoints());
		assertEquals(Set.of(bpt), enLb.getTraceBreakpoints(trace));
		assertEquals(Set.of(bpt), enLb.getTraceBreakpoints());

		assertEquals(Enablement.ENABLED, enLb.computeEnablementForProgram(program));
		assertEquals(Enablement.ENABLED, enLb.computeEnablementForTrace(trace));

		LogicalBreakpoint disLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400321)));
		assertEquals(program, disLb.getProgram());
		assertEquals(addr(program, 0x00400321), disLb.getProgramLocation().getAddress());
		assertEquals(disBm, disLb.getProgramBookmark());
		assertEquals(Set.of(trace), disLb.getMappedTraces());
		assertEquals(addr(trace, 0x55550321), disLb.getTraceAddress(trace));
		assertEquals(Set.of(), disLb.getTraceBreakpoints(trace));
		assertEquals(Set.of(), disLb.getTraceBreakpoints());
		assertEquals(Enablement.DISABLED, disLb.computeEnablementForProgram(program));
		assertEquals(Enablement.DISABLED, disLb.computeEnablementForTrace(trace));
	}

	@Test
	public void testEmptyTool() {
		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	/**
	 * TODO: When "resume recording" is implemented, consider that a "new" trace may already have
	 * breakpoints
	 */
	@Test
	@Ignore
	public void testRecordTraceWithBreakpoints() {
		TODO();
	}

	@Test
	public void testRecordTraceThenOpenTraceThenAddBreakpoint() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		addTargetDataRegion(mb.testProcess1);
		addTargetAccessBreakpoint(recorder1);
		waitForDomainObject(trace);

		assertLogicalBreakpointForLoneAccessBreakpoint(trace);
	}

	@Test
	public void testRecordTraceThenAddBreakpointThenOpenTrace() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();

		addTargetDataRegion(mb.testProcess1);
		addTargetAccessBreakpoint(recorder1);
		waitForDomainObject(trace);

		traceManager.openTrace(trace);
		waitForSwing();

		assertLogicalBreakpointForLoneAccessBreakpoint(trace);
	}

	@Test
	public void testOpenProgramWithBookmarks() throws Exception {
		createProgram();
		addProgramTextBlock(program);
		addProgramBreakpoints(program);

		// Not open, yet
		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
		programManager.openProgram(program);
		waitForSwing();

		assertLogicalBreakpointsForUnmappedBookmarks();
	}

	@Test
	public void testRecordTraceThenOpenEmptyProgram() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		programManager.openProgram(program);
		waitForSwing();

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testRecordTraceThenOpenProgramThenAddMapping() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		waitForSwing();

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testRecordTraceThenOpenProgramThenAddMappingThenAddBookmarks() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		addProgramBreakpoints(program);
		waitForSwing();

		assertLogicalBreakpointsForMappedBookmarks(trace);
	}

	@Test
	public void testRecordTraceThenOpenProgramThenAddBookmarksThenAddMapping() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		addProgramBreakpoints(program);
		waitForSwing();

		changeListener.assertAccurate();

		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		waitForSwing();

		assertLogicalBreakpointsForMappedBookmarks(trace);
	}

	@Test
	public void testRecordTraceThenOpenProgramThenAddMappingThenAddBreakpoint() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		addTargetSoftwareBreakpoint(recorder1, text);
		waitForDomainObject(trace);

		assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);
	}

	@Test
	public void testRecordTraceThenOpenProgramThenAddBreakpointThenAddMapping() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		addTargetSoftwareBreakpoint(recorder1, text);
		waitForDomainObject(trace);

		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace);
		changeListener.assertAccurate();

		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		waitForSwing();

		assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);
	}

	/**
	 * TODO: When "resume recording" is implemented, consider that a "new" trace may already have
	 * mappings
	 */
	@Test
	@Ignore
	public void testOpenProgramWithBookmarkThenRecordTraceWithMapping() {
		TODO();
	}

	@Test
	public void testOpenProgramThenAddBookmarksThenRecordTraceThenAddMapping() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		// delay opening

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		addProgramBreakpoints(program);
		waitForSwing();

		assertLogicalBreakpointsForUnmappedBookmarks();
		changeListener.assertAccurate();

		traceManager.openTrace(trace);
		// NOTE: Extraneous mappings-changed events can cause timing issues here.
		// TODO: Button down testing for static mapping listener events
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		waitForSwing();

		assertLogicalBreakpointsForMappedBookmarks(trace);
	}

	@Test
	public void testRecordTraceThenAddMappingThenOpenProgramWithBookmark() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		// delay opening

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		addTextMapping(recorder1, text, program);
		addProgramBreakpoints(program);
		waitForSwing();

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());

		expectMappingChange(() -> programManager.openProgram(program));
		waitForSwing();

		assertLogicalBreakpointsForMappedBookmarks(trace);
	}

	@Test
	public void testRecordTraceThenAddMappingThenAddBreakpointThenOpenProgram() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		// delay opening

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		addTextMapping(recorder1, text, program);
		addTargetSoftwareBreakpoint(recorder1, text);
		waitForSwing();

		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace);

		expectMappingChange(() -> programManager.openProgram(program));
		waitForSwing();

		assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);
	}

	@Test
	public void testRecordTraceThenOpenProgramThenCloseProgram() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);
		waitForSwing();

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());

		programManager.closeProgram(program, true);
		waitForSwing();

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testRecordTraceThenOpenProgramThenCloseAndStopTrace() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);
		waitForSwing();

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());

		traceManager.closeTrace(trace);
		recorder1.stopRecording();
		waitForSwing();

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testRecordTraceThenOpenProgramThenAddBookmarksThenAddMappingThenRemoveBookmark()
			throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		addProgramBreakpoints(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		waitForSwing();

		assertLogicalBreakpointsForMappedBookmarks(trace);

		removeProgramBreakpoints(program);
		waitForSwing();

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testRecordTraceThenOpenProgramThenAddBookmarksThenAddMappingThenRemoveMapping()
			throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		addProgramBreakpoints(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		waitForSwing();

		assertLogicalBreakpointsForMappedBookmarks(trace);

		expectMappingChange(() -> removeTextMapping(recorder1, program));
		waitForSwing();

		assertLogicalBreakpointsForUnmappedBookmarks();
		assertTrue(breakpointService.getBreakpoints(trace).isEmpty());
	}

	@Test
	public void testRecordTraceThenAddBreakpointThenOpenProgramThenAddMappingThenRemoveBreakpoint()
			throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		addTargetSoftwareBreakpoint(recorder1, text);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		waitForSwing();

		assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);
		assertConsistent();

		removeTargetSoftwareBreakpoint(recorder1);
		waitForSwing();

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testRecordTraceThenAddBreakpointThenOpenProgramThenAddMappingThenRemoveMapping()
			throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		addTargetSoftwareBreakpoint(recorder1, text);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		waitForSwing();

		assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);
		assertConsistent();

		expectMappingChange(() -> removeTextMapping(recorder1, program));
		waitForSwing();

		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace);
	}

	@Test
	public void testFill1Program2Traces() throws Exception {
		startRecorder1();
		Trace trace1 = recorder1.getTrace();
		traceManager.openTrace(trace1);

		startRecorder3();
		Trace trace3 = recorder3.getTrace();
		traceManager.openTrace(trace3);

		createProgramFromTrace(trace1); // Also suitable for trace3
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text1 = addTargetTextRegion(mb.testProcess1);
		TestTargetMemoryRegion text3 = addTargetTextRegion(mb.testProcess3, 0x55551000);
		expectMappingChange(() -> addTextMapping(recorder1, text1, program));
		expectMappingChange(() -> addTextMapping(recorder3, text3, program));
		waitForSwing();

		addProgramBreakpoints(program);
		addTargetSoftwareBreakpoint(recorder1, text1);
		addTargetSoftwareBreakpoint(recorder3, text3);
		waitForSwing();

		assertLogicalBreakpointForMappedBookmarkAnd2TraceBreakpoints(trace1, trace3);
	}

	@Test
	public void testFill1Program2TracesThenCloseProgram() throws Exception {
		startRecorder1();
		Trace trace1 = recorder1.getTrace();
		traceManager.openTrace(trace1);

		startRecorder3();
		Trace trace3 = recorder3.getTrace();
		traceManager.openTrace(trace3);

		createProgramFromTrace(trace1); // Also suitable for trace3
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text1 = addTargetTextRegion(mb.testProcess1);
		TestTargetMemoryRegion text3 = addTargetTextRegion(mb.testProcess3, 0x55551000);
		expectMappingChange(() -> addTextMapping(recorder1, text1, program));
		expectMappingChange(() -> addTextMapping(recorder3, text3, program));
		waitForSwing();

		addProgramBreakpoints(program);
		addTargetSoftwareBreakpoint(recorder1, text1);
		addTargetSoftwareBreakpoint(recorder3, text3);
		waitForSwing();

		assertLogicalBreakpointForMappedBookmarkAnd2TraceBreakpoints(trace1, trace3);

		expectMappingChange(() -> programManager.closeProgram(program, true));
		waitForSwing();

		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace1, 0x55550123, 2);
		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace3, 0x55551123, 2);
	}

	@Test
	public void testFill1Program2TracesThenCloseProgramThenReopenProgram() throws Exception {
		startRecorder1();
		Trace trace1 = recorder1.getTrace();
		traceManager.openTrace(trace1);

		startRecorder3();
		Trace trace3 = recorder3.getTrace();
		traceManager.openTrace(trace3);

		createProgramFromTrace(trace1); // Also suitable for trace3
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text1 = addTargetTextRegion(mb.testProcess1);
		TestTargetMemoryRegion text3 = addTargetTextRegion(mb.testProcess3, 0x55551000);
		expectMappingChange(() -> addTextMapping(recorder1, text1, program));
		expectMappingChange(() -> addTextMapping(recorder3, text3, program));
		waitForSwing();

		addProgramBreakpoints(program);
		addTargetSoftwareBreakpoint(recorder1, text1);
		addTargetSoftwareBreakpoint(recorder3, text3);
		waitForSwing();

		assertLogicalBreakpointForMappedBookmarkAnd2TraceBreakpoints(trace1, trace3);

		expectMappingChange(() -> programManager.closeProgram(program, true));
		waitForSwing();

		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace1, 0x55550123, 2);
		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace3, 0x55551123, 2);

		expectMappingChange(() -> programManager.openProgram(program));
		waitForSwing();

		assertLogicalBreakpointForMappedBookmarkAnd2TraceBreakpoints(trace1, trace3);
	}

	@Test
	public void testFill1Program2TracesThenStop1Trace() throws Exception {
		startRecorder1();
		Trace trace1 = recorder1.getTrace();
		traceManager.openTrace(trace1);

		startRecorder3();
		Trace trace3 = recorder3.getTrace();
		traceManager.openTrace(trace3);

		createProgramFromTrace(trace1); // Also suitable for trace3
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text1 = addTargetTextRegion(mb.testProcess1);
		TestTargetMemoryRegion text3 = addTargetTextRegion(mb.testProcess3, 0x55551000);
		expectMappingChange(() -> addTextMapping(recorder1, text1, program));
		expectMappingChange(() -> addTextMapping(recorder3, text3, program));
		waitForSwing();

		addProgramBreakpoints(program);
		addTargetSoftwareBreakpoint(recorder1, text1);
		addTargetSoftwareBreakpoint(recorder3, text3);
		waitForSwing();

		waitForPass(
			() -> assertLogicalBreakpointForMappedBookmarkAnd2TraceBreakpoints(trace1, trace3));

		expectMappingChange(() -> {
			// TODO: Change breakpoint manager to require both open and recording...
			// If I don't close the trace here, the test will fail.
			recorder3.stopRecording();
			// NB. Auto-close on stop is the default
			//traceManager.closeTrace(trace3);
		});
		waitForSwing();

		// NB. Auto-close is possibly delayed because of auto-save
		waitForPass(() -> assertLogicalBreakpointForMappedBookmarkAnd1TraceBreakpoint(trace1));
	}

	/**
	 * I don't think this test is actually sane. The recorder should never abort a transaction,
	 * unless something has already gone wrong. The logical breakpoint service only cares about live
	 * breakpoints, so there's no context in which testing this service with aborted transactions on
	 * breakpoints is sane.
	 */
	//@Test 
	public void testAbortAddBreakpoint() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		waitForSwing();

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Will abort", false)) {
			addTargetSoftwareBreakpoint(recorder1, text);
			waitForDomainObject(trace);

			// Sanity
			assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);
		}
		waitForDomainObject(trace);

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testAbortAddMapping() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		addTargetSoftwareBreakpoint(recorder1, text);
		waitForDomainObject(trace);

		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace);
		changeListener.assertAccurate();

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Will abort", false)) {
			expectMappingChange(() -> addTextMapping(recorder1, text, program));
			waitForSwing();

			// Sanity
			assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);

			expectMappingChange(() -> tid.abort());
		}
		waitForDomainObject(trace); // Duplicative, but for form's sake....

		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace);
	}

	@Test
	public void testAbortAddBreakpointAndMapping() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Will abort", false)) {
			addTargetSoftwareBreakpoint(recorder1, text);

			expectMappingChange(() -> addTextMapping(recorder1, text, program));
			waitForSwing();

			// Sanity
			assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);

			expectMappingChange(() -> tid.abort());
		}
		waitForDomainObject(trace); // Duplicative, but for form's sake....

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testAbortAddBookmarks() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		waitForSwing();

		try (UndoableTransaction tid = UndoableTransaction.start(program, "Will abort", false)) {
			addProgramBreakpoints(program);
			waitForDomainObject(program);

			// Sanity
			assertLogicalBreakpointsForMappedBookmarks(trace);
		}
		waitForDomainObject(program);

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testUndoRedoAddBreakpointAndMapping() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Will undo", true)) {
			addTargetSoftwareBreakpoint(recorder1, text);
			expectMappingChange(() -> addTextMapping(recorder1, text, program));
		}
		waitForDomainObject(trace);

		// Sanity
		assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);

		expectMappingChange(() -> undo(trace));

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());

		expectMappingChange(() -> redo(trace));

		// Mapping, breakpoint may be processed in whatever order
		waitForPass(() -> assertLogicalBreakpointForMappedSoftwareBreakpoint(trace));
	}

	@Test
	public void testUndoRedoAddBookmarks() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		waitForSwing();

		try (UndoableTransaction tid = UndoableTransaction.start(program, "Will undo", true)) {
			addProgramBreakpoints(program);
		}
		waitForDomainObject(program);

		// Sanity
		assertLogicalBreakpointsForMappedBookmarks(trace);

		undo(program);

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());

		redo(program);

		refetchProgramBreakpoints(program);
		assertLogicalBreakpointsForMappedBookmarks(trace);
	}

	@Test
	public void testPlaceDisableStepThenEnableTraceOnly() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);

		addTargetSoftwareBreakpoint(recorder1, text);
		waitForDomainObject(trace);

		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace);

		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
		waitOn(lb.disable());
		waitForDomainObject(trace);
		assertEquals(Enablement.DISABLED, lb.computeEnablement());

		// Simulate a step, which should also cause snap advance in recorder
		long oldSnap = recorder1.getSnap();
		mb.testModel.session.simulateStep(mb.testThread1);
		waitOn(mb.testModel.getClientExecutor());
		assertEquals(oldSnap + 1, recorder1.getSnap());

		assertEquals(Enablement.DISABLED, lb.computeEnablement());

		waitOn(lb.enable());
		waitForDomainObject(trace);
		assertEquals(Enablement.ENABLED, lb.computeEnablement());
	}

	@Test
	public void testDeleteBreakpointTraceOnly() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);

		addTargetSoftwareBreakpoint(recorder1, text);
		waitForDomainObject(trace);

		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace);

		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		waitOn(lb.delete());
		waitForDomainObject(trace);

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testPlaceStepThenDeleteBreakpointTraceOnly() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);

		addTargetSoftwareBreakpoint(recorder1, text);
		waitForDomainObject(trace);

		waitForPass(() -> assertLogicalBreakpointForLoneSoftwareBreakpoint(trace));

		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		// Simulate a step, which should also cause snap advance in recorder
		long oldSnap = recorder1.getSnap();
		mb.testModel.session.simulateStep(mb.testThread1);
		waitOn(mb.testModel.getClientExecutor());
		assertEquals(oldSnap + 1, recorder1.getSnap());

		waitOn(lb.delete());
		waitForDomainObject(trace);

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testRecordThenCloseTraceOnly() throws Exception {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);

		addTargetSoftwareBreakpoint(recorder1, text);
		waitForDomainObject(trace);

		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace);

		// NOTE: Still recording in the background
		traceManager.closeTrace(trace);
		waitForSwing();

		assertEquals(0, breakpointService.getAllBreakpoints().size());
	}
}
