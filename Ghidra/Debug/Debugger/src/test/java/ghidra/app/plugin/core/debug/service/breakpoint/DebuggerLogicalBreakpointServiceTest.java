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

import static org.junit.Assert.*;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

import org.junit.*;

import db.Transaction;
import generic.Unique;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.services.*;
import ghidra.app.services.LogicalBreakpoint.State;
import ghidra.async.AsyncReference;
import ghidra.dbg.model.TestTargetMemoryRegion;
import ghidra.dbg.model.TestTargetProcess;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.TraceStaticMapping;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.ListenerMap;

public class DebuggerLogicalBreakpointServiceTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected static final long TIMEOUT_MILLIS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

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
			Msg.debug(this,
				"LogicalBreakpoint updated: (" + System.identityHashCode(lb) + ")" + lb);
			assertTrue(current.contains(lb));
		}

		@Override
		public synchronized void breakpointRemoved(LogicalBreakpoint lb) {
			Msg.debug(this,
				"LogicalBreakpoint removed: (" + System.identityHashCode(lb) + ")" + lb);
			assertTrue(current.remove(lb));
		}

		public synchronized void assertAgreesWithService() {
			waitForPass(() -> {
				assertEquals(breakpointService.getAllBreakpoints(), current);
			});
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
			throws Throwable {
		mappingChangeListener.ar.set(false, null);
		T result = supplier.get();
		waitOn(mappingChangeListener.ar.waitValue(true));
		return result;
	}

	protected <E extends Throwable> void expectMappingChange(ExceptionalRunnable<E> runnable)
			throws Throwable {
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
	public void setUpBreakpointServiceTest() throws Throwable {
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

	public void startRecorder1() throws Throwable {
		recorder1 = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
	}

	public void startRecorder3() throws Throwable {
		recorder3 = modelService.recordTarget(mb.testProcess3,
			createTargetTraceMapper(mb.testProcess3), ActionSource.AUTOMATIC);
	}

	@After
	public void tearDownBreakpointServiceTest() throws Throwable {
		Msg.debug(this, "Tearing down");
		try {
			waitRecorder(recorder1);
			waitRecorder(recorder3);
			waitForProgram(program);

			assertServiceAgreesWithOpenProgramsAndTraces();
			changeListener.assertAgreesWithService();
			if (recorder1 != null && recorder1.isRecording()) {
				waitForLock(recorder1.getTrace());
				recorder1.stopRecording();
			}
			if (recorder3 != null && recorder3.isRecording()) {
				waitForLock(recorder3.getTrace());
				recorder3.stopRecording();
			}
			ListenerMap.checkErr();
		}
		catch (Throwable t) {
			Msg.error(this, "Failed during tear down: " + t);
			throw t;
		}
	}

	protected void assertServiceAgreesWithOpenProgramsAndTraces() {
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
	}

	protected void addProgramTextBlock(Program p) throws Throwable {
		try (Transaction tx = program.openTransaction("Add .text block")) {
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
			throws Throwable {
		Trace t = r.getTrace();
		TraceMemoryRegion textRegion =
			waitFor(() -> r.getTraceMemoryRegion(region), "Recorder missed region: " + region);
		try (Transaction tx = t.openTransaction("Add .text mapping")) {
			DebuggerStaticMappingUtils.addMapping(
				new DefaultTraceLocation(t, null, textRegion.getLifespan(),
					textRegion.getMinAddress()),
				new ProgramLocation(p, addr(p, 0x00400000)), 0x1000,
				false);
		}
	}

	protected void removeTextMapping(TraceRecorder r, Program p) throws Throwable {
		Trace t = r.getTrace();
		try (Transaction tx = t.openTransaction("Remove .text mapping")) {
			TraceStaticMapping mapping =
				t.getStaticMappingManager().findContaining(addr(t, 0x55550000), r.getSnap());
			mapping.delete();
		}
	}

	protected void addTargetAccessBreakpoint(TraceRecorder r, TestTargetMemoryRegion region)
			throws Throwable {
		TraceMemoryRegion traceRegion =
			waitFor(() -> r.getTraceMemoryRegion(region), "Recorder missed region: " + region);
		long offset = traceRegion.getMinAddress().getOffset() + 0x0123;
		TargetBreakpointSpecContainer cont = getBreakpointContainer(r);
		cont.placeBreakpoint(mb.addr(offset),
			Set.of(TargetBreakpointKind.READ, TargetBreakpointKind.WRITE))
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
	}

	protected void addTargetSoftwareBreakpoint(TraceRecorder r, TestTargetMemoryRegion region)
			throws Throwable {
		TraceMemoryRegion traceRegion =
			waitFor(() -> r.getTraceMemoryRegion(region), "Recorder missed region: " + region);
		long offset = traceRegion.getMinAddress().getOffset() + 0x0123;
		TargetBreakpointSpecContainer cont = getBreakpointContainer(r);
		cont.placeBreakpoint(mb.addr(offset), Set.of(TargetBreakpointKind.SW_EXECUTE))
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
	}

	protected void removeTargetSoftwareBreakpoint(TraceRecorder r) throws Throwable {
		TargetBreakpointSpecContainer cont = getBreakpointContainer(r);
		cont.fetchElements().thenAccept(elements -> {
			for (TargetObject obj : elements.values()) {
				if (!(obj instanceof TargetBreakpointSpec) ||
					!(obj instanceof TargetDeletable)) {
					continue;
				}
				TargetBreakpointSpec spec = (TargetBreakpointSpec) obj;
				if (!spec.getKinds().contains(TargetBreakpointKind.SW_EXECUTE)) {
					continue;
				}
				TargetDeletable del = (TargetDeletable) obj;
				del.delete();
				return;
			}
			fail("No deletable software breakpoint spec found");
		}).get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
	}

	protected void addProgramBreakpoints(Program p) throws Throwable {
		try (Transaction tx = p.openTransaction("Create bookmarks")) {
			enBm = p.getBookmarkManager()
					.setBookmark(addr(p, 0x00400123),
						LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE, "SW_EXECUTE;1", "");
			disBm = p.getBookmarkManager()
					.setBookmark(addr(p, 0x00400321),
						LogicalBreakpoint.BREAKPOINT_DISABLED_BOOKMARK_TYPE, "SW_EXECUTE;1", "");
		}
	}

	protected void refetchProgramBreakpoints(Program p) throws Throwable {
		// After a redo
		enBm = p.getBookmarkManager()
				.getBookmark(addr(p, 0x00400123),
					LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE, "SW_EXECUTE;1");
		disBm = p.getBookmarkManager()
				.getBookmark(addr(p, 0x00400321),
					LogicalBreakpoint.BREAKPOINT_DISABLED_BOOKMARK_TYPE, "SW_EXECUTE;1");
	}

	protected void removeProgramBreakpoints(Program p) throws Throwable {
		try (Transaction tx = p.openTransaction("Remove breakpoints")) {
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
		assertEquals(State.INCONSISTENT_ENABLED, enLb.computeStateForTrace(trace));
	}

	protected void assertLogicalBreakpointForLoneSoftwareBreakpoint(Trace trace, int total) {
		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace, 0x55550123, total);
	}

	protected void assertLogicalBreakpointForLoneSoftwareBreakpoint(Trace trace, long offset,
			int total) {
		assertEquals(total, breakpointService.getAllBreakpoints().size());

		LogicalBreakpoint enLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(trace, addr(trace, offset)));
		assertNull(enLb.getProgramLocation());
		assertEquals(Set.of(TraceBreakpointKind.SW_EXECUTE), enLb.getKinds());

		TraceBreakpoint bpt = Unique.assertOne(trace.getBreakpointManager().getAllBreakpoints());
		assertEquals(Set.of(trace), enLb.getMappedTraces());
		assertEquals(addr(trace, offset), enLb.getTraceAddress(trace));
		assertEquals(Set.of(bpt), enLb.getTraceBreakpoints(trace));
		assertEquals(Set.of(bpt), enLb.getTraceBreakpoints());
		assertEquals(State.INCONSISTENT_ENABLED, enLb.computeStateForTrace(trace));
	}

	protected void assertLogicalBreakpointForMappedSoftwareBreakpoint(Trace trace) {
		assertEquals(1, breakpointService.getAllBreakpoints().size());

		LogicalBreakpoint enLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400123)));
		assertNotNull(enLb.getProgramBookmark()); // Created automatically when trace breakpoint set.
		assertEquals(State.ENABLED, enLb.computeStateForProgram(program));
		assertEquals(Set.of(TraceBreakpointKind.SW_EXECUTE), enLb.getKinds());

		TraceBreakpoint bpt = Unique.assertOne(trace.getBreakpointManager().getAllBreakpoints());
		assertEquals(Set.of(trace), enLb.getMappedTraces());
		assertEquals(addr(trace, 0x55550123), enLb.getTraceAddress(trace));
		assertEquals(Set.of(bpt), enLb.getTraceBreakpoints(trace));
		assertEquals(Set.of(bpt), enLb.getTraceBreakpoints());
		assertEquals(State.ENABLED, enLb.computeStateForTrace(trace));
	}

	protected void assertLogicalBreakpointsForUnmappedBookmarks() {
		assertEquals(2, breakpointService.getAllBreakpoints().size());

		LogicalBreakpoint enLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400123)));
		assertEquals(program, enLb.getProgram());
		assertEquals(addr(program, 0x00400123), enLb.getProgramLocation().getAddress());
		assertEquals(enBm, enLb.getProgramBookmark());
		assertTrue(enLb.getMappedTraces().isEmpty());
		assertEquals(State.INEFFECTIVE_ENABLED, enLb.computeStateForProgram(program));
		assertEquals(Set.of(TraceBreakpointKind.SW_EXECUTE), enLb.getKinds());

		LogicalBreakpoint disLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400321)));
		assertEquals(program, disLb.getProgram());
		assertEquals(addr(program, 0x00400321), disLb.getProgramLocation().getAddress());
		assertEquals(disBm, disLb.getProgramBookmark());
		assertTrue(disLb.getMappedTraces().isEmpty());
		assertEquals(State.INEFFECTIVE_DISABLED, disLb.computeStateForProgram(program));
		assertEquals(Set.of(TraceBreakpointKind.SW_EXECUTE), disLb.getKinds());
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
		assertEquals(State.INEFFECTIVE_ENABLED, enLb.computeStateForProgram(program));
		assertEquals(State.NONE, enLb.computeStateForTrace(trace));

		LogicalBreakpoint disLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400321)));
		assertEquals(program, disLb.getProgram());
		assertEquals(addr(program, 0x00400321), disLb.getProgramLocation().getAddress());
		assertEquals(disBm, disLb.getProgramBookmark());
		assertEquals(Set.of(trace), disLb.getMappedTraces());
		assertEquals(addr(trace, 0x55550321), disLb.getTraceAddress(trace));
		assertEquals(Set.of(), disLb.getTraceBreakpoints(trace));
		assertEquals(Set.of(), disLb.getTraceBreakpoints());
		assertEquals(State.INEFFECTIVE_DISABLED, disLb.computeStateForProgram(program));
		assertEquals(State.NONE, disLb.computeStateForTrace(trace));
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

		assertEquals(State.ENABLED, enLb.computeStateForProgram(program));
		assertEquals(State.ENABLED, enLb.computeStateForTrace(trace1));
		assertEquals(State.ENABLED, enLb.computeStateForTrace(trace2));

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
		assertEquals(State.INEFFECTIVE_DISABLED, disLb.computeStateForProgram(program));
		assertEquals(State.NONE, disLb.computeStateForTrace(trace1));
		assertEquals(State.NONE, disLb.computeStateForTrace(trace2));
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

		assertEquals(State.ENABLED, enLb.computeStateForProgram(program));
		assertEquals(State.ENABLED, enLb.computeStateForTrace(trace));

		LogicalBreakpoint disLb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400321)));
		assertEquals(program, disLb.getProgram());
		assertEquals(addr(program, 0x00400321), disLb.getProgramLocation().getAddress());
		assertEquals(disBm, disLb.getProgramBookmark());
		assertEquals(Set.of(trace), disLb.getMappedTraces());
		assertEquals(addr(trace, 0x55550321), disLb.getTraceAddress(trace));
		assertEquals(Set.of(), disLb.getTraceBreakpoints(trace));
		assertEquals(Set.of(), disLb.getTraceBreakpoints());
		assertEquals(State.INEFFECTIVE_DISABLED, disLb.computeStateForProgram(program));
		assertEquals(State.NONE, disLb.computeStateForTrace(trace));
	}

	@Test
	public void testEmptyTool() {
		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testRecordTraceThenOpenTraceThenAddBreakpoint() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		TestTargetMemoryRegion data = addTargetDataRegion(mb.testProcess1);
		addTargetAccessBreakpoint(recorder1, data);

		waitForPass(() -> {
			assertLogicalBreakpointForLoneAccessBreakpoint(trace);
		});
	}

	@Test
	public void testRecordTraceThenAddBreakpointThenOpenTrace() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();

		TestTargetMemoryRegion data = addTargetDataRegion(mb.testProcess1);
		addTargetAccessBreakpoint(recorder1, data);
		waitForDomainObject(trace);

		traceManager.openTrace(trace);
		waitForSwing();

		waitForPass(() -> {
			assertLogicalBreakpointForLoneAccessBreakpoint(trace);
		});
	}

	@Test
	public void testOpenProgramWithBookmarks() throws Throwable {
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
	public void testRecordTraceThenOpenEmptyProgram() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		programManager.openProgram(program);
		waitForSwing();

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testRecordTraceThenOpenProgramThenAddMapping() throws Throwable {
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
	public void testRecordTraceThenOpenProgramThenAddMappingThenAddBookmarks() throws Throwable {
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
	public void testRecordTraceThenOpenProgramThenAddBookmarksThenAddMapping() throws Throwable {
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

		changeListener.assertAgreesWithService();

		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		waitForSwing();

		assertLogicalBreakpointsForMappedBookmarks(trace);
	}

	@Test
	public void testRecordTraceThenOpenProgramThenAddMappingThenAddBreakpoint() throws Throwable {
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

		waitForPass(() -> {
			assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);
		});
	}

	@Test
	public void testRecordTraceThenOpenProgramThenAddBreakpointThenAddMapping() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		addTargetSoftwareBreakpoint(recorder1, text);

		waitForPass(() -> {
			assertLogicalBreakpointForLoneSoftwareBreakpoint(trace, 1);
		});
		changeListener.assertAgreesWithService();

		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		waitForSwing();

		assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);
	}

	@Test
	public void testOpenProgramThenAddBookmarksThenRecordTraceThenAddMapping() throws Throwable {
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
		changeListener.assertAgreesWithService();

		traceManager.openTrace(trace);
		// NOTE: Extraneous mappings-changed events can cause timing issues here.
		// TODO: Button down testing for static mapping listener events
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		expectMappingChange(() -> addTextMapping(recorder1, text, program));
		waitForSwing();

		assertLogicalBreakpointsForMappedBookmarks(trace);
	}

	@Test
	public void testRecordTraceThenAddMappingThenOpenProgramWithBookmark() throws Throwable {
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
	public void testRecordTraceThenAddMappingThenAddBreakpointThenOpenProgram() throws Throwable {
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

		waitForPass(() -> assertLogicalBreakpointForLoneSoftwareBreakpoint(trace, 1));

		expectMappingChange(() -> programManager.openProgram(program));
		waitForSwing();

		waitForPass(() -> assertLogicalBreakpointForMappedSoftwareBreakpoint(trace));
	}

	@Test
	public void testRecordTraceThenOpenProgramThenCloseProgram() throws Throwable {
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
	public void testRecordTraceThenOpenProgramThenCloseAndStopTrace() throws Throwable {
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
			throws Throwable {
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
			throws Throwable {
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
			throws Throwable {
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
		assertServiceAgreesWithOpenProgramsAndTraces();

		removeTargetSoftwareBreakpoint(recorder1);

		waitForPass(() -> {
			// NB. The bookmark remains
			LogicalBreakpoint one = Unique.assertOne(breakpointService.getAllBreakpoints());
			assertTrue(one.getTraceBreakpoints().isEmpty());
		});
	}

	@Test
	public void testRecordTraceThenAddBreakpointThenOpenProgramThenAddMappingThenRemoveMapping()
			throws Throwable {
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
		assertServiceAgreesWithOpenProgramsAndTraces();

		expectMappingChange(() -> removeTextMapping(recorder1, program));
		waitForSwing();

		// NB. Bookmark remains
		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace, 2);
	}

	@Test
	public void testFill1Program2Traces() throws Throwable {
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

		addTextMapping(recorder1, text1, program);
		addTextMapping(recorder3, text3, program);
		waitForSwing();
		waitForPass(() -> {
			assertEquals(2, mappingService
					.getOpenMappedLocations(
						new ProgramLocation(program, addr(program, 0x00400123)))
					.size());
		});
		waitForSwing();

		addProgramBreakpoints(program);
		addTargetSoftwareBreakpoint(recorder1, text1);
		addTargetSoftwareBreakpoint(recorder3, text3);

		// NB. Model events in own thread, recorder transactions in another
		waitForPass(() -> {
			assertLogicalBreakpointForMappedBookmarkAnd2TraceBreakpoints(trace1, trace3);
		});
	}

	@Test
	public void testFill1Program2TracesThenCloseProgram() throws Throwable {
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

		addTextMapping(recorder1, text1, program);
		addTextMapping(recorder3, text3, program);
		waitForSwing();
		waitForPass(() -> {
			assertEquals(2, mappingService
					.getOpenMappedLocations(
						new ProgramLocation(program, addr(program, 0x00400123)))
					.size());
		});
		waitForSwing();

		addProgramBreakpoints(program);
		addTargetSoftwareBreakpoint(recorder1, text1);
		addTargetSoftwareBreakpoint(recorder3, text3);

		waitForPass(() -> {
			assertLogicalBreakpointForMappedBookmarkAnd2TraceBreakpoints(trace1, trace3);
		});

		expectMappingChange(() -> programManager.closeProgram(program, true));
		waitForSwing();

		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace1, 0x55550123, 2);
		assertLogicalBreakpointForLoneSoftwareBreakpoint(trace3, 0x55551123, 2);
	}

	@Test
	public void testFill1Program2TracesThenCloseProgramThenReopenProgram() throws Throwable {
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

		addTextMapping(recorder1, text1, program);
		addTextMapping(recorder3, text3, program);
		waitForSwing();
		waitForPass(() -> {
			assertEquals(2, mappingService
					.getOpenMappedLocations(
						new ProgramLocation(program, addr(program, 0x00400123)))
					.size());
		});
		waitForSwing();

		addProgramBreakpoints(program);
		addTargetSoftwareBreakpoint(recorder1, text1);
		addTargetSoftwareBreakpoint(recorder3, text3);

		waitForPass(() -> {
			assertLogicalBreakpointForMappedBookmarkAnd2TraceBreakpoints(trace1, trace3);
		});

		expectMappingChange(() -> programManager.closeProgram(program, true));
		waitForSwing();

		waitForPass(() -> {
			assertLogicalBreakpointForLoneSoftwareBreakpoint(trace1, 0x55550123, 2);
			assertLogicalBreakpointForLoneSoftwareBreakpoint(trace3, 0x55551123, 2);
		});

		expectMappingChange(() -> programManager.openProgram(program));
		waitForSwing();

		waitForPass(() -> {
			assertLogicalBreakpointForMappedBookmarkAnd2TraceBreakpoints(trace1, trace3);
		});
	}

	@Test
	public void testFill1Program2TracesThenStop1Trace() throws Throwable {
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

		addTextMapping(recorder1, text1, program);
		addTextMapping(recorder3, text3, program);
		waitForSwing();
		waitForPass(() -> {
			assertEquals(2, mappingService
					.getOpenMappedLocations(
						new ProgramLocation(program, addr(program, 0x00400123)))
					.size());
		});
		waitForSwing();

		addProgramBreakpoints(program);
		addTargetSoftwareBreakpoint(recorder1, text1);
		addTargetSoftwareBreakpoint(recorder3, text3);
		waitForSwing();

		waitForPass(() -> {
			assertLogicalBreakpointForMappedBookmarkAnd2TraceBreakpoints(trace1, trace3);
		});

		waitForLock(recorder3.getTrace());
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
	public void testAbortAddBreakpoint() throws Throwable {
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

		try (Transaction tx = trace.openTransaction("Will abort")) {
			addTargetSoftwareBreakpoint(recorder1, text);
			waitForDomainObject(trace);

			// Sanity
			assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);
			tx.abort();
		}
		waitForDomainObject(trace);

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testAbortAddMapping() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);
		addTargetSoftwareBreakpoint(recorder1, text);

		waitForPass(() -> {
			assertLogicalBreakpointForLoneSoftwareBreakpoint(trace, 1);
		});
		/**
		 * NB. The recorder could still be mid transaction. If we open this transaction too soon,
		 * then the breakpoint gets aborted as well.
		 */
		waitForLock(trace);
		waitForDomainObject(trace);
		changeListener.assertAgreesWithService();

		try (Transaction tx = trace.openTransaction("Will abort")) {
			expectMappingChange(() -> addTextMapping(recorder1, text, program));
			waitForSwing();

			// Sanity
			assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);

			expectMappingChange(() -> tx.abort());
		}

		waitForPass(() -> {
			// NB. The bookmark is left over, so total increases
			assertLogicalBreakpointForLoneSoftwareBreakpoint(trace, 2);
		});
	}

	@Test
	public void testAbortAddBreakpointAndMapping() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);

		try (Transaction tx = trace.openTransaction("Will abort")) {
			addTargetSoftwareBreakpoint(recorder1, text);

			expectMappingChange(() -> addTextMapping(recorder1, text, program));
			waitForSwing();

			// Sanity
			assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);

			expectMappingChange(() -> tx.abort());
		}
		waitForDomainObject(trace); // Duplicative, but for form's sake....

		// Left over, because it was bookmarked automatically in program
		// Still, there should be no trace breakpoint in it
		LogicalBreakpoint one = Unique.assertOne(breakpointService.getAllBreakpoints());
		assertTrue(one.getTraceBreakpoints().isEmpty());
	}

	@Test
	public void testAbortAddBookmarks() throws Throwable {
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

		try (Transaction tx = program.openTransaction("Will abort")) {
			addProgramBreakpoints(program);
			waitForDomainObject(program);

			// Sanity
			assertLogicalBreakpointsForMappedBookmarks(trace);
			tx.abort();
		}
		waitForDomainObject(program);

		assertTrue(breakpointService.getAllBreakpoints().isEmpty());
	}

	@Test
	public void testUndoRedoAddBreakpointAndMapping() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);

		try (Transaction tx = trace.openTransaction("Will undo")) {
			addTargetSoftwareBreakpoint(recorder1, text);
			expectMappingChange(() -> addTextMapping(recorder1, text, program));
		}
		waitForDomainObject(trace);

		waitOn(mappingService.changesSettled());
		waitOn(breakpointService.changesSettled());

		// Sanity
		assertLogicalBreakpointForMappedSoftwareBreakpoint(trace);

		expectMappingChange(() -> undo(trace));

		waitOn(mappingService.changesSettled());
		waitOn(breakpointService.changesSettled());

		// NB. The bookmark remains
		LogicalBreakpoint one = Unique.assertOne(breakpointService.getAllBreakpoints());
		assertTrue(one.getTraceBreakpoints().isEmpty());

		expectMappingChange(() -> redo(trace));

		// Mapping, breakpoint may be processed in whatever order
		waitForPass(() -> assertLogicalBreakpointForMappedSoftwareBreakpoint(trace));
	}

	@Test
	public void testUndoRedoAddBookmarks() throws Throwable {
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

		try (Transaction tx = program.openTransaction("Will undo")) {
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
		waitForPass(() -> {
			assertLogicalBreakpointForLoneSoftwareBreakpoint(trace, 1);
		});

		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		waitOn(lb.disable());
		waitForPass(() -> {
			assertEquals(State.INCONSISTENT_DISABLED, lb.computeState());
		});

		// Simulate a step, which should also cause snap advance in recorder
		long oldSnap = recorder1.getSnap();
		mb.testModel.session.simulateStep(mb.testThread1);
		waitOn(mb.testModel.flushEvents());
		waitForPass(() -> {
			assertEquals(oldSnap + 1, recorder1.getSnap());
			assertEquals(State.INCONSISTENT_DISABLED, lb.computeState());
		});

		waitOn(lb.enable());
		waitForPass(() -> {
			assertEquals(State.INCONSISTENT_ENABLED, lb.computeState());
		});
	}

	@Test
	public void testDeleteBreakpointTraceOnly() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);

		addTargetSoftwareBreakpoint(recorder1, text);

		waitForPass(() -> {
			assertLogicalBreakpointForLoneSoftwareBreakpoint(trace, 1);
		});

		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		waitOn(lb.delete());

		waitForPass(() -> {
			assertTrue(breakpointService.getAllBreakpoints().isEmpty());
		});
	}

	@Test
	public void testPlaceStepThenDeleteBreakpointTraceOnly() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);

		addTargetSoftwareBreakpoint(recorder1, text);
		waitForDomainObject(trace);

		waitForPass(() -> assertLogicalBreakpointForLoneSoftwareBreakpoint(trace, 1));

		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		// Simulate a step, which should also cause snap advance in recorder
		mb.testModel.session.simulateStep(mb.testThread1);
		waitRecorder(recorder1);

		waitOn(lb.delete());

		waitForPass(() -> {
			assertEquals(0, breakpointService.getAllBreakpoints().size());
		});
	}

	@Test
	public void testRecordThenCloseTraceOnly() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);

		addTargetSoftwareBreakpoint(recorder1, text);

		waitForPass(() -> {
			assertLogicalBreakpointForLoneSoftwareBreakpoint(trace, 1);
		});

		// NOTE: Still recording in the background
		traceManager.closeTrace(trace);
		waitForSwing();

		assertEquals(0, breakpointService.getAllBreakpoints().size());
	}

	@Test
	public void testRecordThenAddTwoBreakpointsDisable1Mixed() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);

		addTextMapping(recorder1, text, program);
		waitForSwing();

		addProgramBreakpoints(program);
		addTargetSoftwareBreakpoint(recorder1, text);
		addTargetSoftwareBreakpoint(recorder1, text);

		waitForPass(() -> {
			assertEquals(2, breakpointService.getAllBreakpoints().size());

			LogicalBreakpoint lb = Unique.assertOne(
				breakpointService.getBreakpointsAt(program, addr(program, 0x00400123)));
			assertEquals(program, lb.getProgram());
			assertEquals(Set.of(trace), lb.getMappedTraces());

			assertEquals(2, lb.getTraceBreakpoints().size());
		});

		LogicalBreakpoint lb = Unique
				.assertOne(breakpointService.getBreakpointsAt(program, addr(program, 0x00400123)));
		Set<TraceBreakpoint> locs = lb.getTraceBreakpoints();

		TraceBreakpoint bpt0 =
			locs.stream().filter(b -> b.getName().equals("0")).findAny().orElseThrow();
		TraceBreakpoint bpt1 =
			locs.stream().filter(b -> b.getName().equals("1")).findAny().orElseThrow();
		breakpointService.disableLocs(Set.of(bpt0));

		waitForPass(() -> {
			assertEquals(State.INCONSISTENT_ENABLED, lb.computeState());
			assertEquals(State.INCONSISTENT_MIXED, lb.computeStateForTrace(trace));
			assertEquals(State.INCONSISTENT_DISABLED, lb.computeStateForLocation(bpt0));
			assertEquals(State.ENABLED, lb.computeStateForLocation(bpt1));
		});
	}

	@Test
	public void testRecordThenAddTwoKindsOfBreakpointsDisable1Mixed() throws Throwable {
		startRecorder1();
		Trace trace = recorder1.getTrace();
		traceManager.openTrace(trace);

		createProgramFromTrace(trace);
		intoProject(program);
		programManager.openProgram(program);

		addProgramTextBlock(program);
		TestTargetMemoryRegion text = addTargetTextRegion(mb.testProcess1);

		addTextMapping(recorder1, text, program);
		waitForSwing();

		addProgramBreakpoints(program);
		addTargetSoftwareBreakpoint(recorder1, text);
		addTargetAccessBreakpoint(recorder1, text);

		waitForPass(() -> {
			assertEquals(3, breakpointService.getAllBreakpoints().size());

			Set<LogicalBreakpoint> lbs =
				breakpointService.getBreakpointsAt(program, addr(program, 0x00400123));
			assertEquals(2, lbs.size());
			lbs.stream()
					.filter(l -> l.getKinds().contains(TraceBreakpointKind.SW_EXECUTE))
					.findAny()
					.orElseThrow();
			lbs.stream()
					.filter(l -> l.getKinds().contains(TraceBreakpointKind.READ))
					.findAny()
					.orElseThrow();
		});
		Set<LogicalBreakpoint> lbs =
			breakpointService.getBreakpointsAt(program, addr(program, 0x00400123));
		LogicalBreakpoint lbEx = lbs.stream()
				.filter(l -> l.getKinds().contains(TraceBreakpointKind.SW_EXECUTE))
				.findAny()
				.orElseThrow();
		LogicalBreakpoint lbRw = lbs.stream()
				.filter(l -> l.getKinds().contains(TraceBreakpointKind.READ))
				.findAny()
				.orElseThrow();
		waitOn(lbEx.disable());

		// TODO: This is more a test for the marker plugin, no?
		waitForPass(
			() -> assertEquals(State.MIXED, lbEx.computeState().sameAdddress(lbRw.computeState())));
	}

	protected void addTextMappingDead(Program p, ToyDBTraceBuilder tb) throws Throwable {
		addProgramTextBlock(p);
		try (Transaction tid = tb.startTransaction()) {
			TraceMemoryRegion textRegion = tb.trace.getMemoryManager()
					.addRegion("Processes[1].Memory[bin:.text]", Lifespan.nowOn(0),
						tb.range(0x55550000, 0x55550fff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			DebuggerStaticMappingUtils.addMapping(
				new DefaultTraceLocation(tb.trace, null, textRegion.getLifespan(),
					textRegion.getMinAddress()),
				new ProgramLocation(p, addr(p, 0x00400000)), 0x1000,
				false);
		}
	}

	protected void addEnabledProgramBreakpointWithSleigh(Program p) {
		try (Transaction tid = p.openTransaction("Create bookmark bp with sleigh")) {
			enBm = p.getBookmarkManager()
					.setBookmark(addr(p, 0x00400123),
						LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE, "SW_EXECUTE;1",
						"{sleigh: 'r0=0xbeef;'}");
		}
	}

	@Test
	public void testMapThenAddProgramBreakpointWithSleighThenEnableOnTraceCopiesSleigh()
			throws Throwable {
		createTrace();
		traceManager.openTrace(tb.trace);
		createProgramFromTrace();
		intoProject(program);
		programManager.openProgram(program);

		addTextMappingDead(program, tb);
		waitForSwing();

		addEnabledProgramBreakpointWithSleigh(program);
		LogicalBreakpoint lb = waitForValue(() -> Unique.assertAtMostOne(
			breakpointService.getBreakpointsAt(program, addr(program, 0x00400123))));

		assertEquals("r0=0xbeef;", lb.getEmuSleigh());

		waitOn(lb.enable());
		waitForSwing();

		TraceBreakpoint bpt = Unique.assertOne(
			tb.trace.getBreakpointManager().getBreakpointsAt(0, tb.addr(0x55550123)));
		assertEquals("r0=0xbeef;", bpt.getEmuSleigh());
	}

	@Test
	public void testAddProgramBreakpointWithSleighThenMapThenEnableOnTraceCopiesSleigh()
			throws Throwable {
		createTrace();
		traceManager.openTrace(tb.trace);
		createProgramFromTrace();
		intoProject(program);
		programManager.openProgram(program);

		addEnabledProgramBreakpointWithSleigh(program);
		LogicalBreakpoint lb = waitForValue(() -> Unique.assertAtMostOne(
			breakpointService.getBreakpointsAt(program, addr(program, 0x00400123))));

		assertEquals("r0=0xbeef;", lb.getEmuSleigh());

		addTextMappingDead(program, tb);
		lb = waitForPass(() -> {
			LogicalBreakpoint newLb = Unique.assertOne(
				breakpointService.getBreakpointsAt(program, addr(program, 0x00400123)));
			assertTrue(newLb.getMappedTraces().contains(tb.trace));
			return newLb;
		});

		waitOn(lb.enable());
		waitForSwing();

		TraceBreakpoint bpt = Unique.assertOne(
			tb.trace.getBreakpointManager().getBreakpointsAt(0, tb.addr(0x55550123)));
		assertEquals("r0=0xbeef;", bpt.getEmuSleigh());
	}

	@Test
	public void testAddTraceBreakpointSetSleighThenMapThenSaveToProgramCopiesSleigh()
			throws Throwable {
		DebuggerControlService editingService =
			addPlugin(tool, DebuggerControlServicePlugin.class);

		// TODO: What if already mapped?
		// Not sure I care about tb.setEmuSleigh() out of band

		createTrace();
		traceManager.openTrace(tb.trace);
		editingService.setCurrentMode(tb.trace, ControlMode.RW_EMULATOR);
		createProgramFromTrace();
		intoProject(program);
		programManager.openProgram(program);

		try (Transaction tid = tb.startTransaction()) {
			TraceBreakpoint bpt = tb.trace.getBreakpointManager()
					.addBreakpoint("Processes[1].Breakpoints[0]", Lifespan.nowOn(0),
						tb.addr(0x55550123),
						Set.of(), Set.of(TraceBreakpointKind.SW_EXECUTE),
						false /* emuEnabled defaults to true */, "");
			bpt.setEmuSleigh("r0=0xbeef;");
		}
		LogicalBreakpoint lb = waitForValue(() -> Unique.assertAtMostOne(
			breakpointService.getBreakpointsAt(tb.trace, tb.addr(0x55550123))));

		assertEquals("r0=0xbeef;", lb.getEmuSleigh());

		addTextMappingDead(program, tb);
		lb = waitForPass(() -> {
			LogicalBreakpoint newLb = Unique.assertOne(
				breakpointService.getBreakpointsAt(program, addr(program, 0x00400123)));
			assertTrue(newLb.getMappedTraces().contains(tb.trace));
			return newLb;
		});

		lb.enableForProgram();
		waitForSwing();

		assertEquals("{\"sleigh\":\"r0\\u003d0xbeef;\"}", lb.getProgramBookmark().getComment());
	}
}
