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

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.MenuElement;
import javax.swing.SwingUtilities;

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import db.Transaction;
import docking.action.DockingAction;
import docking.widgets.fieldpanel.FieldPanel;
import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompileData;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.services.*;
import ghidra.app.services.LogicalBreakpoint.State;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.framework.store.LockException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class DebuggerBreakpointMarkerPluginTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected static final long TIMEOUT_MILLIS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

	protected static final Map<State, Color> COLOR_FOR_STATE =
		Stream.of(State.values()).collect(Collectors.toMap(s -> s, s -> new Color(s.ordinal())));

	protected DebuggerBreakpointMarkerPlugin breakpointMarkerPlugin;
	protected DebuggerListingPlugin listingPlugin;
	protected CodeBrowserPlugin codeBrowserPlugin;

	protected DebuggerLogicalBreakpointService breakpointService;
	protected DebuggerStaticMappingService mappingService;
	protected MarkerService markerService;

	protected Function function;
	protected Address entry;
	protected DecompilerProvider decompilerProvider;

	@Before
	public void setUpBreakpointMarkerPluginTest() throws Exception {
		breakpointMarkerPlugin = addPlugin(tool, DebuggerBreakpointMarkerPlugin.class);
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		codeBrowserPlugin = addPlugin(tool, CodeBrowserPlugin.class);

		mappingService = tool.getService(DebuggerStaticMappingService.class);
		breakpointService = tool.getService(DebuggerLogicalBreakpointService.class);
		markerService = tool.getService(MarkerService.class);
	}

	protected void prepareDecompiler() throws Throwable {
		addPlugin(tool, DecompilePlugin.class);
		decompilerProvider = waitForComponentProvider(DecompilerProvider.class);
		runSwing(() -> tool.showComponentProvider(decompilerProvider, true));
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		try (Transaction tx = program.openTransaction("Create function")) {
			entry = addr(program, 0x00400000);
			program.getMemory()
					.createInitializedBlock(".text", entry, 0x1000, (byte) 0,
						TaskMonitor.DUMMY, false);
			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			dis.disassemble(entry, new AddressSet(entry));

			function = program.getFunctionManager()
					.createFunction("test", entry,
						new AddressSet(entry), SourceType.USER_DEFINED);
		}
	}

	protected void addLiveMemoryAndBreakpoint(TraceRecorder recorder)
			throws InterruptedException, ExecutionException, TimeoutException {
		mb.testProcess1.addRegion("bin:.text", mb.rng(0x55550000, 0x55550fff), "rx");
		TargetBreakpointSpecContainer cont = getBreakpointContainer(recorder);
		cont.placeBreakpoint(mb.addr(0x55550123), Set.of(TargetBreakpointKind.SW_EXECUTE))
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

	protected void addMapping(Trace trace) throws Exception {
		try (Transaction tx = trace.openTransaction("Add mapping")) {
			DebuggerStaticMappingUtils.addMapping(
				new DefaultTraceLocation(trace, null, Lifespan.nowOn(0), addr(trace, 0x55550123)),
				new ProgramLocation(program, addr(program, 0x00400123)), 0x1000, false);
		}
	}

	protected void waitForMappedEnabledBreakpoint(Trace trace) throws Exception {
		waitForPass(() -> {
			LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
			assertEquals(program, lb.getProgram());
			assertEquals(Set.of(trace), lb.getParticipatingTraces());
			assertEquals(State.ENABLED, lb.computeState());
		});
	}

	protected TraceRecorder addMappedBreakpointOpenAndWait() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		waitRecorder(recorder);
		Trace trace = recorder.getTrace();
		createProgramFromTrace(trace);
		intoProject(trace);
		intoProject(program);

		addMapping(trace);
		addStaticMemoryAndBreakpoint();
		addLiveMemoryAndBreakpoint(recorder);
		programManager.openProgram(program);
		traceManager.openTrace(trace);
		waitForMappedEnabledBreakpoint(trace);

		return recorder;
	}

	protected Color getBackgroundColor(Program p, Address address) {
		return runSwing(() -> markerService.getBackgroundColor(p, address));
	}

	/**
	 * HACK: since service doesn't let me get markers for an address, change each that I can about
	 * to have a distinct background color
	 */
	protected void hackMarkerBackgroundColors(Program p) throws Exception {
		SwingUtilities.invokeAndWait(() -> {
			for (State state : State.values()) {
				if (state == State.NONE) {
					continue;
				}
				MarkerSet ms = markerService.getMarkerSet(state.display, p);
				ms.setMarkerColor(COLOR_FOR_STATE.get(state));
				ms.setColoringBackground(true);
			}
		});
	}

	protected static void clickListing(ListingPanel panel, Address address, int button)
			throws Exception {
		runSwing(() -> panel.goTo(address));
		waitForCondition(() -> {
			Rectangle cursor = panel.getCursorBounds();
			if (cursor == null) {
				return false;
			}
			Rectangle visible = panel.getVisibleRect();
			return visible.contains(cursor);
		});
		clickListing(panel.getFieldPanel(), button);
	}

	protected static void clickListing(FieldPanel fp, int button) throws Exception {
		clickListing(fp, fp.getCursorPoint(), button);
	}

	protected static void clickListing(FieldPanel fp, Point p, int button) throws Exception {
		Point fpsl = fp.getLocationOnScreen();
		Point s = new Point(fpsl.x + p.x, fpsl.y + p.y);
		clickMouse(button, s);
	}

	@Test
	public void testBreakpointMarked() throws Throwable {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		traceManager.activateTrace(trace);
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
		Address dAddr = addr(trace, 0x55550123);
		Address sAddr = addr(program, 0x00400123);
		TraceProgramView view = trace.getProgramView();
		hackMarkerBackgroundColors(view);
		hackMarkerBackgroundColors(program);

		waitForPass(() -> assertEquals(State.ENABLED, lb.computeStateForTrace(trace)));
		waitForPass(() -> assertEquals(COLOR_FOR_STATE.get(State.ENABLED),
			getBackgroundColor(view, dAddr)));
		waitForPass(() -> assertEquals(State.ENABLED, lb.computeStateForProgram(program)));
		waitForPass(() -> assertEquals(COLOR_FOR_STATE.get(State.ENABLED),
			getBackgroundColor(program, sAddr)));

		lb.disableForProgram();
		waitForDomainObject(program);

		waitForPass(() -> assertEquals(State.INCONSISTENT_ENABLED, lb.computeStateForTrace(trace)));
		waitForPass(() -> assertEquals(COLOR_FOR_STATE.get(State.INCONSISTENT_ENABLED),
			getBackgroundColor(view, dAddr)));
		waitForPass(
			() -> assertEquals(State.INCONSISTENT_DISABLED, lb.computeStateForProgram(program)));
		waitForPass(() -> assertEquals(COLOR_FOR_STATE.get(State.INCONSISTENT_DISABLED),
			getBackgroundColor(program, sAddr)));

		waitOn(lb.disableForTrace(trace));
		waitRecorder(recorder);

		waitForPass(() -> assertEquals(State.DISABLED, lb.computeStateForTrace(trace)));
		waitForPass(() -> assertEquals(COLOR_FOR_STATE.get(State.DISABLED),
			getBackgroundColor(view, dAddr)));
		waitForPass(() -> assertEquals(State.DISABLED, lb.computeStateForProgram(program)));
		waitForPass(() -> assertEquals(COLOR_FOR_STATE.get(State.DISABLED),
			getBackgroundColor(program, sAddr)));

		lb.enableForProgram();
		waitForDomainObject(program);

		waitForPass(
			() -> assertEquals(State.INCONSISTENT_DISABLED, lb.computeStateForTrace(trace)));
		waitForPass(() -> assertEquals(COLOR_FOR_STATE.get(State.INCONSISTENT_DISABLED),
			getBackgroundColor(view, dAddr)));
		waitForPass(
			() -> assertEquals(State.INCONSISTENT_ENABLED, lb.computeStateForProgram(program)));
		waitForPass(() -> assertEquals(COLOR_FOR_STATE.get(State.INCONSISTENT_ENABLED),
			getBackgroundColor(program, sAddr)));
	}

	protected static final Set<String> POPUP_ACTIONS = Set.of(AbstractSetBreakpointAction.NAME,
		AbstractToggleBreakpointAction.NAME, AbstractEnableBreakpointAction.NAME,
		AbstractDisableBreakpointAction.NAME, AbstractClearBreakpointAction.NAME);

	protected static final Set<String> SET_ACTIONS =
		Set.of("SW_EXECUTE", "HW_EXECUTE", "READ,WRITE", "READ", "WRITE");

	@Test
	public void testProgramNoBreakPopupMenus() throws Throwable {
		// NOTE: Need a target to have any breakpoint actions, even on programs
		addMappedBreakpointOpenAndWait();

		clickListing(codeBrowserPlugin.getListingPanel(), addr(program, 0x00400321),
			MouseEvent.BUTTON3);

		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME));
		MenuElement elem = getSubMenuElementByText(AbstractSetBreakpointAction.NAME);
		assertSubMenu(elem, SET_ACTIONS, SET_ACTIONS); // All of them

		// TODO: Margin, too?
	}

	@Test
	public void testTraceNoBreakPopupMenus() throws Throwable {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		traceManager.activateTrace(trace);
		waitForSwing();

		clickListing(listingPlugin.getListingPanel(), addr(trace, 0x55550321), MouseEvent.BUTTON3);

		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME));
		MenuElement elem = getSubMenuElementByText(AbstractSetBreakpointAction.NAME);
		assertSubMenu(elem, SET_ACTIONS, SET_ACTIONS); // All of them

		// TODO: Margin, too? (Is there one?)
	}

	@Test
	public void testProgramBreakpointPopupMenus() throws Throwable {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
		waitForPass(
			() -> assertEquals(State.ENABLED, lb.computeStateForProgram(program)));

		clickListing(codeBrowserPlugin.getListingPanel(), addr(program, 0x00400123),
			MouseEvent.BUTTON3);
		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractDisableBreakpointAction.NAME, AbstractClearBreakpointAction.NAME));

		pressEscape();
		lb.disableForProgram();
		waitForDomainObject(program);
		waitForPass(
			() -> assertEquals(State.INCONSISTENT_DISABLED, lb.computeStateForProgram(program)));

		clickListing(codeBrowserPlugin.getListingPanel(), addr(program, 0x00400123),
			MouseEvent.BUTTON3);
		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractEnableBreakpointAction.NAME, AbstractDisableBreakpointAction.NAME,
				AbstractClearBreakpointAction.NAME));

		pressEscape();
		waitOn(lb.disableForTrace(trace));
		waitRecorder(recorder);
		waitForPass(
			() -> assertEquals(State.DISABLED, lb.computeStateForProgram(program)));

		clickListing(codeBrowserPlugin.getListingPanel(), addr(program, 0x00400123),
			MouseEvent.BUTTON3);
		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractEnableBreakpointAction.NAME, AbstractClearBreakpointAction.NAME));

		pressEscape();
		lb.enableForProgram();
		waitForDomainObject(program);
		waitForPass(
			() -> assertEquals(State.INCONSISTENT_ENABLED, lb.computeStateForProgram(program)));

		clickListing(codeBrowserPlugin.getListingPanel(), addr(program, 0x00400123),
			MouseEvent.BUTTON3);
		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractEnableBreakpointAction.NAME, AbstractDisableBreakpointAction.NAME,
				AbstractClearBreakpointAction.NAME));

		// TODO: Margin, too?
	}

	@Test
	public void testTraceBreakpointPopupMenus() throws Throwable {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
		traceManager.activateTrace(trace);
		waitForSwing();
		waitForPass(
			() -> assertEquals(State.ENABLED, lb.computeStateForTrace(trace)));

		clickListing(listingPlugin.getListingPanel(), addr(trace, 0x55550123), MouseEvent.BUTTON3);
		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractDisableBreakpointAction.NAME, AbstractClearBreakpointAction.NAME));

		pressEscape();
		lb.disableForProgram(); // Adds "enable", which will only affect bookmark
		waitForDomainObject(program);
		waitForPass(
			() -> assertEquals(State.INCONSISTENT_ENABLED, lb.computeStateForTrace(trace)));

		clickListing(listingPlugin.getListingPanel(), addr(trace, 0x55550123), MouseEvent.BUTTON3);
		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractEnableBreakpointAction.NAME, AbstractDisableBreakpointAction.NAME,
				AbstractClearBreakpointAction.NAME));

		pressEscape();
		waitOn(lb.disableForTrace(trace));
		waitRecorder(recorder);
		waitForPass(
			() -> assertEquals(State.DISABLED, lb.computeStateForTrace(trace)));

		clickListing(listingPlugin.getListingPanel(), addr(trace, 0x55550123), MouseEvent.BUTTON3);
		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractEnableBreakpointAction.NAME, AbstractClearBreakpointAction.NAME));

		pressEscape();
		lb.enableForProgram(); // This time, adds "disable", which will only affect bookmark
		waitForDomainObject(program);
		waitForPass(
			() -> assertEquals(State.INCONSISTENT_DISABLED, lb.computeStateForTrace(trace)));

		clickListing(listingPlugin.getListingPanel(), addr(trace, 0x55550123), MouseEvent.BUTTON3);
		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractEnableBreakpointAction.NAME, AbstractDisableBreakpointAction.NAME,
				AbstractClearBreakpointAction.NAME));

		// TODO: Should mixed trace enablement be considered?
		// TODO: Margin, too?
	}

	protected ProgramLocationActionContext staticCtx(Address address) {
		return new ProgramLocationActionContext(codeBrowserPlugin.getProvider(), program,
			new ProgramLocation(program, address), null, null);
	}

	protected ProgramLocationActionContext dynamicCtx(Trace trace, Address address) {
		TraceProgramView view = trace.getProgramView();
		return new ProgramLocationActionContext(listingPlugin.getProvider(), view,
			new ProgramLocation(view, address), null, null);
	}

	@Test
	public void testActionToggleBreakpointProgramWithNoCurrentBreakpointOnInstruction()
			throws Throwable {
		addMappedBreakpointOpenAndWait(); // wasteful, but whatever
		for (LogicalBreakpoint lb : List.copyOf(breakpointService.getAllBreakpoints())) {
			lb.delete();
		}
		waitForPass(() -> assertEquals(0, breakpointService.getAllBreakpoints().size()));

		try (Transaction tx = program.openTransaction("Disassemble")) {
			Disassembler.getDisassembler(program, TaskMonitor.DUMMY, msg -> {
			}).disassemble(addr(program, 0x00400123), set(rng(program, 0x00400123, 0x00400123)));
		}
		waitForDomainObject(program);

		ProgramLocationActionContext ctx = staticCtx(addr(program, 0x00400123));
		assertTrue(breakpointMarkerPlugin.actionToggleBreakpoint.isAddToPopup(ctx));
		performAction(breakpointMarkerPlugin.actionToggleBreakpoint, ctx, false);
		DebuggerPlaceBreakpointDialog dialog =
			waitForDialogComponent(DebuggerPlaceBreakpointDialog.class);
		runSwing(() -> dialog.okCallback());

		waitForPass(() -> {
			LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
			assertEquals(State.ENABLED, lb.computeState());
			// TODO: Different cases for different expected default kinds?
			assertEquals(Set.of(TraceBreakpointKind.SW_EXECUTE), lb.getKinds());
		});
	}

	@Test
	public void testActionToggleBreakpointProgramWithNoCurrentBreakpointOnData() throws Throwable {
		addMappedBreakpointOpenAndWait(); // wasteful, but whatever
		for (LogicalBreakpoint lb : List.copyOf(breakpointService.getAllBreakpoints())) {
			lb.delete();
		}
		waitForPass(() -> assertEquals(0, breakpointService.getAllBreakpoints().size()));

		try (Transaction tx = program.openTransaction("Disassemble")) {
			program.getListing().createData(addr(program, 0x00400123), ByteDataType.dataType);
		}
		waitForDomainObject(program);

		ProgramLocationActionContext ctx = staticCtx(addr(program, 0x00400123));
		assertTrue(breakpointMarkerPlugin.actionToggleBreakpoint.isAddToPopup(ctx));
		performAction(breakpointMarkerPlugin.actionToggleBreakpoint, ctx, false);
		DebuggerPlaceBreakpointDialog dialog =
			waitForDialogComponent(DebuggerPlaceBreakpointDialog.class);
		runSwing(() -> dialog.okCallback());

		waitForPass(() -> {
			LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
			assertEquals(State.ENABLED, lb.computeState());
			// TODO: Different cases for different expected default kinds?
			assertEquals(Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE),
				lb.getKinds());
		});
	}

	@Test
	public void testActionToggleBreakpointProgram() throws Throwable {
		addMappedBreakpointOpenAndWait();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		ProgramLocationActionContext ctx = staticCtx(addr(program, 0x00400123));
		assertTrue(breakpointMarkerPlugin.actionToggleBreakpoint.isAddToPopup(ctx));
		performAction(breakpointMarkerPlugin.actionToggleBreakpoint, ctx, false);

		waitForPass(() -> assertEquals(State.DISABLED, lb.computeState()));

		assertTrue(breakpointMarkerPlugin.actionToggleBreakpoint.isAddToPopup(ctx));
		performAction(breakpointMarkerPlugin.actionToggleBreakpoint, ctx, false);

		waitForPass(() -> assertEquals(State.ENABLED, lb.computeState()));
	}

	@Test
	public void testActionToggleBreakpointTrace() throws Throwable {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		// NB. addMappedBreakpointOpenAndWait already makes this assertion. Just a reminder:
		waitForPass(() -> assertEquals(State.ENABLED, lb.computeStateForTrace(trace)));

		ProgramLocationActionContext ctx = dynamicCtx(trace, addr(trace, 0x55550123));
		assertTrue(breakpointMarkerPlugin.actionToggleBreakpoint.isAddToPopup(ctx));
		performAction(breakpointMarkerPlugin.actionToggleBreakpoint, ctx, true);

		waitForPass(() -> assertEquals(State.DISABLED, lb.computeStateForTrace(trace)));

		assertTrue(breakpointMarkerPlugin.actionToggleBreakpoint.isAddToPopup(ctx));
		performAction(breakpointMarkerPlugin.actionToggleBreakpoint, ctx, true);

		waitForPass(() -> assertEquals(State.ENABLED, lb.computeStateForTrace(trace)));

		// TODO: Add a second trace breakpoint and verify program toggling behavior
		// For now, just force an inconsistent state and see what happens when we toggle

		lb.disableForProgram();
		waitForPass(() -> assertEquals(State.INCONSISTENT_ENABLED, lb.computeStateForTrace(trace)));

		assertTrue(breakpointMarkerPlugin.actionToggleBreakpoint.isAddToPopup(ctx));
		performAction(breakpointMarkerPlugin.actionToggleBreakpoint, ctx, true);

		// NB. toggling from dynamic view, this toggles trace bpt, not logical/program bpt
		waitForPass(() -> assertEquals(State.DISABLED, lb.computeStateForTrace(trace)));

		lb.enableForProgram();
		waitForPass(
			() -> assertEquals(State.INCONSISTENT_DISABLED, lb.computeStateForTrace(trace)));

		assertTrue(breakpointMarkerPlugin.actionToggleBreakpoint.isAddToPopup(ctx));
		performAction(breakpointMarkerPlugin.actionToggleBreakpoint, ctx, true);

		waitForPass(() -> assertEquals(State.ENABLED, lb.computeStateForTrace(trace)));
	}

	protected void testActionSetBreakpointProgram(DockingAction action,
			Set<TraceBreakpointKind> expectedKinds) throws Throwable {
		addMappedBreakpointOpenAndWait(); // Adds an unneeded breakpoint. Aw well.

		ProgramLocationActionContext ctx = staticCtx(addr(program, 0x0400321));
		assertTrue(action.isAddToPopup(ctx));
		performAction(action, ctx, false);
		DebuggerPlaceBreakpointDialog dialog =
			waitForDialogComponent(DebuggerPlaceBreakpointDialog.class);
		runSwing(() -> {
			dialog.setName("Test name");
			dialog.okCallback();
		});

		waitForPass(() -> {
			LogicalBreakpoint lb = Unique.assertOne(
				breakpointService.getBreakpointsAt(program, addr(program, 0x00400321)));
			assertEquals(expectedKinds, lb.getKinds());
			assertEquals(State.ENABLED, lb.computeState());
			assertEquals("Test name", lb.getName());
		});
	}

	protected void testActionSetBreakpointTrace(DockingAction action,
			Set<TraceBreakpointKind> expectedKinds) throws Throwable {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait(); // Adds an unneeded breakpoint. Aw well.
		Trace trace = recorder.getTrace();

		ProgramLocationActionContext ctx = dynamicCtx(trace, addr(trace, 0x55550321));
		assertTrue(action.isAddToPopup(ctx));
		performAction(action, ctx, false);
		DebuggerPlaceBreakpointDialog dialog =
			waitForDialogComponent(DebuggerPlaceBreakpointDialog.class);
		runSwing(() -> dialog.okCallback());

		waitForPass(() -> {
			LogicalBreakpoint lb = Unique
					.assertOne(breakpointService.getBreakpointsAt(trace, addr(trace, 0x55550321)));
			assertEquals(expectedKinds, lb.getKinds());
			assertEquals(State.ENABLED, lb.computeStateForTrace(trace));
		});
		/**
		 * TODO: Test with a second trace? ATM, the program state is auto-synced with single trace,
		 * so might be difficult to assess more complex state changes.
		 */
	}

	@Test
	public void testActionSetSoftwareBreakpointProgram() throws Throwable {
		testActionSetBreakpointProgram(breakpointMarkerPlugin.actionSetSoftwareBreakpoint,
			Set.of(TraceBreakpointKind.SW_EXECUTE));
	}

	@Test
	public void testActionSetSoftwareBreakpointTrace() throws Throwable {
		testActionSetBreakpointTrace(breakpointMarkerPlugin.actionSetSoftwareBreakpoint,
			Set.of(TraceBreakpointKind.SW_EXECUTE));
	}

	@Test
	public void testActionSetExecuteBreakpointProgram() throws Throwable {
		testActionSetBreakpointProgram(breakpointMarkerPlugin.actionSetExecuteBreakpoint,
			Set.of(TraceBreakpointKind.HW_EXECUTE));
	}

	@Test
	public void testActionSetExecuteBreakpointTrace() throws Throwable {
		testActionSetBreakpointTrace(breakpointMarkerPlugin.actionSetExecuteBreakpoint,
			Set.of(TraceBreakpointKind.HW_EXECUTE));
	}

	@Test
	public void testActionSetReadWriteBreakpointProgram() throws Throwable {
		testActionSetBreakpointProgram(breakpointMarkerPlugin.actionSetReadWriteBreakpoint,
			Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE));
	}

	@Test
	public void testActionSetReadWriteBreakpointTrace() throws Throwable {
		testActionSetBreakpointTrace(breakpointMarkerPlugin.actionSetReadWriteBreakpoint,
			Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE));
	}

	@Test
	public void testActionSetReadBreakpointProgram() throws Throwable {
		testActionSetBreakpointProgram(breakpointMarkerPlugin.actionSetReadBreakpoint,
			Set.of(TraceBreakpointKind.READ));
	}

	@Test
	public void testActionSetReadBreakpointTrace() throws Throwable {
		testActionSetBreakpointTrace(breakpointMarkerPlugin.actionSetReadBreakpoint,
			Set.of(TraceBreakpointKind.READ));
	}

	@Test
	public void testActionSetWriteBreakpointProgram() throws Throwable {
		testActionSetBreakpointProgram(breakpointMarkerPlugin.actionSetWriteBreakpoint,
			Set.of(TraceBreakpointKind.WRITE));
	}

	@Test
	public void testActionSetWriteBreakpointTrace() throws Throwable {
		testActionSetBreakpointTrace(breakpointMarkerPlugin.actionSetWriteBreakpoint,
			Set.of(TraceBreakpointKind.WRITE));
	}

	@Test
	public void testActionEnableBreakpointProgram() throws Throwable {
		addMappedBreakpointOpenAndWait();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
		lb.disable();
		waitForPass(() -> assertEquals(State.DISABLED, lb.computeState()));

		ProgramLocationActionContext ctx = staticCtx(addr(program, 0x00400123));
		assertTrue(breakpointMarkerPlugin.actionEnableBreakpoint.isAddToPopup(ctx));
		performAction(breakpointMarkerPlugin.actionEnableBreakpoint, ctx, true);

		waitForPass(() -> assertEquals(State.ENABLED, lb.computeState()));
	}

	@Test
	public void testActionEnableBreakpointTrace() throws Throwable {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
		lb.disable();
		waitForPass(() -> assertEquals(State.DISABLED, lb.computeState()));

		ProgramLocationActionContext ctx = dynamicCtx(trace, addr(trace, 0x55550123));
		assertTrue(breakpointMarkerPlugin.actionEnableBreakpoint.isAddToPopup(ctx));
		performAction(breakpointMarkerPlugin.actionEnableBreakpoint, ctx, true);

		waitForPass(() -> assertEquals(State.ENABLED, lb.computeStateForTrace(trace)));
		// TODO: Same test but with multiple traces
	}

	@Test
	public void testActionDisableBreakpointProgram() throws Throwable {
		addMappedBreakpointOpenAndWait();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		ProgramLocationActionContext ctx = staticCtx(addr(program, 0x00400123));
		assertTrue(breakpointMarkerPlugin.actionDisableBreakpoint.isAddToPopup(ctx));
		performAction(breakpointMarkerPlugin.actionDisableBreakpoint, ctx, true);

		waitForPass(() -> assertEquals(State.DISABLED, lb.computeState()));
	}

	@Test
	public void testActionDisableBreakpointTrace() throws Throwable {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		ProgramLocationActionContext ctx = dynamicCtx(trace, addr(trace, 0x55550123));
		assertTrue(breakpointMarkerPlugin.actionDisableBreakpoint.isAddToPopup(ctx));
		performAction(breakpointMarkerPlugin.actionDisableBreakpoint, ctx, true);

		waitForPass(() -> assertEquals(State.DISABLED, lb.computeStateForTrace(trace)));
		// TODO: Same test but with multiple traces
	}

	@Test
	public void testActionClearBreakpointProgram() throws Throwable {
		addMappedBreakpointOpenAndWait();

		ProgramLocationActionContext ctx = staticCtx(addr(program, 0x00400123));
		assertTrue(breakpointMarkerPlugin.actionClearBreakpoint.isAddToPopup(ctx));
		performAction(breakpointMarkerPlugin.actionClearBreakpoint, ctx, true);

		waitForPass(() -> assertTrue(breakpointService.getAllBreakpoints().isEmpty()));
	}

	@Test
	public void testActionClearBreakpointTrace() throws Throwable {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		ProgramLocationActionContext ctx = dynamicCtx(trace, addr(trace, 0x55550123));
		assertTrue(breakpointMarkerPlugin.actionClearBreakpoint.isAddToPopup(ctx));
		performAction(breakpointMarkerPlugin.actionClearBreakpoint, ctx, true);

		waitForPass(() -> assertEquals(State.NONE, lb.computeStateForTrace(trace)));
		// TODO: Same test but with multiple traces
	}

	protected static DecompileData mockData(DecompileResults decompileResults) {
		Function function = decompileResults.getFunction();
		Program program = function.getProgram();
		ProgramLocation location = new ProgramLocation(program, function.getEntryPoint());
		return new DecompileData(program, function, location, decompileResults, "", null, null);
	}

	@Test
	public void testToggleBreakpointDecompilerNoAddress() throws Throwable {
		prepareDecompiler();
		DecompileResults results = new MockDecompileResults(function) {
			{
				root(function(token("token_no_addr")));
			}
		};
		runSwing(() -> decompilerProvider.getController().setDecompileData(mockData(results)));

		runSwing(() -> assertFalse(breakpointMarkerPlugin.actionToggleBreakpoint
				.isEnabledForContext(decompilerProvider.getActionContext(null))));
	}

	@Test
	public void testToggleBreakpointDecompilerOneAddress() throws Throwable {
		prepareDecompiler();
		DecompileResults results = new MockDecompileResults(function) {
			{
				root(function(token("token_with_addr", entry)));
			}
		};
		runSwing(() -> decompilerProvider.getController().setDecompileData(mockData(results)));

		performEnabledAction(decompilerProvider, breakpointMarkerPlugin.actionToggleBreakpoint,
			false);
		DebuggerPlaceBreakpointDialog dialog =
			waitForDialogComponent(DebuggerPlaceBreakpointDialog.class);
		runSwing(() -> dialog.okCallback());
		waitForPass(() -> {
			LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
			assertEquals(State.INEFFECTIVE_ENABLED, lb.computeState());
			assertEquals(Set.of(TraceBreakpointKind.SW_EXECUTE), lb.getKinds());
		});

		performEnabledAction(decompilerProvider, breakpointMarkerPlugin.actionToggleBreakpoint,
			true);
		waitForPass(() -> {
			LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
			assertEquals(State.INEFFECTIVE_DISABLED, lb.computeState());
			assertEquals(Set.of(TraceBreakpointKind.SW_EXECUTE), lb.getKinds());
		});
	}

	@Test
	public void testToggleBreakpointDecompilerTwoAddresses() throws Throwable {
		prepareDecompiler();
		DecompileResults results = new MockDecompileResults(function) {
			{
				root(function(token("token1_with_addr", entry),
					token("token2_with_addr", entry.add(2))));
			}
		};
		runSwing(() -> decompilerProvider.getController().setDecompileData(mockData(results)));

		waitOn(breakpointService.placeBreakpointAt(program, entry, 1,
			Set.of(TraceBreakpointKind.SW_EXECUTE), ""));
		waitOn(breakpointService.placeBreakpointAt(program, entry.add(2), 1,
			Set.of(TraceBreakpointKind.SW_EXECUTE), ""));
		waitForPass(() -> {
			assertEquals(2, breakpointService.getAllBreakpoints().size());
		});

		performEnabledAction(decompilerProvider, breakpointMarkerPlugin.actionToggleBreakpoint,
			true);
		waitForPass(() -> {
			Set<LogicalBreakpoint> all = breakpointService.getAllBreakpoints();
			assertEquals(2, all.size());
			for (LogicalBreakpoint lb : all) {
				assertEquals(State.INEFFECTIVE_DISABLED, lb.computeState());
			}
		});
	}
}
