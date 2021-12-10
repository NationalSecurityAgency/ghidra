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
import java.util.Set;
import java.util.concurrent.*;

import javax.swing.MenuElement;
import javax.swing.SwingUtilities;

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import com.google.common.collect.Range;

import docking.action.DockingAction;
import docking.widgets.fieldpanel.FieldPanel;
import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.services.*;
import ghidra.app.services.LogicalBreakpoint.Enablement;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.framework.store.LockException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.SystemUtilities;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class DebuggerBreakpointMarkerPluginTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected static final long TIMEOUT_MILLIS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

	protected static final Color D_COLOR = new Color(255, 192, 192);
	protected static final Color E_COLOR = new Color(255, 128, 128);
	protected static final Color DE_COLOR = new Color(255, 192, 128);
	protected static final Color ED_COLOR = new Color(255, 128, 192);

	protected DebuggerBreakpointMarkerPlugin breakpointMarkerPlugin;
	protected DebuggerListingPlugin listingPlugin;
	protected CodeBrowserPlugin codeBrowserPlugin;

	protected DebuggerLogicalBreakpointService breakpointService;
	protected DebuggerStaticMappingService mappingService;
	protected MarkerService markerService;

	@Before
	public void setUpBreakpointMarkerPluginTest() throws Exception {
		breakpointMarkerPlugin = addPlugin(tool, DebuggerBreakpointMarkerPlugin.class);
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		codeBrowserPlugin = addPlugin(tool, CodeBrowserPlugin.class);

		mappingService = tool.getService(DebuggerStaticMappingService.class);
		breakpointService = tool.getService(DebuggerLogicalBreakpointService.class);
		markerService = tool.getService(MarkerService.class);
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
		try (UndoableTransaction tid =
			UndoableTransaction.start(program, "Add bookmark break", true)) {
			program.getMemory()
					.createInitializedBlock(".text", addr(program, 0x00400000), 0x1000, (byte) 0,
						TaskMonitor.DUMMY, false);
			program.getBookmarkManager()
					.setBookmark(addr(program, 0x00400123),
						LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE, "SW_EXECUTE;1", "");
		}
	}

	protected void addMapping(Trace trace) throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Add mapping", true)) {
			DebuggerStaticMappingUtils.addMapping(
				new DefaultTraceLocation(trace, null, Range.atLeast(0L), addr(trace, 0x55550123)),
				new ProgramLocation(program, addr(program, 0x00400123)), 0x1000, false);
		}
	}

	protected void waitForMappedEnabledBreakpoint(Trace trace) throws Exception {
		waitForPass(() -> {
			LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
			assertEquals(program, lb.getProgram());
			assertEquals(Set.of(trace), lb.getParticipatingTraces());
			assertEquals(Enablement.ENABLED, lb.computeEnablement());
		});
	}

	protected TraceRecorder addMappedBreakpointOpenAndWait() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
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
			MarkerSet dd =
				markerService.getMarkerSet(DebuggerResources.MARKER_NAME_BREAKPOINT_DISABLED, p);
			dd.setMarkerColor(D_COLOR);
			dd.setColoringBackground(true);
			MarkerSet ee =
				markerService.getMarkerSet(DebuggerResources.MARKER_NAME_BREAKPOINT_ENABLED, p);
			ee.setMarkerColor(E_COLOR);
			ee.setColoringBackground(true);
			MarkerSet de =
				markerService.getMarkerSet(DebuggerResources.MARKER_NAME_BREAKPOINT_MIXED_DE, p);
			de.setMarkerColor(DE_COLOR);
			de.setColoringBackground(true);
			MarkerSet ed =
				markerService.getMarkerSet(DebuggerResources.MARKER_NAME_BREAKPOINT_MIXED_ED, p);
			ed.setMarkerColor(ED_COLOR);
			ed.setColoringBackground(true);
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
	public void testProgramBreakpointMarked() throws Exception {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
		Address addr = addr(program, 0x00400123);
		hackMarkerBackgroundColors(program);

		waitForPass(() -> assertEquals(E_COLOR, getBackgroundColor(program, addr)));

		lb.disableForProgram();
		waitForDomainObject(program);

		waitForPass(() -> assertEquals(DE_COLOR, getBackgroundColor(program, addr)));

		lb.disableForTrace(trace);
		waitForDomainObject(trace);

		waitForPass(() -> assertEquals(D_COLOR, getBackgroundColor(program, addr)));

		lb.enableForProgram();
		waitForDomainObject(program);

		waitForPass(() -> assertEquals(ED_COLOR, getBackgroundColor(program, addr)));
	}

	@Test
	public void testTraceBreakpointMarked() throws Exception {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
		Address addr = addr(trace, 0x55550123);
		TraceProgramView view = trace.getProgramView();
		hackMarkerBackgroundColors(view);

		assertEquals(E_COLOR, getBackgroundColor(view, addr));

		lb.disableForProgram();
		waitForDomainObject(program);

		waitForPass(() -> assertEquals(ED_COLOR, getBackgroundColor(view, addr)));

		lb.disableForTrace(trace);
		waitForDomainObject(trace);

		waitForPass(() -> assertEquals(D_COLOR, getBackgroundColor(view, addr)));

		lb.enableForProgram();
		waitForDomainObject(program);

		waitForPass(() -> assertEquals(DE_COLOR, getBackgroundColor(view, addr)));
	}

	protected static final Set<String> POPUP_ACTIONS = Set.of(AbstractSetBreakpointAction.NAME,
		AbstractToggleBreakpointAction.NAME, AbstractEnableBreakpointAction.NAME,
		AbstractDisableBreakpointAction.NAME, AbstractClearBreakpointAction.NAME);

	protected static final Set<String> SET_ACTIONS =
		Set.of("SW_EXECUTE", "HW_EXECUTE", "READ,WRITE", "READ", "WRITE");

	@Test
	public void testProgramNoBreakPopupMenus() throws Exception {
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
	public void testTraceNoBreakPopupMenus() throws Exception {
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
	public void testProgramBreakpointPopupMenus() throws Exception {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		clickListing(codeBrowserPlugin.getListingPanel(), addr(program, 0x00400123),
			MouseEvent.BUTTON3);

		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractDisableBreakpointAction.NAME, AbstractClearBreakpointAction.NAME));

		pressEscape();
		lb.disableForProgram();
		waitForDomainObject(program);

		clickListing(codeBrowserPlugin.getListingPanel(), addr(program, 0x00400123),
			MouseEvent.BUTTON3);

		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractEnableBreakpointAction.NAME, AbstractDisableBreakpointAction.NAME,
				AbstractClearBreakpointAction.NAME));

		pressEscape();
		lb.disableForTrace(trace);
		waitForDomainObject(trace);

		clickListing(codeBrowserPlugin.getListingPanel(), addr(program, 0x00400123),
			MouseEvent.BUTTON3);

		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractEnableBreakpointAction.NAME, AbstractClearBreakpointAction.NAME));

		pressEscape();
		lb.enableForProgram();
		waitForDomainObject(program);

		clickListing(codeBrowserPlugin.getListingPanel(), addr(program, 0x00400123),
			MouseEvent.BUTTON3);

		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractEnableBreakpointAction.NAME, AbstractDisableBreakpointAction.NAME,
				AbstractClearBreakpointAction.NAME));

		// TODO: Margin, too?
	}

	@Test
	public void testTraceBreakpointPopupMenus() throws Exception {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
		traceManager.activateTrace(trace);
		waitForSwing();

		clickListing(listingPlugin.getListingPanel(), addr(trace, 0x55550123), MouseEvent.BUTTON3);

		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractDisableBreakpointAction.NAME, AbstractClearBreakpointAction.NAME));

		pressEscape();
		lb.disableForProgram(); // Should not change anything
		waitForDomainObject(program);

		clickListing(listingPlugin.getListingPanel(), addr(trace, 0x55550123), MouseEvent.BUTTON3);

		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractDisableBreakpointAction.NAME, AbstractClearBreakpointAction.NAME));

		pressEscape();
		lb.disableForTrace(trace);
		waitForDomainObject(trace);

		clickListing(listingPlugin.getListingPanel(), addr(trace, 0x55550123), MouseEvent.BUTTON3);

		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractEnableBreakpointAction.NAME, AbstractClearBreakpointAction.NAME));

		pressEscape();
		lb.enableForProgram(); // Again, no change
		waitForDomainObject(program);

		clickListing(listingPlugin.getListingPanel(), addr(trace, 0x55550123), MouseEvent.BUTTON3);

		assertMenu(POPUP_ACTIONS,
			Set.of(AbstractSetBreakpointAction.NAME, AbstractToggleBreakpointAction.NAME,
				AbstractEnableBreakpointAction.NAME, AbstractClearBreakpointAction.NAME));

		// TODO: Should mixed trace enablement be considered?
		// TODO: Margin, too? (Is there one?)
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
			throws Exception {
		addMappedBreakpointOpenAndWait(); // wasteful, but whatever
		for (LogicalBreakpoint lb : List.copyOf(breakpointService.getAllBreakpoints())) {
			lb.delete();
		}
		waitForPass(() -> assertEquals(0, breakpointService.getAllBreakpoints().size()));

		try (UndoableTransaction tid = UndoableTransaction.start(program, "Disassemble", true)) {
			Disassembler.getDisassembler(program, TaskMonitor.DUMMY, msg -> {
			}).disassemble(addr(program, 0x00400123), set(rng(program, 0x00400123, 0x00400123)));
		}
		waitForDomainObject(program);

		performAction(breakpointMarkerPlugin.actionToggleBreakpoint,
			staticCtx(addr(program, 0x00400123)), false);
		DebuggerPlaceBreakpointDialog dialog =
			waitForDialogComponent(DebuggerPlaceBreakpointDialog.class);
		dialog.okCallback();

		waitForPass(() -> {
			LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
			assertEquals(Enablement.ENABLED, lb.computeEnablement());
			// TODO: Different cases for different expected default kinds?
			assertEquals(Set.of(TraceBreakpointKind.SW_EXECUTE), lb.getKinds());
		});
	}

	@Test
	public void testActionToggleBreakpointProgramWithNoCurrentBreakpointOnData() throws Exception {
		addMappedBreakpointOpenAndWait(); // wasteful, but whatever
		for (LogicalBreakpoint lb : List.copyOf(breakpointService.getAllBreakpoints())) {
			lb.delete();
		}
		waitForPass(() -> assertEquals(0, breakpointService.getAllBreakpoints().size()));

		try (UndoableTransaction tid = UndoableTransaction.start(program, "Disassemble", true)) {
			program.getListing().createData(addr(program, 0x00400123), ByteDataType.dataType);
		}
		waitForDomainObject(program);

		performAction(breakpointMarkerPlugin.actionToggleBreakpoint,
			staticCtx(addr(program, 0x00400123)), false);
		DebuggerPlaceBreakpointDialog dialog =
			waitForDialogComponent(DebuggerPlaceBreakpointDialog.class);
		dialog.okCallback();

		waitForPass(() -> {
			LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
			assertEquals(Enablement.ENABLED, lb.computeEnablement());
			// TODO: Different cases for different expected default kinds?
			assertEquals(Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE),
				lb.getKinds());
		});
	}

	@Test
	public void testActionToggleBreakpointProgram() throws Exception {
		addMappedBreakpointOpenAndWait();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		performAction(breakpointMarkerPlugin.actionToggleBreakpoint,
			staticCtx(addr(program, 0x00400123)), false);

		waitForPass(() -> assertEquals(Enablement.DISABLED, lb.computeEnablement()));

		performAction(breakpointMarkerPlugin.actionToggleBreakpoint,
			staticCtx(addr(program, 0x00400123)), false);

		waitForPass(() -> assertEquals(Enablement.ENABLED, lb.computeEnablement()));
	}

	@Test
	public void testActionToggleBreakpointTrace() throws Exception {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		performAction(breakpointMarkerPlugin.actionToggleBreakpoint,
			dynamicCtx(trace, addr(trace, 0x55550123)), true);

		waitForPass(
			() -> assertEquals(Enablement.DISABLED_ENABLED, lb.computeEnablementForTrace(trace)));

		performAction(breakpointMarkerPlugin.actionToggleBreakpoint,
			dynamicCtx(trace, addr(trace, 0x55550123)), true);

		waitForPass(() -> assertEquals(Enablement.ENABLED, lb.computeEnablementForTrace(trace)));
	}

	protected void testActionSetBreakpointProgram(DockingAction action,
			Set<TraceBreakpointKind> expectedKinds) throws Exception {
		addMappedBreakpointOpenAndWait(); // Adds an unneeded breakpoint. Aw well.

		performAction(action, staticCtx(addr(program, 0x0400321)), false);
		DebuggerPlaceBreakpointDialog dialog =
			waitForDialogComponent(DebuggerPlaceBreakpointDialog.class);
		dialog.okCallback();

		waitForPass(() -> {
			LogicalBreakpoint lb = Unique.assertOne(
				breakpointService.getBreakpointsAt(program, addr(program, 0x00400321)));
			assertEquals(expectedKinds, lb.getKinds());
			assertEquals(Enablement.ENABLED, lb.computeEnablement());
		});
	}

	protected void testActionSetBreakpointTrace(DockingAction action,
			Set<TraceBreakpointKind> expectedKinds) throws Exception {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait(); // Adds an unneeded breakpoint. Aw well.
		Trace trace = recorder.getTrace();

		performAction(action, dynamicCtx(trace, addr(trace, 0x55550321)), false);
		DebuggerPlaceBreakpointDialog dialog =
			waitForDialogComponent(DebuggerPlaceBreakpointDialog.class);
		dialog.okCallback();

		waitForPass(() -> {
			LogicalBreakpoint lb = Unique
					.assertOne(breakpointService.getBreakpointsAt(trace, addr(trace, 0x55550321)));
			assertEquals(expectedKinds, lb.getKinds());
			assertEquals(Enablement.ENABLED_DISABLED, lb.computeEnablementForTrace(trace));
		});
	}

	@Test
	public void testActionSetSoftwareBreakpointProgram() throws Exception {
		testActionSetBreakpointProgram(breakpointMarkerPlugin.actionSetSoftwareBreakpoint,
			Set.of(TraceBreakpointKind.SW_EXECUTE));
	}

	@Test
	public void testActionSetSoftwareBreakpointTrace() throws Exception {
		testActionSetBreakpointTrace(breakpointMarkerPlugin.actionSetSoftwareBreakpoint,
			Set.of(TraceBreakpointKind.SW_EXECUTE));
	}

	@Test
	public void testActionSetExecuteBreakpointProgram() throws Exception {
		testActionSetBreakpointProgram(breakpointMarkerPlugin.actionSetExecuteBreakpoint,
			Set.of(TraceBreakpointKind.HW_EXECUTE));
	}

	@Test
	public void testActionSetExecuteBreakpointTrace() throws Exception {
		testActionSetBreakpointTrace(breakpointMarkerPlugin.actionSetExecuteBreakpoint,
			Set.of(TraceBreakpointKind.HW_EXECUTE));
	}

	@Test
	public void testActionSetReadWriteBreakpointProgram() throws Exception {
		testActionSetBreakpointProgram(breakpointMarkerPlugin.actionSetReadWriteBreakpoint,
			Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE));
	}

	@Test
	public void testActionSetReadWriteBreakpointTrace() throws Exception {
		testActionSetBreakpointTrace(breakpointMarkerPlugin.actionSetReadWriteBreakpoint,
			Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE));
	}

	@Test
	public void testActionSetReadBreakpointProgram() throws Exception {
		testActionSetBreakpointProgram(breakpointMarkerPlugin.actionSetReadBreakpoint,
			Set.of(TraceBreakpointKind.READ));
	}

	@Test
	public void testActionSetReadBreakpointTrace() throws Exception {
		testActionSetBreakpointTrace(breakpointMarkerPlugin.actionSetReadBreakpoint,
			Set.of(TraceBreakpointKind.READ));
	}

	@Test
	public void testActionSetWriteBreakpointProgram() throws Exception {
		testActionSetBreakpointProgram(breakpointMarkerPlugin.actionSetWriteBreakpoint,
			Set.of(TraceBreakpointKind.WRITE));
	}

	@Test
	public void testActionSetWriteBreakpointTrace() throws Exception {
		testActionSetBreakpointTrace(breakpointMarkerPlugin.actionSetWriteBreakpoint,
			Set.of(TraceBreakpointKind.WRITE));
	}

	@Test
	public void testActionEnableBreakpointProgram() throws Exception {
		addMappedBreakpointOpenAndWait();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
		lb.disable();
		waitForPass(() -> assertEquals(Enablement.DISABLED, lb.computeEnablement()));

		performAction(breakpointMarkerPlugin.actionEnableBreakpoint,
			staticCtx(addr(program, 0x00400123)), true);

		waitForPass(() -> assertEquals(Enablement.ENABLED, lb.computeEnablement()));
	}

	@Test
	public void testActionEnableBreakpointTrace() throws Exception {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
		lb.disable();
		waitForPass(() -> assertEquals(Enablement.DISABLED, lb.computeEnablement()));

		performAction(breakpointMarkerPlugin.actionEnableBreakpoint,
			dynamicCtx(trace, addr(trace, 0x55550123)), true);

		waitForPass(
			() -> assertEquals(Enablement.ENABLED_DISABLED, lb.computeEnablementForTrace(trace)));
	}

	@Test
	public void testActionDisableBreakpointProgram() throws Exception {
		addMappedBreakpointOpenAndWait();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		performAction(breakpointMarkerPlugin.actionDisableBreakpoint,
			staticCtx(addr(program, 0x00400123)), true);

		waitForPass(() -> assertEquals(Enablement.DISABLED, lb.computeEnablement()));
	}

	@Test
	public void testActionDisableBreakpointTrace() throws Exception {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		performAction(breakpointMarkerPlugin.actionDisableBreakpoint,
			dynamicCtx(trace, addr(trace, 0x55550123)), true);

		waitForPass(
			() -> assertEquals(Enablement.DISABLED_ENABLED, lb.computeEnablementForTrace(trace)));
	}

	@Test
	public void testActionClearBreakpointProgram() throws Exception {
		addMappedBreakpointOpenAndWait();

		performAction(breakpointMarkerPlugin.actionClearBreakpoint,
			staticCtx(addr(program, 0x00400123)), true);

		waitForPass(() -> assertTrue(breakpointService.getAllBreakpoints().isEmpty()));
	}

	@Test
	public void testActionClearBreakpointTrace() throws Exception {
		TraceRecorder recorder = addMappedBreakpointOpenAndWait();
		Trace trace = recorder.getTrace();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		performAction(breakpointMarkerPlugin.actionClearBreakpoint,
			dynamicCtx(trace, addr(trace, 0x55550123)), true);

		// NB. Because it was deleted from the *trace context*
		waitForPass(() -> assertEquals(Enablement.INEFFECTIVE_ENABLED,
			lb.computeEnablementForTrace(trace)));
	}
}
