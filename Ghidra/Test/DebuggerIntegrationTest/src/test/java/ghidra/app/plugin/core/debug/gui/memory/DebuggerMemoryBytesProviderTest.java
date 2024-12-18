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
package ghidra.app.plugin.core.debug.gui.memory;

import static ghidra.lifecycle.Unfinished.TODO;
import static org.junit.Assert.*;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyEvent;
import java.awt.image.BufferedImage;
import java.math.BigInteger;
import java.util.Date;
import java.util.Objects;

import org.junit.*;
import org.junit.experimental.categories.Category;

import db.Transaction;
import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.dnd.GClipboard;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.OptionDialog;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.test.category.NightlyCategory;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.byteviewer.ByteViewerComponent;
import ghidra.app.plugin.core.byteviewer.ByteViewerPanel;
import ghidra.app.plugin.core.clipboard.ClipboardPlugin;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerIntegrationTest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.FollowsCurrentThreadAction;
import ghidra.app.plugin.core.debug.gui.action.*;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin;
import ghidra.app.plugin.core.debug.service.progress.ProgressServicePlugin;
import ghidra.app.services.DebuggerControlService;
import ghidra.async.SwingExecutorService;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.stack.DBTraceStackManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceThread;

@Category(NightlyCategory.class)
public class DebuggerMemoryBytesProviderTest extends AbstractGhidraHeadedDebuggerIntegrationTest {

	protected DebuggerMemoryBytesPlugin memBytesPlugin;
	protected DebuggerMemoryBytesProvider memBytesProvider;

	protected DebuggerControlService controlService;

	@Before
	public void setUpMemoryBytesProviderTest() throws Exception {
		memBytesPlugin = addPlugin(tool, DebuggerMemoryBytesPlugin.class);
		memBytesProvider = waitForComponentProvider(DebuggerMemoryBytesProvider.class);
		memBytesProvider.setVisible(true);

		controlService = addPlugin(tool, DebuggerControlServicePlugin.class);
	}

	protected void goToDyn(Address address) {
		goToDyn(new ProgramLocation(traceManager.getCurrentView(), address));
	}

	protected void goToDyn(ProgramLocation location) {
		waitForPass(() -> {
			runSwing(() -> memBytesProvider.goTo(location.getProgram(), location));
			ProgramLocation confirm = runSwing(() -> memBytesProvider.getLocation());
			assertNotNull(confirm);
			assertEquals(location.getAddress(), confirm.getAddress());
		});
	}

	protected static byte[] incBlock() {
		byte[] data = new byte[4096];
		for (int i = 0; i < data.length; i++) {
			data[i] = (byte) i;
		}
		return data;
	}

	@Test
	public void testBytesViewIsRegionsActivateThenAdd() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		waitForDomainObject(tb.trace);

		waitForPass(() -> {
			assertEquals(tb.set(tb.range(0x00400000, 0x0040ffff)),
				memBytesProvider.getByteViewerPanel().getCurrentComponent().getView());
		});
	}

	@Test
	public void testBytesViewIsRegionsAddThenActivate() throws Exception {
		createAndOpenTrace();
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		waitForDomainObject(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(tb.set(tb.range(0x00400000, 0x0040ffff)),
			new AddressSet(memBytesProvider.getByteViewerPanel().getCurrentComponent().getView()));
	}

	@Test
	public void testRegisterTrackingOnRegisterChange() throws Exception {
		createAndOpenTrace();
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceThread thread = tb.getOrAddThread("Thread1", 0);
			waitForDomainObject(tb.trace);
			traceManager.activateThread(thread);
			waitForSwing(); // Ensure the open/activate events are processed first

			assertEquals(tb.trace.getProgramView(), memBytesProvider.getProgram());

			// NOTE: PC-tracking should be the default for the main bytes viewer
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemorySpace regs = memory.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
		}
		waitForDomainObject(tb.trace);

		ProgramLocation loc = memBytesProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00401234), loc.getAddress());
	}

	@Test
	public void testRegisterTrackingOnSnapChange() throws Exception {
		createAndOpenTrace();
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceThread thread = tb.getOrAddThread("Thread1", 0);
			waitForDomainObject(tb.trace);
			traceManager.activateThread(thread);
			waitForSwing(); // Ensure the open/activate events are processed first

			assertEquals(tb.trace.getProgramView(), memBytesProvider.getProgram());

			// NOTE: PC-tracking should be the default for the main bytes viewer
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemorySpace regs = memory.getMemoryRegisterSpace(thread, true);
			regs.setValue(1, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
		}
		waitForDomainObject(tb.trace);
		//Pre-check. NOTE: PC not set at 0, so tracking is not performed.
		// Because BytesProvider is wierd, this means it's currentLocation is null :/
		assertNull(memBytesProvider.getLocation());

		traceManager.activateSnap(1);
		waitForSwing();

		ProgramLocation loc = memBytesProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00401234), loc.getAddress());
	}

	@Test
	public void testRegisterTrackingOnThreadChangeWithFollowsCurrentThread() throws Exception {
		createAndOpenTrace();
		TraceThread thread1;
		TraceThread thread2;
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread1 = tb.getOrAddThread("Thread1", 0);
			thread2 = tb.getOrAddThread("Thread2", 0);

			// NOTE: PC-tracking should be the default for the main bytes viewer
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemorySpace regs1 = memory.getMemoryRegisterSpace(thread1, true);
			regs1.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
			TraceMemorySpace regs2 = memory.getMemoryRegisterSpace(thread2, true);
			regs2.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00405678)));
		}
		waitForDomainObject(tb.trace);
		ProgramLocation loc;

		traceManager.activateThread(thread1);
		waitForSwing();

		loc = memBytesProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00401234), loc.getAddress());

		traceManager.activateThread(thread2);
		waitForSwing();

		loc = memBytesProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00405678), loc.getAddress());
	}

	@Test(expected = IllegalStateException.class)
	public void testMainViewerMustFollowCurrentThread() {
		memBytesProvider.setFollowsCurrentThread(false);
	}

	@Test
	public void testRegisterTrackingOnThreadChangeWithoutFollowsCurrentThread() throws Exception {
		createAndOpenTrace();
		TraceThread thread1;
		TraceThread thread2;
		DebuggerMemoryBytesProvider extraProvider = SwingExecutorService.LATER
				.submit(() -> memBytesPlugin.createViewerIfMissing(PCLocationTrackingSpec.INSTANCE,
					true))
				.get();
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread1 = tb.getOrAddThread("Thread1", 0);
			thread2 = tb.getOrAddThread("Thread2", 0);

			// NOTE: PC-tracking should be the default for the main bytes viewer
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemorySpace regs1 = memory.getMemoryRegisterSpace(thread1, true);
			regs1.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
			TraceMemorySpace regs2 = memory.getMemoryRegisterSpace(thread2, true);
			regs2.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00405678)));
		}
		waitForDomainObject(tb.trace);
		ProgramLocation loc;

		traceManager.activateThread(thread1);
		waitForSwing();

		loc = extraProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00401234), loc.getAddress());

		extraProvider.setFollowsCurrentThread(false);
		traceManager.activateThread(thread2);
		waitForSwing();

		loc = extraProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00401234), loc.getAddress());
	}

	@Test
	public void testRegisterTrackingOnTrackingSpecChange() throws Exception {
		createAndOpenTrace();
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			memory.addRegion("[stack]", Lifespan.nowOn(0), tb.range(0x01000000, 0x01ffffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
			TraceThread thread = tb.getOrAddThread("Thread1", 0);
			waitForDomainObject(tb.trace);
			traceManager.activateThread(thread);
			waitForSwing(); // Ensure the open/activate events are processed first

			assertEquals(tb.trace.getProgramView(), memBytesProvider.getProgram());

			TraceMemorySpace regs = memory.getMemoryRegisterSpace(thread, true);
			Register sp = tb.trace.getBaseCompilerSpec().getStackPointer();
			regs.setValue(0, new RegisterValue(sp, BigInteger.valueOf(0x01fff800)));
		}
		waitForDomainObject(tb.trace);
		//Pre-check
		assertNull(memBytesProvider.getLocation());

		runSwing(() -> memBytesProvider.setTrackingSpec(SPLocationTrackingSpec.INSTANCE));

		ProgramLocation loc = waitForValue(() -> memBytesProvider.getLocation());
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x01fff800), loc.getAddress());
	}

	@Test
	public void testFollowsCurrentTraceOnTraceChangeWithoutRegisterTracking() throws Exception {
		runSwing(() -> memBytesProvider.setTrackingSpec(NoneLocationTrackingSpec.INSTANCE));
		try ( //
				ToyDBTraceBuilder b1 =
					new ToyDBTraceBuilder(name.getMethodName() + "_1", LANGID_TOYBE64); //
				ToyDBTraceBuilder b2 =
					new ToyDBTraceBuilder(name.getMethodName() + "_2", LANGID_TOYBE64)) {
			TraceThread t1, t2;

			try (Transaction tx = b1.startTransaction()) {
				b1.trace.getTimeManager().createSnapshot("First snap");
				DBTraceMemoryManager memory = b1.trace.getMemoryManager();
				memory.addRegion("exe:.text", Lifespan.nowOn(0), b1.range(0x00400000, 0x0040ffff),
					TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
				t1 = b1.getOrAddThread("Thread1", 0);

				Register pc = b1.trace.getBaseLanguage().getProgramCounter();
				TraceMemorySpace regs = memory.getMemoryRegisterSpace(t1, true);
				regs.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
			}
			waitForDomainObject(b1.trace);
			try (Transaction tx = b2.startTransaction()) {
				b2.trace.getTimeManager().createSnapshot("First snap");
				DBTraceMemoryManager memory = b2.trace.getMemoryManager();
				memory.addRegion("exe:.text", Lifespan.nowOn(0), b2.range(0x00400000, 0x0040ffff),
					TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
				t2 = b2.getOrAddThread("Thread2", 0);

				Register pc = b2.trace.getBaseLanguage().getProgramCounter();
				TraceMemorySpace regs = memory.getMemoryRegisterSpace(t2, true);
				regs.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00405678)));
			}
			waitForDomainObject(b1.trace);
			waitForDomainObject(b2.trace);
			traceManager.openTrace(b1.trace);
			traceManager.openTrace(b2.trace);
			waitForSwing();

			traceManager.activateTrace(b1.trace);
			waitForSwing();

			assertEquals(b1.trace.getProgramView(), memBytesProvider.getProgram());

			traceManager.activateTrace(b2.trace);
			waitForSwing();

			assertEquals(b2.trace.getProgramView(), memBytesProvider.getProgram());
		}
	}

	@Test
	public void testFollowsCurrentThreadOnThreadChangeWithoutRegisterTracking() throws Exception {
		runSwing(() -> memBytesProvider.setTrackingSpec(NoneLocationTrackingSpec.INSTANCE));
		try ( //
				ToyDBTraceBuilder b1 =
					new ToyDBTraceBuilder(name.getMethodName() + "_1", LANGID_TOYBE64); //
				ToyDBTraceBuilder b2 =
					new ToyDBTraceBuilder(name.getMethodName() + "_2", LANGID_TOYBE64)) {
			TraceThread t1, t2;

			try (Transaction tx = b1.startTransaction()) {
				b1.trace.getTimeManager().createSnapshot("First snap");
				DBTraceMemoryManager memory = b1.trace.getMemoryManager();
				memory.addRegion("exe:.text", Lifespan.nowOn(0), b1.range(0x00400000, 0x0040ffff),
					TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
				t1 = b1.getOrAddThread("Thread1", 0);

				Register pc = b1.trace.getBaseLanguage().getProgramCounter();
				TraceMemorySpace regs = memory.getMemoryRegisterSpace(t1, true);
				regs.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
			}
			waitForDomainObject(b1.trace);
			try (Transaction tx = b2.startTransaction()) {
				b2.trace.getTimeManager().createSnapshot("First snap");
				DBTraceMemoryManager memory = b2.trace.getMemoryManager();
				memory.addRegion("exe:.text", Lifespan.nowOn(0), b2.range(0x00400000, 0x0040ffff),
					TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
				t2 = b2.getOrAddThread("Thread2", 0);

				Register pc = b2.trace.getBaseLanguage().getProgramCounter();
				TraceMemorySpace regs = memory.getMemoryRegisterSpace(t2, true);
				regs.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00405678)));
			}
			waitForDomainObject(b1.trace);
			waitForDomainObject(b2.trace);
			traceManager.openTrace(b1.trace);
			traceManager.openTrace(b2.trace);
			waitForSwing();

			traceManager.activateThread(t1);
			waitForSwing();

			assertEquals(b1.trace.getProgramView(), memBytesProvider.getProgram());
			// TODO: Assert thread?

			traceManager.activateThread(t2);
			waitForSwing();

			assertEquals(b2.trace.getProgramView(), memBytesProvider.getProgram());
		}
	}

	protected void assertViewerBackgroundAt(Color expected, ByteViewerPanel panel, Address addr)
			throws AWTException, InterruptedException {
		goToDyn(addr);
		waitForPass(() -> {
			Rectangle r = panel.getBounds();
			// Capture off screen, so that focus/stacking doesn't matter
			BufferedImage image = new BufferedImage(r.width, r.height, BufferedImage.TYPE_INT_ARGB);
			Graphics g = image.getGraphics();
			ByteViewerComponent component = panel.getCurrentComponent();
			try {
				runSwing(() -> component.paint(g));
			}
			finally {
				g.dispose();
			}
			Rectangle cursor = component.getCursorBounds();
			Color actual = new Color(image.getRGB(cursor.x + 8, cursor.y));
			assertEquals(expected.getRGB(), actual.getRGB());
		});
	}

	@Test
	public void testDynamicBytesViewerMarksTrackedRegister() throws Exception {
		// TODO: This shouldn't be a dependency, but it is for option definitions....
		addPlugin(tool, DebuggerListingPlugin.class);

		createAndOpenTrace();
		waitForSwing();

		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			// To keep gray out of the color equation
			memory.setState(0, tb.range(0x00401233, 0x00401235), TraceMemoryState.KNOWN);

			thread = tb.getOrAddThread("Thread1", 0);
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemorySpace regs = memory.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertViewerBackgroundAt(DebuggerResources.COLOR_REGISTER_MARKERS,
			memBytesProvider.getByteViewerPanel(), tb.addr(0x00401234));
	}

	@Test
	public void testAutoReadMemoryReads() throws Exception {
		// Otherwise, some tasks may never finish, and test fails
		addPlugin(tool, ProgressServicePlugin.class);

		assertEquals(readVisROOnce, memBytesProvider.getAutoReadMemorySpec());
		runSwing(() -> memBytesProvider.setAutoReadMemorySpec(readNone));

		createRmiConnection();
		addMemoryMethods();
		createTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();

			tb.trace.getMemoryManager()
					.addRegion("Processes[1].Memory[exe:.text]", Lifespan.nowOn(0L),
						tb.range(0x55550000, 0x5555ffff), TraceMemoryFlag.READ,
						TraceMemoryFlag.EXECUTE);
		}
		waitForDomainObject(tb.trace);
		TraceObject process = tb.obj("Processes[1]");
		rmiCx.publishTarget(tool, tb.trace);

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		goToDyn(tb.addr(0x55550800));
		waitForSwing();
		assertTrue(rmiMethodReadMem.argQueue().isEmpty());

		goToDyn(tb.addr(0x55551800));
		waitForSwing();
		assertTrue(rmiMethodReadMem.argQueue().isEmpty());

		// Should read  upon setting auto-read.
		runSwing(() -> memBytesProvider.setAutoReadMemorySpec(readVisROOnce));
		handleAtLeastOneMemReadInv(memBytesProvider::getLastAutoRead, process,
			tb.range(0x55551000, 0x55551fff));

		// Should also read upon navigating elsewhere.
		goToDyn(tb.addr(0x55550800));
		handleReadMemInvocation(process, tb.range(0x55550000, 0x55550fff));

		/**
		 * Because goToDyn has to retry, it can generate many read requests. Turn off auto-read and
		 * then flush out any pending reads, so that all the tasks can complete.
		 */
		runSwing(() -> memBytesProvider.setAutoReadMemorySpec(readNone));
		flushMemoryReadInvocations(memBytesProvider::getLastAutoRead, process,
			tb.range(0x55550000, 0x55550fff));
	}

	@Test
	public void testMemoryStateBackgroundColors() throws Exception {
		// TODO: This shouldn't be a dependency, but it is for option definitions....
		addPlugin(tool, DebuggerListingPlugin.class);

		createAndOpenTrace();
		waitForSwing();

		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			memory.setState(0, tb.addr(0x00401234), TraceMemoryState.KNOWN);
			memory.setState(0, tb.addr(0x00401235), TraceMemoryState.ERROR);
		}
		waitForDomainObject(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		// TODO: Colors should be blended with cursor color....
		assertViewerBackgroundAt(DebuggerResources.COLOR_BACKGROUND_STALE,
			memBytesProvider.getByteViewerPanel(), tb.addr(0x00401233));
		assertViewerBackgroundAt(GhidraOptions.DEFAULT_CURSOR_LINE_COLOR,
			memBytesProvider.getByteViewerPanel(), tb.addr(0x00401234));
		assertViewerBackgroundAt(DebuggerResources.COLOR_BACKGROUND_ERROR,
			memBytesProvider.getByteViewerPanel(), tb.addr(0x00401235));
	}

	@Test
	public void testCloseCurrentTraceBlanksViewers() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		assertEquals(traceManager.getCurrentView(), memBytesProvider.getProgram());
		assertEquals("(nowhere)", memBytesProvider.locationLabel.getText());

		DebuggerMemoryBytesProvider extraProvider =
			runSwing(() -> memBytesPlugin.createViewerIfMissing(NoneLocationTrackingSpec.INSTANCE,
				false));
		waitForSwing();
		assertEquals(traceManager.getCurrentView(), extraProvider.getProgram());
		assertEquals("(nowhere)", extraProvider.locationLabel.getText());

		traceManager.closeTrace(tb.trace);
		waitForSwing();
		assertNull(memBytesProvider.getProgram());
		assertNull(extraProvider.getProgram());

		assertEquals("", memBytesProvider.locationLabel.getText());
		assertEquals("", extraProvider.locationLabel.getText());
	}

	public static <T> void setActionStateWithTrigger(MultiStateDockingAction<T> action, T userData,
			EventTrigger trigger) {
		runSwing(() -> {
			for (ActionState<T> actionState : action.getAllActionStates()) {
				if (actionState.getUserData() == userData) {
					action.setCurrentActionStateWithTrigger(actionState, trigger);
					return;
				}
			}
			fail("Invalid action state user data");
		});
	}

	@Test
	public void testActionGoTo() throws Exception {
		assertNull(memBytesProvider.current.getView());
		assertFalse(memBytesProvider.actionGoTo.isEnabled());
		createAndOpenTrace();
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread = tb.getOrAddThread("Thread 1", 0);
			TraceMemorySpace regs = mm.getMemoryRegisterSpace(thread, true);
			Register r0 = tb.language.getRegister("r0");
			regs.setValue(0, new RegisterValue(r0, new BigInteger("00401234", 16)));
			mm.putBytes(0, tb.addr(0x00401234), tb.buf(0x00, 0x40, 0x43, 0x21));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertTrue(memBytesProvider.actionGoTo.isEnabled());
		performAction(memBytesProvider.actionGoTo, false);
		DebuggerGoToDialog dialog1 = waitForDialogComponent(DebuggerGoToDialog.class);
		runSwing(() -> {
			dialog1.setOffset("r0");
			dialog1.okCallback();
		});

		waitForPass(() -> {
			ProgramLocation loc = memBytesProvider.getLocation();
			assertNotNull(loc);
			assertEquals(tb.addr(0x00401234), loc.getAddress());
		});

		performAction(memBytesProvider.actionGoTo, false);
		DebuggerGoToDialog dialog2 = waitForDialogComponent(DebuggerGoToDialog.class);
		runSwing(() -> {
			dialog2.setOffset("*:4 r0");
			dialog2.okCallback();
		});

		waitForPass(
			() -> assertEquals(tb.addr(0x00404321), memBytesProvider.getLocation().getAddress()));
	}

	@Test
	public void testActionTrackLocation() throws Exception {
		assertTrue(memBytesProvider.actionTrackLocation.isEnabled());
		createAndOpenTrace();
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			mm.addRegion("[stack]", Lifespan.nowOn(0), tb.range(0x1f000000, 0x1fffffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
			thread = tb.getOrAddThread("Thread 1", 0);
			TraceMemorySpace regs = mm.getMemoryRegisterSpace(thread, true);
			Register pc = tb.language.getProgramCounter();
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00401234", 16)));
			Register sp = tb.trace.getBaseCompilerSpec().getStackPointer();
			regs.setValue(0, new RegisterValue(sp, new BigInteger("1fff8765", 16)));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		// Check the default is track pc
		assertEquals(PCLocationTrackingSpec.INSTANCE,
			memBytesProvider.actionTrackLocation.getCurrentUserData());
		assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress());

		goToDyn(tb.addr(0x00400000));
		// Ensure it's changed so we know the action is effective
		waitForSwing();
		assertEquals(tb.addr(0x00400000), memBytesProvider.getLocation().getAddress());

		performAction(memBytesProvider.actionTrackLocation);
		assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress());

		setActionStateWithTrigger(memBytesProvider.actionTrackLocation,
			SPLocationTrackingSpec.INSTANCE,
			EventTrigger.GUI_ACTION);
		waitForSwing();
		assertEquals(tb.addr(0x1fff8765), memBytesProvider.getLocation().getAddress());

		runSwing(() -> memBytesProvider.setTrackingSpec(NoneLocationTrackingSpec.INSTANCE));
		assertEquals(NoneLocationTrackingSpec.INSTANCE,
			memBytesProvider.actionTrackLocation.getCurrentUserData());
	}

	@Test
	@Ignore("Haven't specified this action, yet")
	public void testActionTrackOtherRegister() {
		// TODO: Actually, can we make this an arbitrary (pcode/sleigh?) expression.
		TODO();
	}

	@Test
	public void testActionFollowsCurrentThread() throws Exception {
		createAndOpenTrace();
		TraceThread thread1;
		TraceThread thread2;
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread1 = tb.getOrAddThread("Thread1", 0);
			thread2 = tb.getOrAddThread("Thread2", 0);

			// NOTE: PC-tracking should be the default for the main dynamic listing
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemorySpace regs1 = memory.getMemoryRegisterSpace(thread1, true);
			regs1.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
			TraceMemorySpace regs2 = memory.getMemoryRegisterSpace(thread2, true);
			regs2.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00405678)));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread1);

		// NOTE: Action does not exist for main dynamic listing
		DebuggerMemoryBytesProvider extraProvider =
			runSwing(() -> memBytesPlugin.createViewerIfMissing(NoneLocationTrackingSpec.INSTANCE,
				true));
		waitForSwing();
		assertTrue(extraProvider.actionFollowsCurrentThread.isEnabled());
		assertTrue(extraProvider.actionFollowsCurrentThread.isSelected());
		// Verify it has immediately tracked on creation
		assertEquals(tb.trace.getProgramView(), extraProvider.getProgram());
		assertEquals(thread1, extraProvider.current.getThread());
		assertNull(getLocalAction(memBytesProvider, FollowsCurrentThreadAction.NAME));
		assertNotNull(getLocalAction(extraProvider, FollowsCurrentThreadAction.NAME));

		performAction(extraProvider.actionFollowsCurrentThread);
		traceManager.activateThread(thread2);
		assertEquals(thread1, extraProvider.current.getThread());

		performAction(extraProvider.actionFollowsCurrentThread);
		assertEquals(thread2, extraProvider.current.getThread());

		extraProvider.setFollowsCurrentThread(false);
		assertFalse(extraProvider.actionFollowsCurrentThread.isSelected());
	}

	@Test
	public void testActionRefreshMemory() throws Exception {
		DebuggerControlService controlService = addPlugin(tool, DebuggerControlServicePlugin.class);
		assertFalse(memBytesProvider.actionRefreshSelectedMemory.isEnabled());
		runSwing(() -> memBytesProvider.setAutoReadMemorySpec(readNone));

		// To verify enabled requires live target
		createAndOpenTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();
			tb.trace.getMemoryManager()
					.addRegion("Processes[1].Memory[exe:.text]", Lifespan.nowOn(0),
						tb.range(0x55550000, 0x5555ffff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		waitForDomainObject(tb.trace);
		TraceObject process = tb.obj("Processes[1]");
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		controlService.setCurrentMode(tb.trace, ControlMode.RO_TARGET);
		waitForSwing();
		assertFalse(memBytesProvider.actionRefreshSelectedMemory.isEnabled());

		createRmiConnection();
		addMemoryMethods();
		rmiCx.publishTarget(tool, tb.trace);
		waitForSwing();
		// Action no longer requires a selection. It uses visible memory.
		assertTrue(memBytesProvider.actionRefreshSelectedMemory.isEnabled());

		assertTrue(rmiMethodReadMem.argQueue().isEmpty());

		performAction(memBytesProvider.actionRefreshSelectedMemory, false);
		handleReadMemInvocation(process, tb.range(0x55550000, 0x55550fff));

		rmiCx.setLastSnapshot(tb.trace, 1);
		traceManager.activateSnap(1);
		waitForSwing();
		controlService.setCurrentMode(tb.trace, ControlMode.RO_TRACE);
		traceManager.activateSnap(0);
		waitForSwing();
		assertFalse(memBytesProvider.actionRefreshSelectedMemory.isEnabled());

		traceManager.activateSnap(1);
		waitForSwing();
		assertTrue(memBytesProvider.actionRefreshSelectedMemory.isEnabled());

		rmiCx.withdrawTarget(tool, tb.trace);
		waitForSwing();
		assertFalse(memBytesProvider.actionRefreshSelectedMemory.isEnabled());
	}

	@Test
	public void testActionAutoReadMemory() {
		assertTrue(memBytesProvider.actionAutoReadMemory.isEnabled());

		assertEquals(readVisROOnce, memBytesProvider.getAutoReadMemorySpec());
		assertEquals(readVisROOnce, memBytesProvider.actionAutoReadMemory.getCurrentUserData());

		runSwing(
			() -> memBytesProvider.actionAutoReadMemory.setCurrentActionStateByUserData(readNone));
		assertEquals(readNone, memBytesProvider.getAutoReadMemorySpec());
		assertEquals(readNone, memBytesProvider.actionAutoReadMemory.getCurrentUserData());

		runSwing(() -> memBytesProvider.setAutoReadMemorySpec(readVisROOnce));
		assertEquals(readVisROOnce, memBytesProvider.getAutoReadMemorySpec());
		assertEquals(readVisROOnce, memBytesProvider.actionAutoReadMemory.getCurrentUserData());

		runSwing(() -> memBytesProvider.setAutoReadMemorySpec(readNone));
		assertEquals(readNone, memBytesProvider.getAutoReadMemorySpec());
		assertEquals(readNone, memBytesProvider.actionAutoReadMemory.getCurrentUserData());
	}

	@Test
	public void testLocationLabel() throws Exception {
		assertEquals("", memBytesProvider.locationLabel.getText());

		createAndOpenTrace();
		waitForSwing();
		assertEquals("", memBytesProvider.locationLabel.getText());

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		assertEquals("(nowhere)", memBytesProvider.locationLabel.getText());

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("test_region", Lifespan.nowOn(0), tb.range(0x55550000, 0x555502ff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		waitForDomainObject(tb.trace);
		// TODO: This initial goTo should not really be needed
		goToDyn(tb.addr(0x55550000));
		waitForPass(() -> assertEquals("test_region", memBytesProvider.locationLabel.getText()));

		TraceModule modExe;
		try (Transaction tx = tb.startTransaction()) {
			modExe = tb.trace.getModuleManager()
					.addModule("modExe", "modExe", tb.range(0x55550000, 0x555501ff),
						Lifespan.nowOn(0));
		}
		waitForDomainObject(tb.trace);
		waitForPass(() -> assertEquals("modExe", memBytesProvider.locationLabel.getText()));

		try (Transaction tx = tb.startTransaction()) {
			modExe.addSection(".text", tb.range(0x55550000, 0x555500ff));
		}
		waitForDomainObject(tb.trace);
		waitForPass(() -> assertEquals("modExe:.text", memBytesProvider.locationLabel.getText()));
	}

	@Test
	public void testActivateThreadTracks() throws Exception {
		assertEquals(PCLocationTrackingSpec.INSTANCE,
			memBytesProvider.actionTrackLocation.getCurrentUserData());

		createAndOpenTrace();
		Register pc = tb.language.getProgramCounter();
		TraceThread thread1;
		TraceThread thread2;
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread1 = tb.getOrAddThread("Thread 1", 0);
			thread2 = tb.getOrAddThread("Thread 2", 0);
			TraceMemorySpace regs1 = mm.getMemoryRegisterSpace(thread1, true);
			regs1.setValue(0, new RegisterValue(pc, new BigInteger("00401234", 16)));
			TraceMemorySpace regs2 = mm.getMemoryRegisterSpace(thread2, true);
			regs2.setValue(0, new RegisterValue(pc, new BigInteger("00404321", 16)));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread1);
		waitForSwing();

		assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress());

		traceManager.activateThread(thread2);
		waitForSwing();

		assertEquals(tb.addr(0x00404321), memBytesProvider.getLocation().getAddress());
	}

	@Test
	public void testActivateSnapTracks() throws Exception {
		assertEquals(PCLocationTrackingSpec.INSTANCE,
			memBytesProvider.actionTrackLocation.getCurrentUserData());

		createAndOpenTrace();
		Register pc = tb.language.getProgramCounter();
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread = tb.getOrAddThread("Thread 1", 0);
			TraceMemorySpace regs = mm.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00401234", 16)));
			regs.setValue(1, new RegisterValue(pc, new BigInteger("00404321", 16)));
		}
		waitForDomainObject(tb.trace);
		traceManager.activate(DebuggerCoordinates.NOWHERE.thread(thread).snap(0));
		waitForSwing();

		assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress());

		traceManager.activateSnap(1);
		waitForSwing();

		assertEquals(tb.addr(0x00404321), memBytesProvider.getLocation().getAddress());
	}

	@Test
	public void testActivateFrameTracks() throws Exception {
		assertEquals(PCLocationTrackingSpec.INSTANCE,
			memBytesProvider.actionTrackLocation.getCurrentUserData());

		createAndOpenTrace();
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread = tb.getOrAddThread("Thread 1", 0);
			DBTraceStackManager sm = tb.trace.getStackManager();
			TraceStack stack = sm.getStack(thread, 0, true);
			stack.getFrame(0, true).setProgramCounter(Lifespan.ALL, tb.addr(0x00401234));
			stack.getFrame(1, true).setProgramCounter(Lifespan.ALL, tb.addr(0x00404321));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress());

		traceManager.activateFrame(1);
		waitForSwing();

		assertEquals(tb.addr(0x00404321), memBytesProvider.getLocation().getAddress());
	}

	@Test
	public void testRegsPCChangedTracks() throws Exception {
		assertEquals(PCLocationTrackingSpec.INSTANCE,
			memBytesProvider.actionTrackLocation.getCurrentUserData());

		createAndOpenTrace();
		DBTraceMemoryManager mm = tb.trace.getMemoryManager();
		Register pc = tb.language.getProgramCounter();
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			mm.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread = tb.getOrAddThread("Thread 1", 0);
			TraceMemorySpace regs = mm.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00401234", 16)));
		}
		waitForDomainObject(tb.trace);
		traceManager.activate(DebuggerCoordinates.NOWHERE.thread(thread).snap(0));
		waitForSwing();

		assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress());

		try (Transaction tx = tb.startTransaction()) {
			TraceMemorySpace regs = mm.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00404321", 16)));
		}
		waitForDomainObject(tb.trace);

		assertEquals(tb.addr(0x00404321), memBytesProvider.getLocation().getAddress());
	}

	@Test
	public void testRegsPCChangedTracksDespiteStackWithNoPC() throws Exception {
		assertEquals(PCLocationTrackingSpec.INSTANCE,
			memBytesProvider.actionTrackLocation.getCurrentUserData());

		createAndOpenTrace();
		DBTraceMemoryManager mm = tb.trace.getMemoryManager();
		Register pc = tb.language.getProgramCounter();
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			mm.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread = tb.getOrAddThread("Thread 1", 0);
			TraceMemorySpace regs = mm.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00401234", 16)));

			DBTraceStackManager sm = tb.trace.getStackManager();
			TraceStack stack = sm.getStack(thread, 0, true);
			stack.getFrame(0, true);
		}
		waitForDomainObject(tb.trace);
		traceManager.activate(DebuggerCoordinates.NOWHERE.thread(thread).snap(0));
		waitForSwing();

		assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress());

		try (Transaction tx = tb.startTransaction()) {
			TraceMemorySpace regs = mm.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00404321", 16)));
		}
		waitForDomainObject(tb.trace);

		assertEquals(tb.addr(0x00404321), memBytesProvider.getLocation().getAddress());
	}

	@Test
	public void testStackPCChangedTracks() throws Exception {
		assertEquals(PCLocationTrackingSpec.INSTANCE,
			memBytesProvider.actionTrackLocation.getCurrentUserData());

		createAndOpenTrace();
		DBTraceStackManager sm = tb.trace.getStackManager();
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread = tb.getOrAddThread("Thread 1", 0);
			TraceStack stack = sm.getStack(thread, 0, true);
			stack.getFrame(0, true).setProgramCounter(Lifespan.ALL, tb.addr(0x00401234));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress());

		try (Transaction tx = tb.startTransaction()) {
			TraceStack stack = sm.getStack(thread, 0, true);
			stack.getFrame(0, true).setProgramCounter(Lifespan.ALL, tb.addr(0x00404321));
		}
		waitForDomainObject(tb.trace);

		assertEquals(tb.addr(0x00404321), memBytesProvider.getLocation().getAddress());
	}

	protected void sendKeyStroke(int vk, char c) {
		ByteViewerComponent viewer = memBytesProvider.getByteViewerPanel().getViewList().get(0);
		FieldLocation loc = viewer.getCursorLocation();
		KeyEvent ev = new KeyEvent(viewer, 0, new Date().getTime(), 0, vk, c);
		viewer.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(),
			loc.getCol(), viewer.getCurrentField());
	}

	protected void sendKeyStrokeForChar(char c) {
		int vk = KeyEvent.getExtendedKeyCodeForChar(c);
		assertFalse(vk == KeyEvent.VK_UNDEFINED);
		sendKeyStroke(vk, c);
	}

	protected void sendKeyStrokesForText(String text) {
		for (char c : text.toCharArray()) {
			sendKeyStrokeForChar(c);
		}
	}

	@Test
	public void testEditLiveBytesWritesTarget() throws Throwable {
		runSwing(() -> memBytesProvider.setAutoReadMemorySpec(readNone));

		createRmiConnection();
		addMemoryMethods();
		createTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();

			tb.trace.getMemoryManager()
					.addRegion("Processes[1].Memory[exe:.text]", Lifespan.nowOn(0L),
						tb.range(0x55550000, 0x5555ffff), TraceMemoryFlag.READ,
						TraceMemoryFlag.EXECUTE);
		}
		waitForDomainObject(tb.trace);
		TraceObject process = tb.obj("Processes[1]");
		rmiCx.publishTarget(tool, tb.trace);

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		controlService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);
		DockingActionIf actionEdit = getAction(memBytesPlugin, "Enable/Disable Byteviewer Editing");

		performAction(actionEdit);
		goToDyn(tb.addr(0x55550800));
		runSwingLater(() -> sendKeyStrokesForText("42"));
		/**
		 * One for each key press :/
		 * 
		 * TODO: Perhaps also a curious result that the second is 0x02 and not 0x42. In the test, we
		 * can easily see because the method doesn't actually mutate the database. However, in
		 * practice, what if the method is too slow to mutate, and the next keystroke wins the race?
		 */
		handleWriteMemInvocation(process, tb.addr(0x55550800), new Bytes(0x40));
		handleWriteMemInvocation(process, tb.addr(0x55550800), new Bytes(0x02));
		performAction(actionEdit);

		rmiCx.withdrawTarget(tool, tb.trace);
	}

	@Test
	public void testEditTraceBytesWritesNotTarget() throws Throwable {
		runSwing(() -> memBytesProvider.setAutoReadMemorySpec(readNone));

		createRmiConnection();
		addMemoryMethods();
		createTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();

			tb.trace.getMemoryManager()
					.addRegion("Processes[1].Memory[exe:.text]", Lifespan.nowOn(0L),
						tb.range(0x55550000, 0x5555ffff), TraceMemoryFlag.READ,
						TraceMemoryFlag.EXECUTE);
		}
		waitForDomainObject(tb.trace);
		rmiCx.publishTarget(tool, tb.trace);

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
		DockingActionIf actionEdit = getAction(memBytesPlugin, "Enable/Disable Byteviewer Editing");

		performAction(actionEdit);
		goToDyn(tb.addr(0x55550800));
		runSwing(() -> sendKeyStrokesForText("42"));

		Bytes data = new Bytes(new byte[1]);
		tb.trace.getMemoryManager().getBytes(0, tb.addr(0x55550800), data.buf());
		assertEquals(new Bytes(0x42), data);

		assertTrue(rmiMethodWriteMem.argQueue().isEmpty());
		performAction(actionEdit);

		rmiCx.withdrawTarget(tool, tb.trace);
	}

	@Test
	public void testPasteLiveBytesWritesTarget() throws Exception {
		addPlugin(tool, ClipboardPlugin.class);
		ActionContext ctx;

		runSwing(() -> memBytesProvider.setAutoReadMemorySpec(readNone));

		createRmiConnection();
		addMemoryMethods();
		createTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();

			tb.trace.getMemoryManager()
					.addRegion("Processes[1].Memory[exe:.text]", Lifespan.nowOn(0L),
						tb.range(0x55550000, 0x5555ffff), TraceMemoryFlag.READ,
						TraceMemoryFlag.EXECUTE);
		}
		waitForDomainObject(tb.trace);
		TraceObject process = tb.obj("Processes[1]");
		rmiCx.publishTarget(tool, tb.trace);

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		controlService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);
		DockingActionIf actionEdit = getAction(memBytesPlugin, "Enable/Disable Byteviewer Editing");

		performAction(actionEdit);
		goToDyn(tb.addr(0x55550800));
		Clipboard clipboard = GClipboard.getSystemClipboard();
		clipboard.setContents(new StringSelection("42 53 64 75"), null);

		DockingActionIf actionPaste =
			Objects.requireNonNull(getLocalAction(memBytesProvider, "Paste"));

		ctx = waitForValue(() -> memBytesProvider.getActionContext(null));
		assertTrue(actionPaste.isAddToPopup(ctx));
		assertTrue(actionPaste.isEnabledForContext(ctx));

		performAction(actionPaste, memBytesProvider, false);
		OptionDialog confirm = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(confirm, "Yes");
		// TODO: This shouldn't be separate calls per byte!
		handleWriteMemInvocation(process, tb.addr(0x55550800), new Bytes(0x42));
		handleWriteMemInvocation(process, tb.addr(0x55550801), new Bytes(0x53));
		handleWriteMemInvocation(process, tb.addr(0x55550802), new Bytes(0x64));
		handleWriteMemInvocation(process, tb.addr(0x55550803), new Bytes(0x75));

		performAction(actionEdit);

		rmiCx.withdrawTarget(tool, tb.trace);
	}
}
