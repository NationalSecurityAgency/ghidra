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
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.junit.*;

import com.google.common.collect.Range;

import docking.action.DockingActionIf;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.byteviewer.ByteViewerComponent;
import ghidra.app.plugin.core.byteviewer.ByteViewerPanel;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractFollowsCurrentThreadAction;
import ghidra.app.plugin.core.debug.gui.action.*;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.services.TraceRecorder;
import ghidra.async.SwingExecutorService;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.stack.DBTraceStack;
import ghidra.trace.database.stack.DBTraceStackManager;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.database.UndoableTransaction;

public class DebuggerMemoryBytesProviderTest extends AbstractGhidraHeadedDebuggerGUITest {
	static LocationTrackingSpec getLocationTrackingSpec(String name) {
		return LocationTrackingSpec.fromConfigName(name);
	}

	static AutoReadMemorySpec getAutoReadMemorySpec(String name) {
		return AutoReadMemorySpec.fromConfigName(name);
	}

	final LocationTrackingSpec trackNone =
		getLocationTrackingSpec(NoneLocationTrackingSpec.CONFIG_NAME);
	final LocationTrackingSpec trackPc =
		getLocationTrackingSpec(PCLocationTrackingSpec.CONFIG_NAME);
	final LocationTrackingSpec trackSp =
		getLocationTrackingSpec(SPLocationTrackingSpec.CONFIG_NAME);

	final AutoReadMemorySpec readNone =
		getAutoReadMemorySpec(NoneAutoReadMemorySpec.CONFIG_NAME);
	final AutoReadMemorySpec readVisible =
		getAutoReadMemorySpec(VisibleAutoReadMemorySpec.CONFIG_NAME);
	final AutoReadMemorySpec readVisROOnce =
		getAutoReadMemorySpec(VisibleROOnceAutoReadMemorySpec.CONFIG_NAME);

	protected DebuggerMemoryBytesPlugin memBytesPlugin;
	protected DebuggerMemoryBytesProvider memBytesProvider;

	@Before
	public void setUpMemoryBytesProviderTest() throws Exception {
		memBytesPlugin = addPlugin(tool, DebuggerMemoryBytesPlugin.class);
		memBytesProvider = waitForComponentProvider(DebuggerMemoryBytesProvider.class);
		memBytesProvider.setVisible(true);
	}

	protected void goToDyn(Address address) {
		goToDyn(new ProgramLocation(traceManager.getCurrentView(), address));
	}

	protected void goToDyn(ProgramLocation location) {
		waitForPass(() -> {
			runSwing(() -> memBytesProvider.goTo(location.getProgram(), location));
			ProgramLocation confirm = memBytesProvider.getLocation();
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
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
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
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
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
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceThread thread = tb.getOrAddThread("Thread1", 0);
			waitForDomainObject(tb.trace);
			traceManager.activateThread(thread);
			waitForSwing(); // Ensure the open/activate events are processed first

			assertEquals(tb.trace.getProgramView(), memBytesProvider.getProgram());

			// NOTE: PC-tracking should be the default for the main bytes viewer
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(thread, true);
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
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceThread thread = tb.getOrAddThread("Thread1", 0);
			waitForDomainObject(tb.trace);
			traceManager.activateThread(thread);
			waitForSwing(); // Ensure the open/activate events are processed first

			assertEquals(tb.trace.getProgramView(), memBytesProvider.getProgram());

			// NOTE: PC-tracking should be the default for the main bytes viewer
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(thread, true);
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
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread1 = tb.getOrAddThread("Thread1", 0);
			thread2 = tb.getOrAddThread("Thread2", 0);

			// NOTE: PC-tracking should be the default for the main bytes viewer
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemoryRegisterSpace regs1 = memory.getMemoryRegisterSpace(thread1, true);
			regs1.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
			TraceMemoryRegisterSpace regs2 = memory.getMemoryRegisterSpace(thread2, true);
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
		DebuggerMemoryBytesProvider extraProvider = SwingExecutorService.INSTANCE.submit(
			() -> memBytesPlugin.createViewerIfMissing(trackPc, true)).get();
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread1 = tb.getOrAddThread("Thread1", 0);
			thread2 = tb.getOrAddThread("Thread2", 0);

			// NOTE: PC-tracking should be the default for the main bytes viewer
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemoryRegisterSpace regs1 = memory.getMemoryRegisterSpace(thread1, true);
			regs1.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
			TraceMemoryRegisterSpace regs2 = memory.getMemoryRegisterSpace(thread2, true);
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
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			memory.addRegion("[stack]", Range.atLeast(0L), tb.range(0x01000000, 0x01ffffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
			TraceThread thread = tb.getOrAddThread("Thread1", 0);
			waitForDomainObject(tb.trace);
			traceManager.activateThread(thread);
			waitForSwing(); // Ensure the open/activate events are processed first

			assertEquals(tb.trace.getProgramView(), memBytesProvider.getProgram());

			TraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(thread, true);
			Register sp = tb.trace.getBaseCompilerSpec().getStackPointer();
			regs.setValue(0, new RegisterValue(sp, BigInteger.valueOf(0x01fff800)));
		}
		waitForDomainObject(tb.trace);
		//Pre-check
		assertNull(memBytesProvider.getLocation());

		memBytesProvider.setTrackingSpec(trackSp);
		waitForSwing();

		ProgramLocation loc = memBytesProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x01fff800), loc.getAddress());
	}

	@Test
	public void testFollowsCurrentTraceOnTraceChangeWithoutRegisterTracking()
			throws Exception {
		memBytesProvider.setTrackingSpec(trackNone);
		try ( //
				ToyDBTraceBuilder b1 =
					new ToyDBTraceBuilder(name.getMethodName() + "_1", LANGID_TOYBE64); //
				ToyDBTraceBuilder b2 =
					new ToyDBTraceBuilder(name.getMethodName() + "_2", LANGID_TOYBE64)) {
			TraceThread t1, t2;

			try (UndoableTransaction tid = b1.startTransaction()) {
				b1.trace.getTimeManager().createSnapshot("First snap");
				DBTraceMemoryManager memory = b1.trace.getMemoryManager();
				memory.addRegion("exe:.text", Range.atLeast(0L), b1.range(0x00400000, 0x0040ffff),
					TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
				t1 = b1.getOrAddThread("Thread1", 0);

				Register pc = b1.trace.getBaseLanguage().getProgramCounter();
				TraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(t1, true);
				regs.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
			}
			waitForDomainObject(b1.trace);
			try (UndoableTransaction tid = b2.startTransaction()) {
				b2.trace.getTimeManager().createSnapshot("First snap");
				DBTraceMemoryManager memory = b2.trace.getMemoryManager();
				memory.addRegion("exe:.text", Range.atLeast(0L), b2.range(0x00400000, 0x0040ffff),
					TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
				t2 = b2.getOrAddThread("Thread2", 0);

				Register pc = b2.trace.getBaseLanguage().getProgramCounter();
				TraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(t2, true);
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
	public void testFollowsCurrentThreadOnThreadChangeWithoutRegisterTracking()
			throws Exception {
		memBytesProvider.setTrackingSpec(trackNone);
		try ( //
				ToyDBTraceBuilder b1 =
					new ToyDBTraceBuilder(name.getMethodName() + "_1", LANGID_TOYBE64); //
				ToyDBTraceBuilder b2 =
					new ToyDBTraceBuilder(name.getMethodName() + "_2", LANGID_TOYBE64)) {
			TraceThread t1, t2;

			try (UndoableTransaction tid = b1.startTransaction()) {
				b1.trace.getTimeManager().createSnapshot("First snap");
				DBTraceMemoryManager memory = b1.trace.getMemoryManager();
				memory.addRegion("exe:.text", Range.atLeast(0L), b1.range(0x00400000, 0x0040ffff),
					TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
				t1 = b1.getOrAddThread("Thread1", 0);

				Register pc = b1.trace.getBaseLanguage().getProgramCounter();
				TraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(t1, true);
				regs.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
			}
			waitForDomainObject(b1.trace);
			try (UndoableTransaction tid = b2.startTransaction()) {
				b2.trace.getTimeManager().createSnapshot("First snap");
				DBTraceMemoryManager memory = b2.trace.getMemoryManager();
				memory.addRegion("exe:.text", Range.atLeast(0L), b2.range(0x00400000, 0x0040ffff),
					TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
				t2 = b2.getOrAddThread("Thread2", 0);

				Register pc = b2.trace.getBaseLanguage().getProgramCounter();
				TraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(t2, true);
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

	protected void assertViewerBackgroundAt(Color expected, ByteViewerPanel panel,
			Address addr) throws AWTException, InterruptedException {
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
			assertEquals(expected, actual);
		});
	}

	@Test
	public void testDynamicBytesViewerMarksTrackedRegister() throws Exception {
		// TODO: This shouldn't be a dependency, but it is for option definitions....
		addPlugin(tool, DebuggerListingPlugin.class);

		createAndOpenTrace();
		waitForSwing();

		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			// To keep gray out of the color equation
			memory.setState(0, tb.range(0x00401233, 0x00401235), TraceMemoryState.KNOWN);

			thread = tb.getOrAddThread("Thread1", 0);
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertViewerBackgroundAt(DebuggerResources.DEFAULT_COLOR_REGISTER_MARKERS,
			memBytesProvider.getByteViewerPanel(), tb.addr(0x00401234));
	}

	@Test
	public void testAutoReadMemoryReads() throws Exception {
		byte[] data = incBlock();
		byte[] zero = new byte[data.length];
		ByteBuffer buf = ByteBuffer.allocate(data.length);
		assertEquals(readVisROOnce, memBytesProvider.getAutoReadMemorySpec());
		memBytesProvider.setAutoReadMemorySpec(readNone);

		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTargetAndActivateTrace(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		mb.testProcess1.addRegion("exe:.text", mb.rng(0x55550000, 0x5555ffff), "rx");
		waitFor(() -> !trace.getMemoryManager().getAllRegions().isEmpty());

		mb.testProcess1.memory.setMemory(mb.addr(0x55550000), data);
		waitForDomainObject(trace);
		buf.clear();
		assertEquals(data.length,
			trace.getMemoryManager().getBytes(recorder.getSnap(), addr(trace, 0x55550000), buf));
		assertArrayEquals(zero, buf.array());

		goToDyn(addr(trace, 0x55550800));
		waitForDomainObject(trace);
		buf.clear();
		assertEquals(data.length,
			trace.getMemoryManager().getBytes(recorder.getSnap(), addr(trace, 0x55550000), buf));
		assertArrayEquals(zero, buf.array());

		goToDyn(addr(trace, 0x55551800));
		waitForDomainObject(trace);
		buf.clear();
		assertEquals(data.length,
			trace.getMemoryManager().getBytes(recorder.getSnap(), addr(trace, 0x55550000), buf));
		assertArrayEquals(zero, buf.array());

		/**
		 * NOTE: Should read immediately upon setting auto-read, but we're not focused on the
		 * written block
		 */
		memBytesProvider.setAutoReadMemorySpec(readVisROOnce);
		waitForDomainObject(trace);
		buf.clear();
		assertEquals(data.length,
			trace.getMemoryManager().getBytes(recorder.getSnap(), addr(trace, 0x55550000), buf));
		assertArrayEquals(zero, buf.array());

		/**
		 * We're now moving to the written block
		 */
		goToDyn(addr(trace, 0x55550800));
		waitForSwing();
		waitForDomainObject(trace);
		// NB. Recorder can delay writing in a thread / queue
		waitForPass(() -> {
			buf.clear();
			assertEquals(data.length, trace.getMemoryManager()
					.getBytes(recorder.getSnap(), addr(trace, 0x55550000), buf));
			assertArrayEquals(data, buf.array());
		});
	}

	@Test
	public void testMemoryStateBackgroundColors() throws Exception {
		// TODO: This shouldn't be a dependency, but it is for option definitions....
		addPlugin(tool, DebuggerListingPlugin.class);

		createAndOpenTrace();
		waitForSwing();

		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			memory.setState(0, tb.addr(0x00401234), TraceMemoryState.KNOWN);
			memory.setState(0, tb.addr(0x00401235), TraceMemoryState.ERROR);
		}
		waitForDomainObject(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		// TODO: Colors should be blended with cursor color....
		assertViewerBackgroundAt(DebuggerResources.DEFAULT_COLOR_BACKGROUND_STALE,
			memBytesProvider.getByteViewerPanel(), tb.addr(0x00401233));
		assertViewerBackgroundAt(GhidraOptions.DEFAULT_CURSOR_LINE_COLOR,
			memBytesProvider.getByteViewerPanel(), tb.addr(0x00401234));
		assertViewerBackgroundAt(DebuggerResources.DEFAULT_COLOR_BACKGROUND_ERROR,
			memBytesProvider.getByteViewerPanel(), tb.addr(0x00401235));
	}

	@Test
	public void testCloseCurrentTraceBlanksViewers() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		assertEquals(traceManager.getCurrentView(), memBytesProvider.getProgram());
		assertEquals("(nowhere)", memBytesProvider.locationLabel.getText());

		DebuggerMemoryBytesProvider extraProvider = runSwing(
			() -> memBytesPlugin.createViewerIfMissing(trackNone, false));
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
		for (ActionState<T> actionState : action.getAllActionStates()) {
			if (actionState.getUserData() == userData) {
				action.setCurrentActionStateWithTrigger(actionState, trigger);
				return;
			}
		}
		fail("Invalid action state user data");
	}

	@Test
	public void testActionGoTo() throws Exception {
		assertNull(memBytesProvider.current.getView());
		assertFalse(memBytesProvider.actionGoTo.isEnabled());
		createAndOpenTrace();
		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread = tb.getOrAddThread("Thread 1", 0);
			TraceMemoryRegisterSpace regs = mm.getMemoryRegisterSpace(thread, true);
			Register r0 = tb.language.getRegister("r0");
			regs.setValue(0, new RegisterValue(r0, new BigInteger("00401234", 16)));
			mm.putBytes(0, tb.addr(0x00401234), tb.buf(0x00, 0x40, 0x43, 0x21));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertTrue(memBytesProvider.actionGoTo.isEnabled());
		performAction(memBytesProvider.actionGoTo, false);
		DebuggerGoToDialog dialog = waitForDialogComponent(DebuggerGoToDialog.class);

		dialog.setExpression("r0");
		dialog.okCallback();

		waitForPass(
			() -> assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress()));

		performAction(memBytesProvider.actionGoTo, false);
		dialog = waitForDialogComponent(DebuggerGoToDialog.class);
		dialog.setExpression("*:4 r0");
		dialog.okCallback();

		waitForPass(
			() -> assertEquals(tb.addr(0x00404321), memBytesProvider.getLocation().getAddress()));
	}

	@Test
	public void testActionTrackLocation() throws Exception {
		assertTrue(memBytesProvider.actionTrackLocation.isEnabled());
		createAndOpenTrace();
		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			mm.addRegion("[stack]", Range.atLeast(0L), tb.range(0x1f000000, 0x1fffffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
			thread = tb.getOrAddThread("Thread 1", 0);
			TraceMemoryRegisterSpace regs = mm.getMemoryRegisterSpace(thread, true);
			Register pc = tb.language.getProgramCounter();
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00401234", 16)));
			Register sp = tb.trace.getBaseCompilerSpec().getStackPointer();
			regs.setValue(0, new RegisterValue(sp, new BigInteger("1fff8765", 16)));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		// Check the default is track pc
		assertEquals(trackPc, memBytesProvider.actionTrackLocation.getCurrentUserData());
		assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress());

		goToDyn(tb.addr(0x00400000));
		// Ensure it's changed so we know the action is effective
		waitForSwing();
		assertEquals(tb.addr(0x00400000), memBytesProvider.getLocation().getAddress());

		performAction(memBytesProvider.actionTrackLocation);
		assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress());

		setActionStateWithTrigger(memBytesProvider.actionTrackLocation, trackSp,
			EventTrigger.GUI_ACTION);
		waitForSwing();
		assertEquals(tb.addr(0x1fff8765), memBytesProvider.getLocation().getAddress());

		memBytesProvider.setTrackingSpec(trackNone);
		waitForSwing();
		assertEquals(trackNone, memBytesProvider.actionTrackLocation.getCurrentUserData());
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
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread1 = tb.getOrAddThread("Thread1", 0);
			thread2 = tb.getOrAddThread("Thread2", 0);

			// NOTE: PC-tracking should be the default for the main dynamic listing
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemoryRegisterSpace regs1 = memory.getMemoryRegisterSpace(thread1, true);
			regs1.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
			TraceMemoryRegisterSpace regs2 = memory.getMemoryRegisterSpace(thread2, true);
			regs2.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00405678)));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread1);

		// NOTE: Action does not exist for main dynamic listing
		DebuggerMemoryBytesProvider extraProvider = runSwing(
			() -> memBytesPlugin.createViewerIfMissing(trackNone, true));
		waitForSwing();
		assertTrue(extraProvider.actionFollowsCurrentThread.isEnabled());
		assertTrue(extraProvider.actionFollowsCurrentThread.isSelected());
		// Verify it has immediately tracked on creation
		assertEquals(tb.trace.getProgramView(), extraProvider.getProgram());
		assertEquals(thread1, extraProvider.current.getThread());
		assertNull(getLocalAction(memBytesProvider, AbstractFollowsCurrentThreadAction.NAME));
		assertNotNull(getLocalAction(extraProvider, AbstractFollowsCurrentThreadAction.NAME));

		performAction(extraProvider.actionFollowsCurrentThread);
		traceManager.activateThread(thread2);
		assertEquals(thread1, extraProvider.current.getThread());

		performAction(extraProvider.actionFollowsCurrentThread);
		assertEquals(thread2, extraProvider.current.getThread());

		extraProvider.setFollowsCurrentThread(false);
		assertFalse(extraProvider.actionFollowsCurrentThread.isSelected());
	}

	@Test
	@Ignore("TODO") // Needs attention, but low priority
	// Accessibility listener does not seem to work
	public void testActionCaptureSelectedMemory() throws Exception {
		byte[] data = incBlock();
		byte[] zero = new byte[data.length];
		ByteBuffer buf = ByteBuffer.allocate(data.length);
		assertFalse(memBytesProvider.actionCaptureSelectedMemory.isEnabled());
		memBytesProvider.setAutoReadMemorySpec(readNone);

		// To verify enabled requires live target
		createAndOpenTrace();
		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x55550000, 0x555500ff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		ProgramSelection sel = new ProgramSelection(tb.set(tb.range(0x55550040, 0x5555004f)));
		waitForDomainObject(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		// Still
		assertFalse(memBytesProvider.actionCaptureSelectedMemory.isEnabled());

		memBytesProvider.setSelection(sel);
		waitForSwing();
		// Still
		assertFalse(memBytesProvider.actionCaptureSelectedMemory.isEnabled());

		// Now, simulate the sequence that typically enables the action
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTargetAndActivateTrace(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		mb.testProcess1.addRegion("exe:.text", mb.rng(0x55550000, 0x555500ff), "rx");
		mb.testProcess1.memory.setMemory(mb.addr(0x55550000), data); // No effect yet
		waitForDomainObject(trace);
		waitFor(() -> trace.getMemoryManager().getAllRegions().size() == 1);

		// NOTE: recordTargetContainerAndOpenTrace has already activated the trace
		// Action is still disabled, because it requires a selection
		assertFalse(memBytesProvider.actionCaptureSelectedMemory.isEnabled());

		memBytesProvider.setSelection(sel);
		waitForSwing();
		// Now, it should be enabled
		assertTrue(memBytesProvider.actionCaptureSelectedMemory.isEnabled());

		// First check nothing captured yet
		buf.clear();
		assertEquals(data.length,
			trace.getMemoryManager().getBytes(recorder.getSnap(), addr(trace, 0x55550000), buf));
		assertArrayEquals(zero, buf.array());

		// Verify that the action performs the expected task
		performAction(memBytesProvider.actionCaptureSelectedMemory);
		waitForBusyTool(tool);
		waitForDomainObject(trace);

		waitForPass(() -> {
			buf.clear();
			assertEquals(data.length, trace.getMemoryManager()
					.getBytes(recorder.getSnap(), addr(trace, 0x55550000), buf));
			// NOTE: The region is only 256 bytes long
			// TODO: This fails unpredictably, and I'm not sure why.
			assertArrayEquals(Arrays.copyOf(data, 256), Arrays.copyOf(buf.array(), 256));
		});

		// Verify that setting the memory inaccessible disables the action
		mb.testProcess1.memory.setAccessible(false);
		waitForPass(() -> assertFalse(memBytesProvider.actionCaptureSelectedMemory.isEnabled()));

		// Verify that setting it accessible re-enables it (assuming we still have selection)
		mb.testProcess1.memory.setAccessible(true);
		waitForPass(() -> assertTrue(memBytesProvider.actionCaptureSelectedMemory.isEnabled()));

		// Verify that moving into the past disables the action
		TraceSnapshot forced = recorder.forceSnapshot();
		waitForSwing(); // UI Wants to sync with new snap. Wait....
		traceManager.activateSnap(forced.getKey() - 1);
		waitForSwing();
		assertFalse(memBytesProvider.actionCaptureSelectedMemory.isEnabled());

		// Verify that advancing to the present enables the action (assuming a selection)
		traceManager.activateSnap(forced.getKey());
		waitForSwing();
		assertTrue(memBytesProvider.actionCaptureSelectedMemory.isEnabled());

		// Verify that stopping the recording disables the action
		recorder.stopRecording();
		waitForSwing();
		assertFalse(memBytesProvider.actionCaptureSelectedMemory.isEnabled());

		// TODO: When resume recording is implemented, verify action is enabled with selection
	}

	@Test
	public void testActionAutoReadMemory() {
		assertTrue(memBytesProvider.actionAutoReadMemory.isEnabled());

		assertEquals(readVisROOnce, memBytesProvider.getAutoReadMemorySpec());
		assertEquals(readVisROOnce, memBytesProvider.actionAutoReadMemory.getCurrentUserData());

		memBytesProvider.actionAutoReadMemory
				.setCurrentActionStateByUserData(readNone);
		waitForSwing();
		assertEquals(readNone, memBytesProvider.getAutoReadMemorySpec());
		assertEquals(readNone, memBytesProvider.actionAutoReadMemory.getCurrentUserData());

		memBytesProvider.setAutoReadMemorySpec(readVisROOnce);
		waitForSwing();
		assertEquals(readVisROOnce, memBytesProvider.getAutoReadMemorySpec());
		assertEquals(readVisROOnce, memBytesProvider.actionAutoReadMemory.getCurrentUserData());

		memBytesProvider.setAutoReadMemorySpec(readNone);
		waitForSwing();
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

		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("test_region", Range.atLeast(0L), tb.range(0x55550000, 0x555502ff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		waitForDomainObject(tb.trace);
		// TODO: This initial goTo should not really be needed
		goToDyn(tb.addr(0x55550000));
		waitForPass(() -> assertEquals("test_region", memBytesProvider.locationLabel.getText()));

		TraceModule modExe;
		try (UndoableTransaction tid = tb.startTransaction()) {
			modExe = tb.trace.getModuleManager()
					.addModule("modExe", "modExe",
						tb.range(0x55550000, 0x555501ff), Range.atLeast(0L));
		}
		waitForDomainObject(tb.trace);
		waitForPass(() -> assertEquals("modExe", memBytesProvider.locationLabel.getText()));

		try (UndoableTransaction tid = tb.startTransaction()) {
			modExe.addSection(".text", tb.range(0x55550000, 0x555500ff));
		}
		waitForDomainObject(tb.trace);
		waitForPass(() -> assertEquals("modExe:.text", memBytesProvider.locationLabel.getText()));
	}

	@Test
	public void testActivateThreadTracks() throws Exception {
		assertEquals(trackPc, memBytesProvider.actionTrackLocation.getCurrentUserData());

		createAndOpenTrace();
		Register pc = tb.language.getProgramCounter();
		TraceThread thread1;
		TraceThread thread2;
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread1 = tb.getOrAddThread("Thread 1", 0);
			thread2 = tb.getOrAddThread("Thread 2", 0);
			TraceMemoryRegisterSpace regs1 = mm.getMemoryRegisterSpace(thread1, true);
			regs1.setValue(0, new RegisterValue(pc, new BigInteger("00401234", 16)));
			TraceMemoryRegisterSpace regs2 = mm.getMemoryRegisterSpace(thread2, true);
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
		assertEquals(trackPc, memBytesProvider.actionTrackLocation.getCurrentUserData());

		createAndOpenTrace();
		Register pc = tb.language.getProgramCounter();
		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread = tb.getOrAddThread("Thread 1", 0);
			TraceMemoryRegisterSpace regs = mm.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00401234", 16)));
			regs.setValue(1, new RegisterValue(pc, new BigInteger("00404321", 16)));
		}
		waitForDomainObject(tb.trace);
		traceManager.activate(DebuggerCoordinates.threadSnap(thread, 0));
		waitForSwing();

		assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress());

		traceManager.activateSnap(1);
		waitForSwing();

		assertEquals(tb.addr(0x00404321), memBytesProvider.getLocation().getAddress());
	}

	@Test
	public void testActivateFrameTracks() throws Exception {
		assertEquals(trackPc, memBytesProvider.actionTrackLocation.getCurrentUserData());

		createAndOpenTrace();
		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread = tb.getOrAddThread("Thread 1", 0);
			DBTraceStackManager sm = tb.trace.getStackManager();
			DBTraceStack stack = sm.getStack(thread, 0, true);
			stack.getFrame(0, true).setProgramCounter(tb.addr(0x00401234));
			stack.getFrame(1, true).setProgramCounter(tb.addr(0x00404321));
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
		assertEquals(trackPc, memBytesProvider.actionTrackLocation.getCurrentUserData());

		createAndOpenTrace();
		DBTraceMemoryManager mm = tb.trace.getMemoryManager();
		Register pc = tb.language.getProgramCounter();
		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			mm.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread = tb.getOrAddThread("Thread 1", 0);
			TraceMemoryRegisterSpace regs = mm.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00401234", 16)));
		}
		waitForDomainObject(tb.trace);
		traceManager.activate(DebuggerCoordinates.threadSnap(thread, 0));
		waitForSwing();

		assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress());

		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryRegisterSpace regs = mm.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00404321", 16)));
		}
		waitForDomainObject(tb.trace);

		assertEquals(tb.addr(0x00404321), memBytesProvider.getLocation().getAddress());
	}

	@Test
	public void testRegsPCChangedTracksDespiteStackWithNoPC() throws Exception {
		assertEquals(trackPc, memBytesProvider.actionTrackLocation.getCurrentUserData());

		createAndOpenTrace();
		DBTraceMemoryManager mm = tb.trace.getMemoryManager();
		Register pc = tb.language.getProgramCounter();
		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			mm.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread = tb.getOrAddThread("Thread 1", 0);
			TraceMemoryRegisterSpace regs = mm.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00401234", 16)));

			DBTraceStackManager sm = tb.trace.getStackManager();
			DBTraceStack stack = sm.getStack(thread, 0, true);
			stack.getFrame(0, true);
		}
		waitForDomainObject(tb.trace);
		traceManager.activate(DebuggerCoordinates.threadSnap(thread, 0));
		waitForSwing();

		assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress());

		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryRegisterSpace regs = mm.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00404321", 16)));
		}
		waitForDomainObject(tb.trace);

		assertEquals(tb.addr(0x00404321), memBytesProvider.getLocation().getAddress());
	}

	@Test
	public void testStackPCChangedTracks() throws Exception {
		assertEquals(trackPc, memBytesProvider.actionTrackLocation.getCurrentUserData());

		createAndOpenTrace();
		DBTraceStackManager sm = tb.trace.getStackManager();
		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			thread = tb.getOrAddThread("Thread 1", 0);
			DBTraceStack stack = sm.getStack(thread, 0, true);
			stack.getFrame(0, true).setProgramCounter(tb.addr(0x00401234));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertEquals(tb.addr(0x00401234), memBytesProvider.getLocation().getAddress());

		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceStack stack = sm.getStack(thread, 0, true);
			stack.getFrame(0, true).setProgramCounter(tb.addr(0x00404321));
		}
		waitForDomainObject(tb.trace);

		assertEquals(tb.addr(0x00404321), memBytesProvider.getLocation().getAddress());
	}

	@Test
	@Ignore("TODO")
	public void testEditLiveBytesWritesTarget() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTargetAndActivateTrace(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		mb.testProcess1.addRegion("exe:.text", mb.rng(0x55550000, 0x5555ffff), "rx");
		waitFor(() -> !trace.getMemoryManager().getAllRegions().isEmpty());

		goToDyn(addr(trace, 0x55550800));
		DockingActionIf actionEdit = getAction(memBytesPlugin, "Enable/Disable Byteviewer Editing");
		performAction(actionEdit);

		Robot robot = new Robot();
		robot.keyPress(KeyEvent.VK_4);
		robot.keyRelease(KeyEvent.VK_4);
		robot.keyPress(KeyEvent.VK_2);
		robot.keyRelease(KeyEvent.VK_2);

		performAction(actionEdit);

		byte[] data = new byte[4];
		waitForPass(() -> {
			mb.testProcess1.memory.getMemory(mb.addr(0x55550800), data);
			assertArrayEquals(mb.arr(0x42, 0, 0, 0), data);
		});
	}

	@Test
	@Ignore("TODO")
	public void testEditPastBytesWritesNotTarget() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTargetAndActivateTrace(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		mb.testProcess1.addRegion("exe:.text", mb.rng(0x55550000, 0x5555ffff), "rx");
		waitFor(() -> !trace.getMemoryManager().getAllRegions().isEmpty());

		TraceSnapshot present = recorder.forceSnapshot();

		goToDyn(addr(trace, 0x55550800));
		long snap = present.getKey() - 1;
		traceManager.activateSnap(snap);
		waitForSwing();

		DockingActionIf actionEdit = getAction(memBytesPlugin, "Enable/Disable Byteviewer Editing");
		performAction(actionEdit);

		Robot robot = new Robot();
		robot.keyPress(KeyEvent.VK_4);
		robot.keyRelease(KeyEvent.VK_4);
		robot.keyPress(KeyEvent.VK_2);
		robot.keyRelease(KeyEvent.VK_2);

		performAction(actionEdit);

		byte[] data = new byte[4];
		AddressSpace space = trace.getBaseAddressFactory().getDefaultAddressSpace();
		trace.getMemoryManager()
				.getBytes(snap, space.getAddress(0x55550800), ByteBuffer.wrap(data));
		assertArrayEquals(mb.arr(0x42, 0, 0, 0), data);
		// Verify the target was not touched
		Arrays.fill(data, (byte) 0); // test model uses semisparse array
		waitForPass(() -> {
			mb.testProcess1.memory.getMemory(mb.addr(0x55550800), data);
			assertArrayEquals(mb.arr(0, 0, 0, 0), data);
		});
	}

	@Test
	@Ignore("TODO")
	public void testPasteLiveBytesWritesTarget() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTargetAndActivateTrace(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		mb.testProcess1.addRegion("exe:.text", mb.rng(0x55550000, 0x5555ffff), "rx");
		waitFor(() -> !trace.getMemoryManager().getAllRegions().isEmpty());

		goToDyn(addr(trace, 0x55550800));
		DockingActionIf actionEdit = getAction(memBytesPlugin, "Enable/Disable Byteviewer Editing");
		performAction(actionEdit);

		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		clipboard.setContents(new StringSelection("42 53 64 75"), null);
		DockingActionIf actionPaste = getAction(memBytesPlugin, "Paste");
		performAction(actionPaste);

		performAction(actionEdit);
		byte[] data = new byte[4];
		waitForPass(() -> {
			mb.testProcess1.memory.getMemory(mb.addr(0x55550800), data);
			assertArrayEquals(mb.arr(0x42, 0x53, 0x64, 0x75), data);
		});
	}
}
