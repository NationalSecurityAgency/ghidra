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
package ghidra.app.plugin.core.debug.gui.listing;

import static ghidra.lifecycle.Unfinished.TODO;
import static org.junit.Assert.*;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Set;

import org.junit.*;

import com.google.common.collect.Range;

import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractFollowsCurrentThreadAction;
import ghidra.app.plugin.core.debug.gui.action.*;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsolePlugin;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.BoundAction;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.LogRow;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerMissingModuleActionContext;
import ghidra.app.services.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.async.SwingExecutorService;
import ghidra.framework.model.*;
import ghidra.plugin.importer.ImporterPlugin;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.stack.DBTraceStack;
import ghidra.trace.database.stack.DBTraceStackManager;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DebuggerListingProviderTest extends AbstractGhidraHeadedDebuggerGUITest {
	static LocationTrackingSpec getLocationTrackingSpec(String name) {
		return /*waitForValue(() ->*/ LocationTrackingSpec.fromConfigName(name)/*)*/;
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

	protected DebuggerListingPlugin listingPlugin;
	protected DebuggerListingProvider listingProvider;

	protected DebuggerStaticMappingService mappingService;
	protected CodeViewerService codeViewer;

	@Before
	public void setUpListingProviderTest() throws Exception {
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		listingProvider = waitForComponentProvider(DebuggerListingProvider.class);

		mappingService = tool.getService(DebuggerStaticMappingService.class);
		codeViewer = tool.getService(CodeViewerService.class);
	}

	protected void goToDyn(Address address) {
		goToDyn(new ProgramLocation(traceManager.getCurrentView(), address));
	}

	protected void goToDyn(ProgramLocation location) {
		waitForPass(() -> {
			runSwing(() -> listingProvider.goTo(location.getProgram(), location));
			ProgramLocation confirm = listingProvider.getLocation();
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
	public void testListingViewIsRegionsActivateThenAdd() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		waitForDomainObject(tb.trace);

		assertEquals(tb.set(tb.range(0x00400000, 0x0040ffff)),
			listingProvider.getListingPanel().getView());
	}

	@Test
	public void testListingViewIsRegionsAddThenActivate() throws Exception {
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
			new AddressSet(listingProvider.getListingPanel().getView()));
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

			assertEquals(tb.trace.getProgramView(), listingProvider.getProgram());

			// NOTE: PC-tracking should be the default for the main dynamic listing
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
		}
		waitForDomainObject(tb.trace);

		ProgramLocation loc = listingProvider.getLocation();
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

			assertEquals(tb.trace.getProgramView(), listingProvider.getProgram());

			// NOTE: PC-tracking should be the default for the main dynamic listing
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(thread, true);
			regs.setValue(1, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
		}
		waitForDomainObject(tb.trace);
		//Pre-check
		assertEquals(tb.addr(0x00400000), listingProvider.getLocation().getAddress());

		traceManager.activateSnap(1);
		waitForSwing();

		ProgramLocation loc = listingProvider.getLocation();
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

			// NOTE: PC-tracking should be the default for the main dynamic listing
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

		loc = listingProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00401234), loc.getAddress());

		traceManager.activateThread(thread2);
		waitForSwing();

		loc = listingProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00405678), loc.getAddress());
	}

	@Test(expected = IllegalStateException.class)
	public void testMainListingMustFollowCurrentThread() {
		listingProvider.setFollowsCurrentThread(false);
	}

	@Test
	public void testRegisterTrackingOnThreadChangeWithoutFollowsCurrentThread() throws Exception {
		createAndOpenTrace();
		TraceThread thread1;
		TraceThread thread2;
		DebuggerListingProvider extraListing = SwingExecutorService.INSTANCE.submit(
			() -> listingPlugin.createListingIfMissing(trackPc, true)).get();
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
		ProgramLocation loc;

		traceManager.activateThread(thread1);
		waitForSwing();

		loc = extraListing.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00401234), loc.getAddress());

		extraListing.setFollowsCurrentThread(false);
		traceManager.activateThread(thread2);
		waitForSwing();

		loc = extraListing.getLocation();
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

			assertEquals(tb.trace.getProgramView(), listingProvider.getProgram());

			TraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(thread, true);
			Register sp = tb.trace.getBaseCompilerSpec().getStackPointer();
			regs.setValue(0, new RegisterValue(sp, BigInteger.valueOf(0x01fff800)));
		}
		waitForDomainObject(tb.trace);
		//Pre-check
		assertEquals(tb.addr(0x00400000), listingProvider.getLocation().getAddress());

		listingProvider.setTrackingSpec(trackSp);
		waitForSwing();

		ProgramLocation loc = listingProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x01fff800), loc.getAddress());
	}

	@Test
	public void testFollowsCurrentTraceOnTraceChangeWithoutRegisterTracking()
			throws Exception {
		listingProvider.setTrackingSpec(trackNone);
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
			ProgramLocation loc;

			traceManager.activateTrace(b1.trace);
			waitForSwing();

			loc = listingProvider.getLocation();
			assertEquals(b1.trace.getProgramView(), loc.getProgram());
			assertEquals(b1.addr(0x00400000), loc.getAddress());

			traceManager.activateTrace(b2.trace);
			waitForSwing();

			loc = listingProvider.getLocation();
			assertEquals(b2.trace.getProgramView(), loc.getProgram());
			assertEquals(b1.addr(0x00400000), loc.getAddress());
		}
	}

	@Test
	public void testFollowsCurrentThreadOnThreadChangeWithoutRegisterTracking()
			throws Exception {
		listingProvider.setTrackingSpec(trackNone);
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
			ProgramLocation loc;

			traceManager.activateThread(t1);
			waitForSwing();

			loc = listingProvider.getLocation();
			assertEquals(b1.trace.getProgramView(), loc.getProgram());
			assertEquals(b1.addr(0x00400000), loc.getAddress());

			traceManager.activateThread(t2);
			waitForSwing();

			loc = listingProvider.getLocation();
			assertEquals(b2.trace.getProgramView(), loc.getProgram());
			assertEquals(b1.addr(0x00400000), loc.getAddress());
		}
	}

	@Test
	public void testSyncToStaticListingStaticToDynamicOnGoto() throws Exception {
		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Add block", true)) {
			program.getMemory()
					.createInitializedBlock(".text", ss.getAddress(0x00600000), 0x10000, (byte) 0,
						monitor, false);
		}
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceLocation from =
				new DefaultTraceLocation(tb.trace, null, Range.atLeast(0L), tb.addr(0x00400000));
			ProgramLocation to = new ProgramLocation(program, ss.getAddress(0x00600000));
			mappingService.addMapping(from, to, 0x8000, false);
		}
		waitForProgram(program);
		waitForDomainObject(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		ProgramLocation loc;

		goTo(tool, program, ss.getAddress(0x00601234));
		waitForSwing();

		loc = listingProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00401234), loc.getAddress());

		goTo(tool, program, ss.getAddress(0x00608765));
		waitForSwing();

		loc = listingProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00401234), loc.getAddress());

		goTo(tool, program, ss.getAddress(0x00607fff));
		waitForSwing();

		loc = listingProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00407fff), loc.getAddress());
	}

	@Test
	public void testSyncToStaticListingDynamicToStaticOnSnapChange() throws Exception {
		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Add block", true)) {
			program.getMemory()
					.createInitializedBlock(".text", ss.getAddress(0x00600000), 0x10000, (byte) 0,
						monitor, false);
		}
		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceLocation from =
				new DefaultTraceLocation(tb.trace, null, Range.atLeast(0L), tb.addr(0x00400000));
			ProgramLocation to = new ProgramLocation(program, ss.getAddress(0x00600000));
			mappingService.addMapping(from, to, 0x8000, false);

			thread = tb.getOrAddThread("Thread1", 0);
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(thread, true);
			regs.setValue(1, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
		}
		waitForProgram(program);
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		traceManager.activateSnap(1);
		waitForSwing();

		ProgramLocation loc = codeViewer.getCurrentLocation();
		assertEquals(program, loc.getProgram());
		assertEquals(ss.getAddress(0x00601234), loc.getAddress());
	}

	@Test
	public void testSyncToStaticListingDynamicToStaticOnLocationChange() throws Exception {
		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Add block", true)) {
			program.getMemory()
					.createInitializedBlock(".text", ss.getAddress(0x00600000), 0x10000, (byte) 0,
						monitor, false);
		}
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceLocation from =
				new DefaultTraceLocation(tb.trace, null, Range.atLeast(0L), tb.addr(0x00400000));
			ProgramLocation to = new ProgramLocation(program, ss.getAddress(0x00600000));
			mappingService.addMapping(from, to, 0x8000, false);
		}
		waitForProgram(program);
		waitForDomainObject(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		listingProvider.getListingPanel()
				.setCursorPosition(
					new ProgramLocation(tb.trace.getProgramView(), tb.addr(0x00401234)),
					EventTrigger.GUI_ACTION);
		waitForSwing();

		ProgramLocation loc = codeViewer.getCurrentLocation();
		assertEquals(program, loc.getProgram());
		assertEquals(ss.getAddress(0x00601234), loc.getAddress());
	}

	protected void assertListingBackgroundAt(Color expected, ListingPanel panel,
			Address addr, int yAdjust) throws AWTException, InterruptedException {
		ProgramLocation oneBack = new ProgramLocation(panel.getProgram(), addr.previous());
		runSwing(() -> panel.goTo(addr));
		runSwing(() -> panel.goTo(oneBack, false));
		waitForPass(() -> {
			Rectangle r = panel.getBounds();
			// Capture off screen, so that focus/stacking doesn't matter
			BufferedImage image = new BufferedImage(r.width, r.height, BufferedImage.TYPE_INT_ARGB);
			Graphics g = image.getGraphics();
			try {
				runSwing(() -> panel.paint(g));
			}
			finally {
				g.dispose();
			}
			Point locP = panel.getLocationOnScreen();
			Point locFP = panel.getLocationOnScreen();
			locFP.translate(-locP.x, -locP.y);
			Rectangle cursor = panel.getCursorBounds();
			Color actual = new Color(image.getRGB(locFP.x + cursor.x - 1,
				locFP.y + cursor.y + cursor.height * 3 / 2 + yAdjust));
			assertEquals(expected, actual);
		});
	}

	@Test
	public void testDynamicListingMarksTrackedRegister() throws Exception {
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

		assertListingBackgroundAt(DebuggerResources.DEFAULT_COLOR_REGISTER_MARKERS,
			listingProvider.getListingPanel(), tb.addr(0x00401234), 0);
	}

	@Test
	public void testSyncToStaticListingMarksMappedTrackedRegister() throws Exception {
		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Add block", true)) {
			program.getMemory()
					.createInitializedBlock(".text", ss.getAddress(0x00600000), 0x10000, (byte) 0,
						monitor, false);
		}
		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceLocation from =
				new DefaultTraceLocation(tb.trace, null, Range.atLeast(0L), tb.addr(0x00400000));
			ProgramLocation to = new ProgramLocation(program, ss.getAddress(0x00600000));
			mappingService.addMapping(from, to, 0x8000, false);

			thread = tb.getOrAddThread("Thread1", 0);
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
			regs.setValue(1, new RegisterValue(pc, BigInteger.valueOf(0x00408765)));
		}
		waitForProgram(program);
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertListingBackgroundAt(DebuggerResources.DEFAULT_COLOR_REGISTER_MARKERS,
			codeViewer.getListingPanel(), ss.getAddress(0x00601234), 0);

		// For verifying static view didn't move
		Address cur = codeViewer.getCurrentLocation().getAddress();

		// Verify mark disappears when register value moves outside the mapped address range
		traceManager.activateSnap(1);
		waitForSwing();

		// While we're here, ensure static view didn't track anywhere
		assertEquals(cur, codeViewer.getCurrentLocation().getAddress());
		assertListingBackgroundAt(Color.WHITE,
			codeViewer.getListingPanel(), ss.getAddress(0x00601234), 0);
	}

	@Test
	public void testAutoReadMemoryReads() throws Exception {
		byte[] data = incBlock();
		byte[] zero = new byte[data.length];
		ByteBuffer buf = ByteBuffer.allocate(data.length);
		assertEquals(readVisROOnce, listingProvider.getAutoReadMemorySpec());
		listingProvider.setAutoReadMemorySpec(readNone);

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
		listingProvider.setAutoReadMemorySpec(readVisROOnce);
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

		assertListingBackgroundAt(DebuggerResources.DEFAULT_COLOR_BACKGROUND_STALE,
			listingProvider.getListingPanel(), tb.addr(0x00401233), 0);
		assertListingBackgroundAt(Color.WHITE,
			listingProvider.getListingPanel(), tb.addr(0x00401234), 0);
		assertListingBackgroundAt(DebuggerResources.DEFAULT_COLOR_BACKGROUND_ERROR,
			listingProvider.getListingPanel(), tb.addr(0x00401235), 0);
	}

	@Test
	public void testCloseCurrentTraceBlanksListings() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		assertEquals(traceManager.getCurrentView(), listingProvider.getProgram());
		assertEquals("(nowhere)", listingProvider.locationLabel.getText());

		DebuggerListingProvider extraProvider = runSwing(
			() -> listingPlugin.createListingIfMissing(trackNone, false));
		waitForSwing();
		assertEquals(traceManager.getCurrentView(), extraProvider.getProgram());
		assertEquals("(nowhere)", extraProvider.locationLabel.getText());

		traceManager.closeTrace(tb.trace);
		waitForSwing();
		assertNull(listingProvider.getProgram());
		assertNull(extraProvider.getProgram());

		assertEquals("", listingProvider.locationLabel.getText());
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
		assertNull(listingProvider.current.getView());
		assertFalse(listingProvider.actionGoTo.isEnabled());
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

		assertTrue(listingProvider.actionGoTo.isEnabled());
		performAction(listingProvider.actionGoTo, false);
		DebuggerGoToDialog dialog = waitForDialogComponent(DebuggerGoToDialog.class);

		dialog.textExpression.setText("r0");
		dialog.okCallback();

		waitForPass(
			() -> assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress()));

		performAction(listingProvider.actionGoTo, false);
		dialog = waitForDialogComponent(DebuggerGoToDialog.class);
		dialog.textExpression.setText("*:4 r0");
		dialog.okCallback();

		waitForPass(
			() -> assertEquals(tb.addr(0x00404321), listingProvider.getLocation().getAddress()));
	}

	@Test
	public void testActionTrackLocation() throws Exception {
		assertTrue(listingProvider.actionTrackLocation.isEnabled());
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
		assertEquals(trackPc, listingProvider.actionTrackLocation.getCurrentUserData());
		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		goToDyn(tb.addr(0x00400000));
		// Ensure it's changed so we know the action is effective
		waitForSwing();
		assertEquals(tb.addr(0x00400000), listingProvider.getLocation().getAddress());

		performAction(listingProvider.actionTrackLocation);
		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		setActionStateWithTrigger(listingProvider.actionTrackLocation, trackSp,
			EventTrigger.GUI_ACTION);
		waitForSwing();
		assertEquals(tb.addr(0x1fff8765), listingProvider.getLocation().getAddress());

		listingProvider.setTrackingSpec(trackNone);
		waitForSwing();
		assertEquals(trackNone, listingProvider.actionTrackLocation.getCurrentUserData());
	}

	@Test
	@Ignore("Haven't specified this action, yet")
	public void testActionTrackOtherRegister() {
		// TODO: Actually, can we make this an arbitrary (pcode/sleigh?) expression.
		TODO();
	}

	@Test
	public void testActionSyncToStaticListing() throws Exception {
		assertTrue(listingProvider.actionSyncToStaticListing.isEnabled());
		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Add block", true)) {
			program.getMemory()
					.createInitializedBlock(
						".text", ss.getAddress(0x00600000), 0x10000, (byte) 0, monitor, false);
		}
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceLocation from =
				new DefaultTraceLocation(tb.trace, null, Range.atLeast(0L), tb.addr(0x00400000));
			ProgramLocation to = new ProgramLocation(program, ss.getAddress(0x00600000));
			mappingService.addMapping(from, to, 0x8000, false);
		}
		waitForProgram(program);
		waitForDomainObject(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		// Check default is on
		assertTrue(listingProvider.actionSyncToStaticListing.isSelected());
		goTo(tool, program, ss.getAddress(0x00601234));
		waitForSwing();
		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		performAction(listingProvider.actionSyncToStaticListing);
		assertFalse(listingProvider.actionSyncToStaticListing.isSelected());
		goTo(tool, program, ss.getAddress(0x00608765));
		waitForSwing();
		// Verify the goTo was effective, but no change to dynamic listing location
		assertEquals(ss.getAddress(0x00608765), codeViewer.getCurrentLocation().getAddress());
		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		listingProvider.setSyncToStaticListing(true);
		// NOTE: Toggling adjusts the static listing, not the dynamic
		waitForSwing();
		assertTrue(listingProvider.actionSyncToStaticListing.isSelected());
		assertEquals(ss.getAddress(0x00601234), codeViewer.getCurrentLocation().getAddress());
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
		DebuggerListingProvider extraProvider = runSwing(
			() -> listingPlugin.createListingIfMissing(trackNone, true));
		waitForSwing();
		assertTrue(extraProvider.actionFollowsCurrentThread.isEnabled());
		assertTrue(extraProvider.actionFollowsCurrentThread.isSelected());
		// Verify it has immediately tracked on creation
		assertEquals(tb.trace.getProgramView(), extraProvider.getLocation().getProgram());
		assertEquals(thread1, extraProvider.current.getThread());
		assertNull(getLocalAction(listingProvider, AbstractFollowsCurrentThreadAction.NAME));
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
	public void testActionCaptureSelectedMemory() throws Exception {
		byte[] data = incBlock();
		byte[] zero = new byte[data.length];
		ByteBuffer buf = ByteBuffer.allocate(data.length);
		assertFalse(listingProvider.actionCaptureSelectedMemory.isEnabled());
		listingProvider.setAutoReadMemorySpec(readNone);

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
		assertFalse(listingProvider.actionCaptureSelectedMemory.isEnabled());

		listingProvider.setSelection(sel);
		waitForSwing();
		// Still
		assertFalse(listingProvider.actionCaptureSelectedMemory.isEnabled());

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
		assertFalse(listingProvider.actionCaptureSelectedMemory.isEnabled());

		listingProvider.setSelection(sel);
		waitForSwing();
		// Now, it should be enabled
		assertTrue(listingProvider.actionCaptureSelectedMemory.isEnabled());

		// First check nothing captured yet
		buf.clear();
		assertEquals(data.length,
			trace.getMemoryManager().getBytes(recorder.getSnap(), addr(trace, 0x55550000), buf));
		assertArrayEquals(zero, buf.array());

		// Verify that the action performs the expected task
		performAction(listingProvider.actionCaptureSelectedMemory);
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
		waitForPass(() -> assertFalse(listingProvider.actionCaptureSelectedMemory.isEnabled()));

		// Verify that setting it accessible re-enables it (assuming we still have selection)
		mb.testProcess1.memory.setAccessible(true);
		waitForPass(() -> assertTrue(listingProvider.actionCaptureSelectedMemory.isEnabled()));

		// Verify that moving into the past disables the action
		TraceSnapshot forced = recorder.forceSnapshot();
		waitForSwing(); // UI Wants to sync with new snap. Wait....
		traceManager.activateSnap(forced.getKey() - 1);
		waitForSwing();
		assertFalse(listingProvider.actionCaptureSelectedMemory.isEnabled());

		// Verify that advancing to the present enables the action (assuming a selection)
		traceManager.activateSnap(forced.getKey());
		waitForSwing();
		assertTrue(listingProvider.actionCaptureSelectedMemory.isEnabled());

		// Verify that stopping the recording disables the action
		recorder.stopRecording();
		waitForSwing();
		assertFalse(listingProvider.actionCaptureSelectedMemory.isEnabled());

		// TODO: When resume recording is implemented, verify action is enabled with selection
	}

	@Test
	public void testActionAutoReadMemory() {
		assertTrue(listingProvider.actionAutoReadMemory.isEnabled());

		assertEquals(readVisROOnce, listingProvider.getAutoReadMemorySpec());
		assertEquals(readVisROOnce, listingProvider.actionAutoReadMemory.getCurrentUserData());

		listingProvider.actionAutoReadMemory
				.setCurrentActionStateByUserData(readNone);
		waitForSwing();
		assertEquals(readNone, listingProvider.getAutoReadMemorySpec());
		assertEquals(readNone, listingProvider.actionAutoReadMemory.getCurrentUserData());

		listingProvider.setAutoReadMemorySpec(readVisROOnce);
		waitForSwing();
		assertEquals(readVisROOnce, listingProvider.getAutoReadMemorySpec());
		assertEquals(readVisROOnce, listingProvider.actionAutoReadMemory.getCurrentUserData());

		listingProvider.setAutoReadMemorySpec(readNone);
		waitForSwing();
		assertEquals(readNone, listingProvider.getAutoReadMemorySpec());
		assertEquals(readNone, listingProvider.actionAutoReadMemory.getCurrentUserData());
	}

	@Test
	public void testPromptImportCurrentModuleWithSections() throws Exception {
		addPlugin(tool, ImporterPlugin.class);
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		createAndOpenTrace();
		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("bash:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0041ffff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));

			TraceModule bin = tb.trace.getModuleManager()
					.addLoadedModule("/bin/bash", "/bin/bash",
						tb.range(0x00400000, 0x0041ffff), 0);
			bin.addSection("bash[.text]", tb.range(0x00400000, 0x0040ffff));

			traceManager.activateTrace(tb.trace);
		}

		// In the module, but not in its section
		listingPlugin.goTo(tb.addr(0x00411234), true);
		waitForSwing();
		waitForPass(() -> assertEquals(0,
			consolePlugin.getRowCount(DebuggerMissingModuleActionContext.class)));

		listingPlugin.goTo(tb.addr(0x00401234), true);
		waitForSwing();
		waitForPass(() -> assertEquals(1,
			consolePlugin.getRowCount(DebuggerMissingModuleActionContext.class)));
	}

	@Test
	public void testPromptImportCurrentModuleWithoutSections() throws Exception {
		addPlugin(tool, ImporterPlugin.class);
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		createAndOpenTrace();
		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("bash:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0041ffff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));

			tb.trace.getModuleManager()
					.addLoadedModule("/bin/bash", "/bin/bash",
						tb.range(0x00400000, 0x0041ffff), 0);

			traceManager.activateTrace(tb.trace);
		}

		// In the module, but not in its section
		listingPlugin.goTo(tb.addr(0x00411234), true);
		waitForSwing();
		waitForPass(() -> assertEquals(1,
			consolePlugin.getRowCount(DebuggerMissingModuleActionContext.class)));
	}

	@Test
	public void testLocationLabel() throws Exception {
		assertEquals("", listingProvider.locationLabel.getText());

		createAndOpenTrace();
		waitForSwing();
		assertEquals("", listingProvider.locationLabel.getText());

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		assertEquals("(nowhere)", listingProvider.locationLabel.getText());

		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("test_region", Range.atLeast(0L), tb.range(0x55550000, 0x555502ff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		waitForDomainObject(tb.trace);
		waitForPass(() -> assertEquals("test_region", listingProvider.locationLabel.getText()));

		TraceModule modExe;
		try (UndoableTransaction tid = tb.startTransaction()) {
			modExe = tb.trace.getModuleManager()
					.addModule("modExe", "modExe",
						tb.range(0x55550000, 0x555501ff), Range.atLeast(0L));
		}
		waitForDomainObject(tb.trace);
		waitForPass(() -> assertEquals("modExe", listingProvider.locationLabel.getText()));

		try (UndoableTransaction tid = tb.startTransaction()) {
			modExe.addSection(".text", tb.range(0x55550000, 0x555500ff));
		}
		waitForDomainObject(tb.trace);
		waitForPass(() -> assertEquals("modExe:.text", listingProvider.locationLabel.getText()));
	}

	@Test
	public void testActivateThreadTracks() throws Exception {
		assertEquals(trackPc, listingProvider.actionTrackLocation.getCurrentUserData());

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

		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		traceManager.activateThread(thread2);
		waitForSwing();

		assertEquals(tb.addr(0x00404321), listingProvider.getLocation().getAddress());
	}

	@Test
	public void testActivateSnapTracks() throws Exception {
		assertEquals(trackPc, listingProvider.actionTrackLocation.getCurrentUserData());

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

		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		traceManager.activateSnap(1);
		waitForSwing();

		assertEquals(tb.addr(0x00404321), listingProvider.getLocation().getAddress());
	}

	@Test
	public void testActivateFrameTracks() throws Exception {
		assertEquals(trackPc, listingProvider.actionTrackLocation.getCurrentUserData());

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

		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		traceManager.activateFrame(1);
		waitForSwing();

		assertEquals(tb.addr(0x00404321), listingProvider.getLocation().getAddress());
	}

	@Test
	public void testRegsPCChangedTracks() throws Exception {
		assertEquals(trackPc, listingProvider.actionTrackLocation.getCurrentUserData());

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

		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryRegisterSpace regs = mm.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00404321", 16)));
		}
		waitForDomainObject(tb.trace);

		assertEquals(tb.addr(0x00404321), listingProvider.getLocation().getAddress());
	}

	@Test
	public void testRegsPCChangedTracksDespiteStackWithNoPC() throws Exception {
		assertEquals(trackPc, listingProvider.actionTrackLocation.getCurrentUserData());

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

		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryRegisterSpace regs = mm.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00404321", 16)));
		}
		waitForDomainObject(tb.trace);

		assertEquals(tb.addr(0x00404321), listingProvider.getLocation().getAddress());
	}

	@Test
	public void testStackPCChangedTracks() throws Exception {
		assertEquals(trackPc, listingProvider.actionTrackLocation.getCurrentUserData());

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

		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceStack stack = sm.getStack(thread, 0, true);
			stack.getFrame(0, true).setProgramCounter(tb.addr(0x00404321));
		}
		waitForDomainObject(tb.trace);

		assertEquals(tb.addr(0x00404321), listingProvider.getLocation().getAddress());
	}

	@Test
	public void testSyncToStaticListingOpensModule() throws Exception {
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Add block", true)) {
			program.getMemory()
					.createInitializedBlock(".text", ss.getAddress(0x00600000), 0x10000, (byte) 0,
						monitor, false);
		}
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceLocation from =
				new DefaultTraceLocation(tb.trace, null, Range.atLeast(0L), tb.addr(0x00400000));
			ProgramLocation to = new ProgramLocation(program, ss.getAddress(0x00600000));
			mappingService.addMapping(from, to, 0x8000, false);
		}
		waitForProgram(program);
		waitForDomainObject(tb.trace);

		programManager.closeAllPrograms(true);
		waitForPass(() -> assertEquals(0, programManager.getAllOpenPrograms().length));

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		listingProvider.getListingPanel()
				.setCursorPosition(
					new ProgramLocation(tb.trace.getProgramView(), tb.addr(0x00401234)),
					EventTrigger.GUI_ACTION);
		waitForSwing();

		waitForPass(() -> assertEquals(1, programManager.getAllOpenPrograms().length));
		assertTrue(java.util.List.of(programManager.getAllOpenPrograms()).contains(program));

		assertFalse(consolePlugin
				.logContains(new DebuggerOpenProgramActionContext(program.getDomainFile())));
	}

	@Test
	public void testSyncToStaticLogsRecoverableProgram() throws Exception {
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		TestDummyDomainFolder root = new TestDummyDomainFolder(null, "root");
		DomainFile df = new TestDummyDomainFile(root, "dummyFile") {
			@Override
			public boolean canRecover() {
				return true;
			}
		};

		listingProvider.doTryOpenProgram(df, DomainFile.DEFAULT_VERSION,
			ProgramManager.OPEN_CURRENT);
		waitForSwing();

		DebuggerOpenProgramActionContext ctx = new DebuggerOpenProgramActionContext(df);
		waitForPass(() -> assertTrue(consolePlugin.logContains(ctx)));
		assertTrue(consolePlugin.getLogRow(ctx).getMessage().contains("recovery"));
	}

	@Test
	public void testSyncToStaticLogsUpgradeableProgram() throws Exception {
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		TestDummyDomainFolder root = new TestDummyDomainFolder(null, "root");
		DomainFile df = new TestDummyDomainFile(root, "dummyFile") {
			@Override
			public boolean canRecover() {
				return false;
			}

			@Override
			public DomainObject getDomainObject(Object consumer, boolean okToUpgrade,
					boolean okToRecover, TaskMonitor monitor)
					throws VersionException, IOException, CancelledException {
				throw new VersionException();
			}
		};

		listingProvider.doTryOpenProgram(df, DomainFile.DEFAULT_VERSION,
			ProgramManager.OPEN_CURRENT);
		waitForSwing();

		DebuggerOpenProgramActionContext ctx = new DebuggerOpenProgramActionContext(df);
		waitForPass(() -> assertTrue(consolePlugin.logContains(ctx)));
		assertTrue(consolePlugin.getLogRow(ctx).getMessage().contains("version"));
	}

	@Test
	public void testActionOpenProgram() throws Exception {
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		createProgram();
		intoProject(program);

		assertEquals(0, programManager.getAllOpenPrograms().length);

		DebuggerOpenProgramActionContext ctx =
			new DebuggerOpenProgramActionContext(program.getDomainFile());
		consolePlugin.log(DebuggerResources.ICON_MODULES, "Test resolution", ctx);
		waitForSwing();

		LogRow row = consolePlugin.getLogRow(ctx);
		assertEquals(1, row.getActions().size());
		BoundAction boundAction = row.getActions().get(0);
		assertEquals(listingProvider.actionOpenProgram, boundAction.action);

		boundAction.perform();
		waitForSwing();

		waitForPass(() -> assertEquals(1, programManager.getAllOpenPrograms().length));
		assertTrue(java.util.List.of(programManager.getAllOpenPrograms()).contains(program));
		// TODO: Test this independent of this particular action?
		assertNull(consolePlugin.getLogRow(ctx));
	}
}
