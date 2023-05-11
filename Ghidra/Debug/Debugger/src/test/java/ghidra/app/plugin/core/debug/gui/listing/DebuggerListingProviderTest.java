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

import static org.junit.Assert.*;

import java.awt.Component;
import java.awt.Point;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Set;

import org.junit.*;
import org.junit.experimental.categories.Category;

import db.Transaction;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import generic.test.category.NightlyCategory;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.codebrowser.hover.ReferenceListingHoverPlugin;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.FollowsCurrentThreadAction;
import ghidra.app.plugin.core.debug.gui.action.*;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsolePlugin;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.BoundAction;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.LogRow;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerMissingModuleActionContext;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.services.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.async.SwingExecutorService;
import ghidra.framework.model.*;
import ghidra.lifecycle.Unfinished;
import ghidra.plugin.importer.ImporterPlugin;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.util.*;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.stack.DBTraceStackManager;
import ghidra.trace.model.*;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

@Category(NightlyCategory.class)
public class DebuggerListingProviderTest extends AbstractGhidraHeadedDebuggerGUITest {

	protected DebuggerListingPlugin listingPlugin;
	protected DebuggerListingProvider listingProvider;

	protected DebuggerStaticMappingService mappingService;
	protected CodeBrowserPlugin codePlugin;
	protected CodeViewerProvider codeProvider;

	@Before
	public void setUpListingProviderTest() throws Exception {
		// Do before listingPlugin, since types collide
		codePlugin = addPlugin(tool, CodeBrowserPlugin.class);
		codeProvider = waitForComponentProvider(CodeViewerProvider.class);

		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		listingProvider = waitForComponentProvider(DebuggerListingProvider.class);

		mappingService = tool.getService(DebuggerStaticMappingService.class);
	}

	protected void goToDyn(Address address) {
		goToDyn(new ProgramLocation(traceManager.getCurrentView(), address));
	}

	protected void goToDyn(ProgramLocation location) {
		goTo(listingProvider.getListingPanel(), location);
	}

	protected static byte[] incBlock() {
		byte[] data = new byte[4096];
		for (int i = 0; i < data.length; i++) {
			data[i] = (byte) i;
		}
		return data;
	}

	protected void createMappedTraceAndProgram() throws Exception {
		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();
		try (Transaction tx = program.openTransaction("Add block")) {
			program.getMemory()
					.createInitializedBlock(".text", ss.getAddress(0x00600000), 0x10000, (byte) 0,
						monitor, false);
		}
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceLocation from =
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x00400000));
			ProgramLocation to = new ProgramLocation(program, ss.getAddress(0x00600000));
			DebuggerStaticMappingUtils.addMapping(from, to, 0x8000, false);
		}
		waitForProgram(program);
		waitForDomainObject(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
	}

	@Test
	public void testListingViewIsRegionsActivateThenAdd() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		waitForDomainObject(tb.trace);

		assertEquals(tb.set(tb.range(0x00400000, 0x0040ffff)),
			listingProvider.getListingPanel().getView());
	}

	@Test
	public void testListingViewIsRegionsAddThenActivate() throws Exception {
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
			new AddressSet(listingProvider.getListingPanel().getView()));
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

			assertEquals(tb.trace.getProgramView(), listingProvider.getProgram());

			// NOTE: PC-tracking should be the default for the main dynamic listing
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemorySpace regs = memory.getMemoryRegisterSpace(thread, true);
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
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceThread thread = tb.getOrAddThread("Thread1", 0);
			waitForDomainObject(tb.trace);
			traceManager.activateThread(thread);
			waitForSwing(); // Ensure the open/activate events are processed first

			assertEquals(tb.trace.getProgramView(), listingProvider.getProgram());

			// NOTE: PC-tracking should be the default for the main dynamic listing
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemorySpace regs = memory.getMemoryRegisterSpace(thread, true);
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
		DebuggerListingProvider extraProvider = SwingExecutorService.LATER
				.submit(() -> listingPlugin.createListingIfMissing(PCLocationTrackingSpec.INSTANCE,
					true))
				.get();
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

			assertEquals(tb.trace.getProgramView(), listingProvider.getProgram());

			TraceMemorySpace regs = memory.getMemoryRegisterSpace(thread, true);
			Register sp = tb.trace.getBaseCompilerSpec().getStackPointer();
			regs.setValue(0, new RegisterValue(sp, BigInteger.valueOf(0x01fff800)));
		}
		waitForDomainObject(tb.trace);
		//Pre-check
		assertEquals(tb.addr(0x00400000), listingProvider.getLocation().getAddress());

		listingProvider.setTrackingSpec(SPLocationTrackingSpec.INSTANCE);
		waitForSwing();

		ProgramLocation loc = listingProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x01fff800), loc.getAddress());
	}

	@Test
	public void testFollowsCurrentTraceOnTraceChangeWithoutRegisterTracking() throws Exception {
		listingProvider.setTrackingSpec(NoneLocationTrackingSpec.INSTANCE);
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
	public void testFollowsCurrentThreadOnThreadChangeWithoutRegisterTracking() throws Exception {
		listingProvider.setTrackingSpec(NoneLocationTrackingSpec.INSTANCE);
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
			ProgramLocation loc;

			traceManager.activateThread(t1);
			waitForSwing();

			loc = listingProvider.getLocation();
			assertEquals(b1.trace.getProgramView(), loc.getProgram());
			assertEquals(b1.addr(0x00400000), loc.getAddress());
			// TODO: Assert thread?

			traceManager.activateThread(t2);
			waitForSwing();

			loc = listingProvider.getLocation();
			assertEquals(b2.trace.getProgramView(), loc.getProgram());
			assertEquals(b1.addr(0x00400000), loc.getAddress());
		}
	}

	@Test
	public void testSyncCursorToStaticListingStaticToDynamicOnGoto() throws Exception {
		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

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
	public void testSyncCursorToStaticListingDynamicToStaticOnSnapChange() throws Exception {
		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();
		try (Transaction tx = program.openTransaction("Add block")) {
			program.getMemory()
					.createInitializedBlock(".text", ss.getAddress(0x00600000), 0x10000, (byte) 0,
						monitor, false);
		}
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceLocation from =
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x00400000));
			ProgramLocation to = new ProgramLocation(program, ss.getAddress(0x00600000));
			DebuggerStaticMappingUtils.addMapping(from, to, 0x8000, false);

			thread = tb.getOrAddThread("Thread1", 0);
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemorySpace regs = memory.getMemoryRegisterSpace(thread, true);
			regs.setValue(1, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
		}
		waitForProgram(program);
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		traceManager.activateSnap(1);
		waitForSwing();

		ProgramLocation loc = codePlugin.getCurrentLocation();
		assertEquals(program, loc.getProgram());
		assertEquals(ss.getAddress(0x00601234), loc.getAddress());
	}

	@Test
	public void testSyncCursorToStaticListingDynamicToStaticOnLocationChange() throws Exception {
		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		listingProvider.getListingPanel()
				.setCursorPosition(
					new ProgramLocation(tb.trace.getProgramView(), tb.addr(0x00401234)),
					EventTrigger.GUI_ACTION);
		waitForSwing();

		ProgramLocation loc = codePlugin.getCurrentLocation();
		assertEquals(program, loc.getProgram());
		assertEquals(ss.getAddress(0x00601234), loc.getAddress());
	}

	@Test
	public void testSyncSelectionToStaticListingDynamicToStaticOnSelectionChange()
			throws Exception {
		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		runSwing(() -> listingProvider.getListingPanel()
				.setSelection(new ProgramSelection(tb.addr(0x00401234), tb.addr(0x00404321)),
					EventTrigger.GUI_ACTION));
		waitForSwing();

		assertEquals(tb.set(tb.range(ss, 0x00601234, 0x00604321)),
			codePlugin.getCurrentSelection());
	}

	@Test
	public void testSyncSelectionToStaticListingStaticToDynamicOnSelectionChange()
			throws Exception {
		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		runSwing(() -> codePlugin.getListingPanel()
				.setSelection(
					new ProgramSelection(tb.addr(ss, 0x00601234), tb.addr(ss, 0x00604321)),
					EventTrigger.GUI_ACTION));
		waitForSwing();

		assertEquals(tb.set(tb.range(0x00401234, 0x00404321)), listingPlugin.getCurrentSelection());
	}

	@Test
	public void testDynamicListingMarksTrackedRegister() throws Exception {
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

		assertListingBackgroundAt(DebuggerResources.COLOR_REGISTER_MARKERS,
			listingProvider.getListingPanel(), tb.addr(0x00401234), 0);
	}

	@Test
	public void testSyncCursorToStaticListingMarksMappedTrackedRegister() throws Exception {
		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();
		try (Transaction tx = program.openTransaction("Add block")) {
			program.getMemory()
					.createInitializedBlock(".text", ss.getAddress(0x00600000), 0x10000, (byte) 0,
						monitor, false);
		}
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceLocation from =
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x00400000));
			ProgramLocation to = new ProgramLocation(program, ss.getAddress(0x00600000));
			DebuggerStaticMappingUtils.addMapping(from, to, 0x8000, false);

			thread = tb.getOrAddThread("Thread1", 0);
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemorySpace regs = memory.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
			regs.setValue(1, new RegisterValue(pc, BigInteger.valueOf(0x00408765)));
		}
		waitForProgram(program);
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertListingBackgroundAt(DebuggerResources.COLOR_REGISTER_MARKERS,
			codePlugin.getListingPanel(), ss.getAddress(0x00601234), 0);

		// For verifying static view didn't move
		Address cur = codePlugin.getCurrentLocation().getAddress();

		// Verify mark disappears when register value moves outside the mapped address range
		traceManager.activateSnap(1);
		waitForSwing();

		// While we're here, ensure static view didn't track anywhere
		assertEquals(cur, codePlugin.getCurrentLocation().getAddress());
		assertListingBackgroundAt(Colors.BACKGROUND, codePlugin.getListingPanel(),
			ss.getAddress(0x00601234), 0);
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
			createTargetTraceMapper(mb.testProcess1));
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

	public void runTestAutoReadMemoryReadsWithForceFullView(AutoReadMemorySpec spec)
			throws Throwable {
		byte[] data = incBlock();
		byte[] zero = new byte[data.length];
		ByteBuffer buf = ByteBuffer.allocate(data.length);
		listingProvider.setAutoReadMemorySpec(spec);

		createTestModel();
		mb.createTestProcessesAndThreads();

		// NOTE: Do not add a region. Depend on Force full view!
		// Populate target memory before recording
		mb.testProcess1.memory.setMemory(mb.addr(0x55550000), data);

		TraceRecorder recorder = modelService.recordTargetAndActivateTrace(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();
		waitRecorder(recorder);
		traceManager.activateTrace(trace);
		waitForSwing();

		buf.clear();
		assertEquals(data.length,
			trace.getMemoryManager().getBytes(recorder.getSnap(), addr(trace, 0x55550000), buf));
		assertArrayEquals(zero, buf.array());

		runSwing(() -> trace.getProgramView().getMemory().setForceFullView(true));

		waitForPass(noExc(() -> {
			goToDyn(addr(trace, 0x55550000));
			waitRecorder(recorder);

			buf.clear();
			assertEquals(data.length,
				trace.getMemoryManager()
						.getBytes(recorder.getSnap(), addr(trace, 0x55550000), buf));
			assertArrayEquals(data, buf.array());
		}));
	}

	@Test
	public void testAutoReadMemoryVisROOnceReadsWithForceFullView() throws Throwable {
		runTestAutoReadMemoryReadsWithForceFullView(readVisROOnce);
	}

	@Test
	public void testAutoReadMemoryVisibleReadsWithForceFullView() throws Throwable {
		runTestAutoReadMemoryReadsWithForceFullView(readVisible);
	}

	@Test
	public void testMemoryStateBackgroundColors() throws Exception {
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

		assertListingBackgroundAt(DebuggerResources.COLOR_BACKGROUND_STALE,
			listingProvider.getListingPanel(), tb.addr(0x00401233), 0);
		assertListingBackgroundAt(Colors.BACKGROUND, listingProvider.getListingPanel(),
			tb.addr(0x00401234), 0);
		assertListingBackgroundAt(DebuggerResources.COLOR_BACKGROUND_ERROR,
			listingProvider.getListingPanel(), tb.addr(0x00401235), 0);
	}

	@Test
	public void testCloseCurrentTraceBlanksListings() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		assertEquals(traceManager.getCurrentView(), listingProvider.getProgram());
		assertEquals("(nowhere)", listingProvider.locationLabel.getText());

		DebuggerListingProvider extraProvider =
			runSwing(() -> listingPlugin.createListingIfMissing(NoneLocationTrackingSpec.INSTANCE,
				false));
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

		assertTrue(listingProvider.actionGoTo.isEnabled());

		performAction(listingProvider.actionGoTo, false);
		DebuggerGoToDialog dialog1 = waitForDialogComponent(DebuggerGoToDialog.class);
		runSwing(() -> {
			dialog1.setOffset("00400123");
			dialog1.okCallback();
		});
		waitForPass(
			() -> assertEquals(tb.addr(0x00400123), listingProvider.getLocation().getAddress()));

		performAction(listingProvider.actionGoTo, false);
		DebuggerGoToDialog dialog2 = waitForDialogComponent(DebuggerGoToDialog.class);
		runSwing(() -> {
			dialog2.setOffset("r0");
			dialog2.okCallback();
		});
		waitForPass(
			() -> assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress()));

		performAction(listingProvider.actionGoTo, false);
		DebuggerGoToDialog dialog3 = waitForDialogComponent(DebuggerGoToDialog.class);
		runSwing(() -> {
			dialog3.setOffset("*:4 r0");
			dialog3.okCallback();
		});
		waitForPass(
			() -> assertEquals(tb.addr(0x00404321), listingProvider.getLocation().getAddress()));
	}

	@Test
	public void testActionTrackLocation() throws Exception {
		assertTrue(listingProvider.actionTrackLocation.isEnabled());
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
			listingProvider.actionTrackLocation.getCurrentUserData());
		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		goToDyn(tb.addr(0x00400000));
		// Ensure it's changed so we know the action is effective
		waitForSwing();
		assertEquals(tb.addr(0x00400000), listingProvider.getLocation().getAddress());

		performAction(listingProvider.actionTrackLocation);
		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		setActionStateWithTrigger(listingProvider.actionTrackLocation,
			SPLocationTrackingSpec.INSTANCE,
			EventTrigger.GUI_ACTION);
		waitForSwing();
		assertEquals(tb.addr(0x1fff8765), listingProvider.getLocation().getAddress());

		listingProvider.setTrackingSpec(NoneLocationTrackingSpec.INSTANCE);
		waitForSwing();
		assertEquals(NoneLocationTrackingSpec.INSTANCE,
			listingProvider.actionTrackLocation.getCurrentUserData());
	}

	@Test
	@Ignore("Haven't specified this action, yet")
	public void testActionTrackOtherRegister() {
		// TODO: Actually, can we make this an arbitrary (pcode/sleigh?) expression.
		Unfinished.TODO();
	}

	@Test
	public void testActionSyncCursorToStaticListing() throws Exception {
		assertTrue(listingProvider.actionAutoSyncCursorWithStaticListing.isEnabled());

		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		// Check default is on
		assertTrue(listingProvider.actionAutoSyncCursorWithStaticListing.isSelected());
		goTo(tool, program, ss.getAddress(0x00601234));
		waitForSwing();
		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		performAction(listingProvider.actionAutoSyncCursorWithStaticListing);
		assertFalse(listingProvider.actionAutoSyncCursorWithStaticListing.isSelected());
		goTo(tool, program, ss.getAddress(0x00608765));
		waitForSwing();
		// Verify the goTo was effective, but no change to dynamic listing location
		assertEquals(ss.getAddress(0x00608765), codePlugin.getCurrentLocation().getAddress());
		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		listingProvider.setAutoSyncCursorWithStaticListing(true);
		// NOTE: Toggling adjusts the static listing, not the dynamic
		waitForSwing();
		assertTrue(listingProvider.actionAutoSyncCursorWithStaticListing.isSelected());
		assertEquals(ss.getAddress(0x00601234), codePlugin.getCurrentLocation().getAddress());
	}

	@Test
	public void testActionSyncSelectionToStaticListing() throws Exception {
		assertTrue(listingProvider.actionAutoSyncCursorWithStaticListing.isEnabled());

		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		// Check default is on
		assertTrue(listingProvider.actionAutoSyncSelectionWithStaticListing.isSelected());
		makeSelection(tool, program, tb.range(ss, 0x00601234, 0x00604321));
		goTo(tool, program, ss.getAddress(0x00601234));
		waitForSwing();
		assertEquals(tb.set(tb.range(0x00401234, 0x00404321)), listingPlugin.getCurrentSelection());

		performAction(listingProvider.actionAutoSyncSelectionWithStaticListing);
		assertFalse(listingProvider.actionAutoSyncSelectionWithStaticListing.isSelected());
		goTo(tool, program, ss.getAddress(0x00608765));
		makeSelection(tool, program, tb.range(ss, 0x00605678, 0x00608765));
		waitForSwing();
		// Verify the makeSelection was effective, but no change to dynamic listing location
		assertEquals(tb.set(tb.range(ss, 0x00605678, 0x00608765)),
			codePlugin.getCurrentSelection());
		assertEquals(tb.set(tb.range(0x00401234, 0x00404321)), listingPlugin.getCurrentSelection());

		listingProvider.setAutoSyncSelectionWithStaticListing(true);
		// NOTE: Toggling adjusts the static listing, not the dynamic
		waitForSwing();
		assertTrue(listingProvider.actionAutoSyncSelectionWithStaticListing.isSelected());
		assertEquals(tb.set(tb.range(ss, 0x00601234, 0x00604321)),
			codePlugin.getCurrentSelection());
		assertEquals(tb.set(tb.range(0x00401234, 0x00404321)), listingPlugin.getCurrentSelection());
	}

	@Test
	public void testActionMapAddressesToStatic() throws Exception {
		listingProvider.setAutoSyncSelectionWithStaticListing(false);
		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		listingProvider.getListingPanel()
				.setSelection(new ProgramSelection(tb.set(tb.range(0x00401234, 0x00404321))),
					EventTrigger.GUI_ACTION);
		assertTrue(codePlugin.getCurrentSelection().isEmpty());

		performAction(listingProvider.actionSyncSelectionIntoStaticListing,
			listingProvider.getActionContext(null), true);
		assertEquals(tb.set(tb.range(ss, 0x00601234, 0x00604321)),
			codePlugin.getCurrentSelection());
	}

	@Test
	public void testActionMapAddressesToDynamic() throws Exception {
		listingProvider.setAutoSyncSelectionWithStaticListing(false);
		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		makeSelection(tool, program, tb.set(tb.range(ss, 0x00601234, 0x00604321)));
		assertTrue(listingPlugin.getCurrentSelection().isEmpty());

		performAction(listingProvider.actionSyncSelectionFromStaticListing,
			codeProvider.getActionContext(null), true);
		assertEquals(tb.set(tb.range(0x00401234, 0x00404321)),
			listingPlugin.getCurrentSelection());
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
		DebuggerListingProvider extraProvider =
			runSwing(() -> listingPlugin.createListingIfMissing(NoneLocationTrackingSpec.INSTANCE,
				true));
		waitForSwing();
		assertTrue(extraProvider.actionFollowsCurrentThread.isEnabled());
		assertTrue(extraProvider.actionFollowsCurrentThread.isSelected());
		// Verify it has immediately tracked on creation
		assertEquals(tb.trace.getProgramView(), extraProvider.getLocation().getProgram());
		assertEquals(thread1, extraProvider.current.getThread());
		assertNull(getLocalAction(listingProvider, FollowsCurrentThreadAction.NAME));
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
	@Ignore("TODO") // Needs attention, but low priority
	public void testActionReadSelectedMemory() throws Exception {
		byte[] data = incBlock();
		byte[] zero = new byte[data.length];
		ByteBuffer buf = ByteBuffer.allocate(data.length);
		assertFalse(listingProvider.actionRefreshSelectedMemory.isEnabled());
		listingProvider.setAutoReadMemorySpec(readNone);

		// To verify enabled requires live target
		createAndOpenTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x55550000, 0x555500ff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		ProgramSelection sel = new ProgramSelection(tb.set(tb.range(0x55550040, 0x5555004f)));
		waitForDomainObject(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		// Still
		assertFalse(listingProvider.actionRefreshSelectedMemory.isEnabled());

		listingProvider.setSelection(sel);
		waitForSwing();
		// Still
		assertFalse(listingProvider.actionRefreshSelectedMemory.isEnabled());

		// Now, simulate the sequence that typically enables the action
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTargetAndActivateTrace(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		mb.testProcess1.addRegion("exe:.text", mb.rng(0x55550000, 0x555500ff), "rx");
		mb.testProcess1.memory.setMemory(mb.addr(0x55550000), data); // No effect yet
		waitForDomainObject(trace);
		waitFor(() -> trace.getMemoryManager().getAllRegions().size() == 1);

		// NOTE: recordTargetContainerAndOpenTrace has already activated the trace
		// Action is still disabled, because it requires a selection
		assertFalse(listingProvider.actionRefreshSelectedMemory.isEnabled());

		listingProvider.setSelection(sel);
		waitForSwing();
		// Now, it should be enabled
		assertTrue(listingProvider.actionRefreshSelectedMemory.isEnabled());

		// First check nothing captured yet
		buf.clear();
		assertEquals(data.length,
			trace.getMemoryManager().getBytes(recorder.getSnap(), addr(trace, 0x55550000), buf));
		assertArrayEquals(zero, buf.array());

		// Verify that the action performs the expected task
		performAction(listingProvider.actionRefreshSelectedMemory);
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
		waitForPass(() -> assertFalse(listingProvider.actionRefreshSelectedMemory.isEnabled()));

		// Verify that setting it accessible re-enables it (assuming we still have selection)
		mb.testProcess1.memory.setAccessible(true);
		waitForPass(() -> assertTrue(listingProvider.actionRefreshSelectedMemory.isEnabled()));

		// Verify that moving into the past disables the action
		TraceSnapshot forced = recorder.forceSnapshot();
		waitForSwing(); // UI Wants to sync with new snap. Wait....
		traceManager.activateSnap(forced.getKey() - 1);
		waitForSwing();
		assertFalse(listingProvider.actionRefreshSelectedMemory.isEnabled());

		// Verify that advancing to the present enables the action (assuming a selection)
		traceManager.activateSnap(forced.getKey());
		waitForSwing();
		assertTrue(listingProvider.actionRefreshSelectedMemory.isEnabled());

		// Verify that stopping the recording disables the action
		recorder.stopRecording();
		waitForSwing();
		assertFalse(listingProvider.actionRefreshSelectedMemory.isEnabled());

		// TODO: When resume recording is implemented, verify action is enabled with selection
	}

	@Test
	public void testActionAutoReadMemory() {
		assertTrue(listingProvider.actionAutoReadMemory.isEnabled());

		assertEquals(readVisROOnce, listingProvider.getAutoReadMemorySpec());
		assertEquals(readVisROOnce, listingProvider.actionAutoReadMemory.getCurrentUserData());

		listingProvider.actionAutoReadMemory.setCurrentActionStateByUserData(readNone);
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
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("bash:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0041ffff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));

			TraceModule bin = tb.trace.getModuleManager()
					.addLoadedModule("/bin/bash", "/bin/bash", tb.range(0x00400000, 0x0041ffff), 0);
			bin.addSection("bash[.text]", tb.range(0x00400000, 0x0040ffff));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		// In the module, but not in its section
		assertTrue(listingPlugin.goTo(tb.addr(0x00411234), true));
		waitForSwing();
		waitForPass(() -> assertEquals(0,
			consolePlugin.getRowCount(DebuggerMissingModuleActionContext.class)));

		assertTrue(listingPlugin.goTo(tb.addr(0x00401234), true));
		waitForSwing();
		waitForPass(() -> assertEquals(1,
			consolePlugin.getRowCount(DebuggerMissingModuleActionContext.class)));
	}

	@Test
	public void testPromptImportCurrentModuleWithoutSections() throws Exception {
		addPlugin(tool, ImporterPlugin.class);
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		createAndOpenTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("bash:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0041ffff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));

			tb.trace.getModuleManager()
					.addLoadedModule("/bin/bash", "/bin/bash", tb.range(0x00400000, 0x0041ffff), 0);
		}
		waitForDomainObject(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		// In the module, but not in its section
		assertTrue(listingPlugin.goTo(tb.addr(0x00411234), true));
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

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("test_region", Lifespan.nowOn(0), tb.range(0x55550000, 0x555502ff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		waitForDomainObject(tb.trace);
		waitForPass(() -> assertEquals("test_region", listingProvider.locationLabel.getText()));

		TraceModule modExe;
		try (Transaction tx = tb.startTransaction()) {
			modExe = tb.trace.getModuleManager()
					.addModule("modExe", "modExe", tb.range(0x55550000, 0x555501ff),
						Lifespan.nowOn(0));
		}
		waitForDomainObject(tb.trace);
		waitForPass(() -> assertEquals("modExe", listingProvider.locationLabel.getText()));

		try (Transaction tx = tb.startTransaction()) {
			modExe.addSection(".text", tb.range(0x55550000, 0x555500ff));
		}
		waitForDomainObject(tb.trace);
		waitForPass(() -> assertEquals("modExe:.text", listingProvider.locationLabel.getText()));
	}

	@Test
	public void testActivateTraceChangeLanguage() throws Exception {
		assertEquals(PCLocationTrackingSpec.INSTANCE,
			listingProvider.actionTrackLocation.getCurrentUserData());

		createSnaplessTrace("x86:LE:64:default");

		try (ToyDBTraceBuilder tb2 =
			new ToyDBTraceBuilder("dynamic2-" + name.getMethodName(), "dsPIC33F:LE:24:default")) {

			TraceThread thread1;
			try (Transaction tx = tb.startTransaction()) {
				tb.trace.getTimeManager().createSnapshot("First");
				tb.trace.getMemoryManager()
						.createRegion(".text", 0, tb.range(0x00400000, 0x0040ffff),
							TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
				thread1 = tb.getOrAddThread("Thread1", 0);
				tb.exec(0, thread1, 0, "RIP = 0x00400000;");
			}

			TraceThread thread2;
			try (Transaction tx = tb2.startTransaction()) {
				tb2.trace.getTimeManager().createSnapshot("First");
				tb2.trace.getMemoryManager()
						.createRegion(".text", 0, tb2.range(0x200, 0x3ff), TraceMemoryFlag.READ,
							TraceMemoryFlag.EXECUTE);
				thread2 = tb2.getOrAddThread("Thread2", 0);
				tb2.exec(0, thread2, 0, "PC = 0x100;");
			}

			traceManager.openTrace(tb.trace);
			traceManager.openTrace(tb2.trace);

			traceManager.activateThread(thread1);
			waitForSwing();

			traceManager.activateThread(thread2);
			waitForSwing();

			assertFalse(listingProvider.locationLabel.getText().startsWith("(error)"));
		}
	}

	@Test
	public void testActivateThreadTracks() throws Exception {
		assertEquals(PCLocationTrackingSpec.INSTANCE,
			listingProvider.actionTrackLocation.getCurrentUserData());

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

		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		traceManager.activateThread(thread2);
		waitForSwing();

		assertEquals(tb.addr(0x00404321), listingProvider.getLocation().getAddress());
	}

	@Test
	public void testActivateSnapTracks() throws Exception {
		assertEquals(PCLocationTrackingSpec.INSTANCE,
			listingProvider.actionTrackLocation.getCurrentUserData());

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

		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		traceManager.activateSnap(1);
		waitForSwing();

		assertEquals(tb.addr(0x00404321), listingProvider.getLocation().getAddress());
	}

	@Test
	public void testActivateFrameTracks() throws Exception {
		assertEquals(PCLocationTrackingSpec.INSTANCE,
			listingProvider.actionTrackLocation.getCurrentUserData());

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

		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		traceManager.activateFrame(1);
		waitForSwing();

		assertEquals(tb.addr(0x00404321), listingProvider.getLocation().getAddress());
	}

	@Test
	public void testRegsPCChangedTracks() throws Exception {
		assertEquals(PCLocationTrackingSpec.INSTANCE,
			listingProvider.actionTrackLocation.getCurrentUserData());

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

		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		try (Transaction tx = tb.startTransaction()) {
			TraceMemorySpace regs = mm.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00404321", 16)));
		}
		waitForDomainObject(tb.trace);

		assertEquals(tb.addr(0x00404321), listingProvider.getLocation().getAddress());
	}

	@Test
	public void testRegsPCChangedTracksDespiteStackWithNoPC() throws Exception {
		assertEquals(PCLocationTrackingSpec.INSTANCE,
			listingProvider.actionTrackLocation.getCurrentUserData());

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

		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		try (Transaction tx = tb.startTransaction()) {
			TraceMemorySpace regs = mm.getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00404321", 16)));
		}
		waitForDomainObject(tb.trace);

		assertEquals(tb.addr(0x00404321), listingProvider.getLocation().getAddress());
	}

	@Test
	public void testStackPCChangedTracks() throws Exception {
		assertEquals(PCLocationTrackingSpec.INSTANCE,
			listingProvider.actionTrackLocation.getCurrentUserData());

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

		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		try (Transaction tx = tb.startTransaction()) {
			TraceStack stack = sm.getStack(thread, 0, true);
			stack.getFrame(0, true).setProgramCounter(Lifespan.ALL, tb.addr(0x00404321));
		}
		waitForDomainObject(tb.trace);

		assertEquals(tb.addr(0x00404321), listingProvider.getLocation().getAddress());
	}

	@Test
	public void testSyncCursorToStaticListingOpensModule() throws Exception {
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();
		try (Transaction tx = program.openTransaction("Add block")) {
			program.getMemory()
					.createInitializedBlock(".text", ss.getAddress(0x00600000), 0x10000, (byte) 0,
						monitor, false);
		}
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("exe:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceLocation from =
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x00400000));
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
	public void testSyncCursorToStaticLogsRecoverableProgram() throws Exception {
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
	public void testSyncCursorToStaticLogsUpgradeableProgram() throws Exception {
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

	protected Instruction placeGuestInstruction(int guestRangeLength) throws Throwable {
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("Memory[.text]", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			TraceGuestPlatform toy = tb.trace.getPlatformManager()
					.addGuestPlatform(getToyBE64Language().getDefaultCompilerSpec());
			Address hostEntry = tb.addr(0x00400000);
			Address guestEntry = tb.addr(toy, 0x00000000);
			toy.addMappedRange(hostEntry, guestEntry, guestRangeLength);

			Assembler asm = Assemblers.getAssembler(toy.getLanguage());
			AssemblyBuffer buf = new AssemblyBuffer(asm, guestEntry);
			buf.assemble("call 0x123");
			Instruction callInstr =
				tb.addInstruction(0, hostEntry, toy, ByteBuffer.wrap(buf.getBytes()));

			return callInstr;
		}
	}

	@Test
	public void testGuestInstructionNavigation() throws Throwable {
		createAndOpenTrace("DATA:BE:64:default");

		Instruction callInstr = placeGuestInstruction(0x1000);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals("call 0x00400123", callInstr.toString());

		listingPlugin.goTo(new OperandFieldLocation(tb.trace.getProgramView(), tb.addr(0x00400000),
			null, null, null, 0, 0));
		waitForPass(() -> assertEquals(tb.addr(0x00400000), listingPlugin.getCurrentAddress()));

		click(listingPlugin, 2);
		waitForPass(() -> assertEquals(tb.addr(0x00400123), listingPlugin.getCurrentAddress()));
	}

	@Test
	public void testGuestInstructionNavigationUnmapped() throws Throwable {
		createAndOpenTrace("DATA:BE:64:default");

		Instruction callInstr = placeGuestInstruction(0x100);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals("call guest:ram:00000123", callInstr.toString());

		listingPlugin.goTo(new OperandFieldLocation(tb.trace.getProgramView(), tb.addr(0x00400000),
			null, null, null, 0, 0));
		waitForPass(() -> assertEquals(tb.addr(0x00400000), listingPlugin.getCurrentAddress()));

		click(listingPlugin, 2); // It should not move, nor crash
		waitForPass(() -> assertEquals(tb.addr(0x00400000), listingPlugin.getCurrentAddress()));
	}

	private void triggerPopup(Point cursorPoint, Component eventSource) {
		moveMouse(eventSource, cursorPoint.x, cursorPoint.y);
		clickMouse(eventSource, MouseEvent.BUTTON1, cursorPoint.x, cursorPoint.y, 1, 0);
		moveMouse(eventSource, cursorPoint.x + 5, cursorPoint.y);
	}

	@Test
	public void testGuestInstructionHover() throws Throwable {
		ReferenceListingHoverPlugin hoverPlugin =
			addPlugin(tool, ReferenceListingHoverPlugin.class);
		ListingPanel listingPanel = listingProvider.getListingPanel();
		FieldPanel fieldPanel = listingPanel.getFieldPanel();

		createAndOpenTrace("DATA:BE:64:default");

		Instruction callInstr = placeGuestInstruction(0x1000);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals("call 0x00400123", callInstr.toString());

		listingPlugin.goTo(new OperandFieldLocation(tb.trace.getProgramView(), tb.addr(0x00400000),
			null, null, null, 0, 0));
		waitForPass(() -> assertEquals(tb.addr(0x00400000), listingPlugin.getCurrentAddress()));
		Point p = fieldPanel.getCursorPoint();
		triggerPopup(p, fieldPanel);
		waitForPass(() -> assertTrue(listingPanel.isHoverShowing()));

		ListingPanel popupPanel = hoverPlugin.getReferenceHoverService().getPanel();
		assertEquals(tb.addr(0x00400123), popupPanel.getProgramLocation().getAddress());
	}

	@Test
	public void testGuestInstructionHoverUnmapped() throws Throwable {
		addPlugin(tool, ReferenceListingHoverPlugin.class);
		ListingPanel listingPanel = listingProvider.getListingPanel();
		FieldPanel fieldPanel = listingPanel.getFieldPanel();

		createAndOpenTrace("DATA:BE:64:default");

		Instruction callInstr = placeGuestInstruction(0x100);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals("call guest:ram:00000123", callInstr.toString());

		listingPlugin.goTo(new OperandFieldLocation(tb.trace.getProgramView(), tb.addr(0x00400000),
			null, null, null, 0, 0));
		waitForPass(() -> assertEquals(tb.addr(0x00400000), listingPlugin.getCurrentAddress()));
		Point p = fieldPanel.getCursorPoint();
		triggerPopup(p, fieldPanel);
		listingPlugin.updateNow();
		waitForSwing();
		assertFalse(listingPanel.isHoverShowing());
	}
}
