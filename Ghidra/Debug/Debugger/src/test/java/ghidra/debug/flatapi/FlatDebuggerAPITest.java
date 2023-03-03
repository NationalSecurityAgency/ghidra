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
package ghidra.debug.flatapi;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import generic.Unique;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.service.breakpoint.DebuggerLogicalBreakpointServicePlugin;
import ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin;
import ghidra.app.plugin.core.debug.service.model.TestDebuggerProgramLaunchOpinion.TestDebuggerProgramLaunchOffer;
import ghidra.app.plugin.core.debug.service.model.launch.AbstractDebuggerProgramLaunchOffer;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer.LaunchResult;
import ghidra.app.script.GhidraState;
import ghidra.app.services.*;
import ghidra.app.services.LogicalBreakpoint.State;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.model.*;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.TraceSchedule;

public class FlatDebuggerAPITest extends AbstractGhidraHeadedDebuggerGUITest {

	protected static class TestFactory implements DebuggerModelFactory {
		private final DebuggerObjectModel model;

		public TestFactory(DebuggerObjectModel model) {
			this.model = model;
		}

		@Override
		public CompletableFuture<? extends DebuggerObjectModel> build() {
			return CompletableFuture.completedFuture(model);
		}
	}

	protected class TestOffer extends AbstractDebuggerProgramLaunchOffer {
		public TestOffer(Program program, DebuggerModelFactory factory) {
			super(program, env.getTool(), factory);
		}

		public TestOffer(Program program, DebuggerObjectModel model) {
			this(program, new TestFactory(model));
		}

		@Override
		public String getConfigName() {
			return "TEST";
		}

		@Override
		public String getMenuTitle() {
			return "in Test Debugger";
		}
	}

	protected static class TestModelBuilder extends TestDebuggerModelBuilder {
		private final TestDebuggerObjectModel model;

		public TestModelBuilder(TestDebuggerObjectModel model) {
			this.model = model;
		}

		@Override
		protected TestDebuggerObjectModel newModel(String typeHint) {
			return model;
		}
	}

	protected class TestFlatAPI implements FlatDebuggerAPI {
		protected final GhidraState state =
			new GhidraState(env.getTool(), env.getProject(), program, null, null, null);

		@Override
		public GhidraState getState() {
			return state;
		}
	}

	protected DebuggerLogicalBreakpointService breakpointService;
	protected DebuggerStaticMappingService mappingService;
	protected DebuggerEmulationService emulationService;
	protected DebuggerListingService listingService;
	protected DebuggerControlService editingService;
	protected FlatDebuggerAPI flat;

	@Before
	public void setUpFlatAPITest() throws Throwable {
		breakpointService = addPlugin(tool, DebuggerLogicalBreakpointServicePlugin.class);
		mappingService = tool.getService(DebuggerStaticMappingService.class);
		emulationService = addPlugin(tool, DebuggerEmulationServicePlugin.class);
		listingService = addPlugin(tool, DebuggerListingPlugin.class);
		editingService = addPlugin(tool, DebuggerControlServicePlugin.class);
		flat = new TestFlatAPI();
	}

	@Test
	public void testRequireService() throws Throwable {
		assertEquals(modelService, flat.requireService(DebuggerModelService.class));
	}

	interface NoSuchService {
	}

	@Test(expected = IllegalStateException.class)
	public void testRequireServiceAbsentErr() {
		flat.requireService(NoSuchService.class);
	}

	@Test
	public void testGetCurrentDebuggerCoordinates() throws Throwable {
		assertSame(DebuggerCoordinates.NOWHERE, flat.getCurrentDebuggerCoordinates());

		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		assertEquals(DebuggerCoordinates.NOWHERE.trace(tb.trace),
			flat.getCurrentDebuggerCoordinates());
	}

	@Test
	public void testGetCurrentTrace() throws Throwable {
		assertNull(flat.getCurrentTrace());

		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		assertEquals(tb.trace, flat.getCurrentTrace());
	}

	@Test(expected = IllegalStateException.class)
	public void testRequireCurrentTraceAbsentErr() {
		flat.requireCurrentTrace();
	}

	@Test
	public void testGetCurrentThread() throws Throwable {
		assertNull(flat.getCurrentThread());

		createAndOpenTrace();
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			thread = tb.getOrAddThread("Threads[0]", 0);
		}
		waitForSwing();
		traceManager.activateTrace(tb.trace);

		assertEquals(thread, flat.getCurrentThread());
	}

	@Test
	public void testGetCurrentView() throws Throwable {
		assertNull(flat.getCurrentView());

		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		assertEquals(tb.trace.getProgramView(), flat.getCurrentView());
	}

	@Test(expected = IllegalStateException.class)
	public void testRequireCurrentViewAbsentErr() {
		flat.requireCurrentView();
	}

	@Test
	public void testGetCurrentFrame() throws Throwable {
		assertEquals(0, flat.getCurrentFrame());

		createAndOpenTrace();
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			thread = tb.getOrAddThread("Threads[0]", 0);
			TraceStack stack = tb.trace.getStackManager().getStack(thread, 0, true);
			stack.setDepth(3, true);
		}
		waitForSwing();
		traceManager.activateThread(thread);
		traceManager.activateFrame(1);

		assertEquals(1, flat.getCurrentFrame());
	}

	@Test
	public void testGetCurrentSnap() throws Throwable {
		assertEquals(0L, flat.getCurrentSnap());

		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		traceManager.activateSnap(1);

		assertEquals(1L, flat.getCurrentSnap());
	}

	@Test
	public void testGetCurrentEmulationSchedule() throws Throwable {
		assertEquals(TraceSchedule.parse("0"), flat.getCurrentEmulationSchedule());

		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		traceManager.activateSnap(1);

		assertEquals(TraceSchedule.parse("1"), flat.getCurrentEmulationSchedule());
	}

	@Test
	public void testActivateTrace() throws Throwable {
		createAndOpenTrace();
		flat.activateTrace(tb.trace);

		assertEquals(tb.trace, traceManager.getCurrentTrace());
	}

	@Test
	public void testActivateTraceNull() throws Throwable {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		assertEquals(tb.trace, traceManager.getCurrentTrace());

		flat.activateTrace(null);
		assertEquals(null, traceManager.getCurrentTrace());
	}

	@Test
	public void testActivateTraceNotOpen() throws Throwable {
		createTrace();
		assertFalse(traceManager.getOpenTraces().contains(tb.trace));

		flat.activateTrace(tb.trace);

		assertTrue(traceManager.getOpenTraces().contains(tb.trace));
		assertEquals(tb.trace, traceManager.getCurrentTrace());
	}

	protected TraceThread createTraceWithThreadAndStack(boolean open) throws Throwable {
		if (open) {
			createAndOpenTrace();
		}
		else {
			createTrace();
		}
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			thread = tb.getOrAddThread("Threads[0]", 0);
			TraceStack stack = tb.trace.getStackManager().getStack(thread, 0, true);
			stack.setDepth(3, true);
		}
		waitForSwing();
		return thread;
	}

	@Test
	public void testActivateThread() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		flat.activateThread(thread);

		assertEquals(thread, traceManager.getCurrentThread());
	}

	@Test
	public void testActivateThreadNull() throws Throwable {
		flat.activateThread(null);
		assertEquals(null, traceManager.getCurrentThread());

		TraceThread thread = createTraceWithThreadAndStack(true);
		traceManager.activateThread(thread);
		waitForSwing();
		assertEquals(thread, traceManager.getCurrentThread());

		flat.activateThread(null);
		assertNull(traceManager.getCurrentThread());
	}

	@Test
	public void testActivateThreadNotOpen() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(false);
		assertFalse(traceManager.getOpenTraces().contains(tb.trace));

		flat.activateThread(thread);

		assertTrue(traceManager.getOpenTraces().contains(tb.trace));
		assertEquals(thread, traceManager.getCurrentThread());
	}

	@Test
	public void testActivateFrame() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		traceManager.activateThread(thread);
		waitForSwing();
		flat.activateFrame(1);

		assertEquals(1, traceManager.getCurrentFrame());
	}

	@Test
	public void testActivateSnap() throws Throwable {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		flat.activateSnap(1);

		assertEquals(1L, traceManager.getCurrentSnap());
	}

	protected void createTraceWithBinText() throws Throwable {
		createAndOpenTrace();

		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.createRegion("Memory[bin.text]", 0, tb.range(0x00400000, 0x0040ffff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));

			mm.putBytes(0, tb.addr(0x00400000), tb.buf(1, 2, 3, 4, 5, 6, 7, 8));
		}
		traceManager.activateTrace(tb.trace);
		waitForSwing();
	}

	@Test
	public void testGetCurrentDebuggerAddress() throws Throwable {
		assertEquals(null, flat.getCurrentDebuggerAddress());

		createTraceWithBinText();

		assertEquals(tb.addr(0x00400000), flat.getCurrentDebuggerAddress());
	}

	@Test
	public void testGoToDynamic() throws Throwable {
		createTraceWithBinText();

		assertTrue(flat.goToDynamic("00400123"));
		assertEquals(tb.addr(0x00400123), listingService.getCurrentLocation().getAddress());

		assertTrue(flat.goToDynamic(tb.addr(0x00400321)));
		assertEquals(tb.addr(0x00400321), listingService.getCurrentLocation().getAddress());
	}

	@Override
	protected void createProgram(Language lang, CompilerSpec cSpec) throws IOException {
		super.createProgram(lang, cSpec);
		flat.getState().setCurrentProgram(program);
	}

	protected void createMappedTraceAndProgram() throws Throwable {
		createAndOpenTrace();
		createProgramFromTrace();

		intoProject(program);
		intoProject(tb.trace);

		programManager.openProgram(program);
		traceManager.activateTrace(tb.trace);

		try (Transaction tx = program.openTransaction("add block")) {
			program.getMemory()
					.createInitializedBlock(".text", addr(program, 0x00400000), 4096, (byte) 0,
						monitor, false);
		}

		CompletableFuture<Void> changesSettled;
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.createRegion("Memory[bin.text]", 0, tb.range(0x00400000, 0x00400fff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			changesSettled = mappingService.changesSettled();
			mappingService.addIdentityMapping(tb.trace, program, Lifespan.nowOn(0), true);
		}
		waitForSwing();
		waitOn(changesSettled);
	}

	@Test
	public void testGetCurrentProgram() throws Throwable {
		assertEquals(null, flat.getCurrentProgram());

		createProgram();
		programManager.openProgram(program);

		assertEquals(program, flat.getCurrentProgram());
	}

	@Test(expected = IllegalStateException.class)
	public void testRequireCurrentProgramAbsentErr() throws Throwable {
		flat.requireCurrentProgram();
	}

	@Test
	public void testTranslateStaticToDynamic() throws Throwable {
		createMappedTraceAndProgram();

		assertEquals(flat.dynamicLocation("00400123"),
			flat.translateStaticToDynamic(flat.staticLocation("00400123")));
		assertNull(flat.translateStaticToDynamic(flat.staticLocation("00600123")));

		assertEquals(tb.addr(0x00400123), flat.translateStaticToDynamic(addr(program, 0x00400123)));
		assertNull(flat.translateStaticToDynamic(addr(program, 0x00600123)));
	}

	@Test
	public void testTranslateDynamicToStatic() throws Throwable {
		createMappedTraceAndProgram();

		assertEquals(flat.staticLocation("00400123"),
			flat.translateDynamicToStatic(flat.dynamicLocation("00400123")));
		assertNull(flat.translateDynamicToStatic(flat.dynamicLocation("00600123")));

		assertEquals(addr(program, 0x00400123), flat.translateDynamicToStatic(tb.addr(0x00400123)));
		assertNull(flat.translateDynamicToStatic(tb.addr(0x00600123)));
	}

	protected Address createEmulatableProgram() throws Throwable {
		createProgram();
		programManager.openProgram(program);

		Address entry = addr(program, 0x00400000);
		try (Transaction start = program.openTransaction("init")) {
			program.getMemory()
					.createInitializedBlock(".text", entry, 4096, (byte) 0,
						monitor, false);
			Assembler asm = Assemblers.getAssembler(program);
			asm.assemble(entry, "imm r0,#123");
		}

		// Emulate launch will create a static mapping
		intoProject(program);

		return entry;
	}

	@Test
	public void testEmulateLaunch() throws Throwable {
		Address entry = createEmulatableProgram();

		Trace trace = flat.emulateLaunch(entry);
		assertEquals(trace, traceManager.getCurrentTrace());
	}

	@Test
	public void testEmulate() throws Throwable {
		Address entry = createEmulatableProgram();

		flat.emulateLaunch(entry);
		flat.emulate(TraceSchedule.parse("0:t0-1"), monitor);

		assertEquals(TraceSchedule.parse("0:t0-1"), traceManager.getCurrent().getTime());
	}

	@Test
	public void testStepEmuInstruction() throws Throwable {
		Address entry = createEmulatableProgram();

		flat.emulateLaunch(entry);

		flat.stepEmuInstruction(1, monitor);
		assertEquals(TraceSchedule.parse("0:t0-1"), traceManager.getCurrent().getTime());

		flat.stepEmuInstruction(-1, monitor);
		assertEquals(TraceSchedule.parse("0"), traceManager.getCurrent().getTime());
	}

	@Test
	public void testStepEmuPcodeOp() throws Throwable {
		Address entry = createEmulatableProgram();

		flat.emulateLaunch(entry);

		flat.stepEmuPcodeOp(1, monitor);
		assertEquals(TraceSchedule.parse("0:.t0-1"), traceManager.getCurrent().getTime());

		flat.stepEmuPcodeOp(-1, monitor);
		assertEquals(TraceSchedule.parse("0"), traceManager.getCurrent().getTime());
	}

	@Test
	public void testSkipEmuInstruction() throws Throwable {
		Address entry = createEmulatableProgram();

		flat.emulateLaunch(entry);

		flat.skipEmuInstruction(1, monitor);
		assertEquals(TraceSchedule.parse("0:t0-s1"), traceManager.getCurrent().getTime());

		flat.skipEmuInstruction(-1, monitor);
		assertEquals(TraceSchedule.parse("0"), traceManager.getCurrent().getTime());
	}

	@Test
	public void testSkipEmuPcodeOp() throws Throwable {
		Address entry = createEmulatableProgram();

		flat.emulateLaunch(entry);

		flat.skipEmuPcodeOp(1, monitor);
		assertEquals(TraceSchedule.parse("0:.t0-s1"), traceManager.getCurrent().getTime());

		flat.skipEmuPcodeOp(-1, monitor);
		assertEquals(TraceSchedule.parse("0"), traceManager.getCurrent().getTime());
	}

	@Test
	public void testPatchEmu() throws Throwable {
		Address entry = createEmulatableProgram();

		flat.emulateLaunch(entry);

		flat.patchEmu("r0=0x321", monitor);
		assertEquals(TraceSchedule.parse("0:t0-{r0=0x321}"), traceManager.getCurrent().getTime());

		flat.stepEmuInstruction(-1, monitor);
		assertEquals(TraceSchedule.parse("0"), traceManager.getCurrent().getTime());
	}

	@Test
	public void testReadMemoryBuffer() throws Throwable {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		byte[] data = new byte[1024];
		assertEquals(1024, flat.readMemory(tb.addr(0x00400000), data, monitor));
		assertArrayEquals(new byte[1024], data);
	}

	@Test
	public void testReadMemoryLength() throws Throwable {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		byte[] data = flat.readMemory(tb.addr(0x00400000), 1024, monitor);
		assertArrayEquals(new byte[1024], data);
	}

	@Test
	public void testReadLiveMemory() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		mb.testProcess1.memory.writeMemory(mb.addr(0x00400000), mb.arr(1, 2, 3, 4, 5, 6, 7, 8));
		waitOn(mb.testModel.flushEvents());
		TraceRecorder recorder = record(mb.testProcess1);
		waitRecorder(recorder);
		useTrace(recorder.getTrace());
		waitForSwing();

		byte[] data = flat.readMemory(tb.addr(0x00400000), 8, monitor);
		assertArrayEquals(tb.arr(1, 2, 3, 4, 5, 6, 7, 8), data);
	}

	@Test
	public void testSearchMemory() throws Throwable {
		createTraceWithBinText();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(tb.addr(0x00400003), flat.searchMemory(tb.trace, 2, tb.range(0L, -1L),
			tb.arr(4, 5, 6, 7), null, true, monitor));
		assertEquals(tb.addr(0x00400003), flat.searchMemory(tb.trace, 2, tb.range(0L, -1L),
			tb.arr(4, 5, 6, 7), tb.arr(-1, -1, -1, -1), true, monitor));
	}

	@Test
	public void testReadRegister() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		traceManager.activateThread(thread);

		Register r0 = tb.language.getRegister("r0");
		assertEquals(new RegisterValue(r0), flat.readRegister("r0"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testReadRegisterInvalidNameErr() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		traceManager.activateThread(thread);

		flat.readRegister("THERE_IS_NO_SUCH_REGISTER");
	}

	@Test
	public void testReadRegisters() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		traceManager.activateThread(thread);
		waitForSwing();

		Register r0 = tb.language.getRegister("r0");
		Register r1 = tb.language.getRegister("r1");
		assertEquals(List.of(
			new RegisterValue(r0),
			new RegisterValue(r1)),
			flat.readRegistersNamed(List.of("r0", "r1")));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testReadRegistersInvalidNameErr() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		traceManager.activateThread(thread);

		flat.readRegistersNamed(Set.of("THERE_IS_NO_SUCH_REGISTER"));
	}

	@Test
	public void testReadLiveRegister() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		mb.createTestThreadRegisterBanks();
		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(), r -> true);
		mb.testBank1.writeRegister("r0", mb.arr(1, 2, 3, 4, 5, 6, 7, 8));
		waitOn(mb.testModel.flushEvents());
		TraceRecorder recorder = record(mb.testProcess1);
		waitRecorder(recorder);
		useTrace(recorder.getTrace());
		traceManager.activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();

		RegisterValue rv = flat.readRegister("r0");
		assertEquals(BigInteger.valueOf(0x0102030405060708L), rv.getUnsignedValue());
	}

	@Test
	public void testReadLiveRegisters() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		mb.createTestThreadRegisterBanks();
		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(), r -> true);
		mb.testBank1.writeRegister("r0", mb.arr(1, 2, 3, 4, 5, 6, 7, 8));
		mb.testBank1.writeRegister("r1", mb.arr(8, 7, 6, 5, 4, 3, 2, 1));
		waitOn(mb.testModel.flushEvents());
		TraceRecorder recorder = record(mb.testProcess1);
		waitRecorder(recorder);
		useTrace(recorder.getTrace());
		traceManager.activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();

		Register r0 = tb.language.getRegister("r0");
		Register r1 = tb.language.getRegister("r1");
		assertEquals(List.of(
			new RegisterValue(r0, BigInteger.valueOf(0x0102030405060708L)),
			new RegisterValue(r1, BigInteger.valueOf(0x0807060504030201L))),
			flat.readRegistersNamed(List.of("r0", "r1")));
	}

	@Test
	public void testWriteMemoryGivenContext() throws Throwable {
		createTraceWithBinText();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		assertTrue(flat.writeMemory(tb.trace, 0, tb.addr(0x00400123), tb.arr(3, 2, 1)));
		ByteBuffer buf = ByteBuffer.allocate(3);
		assertEquals(3, tb.trace.getMemoryManager().getBytes(0, tb.addr(0x00400123), buf));
		assertArrayEquals(tb.arr(3, 2, 1), buf.array());
	}

	@Test
	public void testWriteMemoryCurrentContext() throws Throwable {
		createTraceWithBinText();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		assertTrue(flat.writeMemory(tb.addr(0x00400123), tb.arr(3, 2, 1)));
		ByteBuffer buf = ByteBuffer.allocate(3);
		assertEquals(3, tb.trace.getMemoryManager().getBytes(0, tb.addr(0x00400123), buf));
		assertArrayEquals(tb.arr(3, 2, 1), buf.array());
	}

	@Test
	public void testWriteRegisterGivenContext() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
		traceManager.activateThread(thread);
		waitForSwing();

		assertTrue(flat.writeRegister(thread, 0, 0, "r0", BigInteger.valueOf(0x0102030405060708L)));
		DBTraceMemorySpace regs =
			tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
		assertNotNull(regs);
		Register r0 = tb.language.getRegister("r0");
		assertEquals(new RegisterValue(r0, BigInteger.valueOf(0x0102030405060708L)),
			regs.getValue(0, r0));
	}

	@Test
	public void testWriteRegisterCurrentContext() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
		traceManager.activateThread(thread);
		waitForSwing();

		assertTrue(flat.writeRegister("r0", BigInteger.valueOf(0x0102030405060708L)));
		DBTraceMemorySpace regs =
			tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
		assertNotNull(regs);
		Register r0 = tb.language.getRegister("r0");
		assertEquals(new RegisterValue(r0, BigInteger.valueOf(0x0102030405060708L)),
			regs.getValue(0, r0));
	}

	@Test
	public void testGetLaunchOffers() throws Throwable {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		DebuggerProgramLaunchOffer offer = Unique.assertOne(flat.getLaunchOffers());
		assertEquals(TestDebuggerProgramLaunchOffer.class, offer.getClass());
	}

	@Test
	public void testLaunchCustomCommandLine() throws Throwable {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		var model = new TestDebuggerObjectModel() {
			Map<String, ?> observedParams;

			@Override
			protected TestTargetSession newTestTargetSession(String rootHint) {
				return new TestTargetSession(this, "Session", ROOT_SCHEMA) {
					@Override
					public CompletableFuture<Void> launch(Map<String, ?> params) {
						observedParams = params;
						throw new CancellationException();
					}
				};
			}
		};
		DebuggerProgramLaunchOffer offer = new TestOffer(program, model);

		LaunchResult result = flat.launch(offer, "custom command line", monitor);

		assertEquals("custom command line",
			model.observedParams.get(TargetCmdLineLauncher.CMDLINE_ARGS_NAME));
		assertNotNull(result.model());
		assertNull(result.target());
		assertEquals(CancellationException.class, result.exception().getClass());
	}

	protected TraceRecorder record(TargetObject target)
			throws LanguageNotFoundException, CompilerSpecNotFoundException, IOException {
		return modelService.recordTargetAndActivateTrace(target,
			new TestDebuggerTargetTraceMapper(target));
	}

	@Test
	public void testGetTarget() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = record(mb.testProcess1);

		assertEquals(mb.testProcess1, flat.getTarget(recorder.getTrace()));
	}

	@Test
	public void testGetTargetThread() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = record(mb.testProcess1);
		waitRecorder(recorder);

		Trace trace = recorder.getTrace();
		TraceThread thread =
			trace.getThreadManager()
					.getLiveThreadByPath(recorder.getSnap(), "Processes[1].Threads[1]");
		assertNotNull(thread);
		assertEquals(mb.testThread1, flat.getTargetThread(thread));
	}

	@Test
	public void testGetTargetFocus() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = record(mb.testProcess1);
		waitRecorder(recorder);

		waitOn(mb.testModel.requestFocus(mb.testThread2));
		waitRecorder(recorder);

		assertEquals(mb.testThread2, flat.getTargetFocus(recorder.getTrace()));
	}

	protected void runTestStep(Function<FlatDebuggerAPI, Boolean> step, TargetStepKind kind)
			throws Throwable {
		var model = new TestDebuggerObjectModel() {
			TestTargetThread observedThread;
			TargetStepKind observedKind;

			@Override
			protected TestTargetThread newTestTargetThread(TestTargetThreadContainer container,
					int tid) {
				return new TestTargetThread(container, tid) {
					@Override
					public CompletableFuture<Void> step(TargetStepKind kind) {
						observedThread = this;
						observedKind = kind;
						return super.step(kind);
					}
				};
			}
		};
		mb = new TestModelBuilder(model);
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = record(mb.testProcess1);
		waitRecorder(recorder);
		assertTrue(waitOn(recorder.requestFocus(mb.testThread2)));
		waitRecorder(recorder);

		assertTrue(step.apply(flat));
		waitRecorder(recorder);
		assertEquals(mb.testThread2, model.observedThread);
		assertEquals(kind, model.observedKind);
	}

	@Test
	public void testStepGivenThread() throws Throwable {
		runTestStep(flat -> flat.step(flat.getCurrentThread(), TargetStepKind.INTO),
			TargetStepKind.INTO);
	}

	@Test
	public void testStepInto() throws Throwable {
		runTestStep(FlatDebuggerAPI::stepInto, TargetStepKind.INTO);
	}

	@Test
	public void testStepOver() throws Throwable {
		runTestStep(FlatDebuggerAPI::stepOver, TargetStepKind.OVER);
	}

	@Test
	public void testStepOut() throws Throwable {
		runTestStep(FlatDebuggerAPI::stepOut, TargetStepKind.FINISH);
	}

	protected void runTestResume(Function<FlatDebuggerAPI, Boolean> resume) throws Throwable {
		var model = new TestDebuggerObjectModel() {
			TestTargetThread observedThread;

			@Override
			protected TestTargetThread newTestTargetThread(TestTargetThreadContainer container,
					int tid) {
				return new TestTargetThread(container, tid) {
					@Override
					public CompletableFuture<Void> resume() {
						observedThread = this;
						return super.resume();
					}
				};
			}
		};
		mb = new TestModelBuilder(model);
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = record(mb.testProcess1);
		waitRecorder(recorder);
		assertTrue(waitOn(recorder.requestFocus(mb.testThread2)));
		waitRecorder(recorder);

		assertTrue(resume.apply(flat));
		waitRecorder(recorder);
		assertEquals(mb.testThread2, model.observedThread);
	}

	@Test
	public void testResumeGivenThread() throws Throwable {
		runTestResume(flat -> flat.resume(flat.getCurrentThread()));
	}

	@Test
	public void testResumeGivenTrace() throws Throwable {
		runTestResume(flat -> flat.resume(flat.getCurrentTrace()));
	}

	@Test
	public void testResume() throws Throwable {
		runTestResume(FlatDebuggerAPI::resume);
	}

	protected void runTestInterrupt(Function<FlatDebuggerAPI, Boolean> interrupt) throws Throwable {
		var model = new TestDebuggerObjectModel() {
			TestTargetThread observedThread;

			@Override
			protected TestTargetThread newTestTargetThread(TestTargetThreadContainer container,
					int tid) {
				return new TestTargetThread(container, tid) {
					@Override
					public CompletableFuture<Void> interrupt() {
						observedThread = this;
						return super.interrupt();
					}
				};
			}
		};
		mb = new TestModelBuilder(model);
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = record(mb.testProcess1);
		waitRecorder(recorder);
		assertTrue(waitOn(recorder.requestFocus(mb.testThread2)));
		waitRecorder(recorder);

		assertTrue(interrupt.apply(flat));
		waitRecorder(recorder);
		assertEquals(mb.testThread2, model.observedThread);
	}

	@Test
	public void testInterruptGivenThread() throws Throwable {
		runTestInterrupt(flat -> flat.interrupt(flat.getCurrentThread()));
	}

	@Test
	public void testInterruptGivenTrace() throws Throwable {
		runTestInterrupt(flat -> flat.interrupt(flat.getCurrentTrace()));
	}

	@Test
	public void testInterrupt() throws Throwable {
		runTestInterrupt(FlatDebuggerAPI::interrupt);
	}

	protected void runTestKill(Function<FlatDebuggerAPI, Boolean> kill) throws Throwable {
		var model = new TestDebuggerObjectModel() {
			TestTargetThread observedThread;

			@Override
			protected TestTargetThread newTestTargetThread(TestTargetThreadContainer container,
					int tid) {
				return new TestTargetThread(container, tid) {
					@Override
					public CompletableFuture<Void> kill() {
						observedThread = this;
						return super.kill();
					}
				};
			}
		};
		mb = new TestModelBuilder(model);
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = record(mb.testProcess1);
		waitRecorder(recorder);
		assertTrue(waitOn(recorder.requestFocus(mb.testThread2)));
		waitRecorder(recorder);

		assertTrue(kill.apply(flat));
		waitRecorder(recorder);
		assertEquals(mb.testThread2, model.observedThread);
	}

	@Test
	public void testKillGivenThread() throws Throwable {
		runTestKill(flat -> flat.kill(flat.getCurrentThread()));
	}

	@Test
	public void testKillGivenTrace() throws Throwable {
		runTestKill(flat -> flat.kill(flat.getCurrentTrace()));
	}

	@Test
	public void testKill() throws Throwable {
		runTestKill(FlatDebuggerAPI::kill);
	}

	protected void runTestExecuteCapture(BiFunction<FlatDebuggerAPI, String, String> executeCapture)
			throws Throwable {
		// NOTE: Can't use TestTargetInterpreter.queueExecute stuff, since flat API waits
		var model = new TestDebuggerObjectModel() {
			@Override
			protected TestTargetInterpreter newTestTargetInterpreter(TestTargetSession session) {
				return new TestTargetInterpreter(session) {
					@Override
					public CompletableFuture<String> executeCapture(String cmd) {
						return CompletableFuture.completedFuture("Response to " + cmd);
					}
				};
			}
		};
		mb = new TestModelBuilder(model);
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = record(mb.testProcess1);
		waitRecorder(recorder);
		assertTrue(waitOn(recorder.requestFocus(mb.testThread2)));
		waitRecorder(recorder);

		assertEquals("Response to cmd", executeCapture.apply(flat, "cmd"));
	}

	@Test
	public void testExecuteCaptureGivenTrace() throws Throwable {
		runTestExecuteCapture((flat, cmd) -> flat.executeCapture(flat.getCurrentTrace(), cmd));
	}

	@Test
	public void testExecuteCapture() throws Throwable {
		runTestExecuteCapture(FlatDebuggerAPI::executeCapture);
	}

	protected void createProgramWithText() throws Throwable {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		try (Transaction tx = program.openTransaction("Add block")) {
			program.getMemory()
					.createInitializedBlock(
						".text", addr(program, 0x00400000), 1024, (byte) 0, monitor, false);
		}
	}

	protected void createProgramWithBreakpoint() throws Throwable {
		createProgramWithText();

		CompletableFuture<Void> changesSettled = breakpointService.changesSettled();
		waitOn(breakpointService.placeBreakpointAt(program, addr(program, 0x00400000), 1,
			Set.of(TraceBreakpointKind.SW_EXECUTE), "name"));
		waitForSwing();
		waitOn(changesSettled);
	}

	@Test
	public void testGetAllBreakpoints() throws Throwable {
		createProgramWithBreakpoint();

		assertEquals(1, flat.getAllBreakpoints().size());
	}

	@Test
	public void testGetBreakpointsAt() throws Throwable {
		createProgramWithBreakpoint();

		assertEquals(1, flat.getBreakpointsAt(flat.staticLocation("00400000")).size());
		assertEquals(0, flat.getBreakpointsAt(flat.staticLocation("00400001")).size());
	}

	@Test
	public void testGetBreakpointsNamed() throws Throwable {
		createProgramWithBreakpoint();

		assertEquals(1, flat.getBreakpointsNamed("name").size());
		assertEquals(0, flat.getBreakpointsNamed("miss").size());
	}

	@Test
	public void testBreakpointsToggle() throws Throwable {
		createProgramWithBreakpoint();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		assertEquals(State.INEFFECTIVE_ENABLED, lb.computeState());
		assertEquals(Set.of(lb), flat.breakpointsToggle(flat.staticLocation("00400000")));
		assertEquals(State.INEFFECTIVE_DISABLED, lb.computeState());
	}

	@Test
	public void testBreakpointSetSoftwareExecute() throws Throwable {
		createProgramWithText();

		LogicalBreakpoint lb = Unique.assertOne(
			flat.breakpointSetSoftwareExecute(flat.staticLocation("00400000"), "name"));
		assertEquals(addr(program, 0x00400000), lb.getAddress());
		assertEquals(TraceBreakpointKindSet.SW_EXECUTE, lb.getKinds());
		assertEquals(1, lb.getLength());
	}

	@Test
	public void testBreakpointSetHardwareExecute() throws Throwable {
		createProgramWithText();

		LogicalBreakpoint lb = Unique.assertOne(
			flat.breakpointSetHardwareExecute(flat.staticLocation("00400000"), "name"));
		assertEquals(addr(program, 0x00400000), lb.getAddress());
		assertEquals(TraceBreakpointKindSet.HW_EXECUTE, lb.getKinds());
		assertEquals(1, lb.getLength());
	}

	@Test
	public void testBreakpointSetRead() throws Throwable {
		createProgramWithText();

		LogicalBreakpoint lb = Unique.assertOne(
			flat.breakpointSetRead(flat.staticLocation("00400000"), 4, "name"));
		assertEquals(addr(program, 0x00400000), lb.getAddress());
		assertEquals(TraceBreakpointKindSet.READ, lb.getKinds());
		assertEquals(4, lb.getLength());
	}

	@Test
	public void testBreakpointSetWrite() throws Throwable {
		createProgramWithText();

		LogicalBreakpoint lb = Unique.assertOne(
			flat.breakpointSetWrite(flat.staticLocation("00400000"), 4, "name"));
		assertEquals(addr(program, 0x00400000), lb.getAddress());
		assertEquals(TraceBreakpointKindSet.WRITE, lb.getKinds());
		assertEquals(4, lb.getLength());
	}

	@Test
	public void testBreakpointSetAccess() throws Throwable {
		createProgramWithText();

		LogicalBreakpoint lb = Unique.assertOne(
			flat.breakpointSetAccess(flat.staticLocation("00400000"), 4, "name"));
		assertEquals(addr(program, 0x00400000), lb.getAddress());
		assertEquals(TraceBreakpointKindSet.ACCESS, lb.getKinds());
		assertEquals(4, lb.getLength());
	}

	@Test
	public void testBreakpointsEnable() throws Throwable {
		createProgramWithBreakpoint();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
		CompletableFuture<Void> changesSettled = breakpointService.changesSettled();
		waitOn(lb.disable());
		waitForSwing();
		waitOn(changesSettled);

		assertEquals(State.INEFFECTIVE_DISABLED, lb.computeState());
		assertEquals(Set.of(lb), flat.breakpointsEnable(flat.staticLocation("00400000")));
		assertEquals(State.INEFFECTIVE_ENABLED, lb.computeState());
	}

	@Test
	public void testBreakpointsDisable() throws Throwable {
		createProgramWithBreakpoint();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		assertEquals(State.INEFFECTIVE_ENABLED, lb.computeState());
		assertEquals(Set.of(lb), flat.breakpointsDisable(flat.staticLocation("00400000")));
		assertEquals(State.INEFFECTIVE_DISABLED, lb.computeState());
	}

	@Test
	public void testBreakpointsClear() throws Throwable {
		createProgramWithBreakpoint();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		assertTrue(flat.breakpointsClear(flat.staticLocation("00400000")));
		assertTrue(lb.isEmpty());
		assertEquals(0, breakpointService.getAllBreakpoints().size());
	}

	@Test
	public void testGetModelValue() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		record(mb.testProcess1);

		assertEquals(mb.testThread2, flat.getModelValue("Processes[1].Threads[2]"));
	}

	@Test
	public void testRefreshObjectChildren() throws Throwable {
		var model = new TestDebuggerObjectModel() {
			Set<TestTargetProcess> observed = new HashSet<>();

			@Override
			protected TestTargetProcess newTestTargetProcess(TestTargetProcessContainer container,
					int pid, AddressSpace space) {
				return new TestTargetProcess(container, pid, space) {
					@Override
					public CompletableFuture<Void> resync(RefreshBehavior refreshAttributes,
							RefreshBehavior refreshElements) {
						observed.add(this);
						return super.resync(refreshAttributes, refreshElements);
					}
				};
			}
		};
		mb = new TestModelBuilder(model);
		createTestModel();
		mb.createTestProcessesAndThreads();

		flat.refreshObjectChildren(mb.testProcess1);
		assertEquals(Set.of(mb.testProcess1), model.observed);
	}

	@Test
	public void testRefreshSubtree() throws Throwable {
		var model = new TestDebuggerObjectModel() {
			Set<TestTargetObject> observed = new HashSet<>();

			@Override
			protected TestTargetProcess newTestTargetProcess(TestTargetProcessContainer container,
					int pid, AddressSpace space) {
				return new TestTargetProcess(container, pid, space) {
					@Override
					public CompletableFuture<Void> resync(RefreshBehavior refreshAttributes,
							RefreshBehavior refreshElements) {
						observed.add(this);
						return super.resync(refreshAttributes, refreshElements);
					}
				};
			}

			@Override
			protected TestTargetThread newTestTargetThread(TestTargetThreadContainer container,
					int tid) {
				return new TestTargetThread(container, tid) {
					@Override
					public CompletableFuture<Void> resync(RefreshBehavior refreshAttributes,
							RefreshBehavior refreshElements) {
						observed.add(this);
						return super.resync(refreshAttributes, refreshElements);
					}
				};
			}
		};
		mb = new TestModelBuilder(model);
		createTestModel();
		mb.createTestProcessesAndThreads();

		flat.refreshSubtree(mb.testModel.session);
		assertEquals(Set.of(mb.testProcess1, mb.testProcess3, mb.testThread1, mb.testThread2,
			mb.testThread3, mb.testThread4), model.observed);
	}

	@Test
	public void testFlushAsyncPipelines() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = record(mb.testProcess1);

		// Ensure it works whether or not there are pending events
		for (int i = 0; i < 10; i++) {
			flat.flushAsyncPipelines(recorder.getTrace());
		}
	}
}
