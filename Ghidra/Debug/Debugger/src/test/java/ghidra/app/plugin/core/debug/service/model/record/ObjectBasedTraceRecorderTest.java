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
package ghidra.app.plugin.core.debug.service.model.record;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;

import org.junit.Test;

import com.google.common.collect.Range;

import generic.Unique;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.app.services.ActionSource;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.model.*;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.*;
import ghidra.trace.model.thread.*;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.util.task.TaskMonitor;

public class ObjectBasedTraceRecorderTest extends AbstractGhidraHeadedDebuggerGUITest {
	DebuggerMappingOpinion opinion = new ObjectBasedDebuggerMappingOpinion();
	TraceRecorder recorder;

	TraceBreakpointManager breaks;
	TraceObjectManager objects;
	TraceMemoryManager memory;
	TraceModuleManager modules;
	TraceThreadManager threads;
	TraceTimeManager time;

	protected void startRecording() throws Exception {
		createTestModel();
		TargetObject target = mb.testModel.session;
		DebuggerTargetTraceMapper mapper = Unique.assertOne(opinion.getOffers(target, true)).take();
		recorder = modelService.recordTarget(mb.testModel.session, mapper, ActionSource.MANUAL);

		useTrace(recorder.getTrace());
		breaks = tb.trace.getBreakpointManager();
		objects = tb.trace.getObjectManager();
		memory = tb.trace.getMemoryManager();
		modules = tb.trace.getModuleManager();
		threads = tb.trace.getThreadManager();
		time = tb.trace.getTimeManager();
	}

	protected void dumpValues(TraceObject obj) {
		System.err.println("Values of " + obj);
		for (TraceObjectValue val : obj.getValues()) {
			System.err.println("  " + val.getEntryKey() + " = " + val.getValue());
		}
	}

	protected void dumpValues(TraceObjectInterface obj) {
		dumpValues(obj.getObject());
	}

	protected void dumpObjects() {
		System.err.println("All objects:");
		for (TraceObject object : objects.getAllObjects()) {
			System.err.println("  " + object);
		}
	}

	@Test
	public void testRecordBaseSession() throws Throwable {
		startRecording();

		waitForPass(noExc(() -> {
			waitOn(recorder.flushTransactions());
			assertEquals(5, objects.getAllObjects().size());
		}));
	}

	@Test
	public void testCloseModelStopsRecording() throws Throwable {
		startRecording();
		waitForPass(() -> assertTrue(recorder.isRecording()));

		waitOn(mb.testModel.close());
		waitForPass(() -> assertFalse(recorder.isRecording()));
	}

	@Test
	public void testRecordEvents() throws Throwable {
		startRecording();

		waitForPass(() -> assertEquals(0, recorder.getSnap()));
		mb.testModel.fire()
				.event(mb.testModel.session, null, TargetEventType.RUNNING, "Test RUNNING",
					List.of());
		mb.testModel.fire()
				.event(mb.testModel.session, null, TargetEventType.STOPPED, "Test STOPPED",
					List.of());
		waitForPass(() -> {
			assertEquals(1, recorder.getSnap());
			TraceSnapshot snapshot = time.getSnapshot(1, false);
			assertEquals("Test STOPPED", snapshot.getDescription());
		});

		mb.createTestProcessesAndThreads();
		mb.testModel.fire()
				.event(mb.testModel.session, mb.testThread1, TargetEventType.STEP_COMPLETED,
					"Test STEP", List.of());
		waitForPass(() -> {
			assertEquals(2, recorder.getSnap());
			TraceSnapshot snapshot = time.getSnapshot(2, false);
			assertEquals("Test STEP", snapshot.getDescription());
			TraceThread thread = recorder.getTraceThread(mb.testThread1);
			assertEquals(thread, snapshot.getEventThread());
		});
	}

	@Test
	public void testRecordThreads() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();

		waitForPass(noExc(() -> {
			waitOn(recorder.flushTransactions());
			assertEquals(4, threads.getAllThreads().size());

			TraceThread thread = recorder.getTraceThread(mb.testThread1);
			assertEquals(mb.testThread1, recorder.getTargetThread(thread));

			assertEquals(TargetExecutionState.STOPPED,
				recorder.getTargetThreadState(mb.testThread1));
			assertEquals(TargetExecutionState.STOPPED, recorder.getTargetThreadState(thread));
		}));

		assertEquals(Set.of(mb.testThread1, mb.testThread2, mb.testThread3, mb.testThread4),
			recorder.getLiveTargetThreads());
	}

	@Test
	public void testRecordThreadNameReuse() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();
		waitRecorder(recorder);
		TraceThread thread1 = recorder.getTraceThread(mb.testThread1);
		assertNotNull(thread1);
		TraceObject object1 = ((TraceObjectThread) thread1).getObject();

		recorder.forceSnapshot();
		mb.testProcess1.threads.removeThreads(mb.testThread1);
		waitRecorder(recorder);
		assertEquals(Range.singleton(0L), thread1.getLifespan());
		assertNull(recorder.getTraceThread(mb.testThread1));

		recorder.forceSnapshot();
		mb.testThread1 = mb.testProcess1.addThread(1);
		waitRecorder(recorder);
		assertSame(thread1, recorder.getTraceThread(mb.testThread1));
		assertEquals(Set.of(Range.singleton(0L), Range.atLeast(2L)), object1.getLife().asRanges());
	}

	@Test
	public void testRecordMemoryRegion() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();
		TestTargetMemoryRegion text =
			mb.testProcess1.memory.addRegion("exe:.text", mb.rng(0x00400000, 0x00400fff), "wrx");

		waitForPass(() -> {
			TraceMemoryRegion region = Unique.assertOne(memory.getAllRegions());
			assertEquals("[exe:.text]", region.getName());
			assertEquals("Processes[1].Memory[exe:.text]", region.getPath());
			assertEquals(tb.range(0x00400000, 0x00400fff), region.getRange());
			assertEquals(
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.WRITE, TraceMemoryFlag.EXECUTE),
				region.getFlags());

			assertEquals(region, recorder.getTraceMemoryRegion(text));
			assertEquals(text, recorder.getTargetMemoryRegion(region));
		});
	}

	@Test
	public void testRecordMemoryAddressSet() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();

		mb.testProcess1.memory.addRegion("exe:.text", mb.rng(0x00400000, 0x00400fff), "rx");
		waitForPass(() -> {
			assertEquals(tb.set(tb.range(0x00400000, 0x00400fff)), recorder.getAccessibleMemory());
		});

		TestTargetMemoryRegion data =
			mb.testProcess1.memory.addRegion("exe:.data", mb.rng(0x00401000, 0x00401fff), "wr");
		waitForPass(() -> {
			assertEquals(tb.set(tb.range(0x00400000, 0x00401fff)), recorder.getAccessibleMemory());
		});

		mb.testProcess1.memory.removeRegion(data);
		waitForPass(() -> {
			assertEquals(tb.set(tb.range(0x00400000, 0x00400fff)), recorder.getAccessibleMemory());
		});

		mb.testModel.removeProcess(mb.testProcess1);
		waitForPass(() -> {
			assertEquals(tb.set(), recorder.getAccessibleMemory());
		});
	}

	@Test
	public void testRecordMemoryBytes() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();
		mb.testProcess1.memory.addRegion("exe:.text", mb.rng(0x00400000, 0x00400fff), "wrx");
		mb.testProcess1.memory.writeMemory(mb.addr(0x00400123), mb.arr(1, 2, 3, 4, 5, 6, 7, 8, 9));

		byte[] data = new byte[9];
		waitForPass(() -> {
			memory.getBytes(recorder.getSnap(), tb.addr(0x00400123), ByteBuffer.wrap(data));
			assertArrayEquals(tb.arr(1, 2, 3, 4, 5, 6, 7, 8, 9), data);
		});
	}

	protected void flushAndWait() throws Throwable {
		waitOn(mb.testModel.flushEvents());
		waitOn(recorder.flushTransactions());
		waitForDomainObject(tb.trace);
	}

	@Test
	public void testRecordMemoryInvalidateCacheRequested() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();

		mb.testProcess1.memory.addRegion("exe:.text", mb.rng(0x00400000, 0x00400fff), "rwx");

		waitOn(mb.testProcess1.memory.writeMemory(mb.addr(0x00400123),
			mb.arr(1, 2, 3, 4, 5, 6, 7, 8, 9)));
		flushAndWait();
		assertEquals(TraceMemoryState.KNOWN,
			memory.getState(recorder.getSnap(), tb.addr(0x00400123)));

		mb.testModel.fire().invalidateCacheRequested(mb.testProcess1.memory);
		flushAndWait();
		assertEquals(TraceMemoryState.UNKNOWN,
			memory.getState(recorder.getSnap(), tb.addr(0x00400123)));

		waitOn(mb.testProcess1.memory.writeMemory(mb.addr(0x00400123),
			mb.arr(1, 2, 3, 4, 5, 6, 7, 8, 9)));
		flushAndWait();
		assertEquals(TraceMemoryState.KNOWN,
			memory.getState(recorder.getSnap(), tb.addr(0x00400123)));

		mb.testModel.fire()
				.event(mb.testModel.session, null, TargetEventType.RUNNING, "Test RUNNING",
					List.of());
		mb.testModel.fire().invalidateCacheRequested(mb.testProcess1.memory);
		flushAndWait();
		assertEquals(TraceMemoryState.KNOWN,
			memory.getState(recorder.getSnap(), tb.addr(0x00400123)));

		mb.testModel.fire()
				.event(mb.testModel.session, null, TargetEventType.STOPPED, "Test STOPPED",
					List.of());
		flushAndWait();
		assertEquals(TraceMemoryState.UNKNOWN,
			memory.getState(recorder.getSnap(), tb.addr(0x00400123)));
	}

	@Test
	public void testReadMemory() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();

		mb.testProcess1.memory.addRegion("exe:.text", mb.rng(0x00400000, 0x00400fff), "rwx");
		mb.testProcess1.memory.setMemory(tb.addr(0x00400123), mb.arr(1, 2, 3, 4, 5, 6, 7, 8, 9));
		flushAndWait();
		assertThat(memory.getState(recorder.getSnap(), tb.addr(0x00400123)),
			is(oneOf(null, TraceMemoryState.UNKNOWN)));

		byte[] data = new byte[10];
		waitOn(recorder.readMemory(tb.addr(0x00400123), 10));
		flushAndWait();
		assertEquals(TraceMemoryState.KNOWN,
			memory.getState(recorder.getSnap(), tb.addr(0x00400123)));
		memory.getBytes(recorder.getSnap(), tb.addr(0x00400123), ByteBuffer.wrap(data));
		assertArrayEquals(tb.arr(1, 2, 3, 4, 5, 6, 7, 8, 9, 0), data);
	}

	protected Map.Entry<TraceAddressSnapRange, TraceMemoryState> stateEntry(long min, long max,
			TraceMemoryState state) {
		return Map.entry(new ImmutableTraceAddressSnapRange(tb.range(min, max), recorder.getSnap()),
			state);
	}

	@Test
	public void testReadMemoryBlocks() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();

		mb.testProcess1.memory.addRegion("exe:.text", mb.rng(0x00400000, 0x00400fff), "rx");
		mb.testProcess1.memory.addRegion("exe:.data", mb.rng(0x00600000, 0x00602fff), "rw");
		mb.testProcess1.memory.setMemory(tb.addr(0x00400123), mb.arr(1, 2, 3, 4, 5, 6, 7, 8, 9));
		flushAndWait();
		assertThat(memory.getState(recorder.getSnap(), tb.addr(0x00400123)),
			is(oneOf(null, TraceMemoryState.UNKNOWN)));

		byte[] data = new byte[10];
		assertNull(waitOn(recorder.readMemoryBlocks(
			tb.set(tb.range(0x00400123, 0x00400123), tb.range(0x00600ffe, 0x00601000)),
			TaskMonitor.DUMMY, false)));
		flushAndWait();
		assertEquals(Set.of(
			stateEntry(0x00400000, 0x00400fff, TraceMemoryState.KNOWN),
			stateEntry(0x00600000, 0x00601fff, TraceMemoryState.KNOWN)),
			Set.copyOf(memory.getStates(recorder.getSnap(), tb.range(0x00400000, 0x00602fff))));
		memory.getBytes(recorder.getSnap(), tb.addr(0x00400123), ByteBuffer.wrap(data));
		assertArrayEquals(tb.arr(1, 2, 3, 4, 5, 6, 7, 8, 9, 0), data);
	}

	@Test
	public void testWriteMemory() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();

		mb.testProcess1.memory.addRegion("exe:.text", mb.rng(0x00400000, 0x00400fff), "rwx");
		flushAndWait();
		assertThat(memory.getState(recorder.getSnap(), tb.addr(0x00400123)),
			is(oneOf(null, TraceMemoryState.UNKNOWN)));

		byte[] data = new byte[10];
		waitOn(recorder.writeMemory(tb.addr(0x00400123), tb.arr(1, 2, 3, 4, 5, 6, 7, 8, 9)));
		flushAndWait();
		assertEquals(TraceMemoryState.KNOWN,
			memory.getState(recorder.getSnap(), tb.addr(0x00400123)));
		memory.getBytes(recorder.getSnap(), tb.addr(0x00400123), ByteBuffer.wrap(data));
		assertArrayEquals(tb.arr(1, 2, 3, 4, 5, 6, 7, 8, 9, 0), data);
	}

	@Test
	public void testRecordMemoryError() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();

		mb.testProcess1.memory.addRegion("exe:.text", mb.rng(0x00400000, 0x00400fff), "rx");
		flushAndWait();
		assertEquals(Set.of(), Set.copyOf(memory.getStates(recorder.getSnap(), tb.range(0, -1))));

		mb.testModel.fire()
				.memoryReadError(mb.testProcess1.memory, mb.rng(0x00400123, 0x00400321),
					new DebuggerMemoryAccessException("Test error"));
		flushAndWait();
		// NB, only the first byte of the reported range is marked.
		assertEquals(Set.of(stateEntry(0x00400123, 0x00400123, TraceMemoryState.ERROR)),
			Set.copyOf(memory.getStates(recorder.getSnap(), tb.range(0, -1))));
	}

	@Test
	public void testRecordMemoryBytes2Processes() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();
		Address tgtAddr1 = mb.addr(0x00400123);
		Address tgtAddr3 = mb.testModel.ram3.getAddress(0x00400123);

		mb.testProcess1.memory.addRegion("exe:.text", mb.rng(0x00400000, 0x00400fff), "wrx");
		mb.testProcess3.memory.addRegion("exe:.text", new AddressRangeImpl(tgtAddr3, 0x1000),
			"rwx");

		mb.testProcess1.memory.writeMemory(tgtAddr1, mb.arr(1, 2, 3, 4, 5, 6, 7, 8, 9));
		mb.testProcess3.memory.writeMemory(tgtAddr3, mb.arr(11, 12, 13, 14, 15));

		Address trcAddr1 = recorder.getMemoryMapper().targetToTrace(tgtAddr1);
		Address trcAddr3 = recorder.getMemoryMapper().targetToTrace(tgtAddr3);

		byte[] data = new byte[9];
		waitForPass(() -> {
			memory.getBytes(recorder.getSnap(), trcAddr1, ByteBuffer.wrap(data));
			assertArrayEquals(tb.arr(1, 2, 3, 4, 5, 6, 7, 8, 9), data);

			memory.getBytes(recorder.getSnap(), trcAddr3, ByteBuffer.wrap(data));
			assertArrayEquals(tb.arr(11, 12, 13, 14, 15, 0, 0, 0, 0), data);
		});
	}

	@Test
	public void testRecordFocus() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();

		flushAndWait();
		// TODO: Is focus really a concern of the recorder?
		assertTrue(recorder.isSupportsFocus());
		assertNull(recorder.getFocus());

		waitOn(recorder.requestFocus(mb.testThread1));
		flushAndWait();
		assertEquals(mb.testThread1, recorder.getFocus());
	}

	@Test
	public void testRecordBreakpoint() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();
		flushAndWait();

		assertEquals(Set.of(TraceBreakpointKind.values()),
			Set.copyOf(recorder.getSupportedBreakpointKinds()));

		waitOn(mb.testProcess1.breaks.placeBreakpoint(mb.rng(0x00400123, 0x00400126),
			Set.of(TargetBreakpointKind.SW_EXECUTE)));
		flushAndWait();

		TraceBreakpoint loc = Unique.assertOne(breaks.getAllBreakpoints());
		assertEquals(tb.range(0x00400123, 0x00400126), loc.getRange());
		assertEquals(Set.of(TraceBreakpointKind.SW_EXECUTE), loc.getKinds());

		assertEquals(List.of(),
			recorder.collectBreakpointContainers(mb.testThread1));
		assertEquals(List.of(mb.testProcess1.breaks, mb.testProcess3.breaks),
			recorder.collectBreakpointContainers(null));

		TargetBreakpointLocation targetLoc = recorder.getTargetBreakpoint(loc);
		assertEquals(loc, recorder.getTraceBreakpoint(targetLoc));

		// This must *not* show as applicable to thread1
		waitOn(mb.testProcess3.breaks.placeBreakpoint(mb.testModel.ram3.getAddress(0x00400321),
			Set.of(TargetBreakpointKind.SW_EXECUTE)));
		flushAndWait();
		assertEquals(2, breaks.getAllBreakpoints().size());
		assertEquals(List.of(targetLoc), recorder.collectBreakpoints(mb.testThread1));
	}

	@Test
	public void testRecordModuleAndSection() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();

		TestTargetModule targetExe =
			mb.testProcess1.modules.addModule("exe", mb.rng(0x00400000, 0x00602fff));
		TestTargetSection targetText =
			targetExe.addSection(".text", mb.rng(0x00400000, 0x00400fff));
		flushAndWait();

		TraceModule exe = Unique.assertOne(modules.getAllModules());
		assertEquals(exe, recorder.getTraceModule(targetExe));
		assertEquals(targetExe, recorder.getTargetModule(exe));

		assertEquals("exe", exe.getName());
		assertEquals("Processes[1].Modules[exe]", exe.getPath());
		assertEquals(tb.range(0x00400000, 0x00602fff), exe.getRange());

		TraceSection text = Unique.assertOne(modules.getAllSections());
		assertEquals(text, recorder.getTraceSection(targetText));
		assertEquals(targetText, recorder.getTargetSection(text));

		assertEquals("[.text]", text.getName());
		assertEquals("Processes[1].Modules[exe].Sections[.text]", text.getPath());
		assertEquals(tb.range(0x00400000, 0x00400fff), text.getRange());

		assertEquals(exe, text.getModule());
		assertEquals(Set.of(text), Set.copyOf(exe.getSections()));
	}

	@Test
	public void testRecordRegisters() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();
		// TODO: Adjust schema to reflect merging of container and bank
		// TODO: Other bank placements. Will need different schemas, though :/
		mb.createTestThreadRegisterBanks();

		TestTargetRegisterValue targetPC = new TestTargetRegisterValue(mb.testBank1, "pc", true,
			BigInteger.valueOf(0x00400123), 8);
		TestTargetRegisterValue targetR0 =
			new TestTargetRegisterValue(mb.testBank1, "r0", false, BigInteger.ZERO, 8);
		mb.testBank1.setElements(Set.of(targetPC, targetR0), "Test registers");
		flushAndWait();

		TraceObjectThread thread = (TraceObjectThread) recorder.getTraceThread(mb.testThread1);
		assertNotNull(thread);

		assertEquals(mb.testBank1, recorder.getTargetRegisterBank(thread, 0));
		assertEquals(thread, recorder.getTraceThreadForSuccessor(mb.testBank1));

		TraceObject traceBank = thread.getObject()
				.querySuccessorsTargetInterface(Range.singleton(recorder.getSnap()),
					TargetRegisterBank.class)
				.map(p -> p.getDestination(thread.getObject()))
				.findAny()
				.orElseThrow();

		TraceObject pc = traceBank.getElement(recorder.getSnap(), "pc").getChild();
		assertArrayEquals(tb.arr(0, 0, 0, 0, 0, 0x40, 0x01, 0x023),
			(byte[]) pc.getAttribute(recorder.getSnap(), TargetObject.VALUE_ATTRIBUTE_NAME)
					.getValue());
		TraceObject r0 = traceBank.getElement(recorder.getSnap(), "r0").getChild();
		assertArrayEquals(tb.arr(0, 0, 0, 0, 0, 0, 0, 0),
			(byte[]) r0.getAttribute(recorder.getSnap(), TargetObject.VALUE_ATTRIBUTE_NAME)
					.getValue());
		// TODO: Test interpretation, once mapping scheme is worked out
		// TODO: How to annotate values with types, etc?
		// TODO:     Perhaps byte-array values are allocated in memory-like byte store?
		// TODO:     Brings endianness into the picture :/
	}

	@Test
	public void testRecordStack() throws Throwable {
		startRecording();
		mb.createTestProcessesAndThreads();

		TestTargetStack targetStack = mb.testThread1.addStack();
		// TODO: These "push" semantics don't seem to work as designed....
		TestTargetStackFrame targetFrame0 = targetStack.pushFrameNoBank(mb.addr(0x00400123));
		TestTargetStackFrame targetFrame1 = targetStack.pushFrameNoBank(mb.addr(0x00400321));
		flushAndWait();

		TraceObjectThread thread = (TraceObjectThread) recorder.getTraceThread(mb.testThread1);
		assertNotNull(thread);

		assertEquals(targetFrame0, recorder.getTargetStackFrame(thread, 0));
		assertEquals(targetFrame1, recorder.getTargetStackFrame(thread, 1));
		assertEquals(thread, recorder.getTraceThreadForSuccessor(targetFrame0));
		assertEquals(thread, recorder.getTraceThreadForSuccessor(targetFrame1));

		TraceStackFrame frame0 = recorder.getTraceStackFrame(targetFrame0);
		TraceStackFrame frame1 = recorder.getTraceStackFrame(targetFrame1);

		// TODO: This can use a bank, once we test the frame-has-bank schema
		assertEquals(frame0, recorder.getTraceStackFrameForSuccessor(targetFrame0));
		assertEquals(frame1, recorder.getTraceStackFrameForSuccessor(targetFrame1));

		assertEquals(0, frame0.getLevel());
		assertEquals(1, frame1.getLevel());

		assertEquals(tb.addr(0x00400123), frame0.getProgramCounter(Long.MAX_VALUE));
		assertEquals(tb.addr(0x00400321), frame1.getProgramCounter(Long.MAX_VALUE));
	}
}
