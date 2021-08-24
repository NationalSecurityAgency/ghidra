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
package ghidra.trace.model.time;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.pcode.emu.*;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSchedule.*;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.task.TaskMonitor;

public class TraceScheduleTest extends AbstractGhidraHeadlessIntegrationTest {

	@Test
	public void testParseZero() {
		TraceSchedule time = TraceSchedule.parse("0:0");
		assertEquals(new TraceSchedule(0, TickSequence.of(), TickSequence.of()), time);
	}

	@Test
	public void testParseSimple() {
		TraceSchedule time = TraceSchedule.parse("0:100");
		assertEquals(
			new TraceSchedule(0, TickSequence.of(new TickStep(-1, 100)), TickSequence.of()), time);
	}

	@Test
	public void testToStringSimple() {
		assertEquals("0:100",
			new TraceSchedule(0, TickSequence.of(new TickStep(-1, 100)), TickSequence.of())
					.toString());
	}

	@Test
	public void testParseWithPcodeSteps() {
		TraceSchedule time = TraceSchedule.parse("0:100.5");
		assertEquals(new TraceSchedule(0, TickSequence.of(new TickStep(-1, 100)),
			TickSequence.of(new TickStep(-1, 5))), time);
	}

	@Test
	public void testToStringWithPcodeSteps() {
		assertEquals("0:100.5", new TraceSchedule(0, TickSequence.of(new TickStep(-1, 100)),
			TickSequence.of(new TickStep(-1, 5))).toString());
	}

	@Test
	public void testParseWithThread() {
		TraceSchedule time = TraceSchedule.parse("1:t3-100");
		assertEquals(new TraceSchedule(1, TickSequence.of(new TickStep(3, 100)), TickSequence.of()),
			time);
	}

	@Test
	public void testToStringWithThread() {
		assertEquals("1:t3-100",
			new TraceSchedule(1, TickSequence.of(new TickStep(3, 100)), TickSequence.of())
					.toString());
	}

	@Test
	public void testParseMultipleSteps() {
		TraceSchedule time = TraceSchedule.parse("1:50,t3-50");
		assertEquals(new TraceSchedule(1,
			TickSequence.of(new TickStep(-1, 50), new TickStep(3, 50)), TickSequence.of()), time);
	}

	@Test
	public void testToStringMultipleSteps() {
		assertEquals("1:50,t3-50",
			new TraceSchedule(1, TickSequence.of(new TickStep(-1, 50), new TickStep(3, 50)),
				TickSequence.of()).toString());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testParseNegativeStepErr() {
		TraceSchedule.parse("0:-100");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNegativeStepErr() {
		new TickStep(0, -100);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testParseBadStepForm3Parts() {
		TraceSchedule.parse("0:t1-10-10");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testParseBadStepFormMissingT() {
		TraceSchedule.parse("0:1-10");
	}

	@Test
	public void testAdvance() {
		TickSequence seq = new TickSequence();
		seq.advance(new TickStep(-1, 0));
		assertEquals(TickSequence.of(), seq);

		seq.advance(new TickStep(-1, 10));
		assertEquals(TickSequence.of(new TickStep(-1, 10)), seq);

		seq.advance(new TickStep(-1, 10));
		assertEquals(TickSequence.of(new TickStep(-1, 20)), seq);

		seq.advance(new TickStep(1, 10));
		assertEquals(TickSequence.of(new TickStep(-1, 20), new TickStep(1, 10)), seq);

		seq.advance(new TickStep(-1, 10));
		assertEquals(TickSequence.of(new TickStep(-1, 20), new TickStep(1, 20)), seq);

		seq.advance(seq);
		assertEquals(TickSequence.of(new TickStep(-1, 20), new TickStep(1, 60)), seq);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAdvanceNegativeErr() {
		new TickStep(-1, 10).advance(-10);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAdvanceOverflowErr() {
		new TickStep(-1, Long.MAX_VALUE).advance(Long.MAX_VALUE);
	}

	@Test
	public void testRewind() {
		TickSequence seq = TickSequence.parse("10,t1-20,t2-30");

		assertEquals(0, seq.rewind(5));
		assertEquals("10,t1-20,t2-25", seq.toString());

		assertEquals(0, seq.rewind(25));
		assertEquals("10,t1-20", seq.toString());

		assertEquals(0, seq.rewind(27));
		assertEquals("3", seq.toString());

		assertEquals(7, seq.rewind(10));
		assertEquals("", seq.toString());

		assertEquals(10, seq.rewind(10));
		assertEquals("", seq.toString());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testRewindNegativeErr() {
		TickSequence seq = TickSequence.parse("10,t1-20,t2-30");
		seq.rewind(-1);
	}

	@Test
	public void testEquals() {
		TraceSchedule time = TraceSchedule.parse("0:10");
		assertTrue(time.equals(time));
		assertFalse(TraceSchedule.parse("0:10").equals(null));
		assertFalse(TraceSchedule.parse("0:10").equals("Hello"));
		assertFalse(TraceSchedule.parse("0:t0-10").equals(TraceSchedule.parse("1:t0-10")));
		assertFalse(TraceSchedule.parse("0:t0-10").equals(TraceSchedule.parse("0:t1-10")));
		assertFalse(TraceSchedule.parse("0:t0-10").equals(TraceSchedule.parse("0:t0-11")));
		assertFalse(TraceSchedule.parse("0:t0-10").equals(TraceSchedule.parse("0:t0-10.1")));
		assertTrue(TraceSchedule.parse("0:t0-10").equals(TraceSchedule.parse("0:t0-10")));
	}

	protected void expectU(String specL, String specG) {
		TraceSchedule timeL = TraceSchedule.parse(specL);
		TraceSchedule timeG = TraceSchedule.parse(specG);
		assertEquals(CompareResult.UNREL_LT, timeL.compareSchedule(timeG));
		assertEquals(CompareResult.UNREL_GT, timeG.compareSchedule(timeL));
	}

	protected void expectR(String specL, String specG) {
		TraceSchedule timeL = TraceSchedule.parse(specL);
		TraceSchedule timeG = TraceSchedule.parse(specG);
		assertEquals(CompareResult.REL_LT, timeL.compareSchedule(timeG));
		assertEquals(CompareResult.REL_GT, timeG.compareSchedule(timeL));
	}

	protected void expectE(String specL, String specG) {
		TraceSchedule timeL = TraceSchedule.parse(specL);
		TraceSchedule timeG = TraceSchedule.parse(specG);
		assertEquals(CompareResult.EQUALS, timeL.compareSchedule(timeG));
		assertEquals(CompareResult.EQUALS, timeG.compareSchedule(timeL));
	}

	@Test
	public void testCompare() {
		expectU("0:10", "1:10");
		expectU("0:t0-10", "0:t1-10");
		// We don't know how many p-code steps complete an instruction step
		expectU("0:t0-10.1", "0:t0-11");
		expectU("0:t0-10,t1-5", "0:t0-11,t1-5");

		expectR("0:t0-10", "0:t0-11");
		expectR("0:t0-10", "0:t0-10,t1-5");
		expectR("0:t0-10", "0:t0-11,t1-5");
		expectR("0:t0-10", "0:t0-10.1");
		expectR("0:t0-10", "0:t0-11.1");
		expectR("0:t0-10", "0:t0-10,t1-5.1");
		expectR("0:t0-10", "0:t0-11,t1-5.1");

		expectE("0:t0-10", "0:t0-10");
		expectE("0:t0-10.1", "0:t0-10.1");
	}

	public String strRelativize(String fromSpec, String toSpec) {
		TickSequence seq = TickSequence.parse(toSpec).relativize(TickSequence.parse(fromSpec));
		return seq == null ? null : seq.toString();
	}

	@Test
	public void testRelativize() {
		assertEquals("10", strRelativize("", "10"));
		assertEquals("", strRelativize("10", "10"));
		assertEquals("9", strRelativize("1", "10"));
		assertEquals("t1-9", strRelativize("t1-1", "t1-10"));
		assertEquals("t1-10", strRelativize("5", "5,t1-10"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testRelativizeNotPrefixErr() {
		strRelativize("t1-5", "5");
	}

	@Test
	public void testTotalStepCount() {
		assertEquals(15, TraceSchedule.parse("0:4,t1-5.6").totalTickCount());
	}

	protected static class TestThread implements PcodeThread<Void> {
		protected final String name;
		protected final TestMachine machine;

		public TestThread(String name, TestMachine machine) {
			this.name = name;
			this.machine = machine;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public TestMachine getMachine() {
			return machine;
		}

		@Override
		public void setCounter(Address counter) {
		}

		@Override
		public Address getCounter() {
			return null;
		}

		@Override
		public void overrideCounter(Address counter) {
		}

		@Override
		public void assignContext(RegisterValue context) {
		}

		@Override
		public RegisterValue getContext() {
			return null;
		}

		@Override
		public void overrideContext(RegisterValue context) {
		}

		@Override
		public void overrideContextWithDefault() {
		}

		@Override
		public void reInitialize() {
		}

		@Override
		public void stepInstruction() {
			machine.record.add("s:" + name);
		}

		@Override
		public void stepPcodeOp() {
			machine.record.add("p:" + name);
		}

		@Override
		public PcodeFrame getFrame() {
			return null;
		}

		@Override
		public void executeInstruction() {
		}

		@Override
		public void finishInstruction() {
		}

		@Override
		public void skipInstruction() {
		}

		@Override
		public void dropInstruction() {
		}

		@Override
		public void run() {
		}

		@Override
		public void setSuspended(boolean suspended) {
		}

		@Override
		public PcodeExecutor<Void> getExecutor() {
			return null;
		}

		@Override
		public SleighUseropLibrary<Void> getUseropLibrary() {
			return null;
		}

		@Override
		public ThreadPcodeExecutorState<Void> getState() {
			return null;
		}

		@Override
		public void inject(Address address, List<String> sleigh) {
		}

		@Override
		public void clearInject(Address address) {
		}

		@Override
		public void clearAllInjects() {
		}
	}

	protected static class TestMachine extends AbstractPcodeMachine<Void> {
		protected final List<String> record = new ArrayList<>();

		public TestMachine() {
			super(null, null, null);
		}

		@Override
		protected PcodeThread<Void> createThread(String name) {
			return new TestThread(name, this);
		}

		@Override
		protected PcodeExecutorState<Void> createSharedState() {
			return null;
		}

		@Override
		protected PcodeExecutorState<Void> createLocalState(PcodeThread<Void> thread) {
			return null;
		}
	}

	@Test
	public void testExecute() throws Exception {
		TestMachine machine = new TestMachine();
		TraceSchedule time = TraceSchedule.parse("1:4,t0-3,t1-2.1");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			TraceThread t2;
			try (UndoableTransaction tid = tb.startTransaction()) {
				tb.trace.getThreadManager().createThread("Threads[0]", 0);
				tb.trace.getThreadManager().createThread("Threads[1]", 0);
				t2 = tb.trace.getThreadManager().createThread("Threads[2]", 0);
				tb.trace.getTimeManager().getSnapshot(1, true).setEventThread(t2);
			}
			time.execute(tb.trace, machine, TaskMonitor.DUMMY);
		}

		assertEquals(List.of(
			"s:Threads[2]",
			"s:Threads[2]",
			"s:Threads[2]",
			"s:Threads[2]",
			"s:Threads[0]",
			"s:Threads[0]",
			"s:Threads[0]",
			"s:Threads[1]",
			"s:Threads[1]",
			"p:Threads[1]"),
			machine.record);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testExecuteNoEventThreadErr() throws Exception {
		TestMachine machine = new TestMachine();
		TraceSchedule time = TraceSchedule.parse("1:4,t0-3,t1-2.1");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			try (UndoableTransaction tid = tb.startTransaction()) {
				tb.trace.getThreadManager().createThread("Threads[0]", 0);
				tb.trace.getThreadManager().createThread("Threads[1]", 0);
				tb.trace.getThreadManager().createThread("Threads[2]", 0);
				tb.trace.getTimeManager().getSnapshot(1, true);
			}
			time.execute(tb.trace, machine, TaskMonitor.DUMMY);
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testExecuteBadThreadKeyErr() throws Exception {
		TestMachine machine = new TestMachine();
		TraceSchedule time = TraceSchedule.parse("1:4,t0-3,t5-2.1");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			TraceThread t2;
			try (UndoableTransaction tid = tb.startTransaction()) {
				tb.trace.getThreadManager().createThread("Threads[0]", 0);
				tb.trace.getThreadManager().createThread("Threads[1]", 0);
				t2 = tb.trace.getThreadManager().createThread("Threads[2]", 0);
				tb.trace.getTimeManager().getSnapshot(1, true).setEventThread(t2);
			}
			time.execute(tb.trace, machine, TaskMonitor.DUMMY);
		}
	}

	@Test
	public void testFinish() throws Exception {
		TestMachine machine = new TestMachine();
		TraceSchedule time = TraceSchedule.parse("1:4,t0-3,t1-2.1");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			TraceThread t2;
			try (UndoableTransaction tid = tb.startTransaction()) {
				tb.trace.getThreadManager().createThread("Threads[0]", 0);
				tb.trace.getThreadManager().createThread("Threads[1]", 0);
				t2 = tb.trace.getThreadManager().createThread("Threads[2]", 0);
				tb.trace.getTimeManager().getSnapshot(1, true).setEventThread(t2);
			}
			time.finish(tb.trace, TraceSchedule.parse("1:4,t0-2"), machine, TaskMonitor.DUMMY);
		}

		assertEquals(List.of(
			"s:Threads[0]",
			"s:Threads[1]",
			"s:Threads[1]",
			"p:Threads[1]"),
			machine.record);
	}

	@Test
	public void testFinishPcode() throws Exception {
		TestMachine machine = new TestMachine();
		TraceSchedule time = TraceSchedule.parse("1:4,t0-3,t1-2.1");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			TraceThread t2;
			try (UndoableTransaction tid = tb.startTransaction()) {
				tb.trace.getThreadManager().createThread("Threads[0]", 0);
				tb.trace.getThreadManager().createThread("Threads[1]", 0);
				t2 = tb.trace.getThreadManager().createThread("Threads[2]", 0);
				tb.trace.getTimeManager().getSnapshot(1, true).setEventThread(t2);
			}
			time.finish(tb.trace, TraceSchedule.parse("1:4,t0-3,t1-2"), machine,
				TaskMonitor.DUMMY);
		}

		assertEquals(List.of(
			"p:Threads[1]"),
			machine.record);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testFinishUnrelatedErr() throws Exception {
		TestMachine machine = new TestMachine();
		TraceSchedule time = TraceSchedule.parse("1:4,t0-3,t1-2.1");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			TraceThread t2;
			try (UndoableTransaction tid = tb.startTransaction()) {
				tb.trace.getThreadManager().createThread("Threads[0]", 0);
				tb.trace.getThreadManager().createThread("Threads[1]", 0);
				t2 = tb.trace.getThreadManager().createThread("Threads[2]", 0);
				tb.trace.getTimeManager().getSnapshot(1, true).setEventThread(t2);
			}
			time.finish(tb.trace, TraceSchedule.parse("1:4,t0-4"), machine, TaskMonitor.DUMMY);
		}
	}
}
