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
package ghidra.trace.model.time.schedule;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.task.TaskMonitor;

public class TraceScheduleTest extends AbstractGhidraHeadlessIntegrationTest {
	protected static SleighLanguage TOY_BE_64_LANG;

	@Before
	public void setUp() {
		try {
			TOY_BE_64_LANG = (SleighLanguage) getLanguageService()
					.getLanguage(new LanguageID(ToyProgramBuilder._TOY64_BE));
		}
		catch (LanguageNotFoundException e) {
			throw new AssertionError(e);
		}
	}

	@Test
	public void testParseZero() {
		TraceSchedule time = TraceSchedule.parse("0:0");
		assertEquals(new TraceSchedule(0, Sequence.of(), Sequence.of()), time);
	}

	@Test
	public void testParseSimple() {
		TraceSchedule time = TraceSchedule.parse("0:100");
		assertEquals(
			new TraceSchedule(0, Sequence.of(new TickStep(-1, 100)), Sequence.of()), time);
	}

	@Test
	public void testToStringSimple() {
		assertEquals("0:100",
			new TraceSchedule(0, Sequence.of(new TickStep(-1, 100)), Sequence.of())
					.toString());
	}

	@Test
	public void testParseWithPcodeSteps() {
		TraceSchedule time = TraceSchedule.parse("0:100.5");
		assertEquals(new TraceSchedule(0, Sequence.of(new TickStep(-1, 100)),
			Sequence.of(new TickStep(-1, 5))), time);
	}

	@Test
	public void testToStringWithPcodeSteps() {
		assertEquals("0:100.5", new TraceSchedule(0, Sequence.of(new TickStep(-1, 100)),
			Sequence.of(new TickStep(-1, 5))).toString());
	}

	@Test
	public void testParseWithThread() {
		TraceSchedule time = TraceSchedule.parse("1:t3-100");
		assertEquals(new TraceSchedule(1, Sequence.of(new TickStep(3, 100)), Sequence.of()),
			time);
	}

	@Test
	public void testToStringWithThread() {
		assertEquals("1:t3-100",
			new TraceSchedule(1, Sequence.of(new TickStep(3, 100)), Sequence.of())
					.toString());
	}

	@Test
	public void testParseMultipleSteps() {
		TraceSchedule time = TraceSchedule.parse("1:50;t3-50");
		assertEquals(new TraceSchedule(1,
			Sequence.of(new TickStep(-1, 50), new TickStep(3, 50)), Sequence.of()), time);
	}

	@Test
	public void testToStringMultipleSteps() {
		assertEquals("1:50;t3-50",
			new TraceSchedule(1, Sequence.of(new TickStep(-1, 50), new TickStep(3, 50)),
				Sequence.of()).toString());
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
		Sequence seq = new Sequence();
		seq.advance(new TickStep(-1, 0));
		assertEquals(Sequence.of(), seq);

		seq.advance(new TickStep(-1, 10));
		assertEquals(Sequence.of(new TickStep(-1, 10)), seq);

		seq.advance(new TickStep(-1, 10));
		assertEquals(Sequence.of(new TickStep(-1, 20)), seq);

		seq.advance(new TickStep(1, 10));
		assertEquals(Sequence.of(new TickStep(-1, 20), new TickStep(1, 10)), seq);

		seq.advance(new TickStep(-1, 10));
		assertEquals(Sequence.of(new TickStep(-1, 20), new TickStep(1, 20)), seq);

		seq.advance(seq);
		assertEquals(Sequence.of(new TickStep(-1, 20), new TickStep(1, 60)), seq);
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
		Sequence seq = Sequence.parse("10;t1-20;t2-30");

		assertEquals(0, seq.rewind(5));
		assertEquals("10;t1-20;t2-25", seq.toString());

		assertEquals(0, seq.rewind(25));
		assertEquals("10;t1-20", seq.toString());

		assertEquals(0, seq.rewind(27));
		assertEquals("3", seq.toString());

		assertEquals(7, seq.rewind(10));
		assertEquals("", seq.toString());

		assertEquals(10, seq.rewind(10));
		assertEquals("", seq.toString());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testRewindNegativeErr() {
		Sequence seq = Sequence.parse("10;t1-20;t2-30");
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
		expectU("0:t0-10;t1-5", "0:t0-11;t1-5");

		expectR("0:t0-10", "0:t0-11");
		expectR("0:t0-10", "0:t0-10;t1-5");
		expectR("0:t0-10", "0:t0-11;t1-5");
		expectR("0:t0-10", "0:t0-10.1");
		expectR("0:t0-10", "0:t0-11.1");
		expectR("0:t0-10", "0:t0-10;t1-5.1");
		expectR("0:t0-10", "0:t0-11;t1-5.1");

		expectE("0:t0-10", "0:t0-10");
		expectE("0:t0-10.1", "0:t0-10.1");
	}

	public String strRelativize(String fromSpec, String toSpec) {
		Sequence seq = Sequence.parse(toSpec).relativize(Sequence.parse(fromSpec));
		return seq == null ? null : seq.toString();
	}

	@Test
	public void testRelativize() {
		assertEquals("10", strRelativize("", "10"));
		assertEquals("", strRelativize("10", "10"));
		assertEquals("9", strRelativize("1", "10"));
		assertEquals("t1-9", strRelativize("t1-1", "t1-10"));
		assertEquals("t1-10", strRelativize("5", "5;t1-10"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testRelativizeNotPrefixErr() {
		strRelativize("t1-5", "5");
	}

	@Test
	public void testTotalStepCount() {
		assertEquals(15, TraceSchedule.parse("0:4;t1-5.6").totalTickCount());
	}

	@Test
	public void testExecute() throws Exception {
		TestMachine machine = new TestMachine();
		TraceSchedule time = TraceSchedule.parse("1:4;t0-3;t1-2.1");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", ToyProgramBuilder._TOY64_BE)) {
			TraceThread t2;
			try (Transaction tx = tb.startTransaction()) {
				tb.trace.getThreadManager().createThread("Threads[0]", 0);
				tb.trace.getThreadManager().createThread("Threads[1]", 0);
				t2 = tb.trace.getThreadManager().createThread("Threads[2]", 0);
				tb.trace.getTimeManager().getSnapshot(1, true).setEventThread(t2);
			}
			time.execute(tb.trace, machine, TaskMonitor.DUMMY);
		}

		assertEquals(List.of(
			"ti:Threads[2]",
			"ti:Threads[2]",
			"ti:Threads[2]",
			"ti:Threads[2]",
			"ti:Threads[0]",
			"ti:Threads[0]",
			"ti:Threads[0]",
			"ti:Threads[1]",
			"ti:Threads[1]",
			"tp:Threads[1]"),
			machine.record);
	}

	@Test
	public void testExecuteWithSkips() throws Exception {
		TestMachine machine = new TestMachine();
		TraceSchedule time = TraceSchedule.parse("1:4;t0-s3;t1-2.s1");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", ToyProgramBuilder._TOY64_BE)) {
			TraceThread t2;
			try (Transaction tx = tb.startTransaction()) {
				tb.trace.getThreadManager().createThread("Threads[0]", 0);
				tb.trace.getThreadManager().createThread("Threads[1]", 0);
				t2 = tb.trace.getThreadManager().createThread("Threads[2]", 0);
				tb.trace.getTimeManager().getSnapshot(1, true).setEventThread(t2);
			}
			time.execute(tb.trace, machine, TaskMonitor.DUMMY);
		}

		assertEquals(List.of(
			"ti:Threads[2]",
			"ti:Threads[2]",
			"ti:Threads[2]",
			"ti:Threads[2]",
			"si:Threads[0]",
			"si:Threads[0]",
			"si:Threads[0]",
			"ti:Threads[1]",
			"ti:Threads[1]",
			"sp:Threads[1]"),
			machine.record);
	}

	@Test
	public void testSleighSteps() throws Exception {
		TestMachine machine = new TestMachine();
		TraceSchedule time = TraceSchedule.parse("1:{r0=0x1234};4");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			TraceThread t2;
			try (Transaction tx = tb.startTransaction()) {
				tb.trace.getThreadManager().createThread("Threads[0]", 0);
				tb.trace.getThreadManager().createThread("Threads[1]", 0);
				t2 = tb.trace.getThreadManager().createThread("Threads[2]", 0);
				tb.trace.getTimeManager().getSnapshot(1, true).setEventThread(t2);
			}
			time.execute(tb.trace, machine, TaskMonitor.DUMMY);
		}

		assertEquals(List.of(
			"x:Threads[2]",
			"ti:Threads[2]",
			"ti:Threads[2]",
			"ti:Threads[2]",
			"ti:Threads[2]"),
			machine.record);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testExecuteNoEventThreadErr() throws Exception {
		TestMachine machine = new TestMachine();
		TraceSchedule time = TraceSchedule.parse("1:4;t0-3;t1-2.1");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			try (Transaction tx = tb.startTransaction()) {
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
		TraceSchedule time = TraceSchedule.parse("1:4;t0-3;t5-2.1");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			TraceThread t2;
			try (Transaction tx = tb.startTransaction()) {
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
		TraceSchedule time = TraceSchedule.parse("1:4;t0-3;t1-2.1");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			TraceThread t2;
			try (Transaction tx = tb.startTransaction()) {
				tb.trace.getThreadManager().createThread("Threads[0]", 0);
				tb.trace.getThreadManager().createThread("Threads[1]", 0);
				t2 = tb.trace.getThreadManager().createThread("Threads[2]", 0);
				tb.trace.getTimeManager().getSnapshot(1, true).setEventThread(t2);
			}
			time.finish(tb.trace, TraceSchedule.parse("1:4;t0-2"), machine, TaskMonitor.DUMMY);
		}

		assertEquals(List.of(
			"ti:Threads[0]",
			"ti:Threads[1]",
			"ti:Threads[1]",
			"tp:Threads[1]"),
			machine.record);
	}

	@Test
	public void testFinishPcode() throws Exception {
		TestMachine machine = new TestMachine();
		TraceSchedule time = TraceSchedule.parse("1:4;t0-3;t1-2.1");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			TraceThread t2;
			try (Transaction tx = tb.startTransaction()) {
				tb.trace.getThreadManager().createThread("Threads[0]", 0);
				tb.trace.getThreadManager().createThread("Threads[1]", 0);
				t2 = tb.trace.getThreadManager().createThread("Threads[2]", 0);
				tb.trace.getTimeManager().getSnapshot(1, true).setEventThread(t2);
			}
			time.finish(tb.trace, TraceSchedule.parse("1:4;t0-3;t1-2"), machine,
				TaskMonitor.DUMMY);
		}

		assertEquals(List.of(
			"tp:Threads[1]"),
			machine.record);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testFinishUnrelatedErr() throws Exception {
		TestMachine machine = new TestMachine();
		TraceSchedule time = TraceSchedule.parse("1:4;t0-3;t1-2.1");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			TraceThread t2;
			try (Transaction tx = tb.startTransaction()) {
				tb.trace.getThreadManager().createThread("Threads[0]", 0);
				tb.trace.getThreadManager().createThread("Threads[1]", 0);
				t2 = tb.trace.getThreadManager().createThread("Threads[2]", 0);
				tb.trace.getTimeManager().getSnapshot(1, true).setEventThread(t2);
			}
			time.finish(tb.trace, TraceSchedule.parse("1:4;t0-4"), machine, TaskMonitor.DUMMY);
		}
	}

	@Test
	public void testCoalescePatches() throws Exception {
		// TODO: Should parse require coalescing? Can't without passing a language...
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			TraceThread thread;
			try (Transaction tx = tb.startTransaction()) {
				thread = tb.trace.getThreadManager().createThread("Threads[0]", 0);
			}
			TraceSchedule time = TraceSchedule.parse("0");
			time = time.patched(thread, tb.language, "r0l=1");
			assertEquals("0:t0-{r0l=0x1}", time.toString());
			time = time.patched(thread, tb.language, "r0h=2");
			assertEquals("0:t0-{r0=0x200000001}", time.toString());
			time = time.patched(thread, tb.language, "r1l=3")
					.patched(thread, tb.language, "*[ram]:4 0xcafe:8=0xdeadbeef");
			assertEquals("0:t0-{*:4 0xcafe:8=0xdeadbeef};t0-{r0=0x200000001};t0-{r1l=0x3}",
				time.toString());

			time = time.patched(thread, tb.language, "*:8 0xcb00:8 = 0x1122334455667788");
			assertEquals("0:t0-{*:8 0xcafe:8=0xdead112233445566};t0-{*:2 0xcb06:8=0x7788};" +
				"t0-{r0=0x200000001};t0-{r1l=0x3}", time.toString());
		}
	}
}
