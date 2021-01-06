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
package ghidra.trace.util;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import com.google.common.collect.*;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.time.DBTraceTimeManager;
import ghidra.trace.model.time.TraceSchedule;
import ghidra.util.database.UndoableTransaction;

public class DefaultTraceTimeViewportTest extends AbstractGhidraHeadlessIntegrationTest {
	public static <C extends Comparable<C>> RangeSet<C> rangeSetOf(List<Range<C>> ranges) {
		RangeSet<C> result = TreeRangeSet.create();
		ranges.forEach(result::add);
		return result;
	}

	@Test
	public void testEmptyTime() throws Exception {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			DefaultTraceTimeViewport viewport = new DefaultTraceTimeViewport(tb.trace);
			viewport.setSnap(10);
			assertEquals(rangeSetOf(List.of(Range.closed(Long.MIN_VALUE, 10L))), viewport.spanSet);
		}
	}

	@Test
	public void testSelfScheduleSnapshot0RemovesScratch() throws Exception {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			try (UndoableTransaction tid = tb.startTransaction()) {
				tb.trace.getTimeManager().getSnapshot(0, true).setSchedule(TraceSchedule.snap(0));
			}

			DefaultTraceTimeViewport viewport = new DefaultTraceTimeViewport(tb.trace);
			viewport.setSnap(10);
			assertEquals(rangeSetOf(List.of(Range.closed(0L, 10L))), viewport.spanSet);
		}
	}

	@Test
	public void testNotationalSchedulesDontFork() throws Exception {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			try (UndoableTransaction tid = tb.startTransaction()) {
				DBTraceTimeManager tm = tb.trace.getTimeManager();
				tm.getSnapshot(0, true).setSchedule(TraceSchedule.snap(0));
				tm.getSnapshot(5, true).setSchedule(TraceSchedule.parse("4:1"));
			}

			DefaultTraceTimeViewport viewport = new DefaultTraceTimeViewport(tb.trace);
			viewport.setSnap(10);
			assertEquals(rangeSetOf(List.of(Range.closed(0L, 10L))), viewport.spanSet);
		}
	}

	@Test
	public void testForkFromScratch() throws Exception {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			try (UndoableTransaction tid = tb.startTransaction()) {
				DBTraceTimeManager tm = tb.trace.getTimeManager();
				tm.getSnapshot(0, true).setSchedule(TraceSchedule.snap(0));
				tm.getSnapshot(Long.MIN_VALUE, true).setSchedule(TraceSchedule.parse("10:4"));
			}

			DefaultTraceTimeViewport viewport = new DefaultTraceTimeViewport(tb.trace);
			viewport.setSnap(Long.MIN_VALUE);
			assertEquals(
				rangeSetOf(List.of(Range.singleton(Long.MIN_VALUE), Range.closed(0L, 10L))),
				viewport.spanSet);
		}
	}

	@Test
	public void testCyclesIgnored() throws Exception {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			try (UndoableTransaction tid = tb.startTransaction()) {
				DBTraceTimeManager tm = tb.trace.getTimeManager();
				tm.getSnapshot(Long.MIN_VALUE, true).setSchedule(TraceSchedule.parse("10:4"));
			}

			DefaultTraceTimeViewport viewport = new DefaultTraceTimeViewport(tb.trace);
			viewport.setSnap(Long.MIN_VALUE);
			assertEquals(rangeSetOf(List.of(Range.singleton(Long.MIN_VALUE))), viewport.spanSet);
		}
	}
}
