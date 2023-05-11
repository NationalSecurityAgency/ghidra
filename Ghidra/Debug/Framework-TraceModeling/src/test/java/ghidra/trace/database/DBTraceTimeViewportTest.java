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
package ghidra.trace.database;

import static org.junit.Assert.*;

import org.junit.Test;

import db.Transaction;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.time.DBTraceTimeManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Lifespan.*;
import ghidra.trace.model.time.schedule.TraceSchedule;

public class DBTraceTimeViewportTest extends AbstractGhidraHeadlessIntegrationTest {
	public static <C extends Comparable<C>> LifeSet lifeSetOf(Lifespan... spans) {
		MutableLifeSet result = new DefaultLifeSet();
		for (Lifespan s : spans) {
			result.add(s);
		}
		return result;
	}

	@Test
	public void testEmptyTime() throws Exception {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			DBTraceTimeViewport viewport = tb.trace.createTimeViewport();
			viewport.setSnap(10);
			assertEquals(lifeSetOf(Lifespan.span(Long.MIN_VALUE, 10)), viewport.spanSet);
		}
	}

	@Test
	public void testSelfScheduleSnapshot0RemovesScratch() throws Exception {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			try (Transaction tx = tb.startTransaction()) {
				tb.trace.getTimeManager().getSnapshot(0, true).setSchedule(TraceSchedule.snap(0));
			}

			DBTraceTimeViewport viewport = tb.trace.createTimeViewport();
			viewport.setSnap(10);
			assertEquals(lifeSetOf(Lifespan.span(0, 10)), viewport.spanSet);
		}
	}

	@Test
	public void testNotationalSchedulesDontFork() throws Exception {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			try (Transaction tx = tb.startTransaction()) {
				DBTraceTimeManager tm = tb.trace.getTimeManager();
				tm.getSnapshot(0, true).setSchedule(TraceSchedule.snap(0));
				tm.getSnapshot(5, true).setSchedule(TraceSchedule.parse("4:1"));
			}

			DBTraceTimeViewport viewport = tb.trace.createTimeViewport();
			viewport.setSnap(10);
			assertEquals(lifeSetOf(Lifespan.span(0, 10)), viewport.spanSet);
		}
	}

	@Test
	public void testForkFromScratch() throws Exception {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			try (Transaction tx = tb.startTransaction()) {
				DBTraceTimeManager tm = tb.trace.getTimeManager();
				tm.getSnapshot(0, true).setSchedule(TraceSchedule.snap(0));
				tm.getSnapshot(Long.MIN_VALUE, true).setSchedule(TraceSchedule.parse("10:4"));
			}

			DBTraceTimeViewport viewport = tb.trace.createTimeViewport();
			viewport.setSnap(Long.MIN_VALUE);
			assertEquals(lifeSetOf(Lifespan.at(Long.MIN_VALUE), Lifespan.span(0, 10)),
				viewport.spanSet);
		}
	}

	@Test
	public void testCyclesIgnored() throws Exception {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("test", "Toy:BE:64:default")) {
			try (Transaction tx = tb.startTransaction()) {
				DBTraceTimeManager tm = tb.trace.getTimeManager();
				tm.getSnapshot(Long.MIN_VALUE, true).setSchedule(TraceSchedule.parse("10:4"));
			}

			DBTraceTimeViewport viewport = tb.trace.createTimeViewport();
			viewport.setSnap(Long.MIN_VALUE);
			assertEquals(lifeSetOf(Lifespan.at(Long.MIN_VALUE)), viewport.spanSet);
		}
	}
}
