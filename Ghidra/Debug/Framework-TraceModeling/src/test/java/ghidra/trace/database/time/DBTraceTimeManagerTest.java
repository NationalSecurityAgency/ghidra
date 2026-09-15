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
package ghidra.trace.database.time;

import static org.junit.Assert.*;

import org.junit.*;

import db.Transaction;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.time.schedule.TraceSchedule;

public class DBTraceTimeManagerTest extends AbstractGhidraHeadlessIntegrationTest {

	ToyDBTraceBuilder b;
	DBTraceTimeManager timeManager;

	@Before
	public void setUpTimeManagerTest() throws Exception {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");
		timeManager = b.trace.getTimeManager();
	}

	@After
	public void tearDownTimeManagerTest() throws Exception {
		b.close();
	}

	@Test
	public void testFindSnapshotWithNearestPrefix() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			assertNotNull(timeManager.findScratchSnapshot(TraceSchedule.parse("0:t0-2")));
			assertNotNull(timeManager.findScratchSnapshot(TraceSchedule.parse("0:t0-20;t1-9")));
			assertNotNull(timeManager.findScratchSnapshot(TraceSchedule.parse("0:t0-20;t1-10")));
			assertNotNull(timeManager.findScratchSnapshot(TraceSchedule.parse("0:t0-3;t1-10")));
			assertNotNull(timeManager.findScratchSnapshot(TraceSchedule.parse("0:t0-4")));
		}

		assertEquals("0:t0-20;t1-10",
			timeManager.findSnapshotWithNearestPrefix(TraceSchedule.parse("0:t0-20;t1-10"))
					.getScheduleString());
		assertEquals("0:t0-20;t1-10",
			timeManager.findSnapshotWithNearestPrefix(TraceSchedule.parse("0:t0-20;t1-11"))
					.getScheduleString());
		assertEquals("0:t0-2",
			timeManager.findSnapshotWithNearestPrefix(TraceSchedule.parse("0:t0-3"))
					.getScheduleString());
		assertEquals("0:t0-4",
			timeManager.findSnapshotWithNearestPrefix(TraceSchedule.parse("0:t0-5"))
					.getScheduleString());

		assertNull(timeManager.findSnapshotWithNearestPrefix(TraceSchedule.parse("1:t0-1")));
	}
}
