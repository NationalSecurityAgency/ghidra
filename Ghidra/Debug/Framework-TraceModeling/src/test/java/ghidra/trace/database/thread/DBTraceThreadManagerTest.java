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
package ghidra.trace.database.thread;

import static ghidra.lifecycle.Unfinished.TODO;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.*;

import com.google.common.collect.Range;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceThreadManagerTest extends AbstractGhidraHeadlessIntegrationTest {

	ToyDBTraceBuilder b;
	DBTraceThreadManager threadManager;

	@Before
	public void setUpThreadManagerTest() throws Exception {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");
		threadManager = b.trace.getThreadManager();
	}

	@After
	public void tearDownThreadManagerTest() throws Exception {
		b.close();
	}

	@Test
	public void testAddThread() throws Exception {
		try (UndoableTransaction tid = b.startTransaction()) {
			threadManager.createThread("Thread 1", 0);
			threadManager.addThread("Thread 2", Range.closed(0L, 10L));
		}

		try (UndoableTransaction tid = b.startTransaction()) {
			threadManager.createThread("Thread 1", 1);
			fail();
		}
		catch (DuplicateNameException e) {
			// pass
		}

		assertEquals(1, threadManager.getThreadsByPath("Thread 1").size());
	}

	@Test
	@Ignore("TODO")
	public void testMore() throws Exception {
		TODO();
	}
}
