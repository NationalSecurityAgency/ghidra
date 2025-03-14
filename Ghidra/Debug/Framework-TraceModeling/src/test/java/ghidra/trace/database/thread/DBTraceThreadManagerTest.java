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

import static org.junit.Assert.*;

import java.util.Set;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.*;

import db.Transaction;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceThreadManagerTest extends AbstractGhidraHeadlessIntegrationTest {

	ToyDBTraceBuilder b;
	DBTraceThreadManager threadManager;

	TraceThread thread1;
	TraceThread thread2;

	protected void addThreads() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			thread1 = threadManager.createThread("Threads[1]", 0);
			thread2 = threadManager.addThread("Threads[2]", Lifespan.span(0, 10));
		}
	}

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
		addThreads();
		try (Transaction tx = b.startTransaction()) {
			// TODO: Let this work by expanding the life instead
			threadManager.createThread("Threads[1]", 1);
			fail();
		}
		catch (DuplicateNameException e) {
			// pass
		}

		assertEquals(Set.of(thread1), Set.copyOf(threadManager.getThreadsByPath("Threads[1]")));
	}

	@Test
	public void testGetAllThreads() throws Exception {
		assertEquals(Set.of(), Set.copyOf(threadManager.getAllThreads()));

		addThreads();
		assertEquals(Set.of(thread1, thread2), Set.copyOf(threadManager.getAllThreads()));
	}

	@Test
	public void testGetThreadsByPath() throws Exception {
		assertEquals(Set.of(), Set.copyOf(threadManager.getThreadsByPath("Threads[1]")));

		addThreads();
		assertEquals(Set.of(thread1), Set.copyOf(threadManager.getThreadsByPath("Threads[1]")));
		assertEquals(Set.of(thread2), Set.copyOf(threadManager.getThreadsByPath("Threads[2]")));
	}

	protected static class InvalidThreadMatcher extends BaseMatcher<TraceThread> {
		private final long snap;

		public InvalidThreadMatcher(long snap) {
			this.snap = snap;
		}

		@Override
		public boolean matches(Object actual) {
			return actual == null || actual instanceof TraceThread thread && !thread.isValid(snap);
		}

		@Override
		public void describeTo(Description description) {
			description.appendText("An invalid or null thread");
		}
	}

	protected static InvalidThreadMatcher invalidThread(long snap) {
		return new InvalidThreadMatcher(snap);
	}

	@Test
	public void testLiveThreadByPath() throws Exception {
		assertNull(threadManager.getLiveThreadByPath(0, "Threads[1]"));

		addThreads();
		assertEquals(thread1, threadManager.getLiveThreadByPath(0, "Threads[1]"));
		assertEquals(thread2, threadManager.getLiveThreadByPath(0, "Threads[2]"));
		assertEquals(thread2, threadManager.getLiveThreadByPath(10, "Threads[2]"));
		assertNull(threadManager.getLiveThreadByPath(0, "Threads[3]"));
		assertThat(threadManager.getLiveThreadByPath(-1, "Threads[2]"), invalidThread(-1));
		assertThat(threadManager.getLiveThreadByPath(11, "Threads[2]"), invalidThread(11));
	}

	@Test
	public void testGetThread() throws Exception {
		assertNull(threadManager.getThread(0));

		addThreads();
		assertEquals(thread1, threadManager.getThread(thread1.getKey()));
		assertEquals(thread2, threadManager.getThread(thread2.getKey()));
	}

	@Test
	public void testGetLiveThreads() throws Exception {
		assertEquals(Set.of(), threadManager.getLiveThreads(0));

		addThreads();
		assertEquals(Set.of(), threadManager.getLiveThreads(-1));
		assertEquals(Set.of(thread1, thread2), threadManager.getLiveThreads(0));
		assertEquals(Set.of(thread1, thread2), threadManager.getLiveThreads(9));
		// NB. Destruction is included
		assertEquals(Set.of(thread1, thread2), threadManager.getLiveThreads(10));
		assertEquals(Set.of(thread1), threadManager.getLiveThreads(11));
	}
}
