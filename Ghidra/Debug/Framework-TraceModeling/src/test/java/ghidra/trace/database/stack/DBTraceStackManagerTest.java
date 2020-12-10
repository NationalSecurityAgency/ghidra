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
package ghidra.trace.database.stack;

import static org.junit.Assert.*;

import java.util.List;

import org.apache.commons.collections4.IterableUtils;
import org.junit.*;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.util.database.UndoableTransaction;

public class DBTraceStackManagerTest extends AbstractGhidraHeadlessIntegrationTest {

	ToyDBTraceBuilder b;
	DBTraceStackManager stackManager;

	@Before
	public void setUpStackManagerTest() throws Exception {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");
		stackManager = b.trace.getStackManager();
	}

	@After
	public void tearDownStackManagerTest() throws Exception {
		b.close();
	}

	@Test
	public void testCreateStack() throws Exception {
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceThread thread = b.getOrAddThread("Thread 1", 0);
			stackManager.getStack(thread, 0, true);
		}
	}

	@Test
	public void testSetDepth() throws Exception {
		DBTraceStack stack;
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceThread thread = b.getOrAddThread("Thread 1", 0);
			stack = stackManager.getStack(thread, 0, true);
			stack.setDepth(1, true);
			stack.setDepth(3, false);
			stack.setDepth(5, true);
		}
		int expectedLevel = 0;
		for (TraceStackFrame frame : stack.getFrames()) {
			assertEquals(expectedLevel++, frame.getLevel());
		}
		assertEquals(5, expectedLevel);

		try (UndoableTransaction tid = b.startTransaction()) {
			stack.setDepth(3, true);
		}

		expectedLevel = 0;
		for (TraceStackFrame frame : stack.getFrames()) {
			assertEquals(expectedLevel++, frame.getLevel());
		}
		assertEquals(3, expectedLevel);

		try (UndoableTransaction tid = b.startTransaction()) {
			stack.setDepth(1, false);
		}

		expectedLevel = 0;
		for (TraceStackFrame frame : stack.getFrames()) {
			assertEquals(expectedLevel++, frame.getLevel());
		}
		assertEquals(1, expectedLevel);
	}

	@Test
	public void testGetLatestStack() throws Exception {
		DBTraceThread thread1;
		DBTraceThread thread2;
		DBTraceStack stack1a;
		DBTraceStack stack1b;
		DBTraceStack stack2a;
		DBTraceStack stack2b;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread1 = b.getOrAddThread("Thread 1", 0);
			thread2 = b.getOrAddThread("Thread 2", 0);
			stack1a = stackManager.getStack(thread1, 2, true);
			stack1b = stackManager.getStack(thread1, 10, true);
			stack2a = stackManager.getStack(thread2, 2, true);
			stack2b = stackManager.getStack(thread2, 10, true);
		}

		assertNull(stackManager.getLatestStack(thread1, 0));
		assertEquals(stack1a, stackManager.getLatestStack(thread1, 2));
		assertEquals(stack1a, stackManager.getLatestStack(thread1, 5));
		assertEquals(stack1b, stackManager.getLatestStack(thread1, 10));
		assertEquals(stack1b, stackManager.getLatestStack(thread1, 100));

		assertNull(stackManager.getLatestStack(thread2, 0));
		assertEquals(stack2a, stackManager.getLatestStack(thread2, 2));
		assertEquals(stack2a, stackManager.getLatestStack(thread2, 5));
		assertEquals(stack2b, stackManager.getLatestStack(thread2, 10));
		assertEquals(stack2b, stackManager.getLatestStack(thread2, 100));
	}

	@Test
	public void testGetFramesIn() throws Exception {
		DBTraceStackFrame frame1a;
		DBTraceStackFrame frame1b;
		DBTraceStackFrame frame2a;
		DBTraceStackFrame frame2b;
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceThread thread = b.getOrAddThread("Thread 1", 0);

			DBTraceStack stack1 = stackManager.getStack(thread, 0, true);
			stack1.setDepth(2, true);
			(frame1a = stack1.getFrame(0, false)).setProgramCounter(b.addr(0x0040100));
			(frame1b = stack1.getFrame(1, false)).setProgramCounter(b.addr(0x0040300));

			DBTraceStack stack2 = stackManager.getStack(thread, 1, true);
			stack2.setDepth(2, true);
			(frame2a = stack2.getFrame(0, false)).setProgramCounter(b.addr(0x0040200));
			(frame2b = stack2.getFrame(1, false)).setProgramCounter(b.addr(0x0040400));
		}

		assertEquals(List.of(frame1a, frame2a, frame1b, frame2b),
			IterableUtils.toList(stackManager.getFramesIn(b.set(b.drng(0x0040000, 0x0050000)))));

		assertEquals(List.of(frame1a, frame1b), IterableUtils.toList(stackManager
				.getFramesIn(b.set(b.drng(0x0040000, 0x00401ff), b.drng(0x0040300, 0x0040300)))));
	}

	@Test
	public void testStackGetThread() throws Exception {
		DBTraceThread thread;
		DBTraceStack stack;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread 1", 0);
			stack = stackManager.getStack(thread, 0, true);
		}

		assertEquals(thread, stack.getThread());
	}

	@Test
	public void testStackGetSnap() throws Exception {
		DBTraceThread thread;
		DBTraceStack stack;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread 1", 0);
			stack = stackManager.getStack(thread, 2, true);
		}

		assertEquals(2, stack.getSnap());
	}

	@Test
	public void testStackGetDepth() throws Exception {
		DBTraceThread thread;
		DBTraceStack stack;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread 1", 0);
			stack = stackManager.getStack(thread, 0, true);
			stack.setDepth(2, true);
		}

		assertEquals(2, stack.getDepth());
	}

	@Test
	public void testStackGetFrames() throws Exception {
		DBTraceThread thread;
		DBTraceStack stack;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread 1", 0);
			stack = stackManager.getStack(thread, 0, true);
			stack.setDepth(2, true);
		}

		List<TraceStackFrame> frames = stack.getFrames();
		assertEquals(2, frames.size());
		assertEquals(stack.getFrame(0, false), frames.get(0));
		assertEquals(stack.getFrame(1, false), frames.get(1));
	}

	@Test
	public void testStackDelete() throws Exception {
		DBTraceThread thread;
		DBTraceStack stack;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread 1", 0);
			stack = stackManager.getStack(thread, 0, true);
			stack.setDepth(2, true);
		}

		assertFalse(stack.isDeleted());
		assertEquals(1, stackManager.stackStore.getRecordCount());
		assertEquals(2, stackManager.frameStore.getRecordCount());

		try (UndoableTransaction tid = b.startTransaction()) {
			stack.delete();
		}

		assertTrue(stack.isDeleted());
		assertEquals(0, stackManager.stackStore.getRecordCount());
		assertEquals(0, stackManager.frameStore.getRecordCount());
	}

	@Test
	public void testStackFrameGetStack() throws Exception {
		DBTraceThread thread;
		DBTraceStack stack;
		DBTraceStackFrame frame;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread 1", 0);
			stack = stackManager.getStack(thread, 0, true);
			frame = stack.getFrame(0, true);
		}

		assertEquals(stack, frame.getStack());
	}

	@Test
	public void testStackFrameGetLevel() throws Exception {
		DBTraceThread thread;
		DBTraceStack stack;
		DBTraceStackFrame frame0;
		DBTraceStackFrame frame1;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread 1", 0);
			stack = stackManager.getStack(thread, 0, true);
			stack.setDepth(2, true);
			frame0 = stack.getFrame(0, false);
			frame1 = stack.getFrame(1, false);
		}

		assertEquals(0, frame0.getLevel());
		assertEquals(1, frame1.getLevel());
	}

	@Test
	public void testStackFrameSetGetProgramCounter() throws Exception {
		DBTraceThread thread;
		DBTraceStack stack;
		DBTraceStackFrame frame;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread 1", 0);
			stack = stackManager.getStack(thread, 0, true);
			stack.setDepth(1, true);
			frame = stack.getFrame(0, false);

			assertNull(frame.getProgramCounter());
			frame.setProgramCounter(b.addr(0x00400123));
		}

		assertEquals(b.addr(0x00400123), frame.getProgramCounter());
	}

	@Test
	public void testStackFrameSetGetComment() throws Exception {
		DBTraceThread thread;
		DBTraceStack stack;
		DBTraceStackFrame frame;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread 1", 0);
			stack = stackManager.getStack(thread, 0, true);
			stack.setDepth(1, true);
			frame = stack.getFrame(0, false);

			assertNull(frame.getComment());
			frame.setComment("Hello, World!");
		}

		assertEquals("Hello, World!", frame.getComment());
	}
}
