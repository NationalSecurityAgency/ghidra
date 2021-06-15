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
package ghidra.dbg.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import org.junit.Test;

import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultDebuggerObjectModelTest.FakeTargetObject;
import ghidra.dbg.agent.DefaultDebuggerObjectModelTest.FakeTargetRegisterBank;
import ghidra.dbg.agent.DefaultTargetModelRoot;
import ghidra.dbg.model.EmptyDebuggerObjectModel;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.testutil.DebuggerModelTestUtils;

public class DebuggerCallbackReordererTest implements DebuggerModelTestUtils {

	@TargetObjectSchemaInfo
	public static class EmptyTargetSession extends DefaultTargetModelRoot {
		public EmptyTargetSession(AbstractDebuggerObjectModel model, String typeHint,
				TargetObjectSchema schema) {
			super(model, typeHint, schema);
		}
	}

	public static final AnnotatedSchemaContext SCHEMA_CTX = new AnnotatedSchemaContext();
	public static final TargetObjectSchema EMPTY_SCHEMA =
		SCHEMA_CTX.getSchemaForClass(EmptyTargetSession.class);

	public static class TestReorderedListener implements DebuggerModelListener {
		protected final DebuggerCallbackReorderer reorderer = new DebuggerCallbackReorderer(this);
		protected final Map<List<String>, CompletableFuture<TargetObject>> waits;
		protected final List<TargetObject> added = new ArrayList<>();

		public TestReorderedListener(Collection<List<String>> paths) {
			waits =
				paths.stream().collect(Collectors.toMap(p -> p, p -> new CompletableFuture<>()));
		}

		protected void done(TargetObject obj) {
			synchronized (added) {
				added.add(obj);
			}
			CompletableFuture<TargetObject> cf = waits.get(obj.getPath());
			if (cf != null) {
				cf.complete(obj);
			}
		}

		public CompletableFuture<TargetObject> get(List<String> path) {
			return waits.get(path);
		}

		public List<TargetObject> getAdded() {
			synchronized (added) {
				assertEquals("Duplicates added: " + added, added.size(), Set.copyOf(added).size());
				return List.copyOf(added);
			}
		}

		@Override
		public void rootAdded(TargetObject root) {
			done(root);
		}

		@Override
		public void attributesChanged(TargetObject object, Collection<String> removed,
				Map<String, ?> added) {
			for (Object val : added.values()) {
				if (val instanceof TargetObject) {
					done((TargetObject) val);
				}
			}
		}

		@Override
		public void elementsChanged(TargetObject object, Collection<String> removed,
				Map<String, ? extends TargetObject> added) {
			for (TargetObject obj : added.values()) {
				done(obj);
			}
		}
	}

	@Test
	public void testRootOnly() throws Throwable {
		EmptyDebuggerObjectModel model = new EmptyDebuggerObjectModel();
		TestReorderedListener listener = new TestReorderedListener(List.of(PathUtils.parse("")));
		model.addModelListener(listener.reorderer);

		assertEquals(List.of(), listener.getAdded());
		DefaultTargetModelRoot root =
			new DefaultTargetModelRoot(model, "Root", model.getRootSchema());
		model.addModelRoot(root);
		assertEquals(root, waitOn(listener.get(PathUtils.parse(""))));
	}

	@Test
	public void testChain2TopDown() throws Throwable {
		EmptyDebuggerObjectModel model = new EmptyDebuggerObjectModel();
		TestReorderedListener listener =
			new TestReorderedListener(List.of(PathUtils.parse("A[1]")));
		model.addModelListener(listener.reorderer);

		DefaultTargetModelRoot root =
			new DefaultTargetModelRoot(model, "Root", model.getRootSchema());
		FakeTargetObject toA = new FakeTargetObject(model, root, "A");
		FakeTargetObject toA1 = new FakeTargetObject(model, toA, "[1]");

		model.addModelRoot(root);
		root.changeAttributes(List.of(), List.of(toA), Map.of(), "Test");
		toA.changeElements(List.of(), List.of(toA1), "Test");

		assertEquals(toA1, waitOn(listener.get(PathUtils.parse("A[1]"))));
		assertEquals(List.of(root, toA, toA1), listener.getAdded());
	}

	@Test
	public void testChain2BottomUp() throws Throwable {
		EmptyDebuggerObjectModel model = new EmptyDebuggerObjectModel();
		TestReorderedListener listener =
			new TestReorderedListener(List.of(PathUtils.parse("A[1]")));
		model.addModelListener(listener.reorderer);

		DefaultTargetModelRoot root =
			new DefaultTargetModelRoot(model, "Root", model.getRootSchema());
		FakeTargetObject toA = new FakeTargetObject(model, root, "A");
		FakeTargetObject toA1 = new FakeTargetObject(model, toA, "[1]");

		toA.changeElements(List.of(), List.of(toA1), "Test");
		root.changeAttributes(List.of(), List.of(toA), Map.of(), "Test");
		model.addModelRoot(root);

		assertEquals(toA1, waitOn(listener.get(PathUtils.parse("A[1]"))));
		assertEquals(List.of(root, toA, toA1), listener.getAdded());
	}

	@Test
	public void testChain3RootLast() throws Throwable {
		EmptyDebuggerObjectModel model = new EmptyDebuggerObjectModel();
		TestReorderedListener listener =
			new TestReorderedListener(List.of(PathUtils.parse("A[1].i")));
		model.addModelListener(listener.reorderer);

		DefaultTargetModelRoot root =
			new DefaultTargetModelRoot(model, "Root", model.getRootSchema());
		FakeTargetObject toA = new FakeTargetObject(model, root, "A");
		FakeTargetObject toA1 = new FakeTargetObject(model, toA, "[1]");
		FakeTargetObject toA1i = new FakeTargetObject(model, toA1, "i");

		toA.changeElements(List.of(), List.of(toA1), "Test");
		root.changeAttributes(List.of(), List.of(toA), Map.of(), "Test");
		toA1.changeAttributes(List.of(), List.of(toA1i), Map.of(), "Test");
		model.addModelRoot(root);

		assertEquals(toA1i, waitOn(listener.get(PathUtils.parse("A[1].i"))));
		assertEquals(List.of(root, toA, toA1, toA1i), listener.getAdded());
	}

	@Test
	public void test2xChain2BottomUpBreadth() throws Throwable {
		EmptyDebuggerObjectModel model = new EmptyDebuggerObjectModel();
		TestReorderedListener listener = new TestReorderedListener(List.of(
			PathUtils.parse("A[1]"),
			PathUtils.parse("B[2]")));
		model.addModelListener(listener.reorderer);

		DefaultTargetModelRoot root =
			new DefaultTargetModelRoot(model, "Root", model.getRootSchema());
		FakeTargetObject toA = new FakeTargetObject(model, root, "A");
		FakeTargetObject toA1 = new FakeTargetObject(model, toA, "[1]");
		FakeTargetObject toB = new FakeTargetObject(model, root, "B");
		FakeTargetObject toB2 = new FakeTargetObject(model, toB, "[2]");

		toA.changeElements(List.of(), List.of(toA1), "Test");
		toB.changeElements(List.of(), List.of(toB2), "Test");
		root.changeAttributes(List.of(), List.of(toA, toB), Map.of(), "Test");
		model.addModelRoot(root);

		assertEquals(toA1, waitOn(listener.get(PathUtils.parse("A[1]"))));
		assertEquals(toB2, waitOn(listener.get(PathUtils.parse("B[2]"))));

		// Note the order is not unique, but there are constraints.
		// It's similar to a topological sort.
		List<TargetObject> order = List.copyOf(listener.getAdded());
		assertEquals(0, order.indexOf(root));
		assertTrue(order.indexOf(root) < order.indexOf(toA));
		assertTrue(order.indexOf(root) < order.indexOf(toB));
		assertTrue(order.indexOf(toA) < order.indexOf(toA1));
		assertTrue(order.indexOf(toB) < order.indexOf(toB2));
	}

	@Test
	public void test2xChain2BottomUpDepthRootBefore2nd() throws Throwable {
		EmptyDebuggerObjectModel model = new EmptyDebuggerObjectModel();
		TestReorderedListener listener = new TestReorderedListener(List.of(
			PathUtils.parse("A[1]"),
			PathUtils.parse("B[2]")));
		model.addModelListener(listener.reorderer);

		DefaultTargetModelRoot root =
			new DefaultTargetModelRoot(model, "Root", model.getRootSchema());
		FakeTargetObject toA = new FakeTargetObject(model, root, "A");
		FakeTargetObject toA1 = new FakeTargetObject(model, toA, "[1]");
		FakeTargetObject toB = new FakeTargetObject(model, root, "B");
		FakeTargetObject toB2 = new FakeTargetObject(model, toB, "[2]");

		toA.changeElements(List.of(), List.of(toA1), "Test");
		root.changeAttributes(List.of(), List.of(toA), Map.of(), "Test");
		model.addModelRoot(root);
		toB.changeElements(List.of(), List.of(toB2), "Test");
		root.changeAttributes(List.of(), List.of(toB), Map.of(), "Test");

		assertEquals(toA1, waitOn(listener.get(PathUtils.parse("A[1]"))));
		assertEquals(toB2, waitOn(listener.get(PathUtils.parse("B[2]"))));
		assertEquals(List.of(root, toA, toA1, toB, toB2), listener.getAdded());
	}

	@Test
	public void testEventOrdering() throws Throwable {
		EmptyDebuggerObjectModel model = new EmptyDebuggerObjectModel();
		var listener = new TestReorderedListener(List.of(PathUtils.parse("A[r1].i"))) {
			List<TargetObject> captured;

			@Override
			public void registersUpdated(TargetObject bank, Map<String, byte[]> updates) {
				captured = getAdded(); // NB. "duplicates" exception may cause NPE
			}
		};
		model.addModelListener(listener.reorderer);

		DefaultTargetModelRoot root =
			new DefaultTargetModelRoot(model, "Root", model.getRootSchema());
		FakeTargetObject toA = new FakeTargetRegisterBank(model, root, "A");
		FakeTargetObject toA1 = new FakeTargetObject(model, toA, "[r1]");
		FakeTargetObject toA1i = new FakeTargetObject(model, toA1, "i");

		/**
		 * Because A's elements will be added before registersUpdated is replayed, we wait on a
		 * child of [r1], to guarantee registersUpdated has happened
		 */
		toA.changeElements(List.of(), List.of(toA1), "Test");
		toA.getListeners().fire.registersUpdated(toA, Map.of("r1", new byte[4]));
		root.changeAttributes(List.of(), List.of(toA), Map.of(), "Test");
		/**
		 * CFs may get queued in depth, so add root here to ensure registersUpdated comes before
		 * toA1i
		 */
		model.addModelRoot(root);
		toA1.changeAttributes(List.of(), List.of(toA1i), Map.of(), "Test");

		assertEquals(toA1i, waitOn(listener.get(PathUtils.parse("A[r1].i"))));
		assertEquals(List.of(root, toA, toA1), listener.captured);
		listener.getAdded();
	}

	public static class FakeTargetRoot extends DefaultTargetModelRoot implements TargetEventScope {
		public FakeTargetRoot(AbstractDebuggerObjectModel model, String typeHint,
				TargetObjectSchema schema) {
			super(model, typeHint, schema);
		}
	}

	public static class FakeTargetThread extends FakeTargetObject implements TargetThread {
		public FakeTargetThread(AbstractDebuggerObjectModel model, TargetObject parent,
				String name) {
			super(model, parent, name);
		}
	}

	public static class FakeTargetProcess extends FakeTargetObject implements TargetProcess {
		public FakeTargetProcess(AbstractDebuggerObjectModel model, TargetObject parent,
				String name) {
			super(model, parent, name);
		}
	}

	@Test
	public void testEventOrderingResilient() throws Throwable {
		EmptyDebuggerObjectModel model = new EmptyDebuggerObjectModel();
		List<String> toWait = PathUtils.parse("Processes[1].Threads[1].i");
		var listener = new TestReorderedListener(List.of(toWait)) {
			Map<String, List<TargetObject>> events = new LinkedHashMap<>();

			@Override
			public void event(TargetObject object, TargetThread eventThread,
					TargetEventType type,
					String description, List<Object> parameters) {
				while (events.containsKey(description)) {
					description = description + " (DUPLICATE)";
				}
				events.put(description, getAdded());
				// Test that errors do not prevent processing of next event(s)
				throw new RuntimeException("This stack is supposed to appear");
			}
		};
		model.addModelListener(listener.reorderer);

		FakeTargetRoot root = new FakeTargetRoot(model, "Root", model.getRootSchema());
		FakeTargetObject processes = new FakeTargetObject(model, root, "Processes");
		FakeTargetProcess proc1 = new FakeTargetProcess(model, processes, "[1]");
		root.getListeners().fire.event(root, null, TargetEventType.PROCESS_CREATED,
			"Process 1 created", List.of(proc1));
		FakeTargetObject p1threads = new FakeTargetObject(model, proc1, "Threads");
		FakeTargetThread thread1 = new FakeTargetThread(model, p1threads, "[1]");
		root.getListeners().fire.event(root, thread1, TargetEventType.THREAD_CREATED,
			"Thread 1 created", List.of());

		p1threads.changeElements(List.of(), List.of(thread1), "Test");
		proc1.changeAttributes(List.of(), List.of(p1threads), Map.of(), "Test");
		processes.changeElements(List.of(), List.of(proc1), "Test");
		root.changeAttributes(List.of(), List.of(processes), Map.of(), "Test");
		model.addModelRoot(root);
		thread1.changeAttributes(List.of(), List.of(new FakeTargetObject(model, thread1, "i")),
			Map.of(), "Dummy");

		waitOn(listener.get(toWait));
		assertEquals(List.of("Process 1 created", "Thread 1 created"),
			List.copyOf(listener.events.keySet()));
		assertTrue(listener.events.get("Process 1 created").contains(proc1));
		assertTrue(listener.events.get("Thread 1 created").contains(thread1));
	}

	@Test
	public void testEventOrderingCareful() throws Throwable {
		EmptyDebuggerObjectModel model = new EmptyDebuggerObjectModel();
		List<String> toWait = PathUtils.parse("Processes[1].Threads[1].i");
		var listener = new TestReorderedListener(List.of(toWait)) {
			Map<String, List<TargetObject>> events = new LinkedHashMap<>();

			@Override
			public void event(TargetObject object, TargetThread eventThread,
					TargetEventType type,
					String description, List<Object> parameters) {
				while (events.containsKey(description)) {
					description = description + " (DUPLICATE)";
				}
				events.put(description, getAdded());
				// Test that errors do not prevent processing of next event(s)
				throw new RuntimeException("This stack is supposed to appear");
			}
		};
		model.addModelListener(listener.reorderer);
		FakeTargetRoot root = new FakeTargetRoot(model, "Root", model.getRootSchema());
		FakeTargetObject processes = new FakeTargetObject(model, root, "Processes");
		FakeTargetProcess proc1 = new FakeTargetProcess(model, processes, "[1]");
		root.getListeners().fire.event(root, null, TargetEventType.PROCESS_CREATED,
			"Process 1 created", List.of(proc1));
		FakeTargetObject p1threads = new FakeTargetObject(model, proc1, "Threads");
		FakeTargetThread thread1 = new FakeTargetThread(model, p1threads, "[1]");
		root.getListeners().fire.event(root, thread1, TargetEventType.THREAD_CREATED,
			"Thread 1 created", List.of());
		FakeTargetThread thread2 = new FakeTargetThread(model, p1threads, "[2]");
		root.getListeners().fire.event(root, thread1, TargetEventType.THREAD_CREATED,
			"Thread 2 created", List.of());

		p1threads.changeElements(List.of(), List.of(thread2), "Test");
		proc1.changeAttributes(List.of(), List.of(p1threads), Map.of(), "Test");
		processes.changeElements(List.of(), List.of(proc1), "Test");
		root.changeAttributes(List.of(), List.of(processes), Map.of(), "Test");
		model.addModelRoot(root);

		assertTrue(listener.events.isEmpty());

		p1threads.changeElements(List.of(), List.of(thread1), "Test");
		thread1.changeAttributes(List.of(), List.of(new FakeTargetObject(model, thread1, "i")),
			Map.of(), "Dummy");

		waitOn(listener.get(toWait));
		assertEquals(List.of("Process 1 created", "Thread 1 created", "Thread 2 created"),
			List.copyOf(listener.events.keySet()));
		assertTrue(listener.events.get("Process 1 created").contains(proc1));
		assertTrue(listener.events.get("Thread 1 created").contains(thread1));
		assertTrue(listener.events.get("Thread 2 created").contains(thread2));
	}

	@Test
	public void testRootLink() throws Throwable {
		EmptyDebuggerObjectModel model = new EmptyDebuggerObjectModel();
		TestReorderedListener listener = new TestReorderedListener(List.of(PathUtils.parse("")));
		model.addModelListener(listener.reorderer);

		assertEquals(List.of(), listener.getAdded());
		DefaultTargetModelRoot root =
			new DefaultTargetModelRoot(model, "Root", model.getRootSchema());
		root.changeAttributes(List.of(), Map.of("link", root), "Test");
		model.addModelRoot(root);
		assertEquals(root, waitOn(listener.get(PathUtils.parse(""))));
	}
}
