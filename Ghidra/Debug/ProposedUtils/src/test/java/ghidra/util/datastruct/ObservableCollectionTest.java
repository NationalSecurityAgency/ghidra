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
package ghidra.util.datastruct;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.After;
import org.junit.Test;

import com.google.common.collect.ImmutableList;

import ghidra.util.datastruct.CollectionChangeListener;
import ghidra.util.datastruct.DefaultObservableCollection;
import ghidra.util.datastruct.ObservableCollection.ChangeAggregator;

public class ObservableCollectionTest {
	// Use Object as type parameter to verify listeners for super-type work.
	// Default all calls to fails. No unexpected events, please.

	public interface TestCollectionListener extends CollectionChangeListener<Object> {
	}

	public abstract class DefaultTestCollectionListener implements TestCollectionListener {
		@Override
		public void elementAdded(Object element) {
			spurious();
		}

		@Override
		public void elementModified(Object element) {
			spurious();
		}

		@Override
		public void elementRemoved(Object element) {
			spurious();
		}
	}

	public class TestObservableCollection
			extends DefaultObservableCollection<String, TestCollectionListener> {
		protected TestObservableCollection() {
			super(new LinkedHashSet<>(), TestCollectionListener.class);
		}
	}

	protected boolean gotSpurious = false;

	protected void spurious() {
		gotSpurious = true;
	}

	@After
	public void checkSpurious() {
		assertFalse(gotSpurious);
	}

	/*// Test the test scaffolding
	@Test
	public void testTestCollectionListener() {
		TestObservableCollection col = new TestObservableCollection();
		col.addChangeListener(new DefaultTestCollectionListener() {});
		col.add("Ent1");
	}*/

	@Test
	public void testIsProperWrapper() {
		Collection<String> col = new TestObservableCollection();
		assertTrue(col.add("Ent1"));
		assertTrue(col.add("Ent2"));
		assertTrue(col.contains("Ent1"));
		assertFalse(col.contains("NoSuchEnt"));
		assertFalse(col.remove("Ent3"));
		assertTrue(col.remove("Ent1"));
		assertFalse(col.contains("Ent1"));
		assertEquals(1, col.size());
		assertTrue(col.addAll(ImmutableList.of("Ent1", "Ent3")));
		assertFalse(col.addAll(ImmutableList.of("Ent2", "Ent1")));
		assertTrue(col.removeAll(ImmutableList.of("Ent1", "Ent2", "Ent3")));
		assertTrue(col.isEmpty());
		assertTrue(col.addAll(ImmutableList.of("Ent2", "Ent3")));
		assertTrue(col.retainAll(ImmutableList.of("Ent2", "Ent1")));
		assertTrue(col.contains("Ent2"));
		assertEquals(1, col.size());
		col.clear();
		assertTrue(col.isEmpty());
	}

	@Test
	public void testAddCausesEvent() {
		TestObservableCollection col = new TestObservableCollection();
		AtomicReference<Object> lastAdded = new AtomicReference<>();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementAdded(Object element) {
				lastAdded.set(element);
			}
		};
		col.addChangeListener(listener);
		col.add("Ent1");
		assertEquals("Ent1", lastAdded.get());
		lastAdded.set(null);
		col.add("Ent1"); // Already there, so no event
		assertEquals(null, lastAdded.get());
	}

	@Test
	public void testRemoveCausesEvent() {
		TestObservableCollection col = new TestObservableCollection();
		col.add("Ent1");
		AtomicReference<Object> lastRemoved = new AtomicReference<>();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementRemoved(Object element) {
				lastRemoved.set(element);
			}
		};
		col.addChangeListener(listener);
		col.remove("Ent1");
		assertEquals("Ent1", lastRemoved.get());
		lastRemoved.set(null);
		col.remove("Ent1"); // Already gone, so no event
		assertEquals(null, lastRemoved.get());
	}

	@Test
	public void testRemoveViaIteratorCausesEvent() {
		TestObservableCollection col = new TestObservableCollection();
		col.addAll(ImmutableList.of("Ent1", "Ent2", "Ent3"));
		AtomicReference<Object> lastRemoved = new AtomicReference<>();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementRemoved(Object element) {
				lastRemoved.set(element);
			}
		};
		col.addChangeListener(listener);
		for (Iterator<String> it = col.iterator(); it.hasNext();) {
			String ent = it.next();
			it.remove();
			assertEquals(ent, lastRemoved.get());
		}
		assertTrue(col.isEmpty());
	}

	@Test
	public void testAddAllCausesEvent() {
		TestObservableCollection col = new TestObservableCollection();
		List<Object> added = new ArrayList<>();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementAdded(Object element) {
				added.add(element);
			}
		};
		col.addChangeListener(listener);
		assertTrue(col.addAll(ImmutableList.of("Ent1", "Ent2")));
		assertTrue(col.addAll(ImmutableList.of("Ent3", "Ent2")));
		assertTrue(col.addAll(ImmutableList.of("Ent3", "Ent4")));
		assertFalse(col.addAll(ImmutableList.of("Ent1", "Ent2")));
		assertEquals(ImmutableList.of("Ent1", "Ent2", "Ent3", "Ent4"), added);
	}

	@Test
	public void testRemovalAllCausesEvent() {
		TestObservableCollection col = new TestObservableCollection();
		col.addAll(ImmutableList.of("Ent1", "Ent2", "Ent3", "Ent4"));
		List<Object> removed = new ArrayList<>();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementRemoved(Object element) {
				removed.add(element);
			}
		};
		col.addChangeListener(listener);
		assertTrue(col.removeAll(ImmutableList.of("Ent1", "Ent2")));
		assertTrue(col.removeAll(ImmutableList.of("Ent3", "Ent2")));
		assertTrue(col.removeAll(ImmutableList.of("Ent3", "Ent4")));
		assertFalse(col.removeAll(ImmutableList.of("Ent1", "Ent2")));
		assertEquals(ImmutableList.of("Ent1", "Ent2", "Ent3", "Ent4"), removed);
	}

	@Test
	public void testRetailAllCausesEvent() {
		TestObservableCollection col = new TestObservableCollection();
		col.addAll(ImmutableList.of("Ent1", "Ent2", "Ent3", "Ent4"));
		List<Object> removed = new ArrayList<>();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementRemoved(Object element) {
				removed.add(element);
			}
		};
		col.addChangeListener(listener);
		assertTrue(col.retainAll(ImmutableList.of("Ent3", "Ent4")));
		assertTrue(col.retainAll(ImmutableList.of("Ent4", "Ent1")));
		assertTrue(col.retainAll(ImmutableList.of("Ent1", "Ent2")));
		assertFalse(col.retainAll(ImmutableList.of("Ent3", "Ent4")));
		assertEquals(ImmutableList.of("Ent1", "Ent2", "Ent3", "Ent4"), removed);
	}

	@Test
	public void testClearCausesEvent() {
		TestObservableCollection col = new TestObservableCollection();
		col.addAll(ImmutableList.of("Ent1", "Ent2", "Ent3", "Ent4"));
		List<Object> removed = new ArrayList<>();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementRemoved(Object element) {
				removed.add(element);
			}
		};
		col.addChangeListener(listener);
		col.clear();
		assertEquals(ImmutableList.of("Ent1", "Ent2", "Ent3", "Ent4"), removed);
	}

	@Test
	public void testNotifyModified() {
		TestObservableCollection col = new TestObservableCollection();
		col.add("Ent1");
		List<Object> modified = new ArrayList<>();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementModified(Object element) {
				modified.add(element);
			}
		};
		col.addChangeListener(listener);
		col.notifyModified("Ent1");
		col.notifyModified("Ent1");
		assertEquals(ImmutableList.of("Ent1", "Ent1"), modified);
	}

	@Test
	public void testRemoveChangeListener() {
		TestObservableCollection col = new TestObservableCollection();
		AtomicBoolean didAdd = new AtomicBoolean();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementAdded(Object element) {
				if (didAdd.getAndSet(true)) {
					fail();
				}
			}
		};
		col.addChangeListener(listener);
		assertTrue(col.add("Ent1"));
		assertTrue(didAdd.get());
		col.removeChangeListener(listener);
		assertTrue(col.add("Ent2"));
		assertTrue(didAdd.get());
	}

	@Test
	public void testAggregateChangesDelays() {
		TestObservableCollection col = new TestObservableCollection();
		List<Object> added = new ArrayList<>();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementAdded(Object element) {
				added.add(element);
			}
		};
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.add("Ent1"));
			assertEquals(ImmutableList.of(), added);
		}
		assertEquals(ImmutableList.of("Ent1"), added);
	}

	@Test
	public void testAggregateChangesAggregates() {
		TestObservableCollection col = new TestObservableCollection();
		List<Object> added = new ArrayList<>();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementAdded(Object element) {
				added.add(element);
			}
		};
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.add("Ent1"));
			assertTrue(col.add("Ent2"));
			assertEquals(ImmutableList.of(), added);
		}
		assertEquals(ImmutableList.of("Ent1", "Ent2"), added);
	}

	@Test
	public void testAggregateChangesAddAddIsAdd() {
		TestObservableCollection col = new TestObservableCollection();
		List<Object> added = new ArrayList<>();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementAdded(Object element) {
				added.add(element);
			}
		};
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.add("Ent1"));
			assertFalse(col.add("Ent1"));
			assertEquals(ImmutableList.of(), added);
		}
		assertEquals(ImmutableList.of("Ent1"), added);
	}

	@Test
	public void testAggregateChangesAddModIsAdd() {
		TestObservableCollection col = new TestObservableCollection();
		List<Object> added = new ArrayList<>();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementAdded(Object element) {
				added.add(element);
			}
		};
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.add("Ent1"));
			col.notifyModified("Ent1");
			assertEquals(ImmutableList.of(), added);
		}
		assertEquals(ImmutableList.of("Ent1"), added);
	}

	@Test
	public void testAggregateChangesAddRemIsNothing() {
		TestObservableCollection col = new TestObservableCollection();
		List<Object> added = new ArrayList<>();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementAdded(Object element) {
				added.add(element);
			}
		};
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.add("Ent1"));
			assertEquals(ImmutableList.of(), added);
			assertTrue(col.remove("Ent1"));
			assertEquals(ImmutableList.of(), added);
		}
		assertEquals(ImmutableList.of(), added);
	}

	@Test
	public void testAggregateChangesModAddIsMod() {
		TestObservableCollection col = new TestObservableCollection();
		List<Object> modified = new ArrayList<>();
		col.add("Ent1");
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementModified(Object element) {
				modified.add(element);
			}
		};
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			col.notifyModified("Ent1");
			assertEquals(ImmutableList.of(), modified);
			assertFalse(col.add("Ent1"));
			assertEquals(ImmutableList.of(), modified);
		}
		assertEquals(ImmutableList.of("Ent1"), modified);
	}

	@Test
	public void testAggregateChangesModModIsMod() {
		TestObservableCollection col = new TestObservableCollection();
		List<Object> modified = new ArrayList<>();
		col.add("Ent1");
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementModified(Object element) {
				modified.add(element);
			}
		};
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			col.notifyModified("Ent1");
			assertEquals(ImmutableList.of(), modified);
			col.notifyModified("Ent1");
			assertEquals(ImmutableList.of(), modified);
		}
		assertEquals(ImmutableList.of("Ent1"), modified);
	}

	@Test
	public void testAggregateChangesModRemIsRem() {
		TestObservableCollection col = new TestObservableCollection();
		List<Object> removed = new ArrayList<>();
		col.add("Ent1");
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementRemoved(Object element) {
				removed.add(element);
			}
		};
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			col.notifyModified("Ent1");
			assertEquals(ImmutableList.of(), removed);
			assertTrue(col.remove("Ent1"));
			assertEquals(ImmutableList.of(), removed);
		}
		assertEquals(ImmutableList.of("Ent1"), removed);
	}

	@Test
	public void testAggregateChangesRemAddIsMod() {
		TestObservableCollection col = new TestObservableCollection();
		List<Object> modified = new ArrayList<>();
		col.add("Ent1");
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementModified(Object element) {
				modified.add(element);
			}
		};
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.remove("Ent1"));
			assertEquals(ImmutableList.of(), modified);
			assertTrue(col.add("Ent1"));
			assertEquals(ImmutableList.of(), modified);
		}
		assertEquals(ImmutableList.of("Ent1"), modified);
	}

	@Test(expected = AssertionError.class)
	public void testAggregateChangesRemModIsError() {
		TestObservableCollection col = new TestObservableCollection();
		List<Object> removed = new ArrayList<>();
		col.add("Ent1");
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementRemoved(Object element) {
				removed.add(element);
			}
		};
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.remove("Ent1"));
			assertEquals(ImmutableList.of(), removed);
			col.notifyModified("Ent1");
		}
	}

	@Test
	public void testAggregateChangesRemRemIsRem() {
		TestObservableCollection col = new TestObservableCollection();
		List<Object> removed = new ArrayList<>();
		col.add("Ent1");
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementRemoved(Object element) {
				removed.add(element);
			}
		};
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.remove("Ent1"));
			assertEquals(ImmutableList.of(), removed);
			assertFalse(col.remove("Ent1"));
			assertEquals(ImmutableList.of(), removed);
		}
		assertEquals(ImmutableList.of("Ent1"), removed);
	}

	@Test
	public void testAggregateChangesNest() {
		TestObservableCollection col = new TestObservableCollection();
		List<Object> added = new ArrayList<>();
		TestCollectionListener listener = new DefaultTestCollectionListener() {
			@Override
			public void elementAdded(Object element) {
				added.add(element);
			}
		};
		col.addChangeListener(listener);
		try (ChangeAggregator changesOuter = col.aggregateChanges()) {
			assertTrue(col.add("Ent1"));
			assertEquals(ImmutableList.of(), added);
			try (ChangeAggregator changesInner = col.aggregateChanges()) {
				assertTrue(col.add("Ent2"));
				assertEquals(ImmutableList.of(), added);
			}
			assertTrue(col.add("Ent3"));
			assertEquals(ImmutableList.of(), added);
		}
		assertEquals(ImmutableList.of("Ent1", "Ent2", "Ent3"), added);
	}
}
