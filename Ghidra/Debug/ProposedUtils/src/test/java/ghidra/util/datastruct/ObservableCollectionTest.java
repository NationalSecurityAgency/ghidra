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

import org.junit.After;
import org.junit.Test;

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

	private TestListener listener = new TestListener();

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
		assertTrue(col.addAll(List.of("Ent1", "Ent3")));
		assertFalse(col.addAll(List.of("Ent2", "Ent1")));
		assertTrue(col.removeAll(List.of("Ent1", "Ent2", "Ent3")));
		assertTrue(col.isEmpty());
		assertTrue(col.addAll(List.of("Ent2", "Ent3")));
		assertTrue(col.retainAll(List.of("Ent2", "Ent1")));
		assertTrue(col.contains("Ent2"));
		assertEquals(1, col.size());
		col.clear();
		assertTrue(col.isEmpty());
	}

	@Test
	public void testAddCausesEvent() {
		TestObservableCollection col = new TestObservableCollection();

		col.addChangeListener(listener);
		col.add("Ent1");
		assertEquals("Ent1", listener.getLastAdded());
		listener.clear();
		col.add("Ent1"); // Already there, so no event
		assertEquals(null, listener.getLastAdded());
	}

	@Test
	public void testRemoveCausesEvent() {
		TestObservableCollection col = new TestObservableCollection();
		col.add("Ent1");

		col.addChangeListener(listener);
		col.remove("Ent1");
		assertEquals("Ent1", listener.getLastRemoved());
		listener.clear();
		col.remove("Ent1"); // Already gone, so no event
		assertEquals(null, listener.getLastRemoved());
	}

	@Test
	public void testRemoveViaIteratorCausesEvent() {
		TestObservableCollection col = new TestObservableCollection();
		col.addAll(List.of("Ent1", "Ent2", "Ent3"));
		col.addChangeListener(listener);
		for (Iterator<String> it = col.iterator(); it.hasNext();) {
			String ent = it.next();
			it.remove();
			assertEquals(ent, listener.getLastRemoved());
		}
		assertTrue(col.isEmpty());
	}

	@Test
	public void testAddAllCausesEvent() {
		TestObservableCollection col = new TestObservableCollection();
		col.addChangeListener(listener);
		assertTrue(col.addAll(List.of("Ent1", "Ent2")));
		assertTrue(col.addAll(List.of("Ent3", "Ent2")));
		assertTrue(col.addAll(List.of("Ent3", "Ent4")));
		assertFalse(col.addAll(List.of("Ent1", "Ent2")));
		assertEquals(List.of("Ent1", "Ent2", "Ent3", "Ent4"), listener.added);
	}

	@Test
	public void testRemovalAllCausesEvent() {
		TestObservableCollection col = new TestObservableCollection();
		col.addAll(List.of("Ent1", "Ent2", "Ent3", "Ent4"));
		col.addChangeListener(listener);
		assertTrue(col.removeAll(List.of("Ent1", "Ent2")));
		assertTrue(col.removeAll(List.of("Ent3", "Ent2")));
		assertTrue(col.removeAll(List.of("Ent3", "Ent4")));
		assertFalse(col.removeAll(List.of("Ent1", "Ent2")));
		assertEquals(List.of("Ent1", "Ent2", "Ent3", "Ent4"), listener.removed);
	}

	@Test
	public void testRetailAllCausesEvent() {
		TestObservableCollection col = new TestObservableCollection();
		col.addAll(List.of("Ent1", "Ent2", "Ent3", "Ent4"));
		col.addChangeListener(listener);
		assertTrue(col.retainAll(List.of("Ent3", "Ent4")));
		assertTrue(col.retainAll(List.of("Ent4", "Ent1")));
		assertTrue(col.retainAll(List.of("Ent1", "Ent2")));
		assertFalse(col.retainAll(List.of("Ent3", "Ent4")));
		assertEquals(List.of("Ent1", "Ent2", "Ent3", "Ent4"), listener.removed);
	}

	@Test
	public void testClearCausesEvent() {
		TestObservableCollection col = new TestObservableCollection();
		col.addAll(List.of("Ent1", "Ent2", "Ent3", "Ent4"));
		col.addChangeListener(listener);
		col.clear();
		assertEquals(List.of("Ent1", "Ent2", "Ent3", "Ent4"), listener.removed);
	}

	@Test
	public void testNotifyModified() {
		TestObservableCollection col = new TestObservableCollection();
		col.add("Ent1");
		col.addChangeListener(listener);
		col.notifyModified("Ent1");
		col.notifyModified("Ent1");
		assertEquals(List.of("Ent1", "Ent1"), listener.modified);
	}

	@Test
	public void testRemoveChangeListener() {
		TestObservableCollection col = new TestObservableCollection();
		col.addChangeListener(listener);
		assertTrue(col.add("Ent1"));
		assertEquals(1, listener.added.size());
		col.removeChangeListener(listener);
		assertTrue(col.add("Ent2"));
	}

	@Test
	public void testAggregateChangesDelays() {
		TestObservableCollection col = new TestObservableCollection();
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.add("Ent1"));
			assertEquals(List.of(), listener.added);
		}
		assertEquals(List.of("Ent1"), listener.added);
	}

	@Test
	public void testAggregateChangesAggregates() {
		TestObservableCollection col = new TestObservableCollection();
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.add("Ent1"));
			assertTrue(col.add("Ent2"));
			assertEquals(List.of(), listener.added);
		}
		assertEquals(List.of("Ent1", "Ent2"), listener.added);
	}

	@Test
	public void testAggregateChangesAddAddIsAdd() {
		TestObservableCollection col = new TestObservableCollection();
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.add("Ent1"));
			assertFalse(col.add("Ent1"));
			assertEquals(List.of(), listener.added);
		}
		assertEquals(List.of("Ent1"), listener.added);
	}

	@Test
	public void testAggregateChangesAddModIsAdd() {
		TestObservableCollection col = new TestObservableCollection();
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.add("Ent1"));
			col.notifyModified("Ent1");
			assertEquals(List.of(), listener.added);
		}
		assertEquals(List.of("Ent1"), listener.added);
	}

	@Test
	public void testAggregateChangesAddRemIsNothing() {
		TestObservableCollection col = new TestObservableCollection();
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.add("Ent1"));
			assertEquals(List.of(), listener.added);
			assertTrue(col.remove("Ent1"));
			assertEquals(List.of(), listener.added);
		}
		assertEquals(List.of(), listener.added);
	}

	@Test
	public void testAggregateChangesModAddIsMod() {
		TestObservableCollection col = new TestObservableCollection();
		col.add("Ent1");
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			col.notifyModified("Ent1");
			assertEquals(List.of(), listener.modified);
			assertFalse(col.add("Ent1"));
			assertEquals(List.of(), listener.modified);
		}
		assertEquals(List.of("Ent1"), listener.modified);
	}

	@Test
	public void testAggregateChangesModModIsMod() {
		TestObservableCollection col = new TestObservableCollection();
		col.add("Ent1");
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			col.notifyModified("Ent1");
			assertEquals(List.of(), listener.modified);
			col.notifyModified("Ent1");
			assertEquals(List.of(), listener.modified);
		}
		assertEquals(List.of("Ent1"), listener.modified);
	}

	@Test
	public void testAggregateChangesModRemIsRem() {
		TestObservableCollection col = new TestObservableCollection();
		col.add("Ent1");
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			col.notifyModified("Ent1");
			assertEquals(List.of(), listener.removed);
			assertTrue(col.remove("Ent1"));
			assertEquals(List.of(), listener.removed);
		}
		assertEquals(List.of("Ent1"), listener.removed);
	}

	@Test
	public void testAggregateChangesRemAddIsMod() {
		TestObservableCollection col = new TestObservableCollection();
		col.add("Ent1");
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.remove("Ent1"));
			assertEquals(List.of(), listener.modified);
			assertTrue(col.add("Ent1"));
			assertEquals(List.of(), listener.modified);
		}
		assertEquals(List.of("Ent1"), listener.modified);
	}

	@Test(expected = AssertionError.class)
	public void testAggregateChangesRemModIsError() {
		TestObservableCollection col = new TestObservableCollection();
		col.add("Ent1");
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.remove("Ent1"));
			assertEquals(List.of(), listener.removed);
			col.notifyModified("Ent1");
		}
	}

	@Test
	public void testAggregateChangesRemRemIsRem() {
		TestObservableCollection col = new TestObservableCollection();
		col.add("Ent1");
		col.addChangeListener(listener);
		try (ChangeAggregator changes = col.aggregateChanges()) {
			assertTrue(col.remove("Ent1"));
			assertEquals(List.of(), listener.removed);
			assertFalse(col.remove("Ent1"));
			assertEquals(List.of(), listener.removed);
		}
		assertEquals(List.of("Ent1"), listener.removed);
	}

	@Test
	public void testAggregateChangesNest() {
		TestObservableCollection col = new TestObservableCollection();
		col.addChangeListener(listener);
		try (ChangeAggregator changesOuter = col.aggregateChanges()) {
			assertTrue(col.add("Ent1"));
			assertEquals(List.of(), listener.added);
			try (ChangeAggregator changesInner = col.aggregateChanges()) {
				assertTrue(col.add("Ent2"));
				assertEquals(List.of(), listener.added);
			}
			assertTrue(col.add("Ent3"));
			assertEquals(List.of(), listener.added);
		}
		assertEquals(List.of("Ent1", "Ent2", "Ent3"), listener.added);
	}

	private class TestListener extends DefaultTestCollectionListener {

		private List<Object> added = new ArrayList<>();
		private List<Object> removed = new ArrayList<>();
		private List<Object> modified = new ArrayList<>();

		@Override
		public void elementAdded(Object element) {
			added.add(element);
		}

		@Override
		public void elementRemoved(Object element) {
			removed.add(element);
		}

		@Override
		public void elementModified(Object element) {
			modified.add(element);
		}

		public void clear() {
			added.clear();
			removed.clear();
			modified.clear();
		}

		public Object getLastRemoved() {
			if (removed.isEmpty()) {
				return null;
			}
			return removed.get(removed.size() - 1);
		}

		public Object getLastAdded() {
			if (added.isEmpty()) {
				return null;
			}
			return added.get(added.size() - 1);
		}

	}

}
