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
package ghidra.framework.data;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;

public class PairedTransactionTest extends AbstractGenericTest {

	DummyDomainObject obj1;
	DummyDomainObject obj2;

	MyListener obj1Listener;
	MyListener obj2Listener;

	Options propertyList1;
	Options propertyList2;

	public PairedTransactionTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		obj1 = new DummyDomainObject("obj1", this);
		obj1Listener = new MyListener(obj1);

		obj2 = new DummyDomainObject("obj2", this);
		obj2Listener = new MyListener(obj2);

		int txId = obj1.startTransaction("Add Property");
		try {
			propertyList1 = obj1.getOptions("Test");
			propertyList1.setString("A1", "listA1");
		}
		finally {
			obj1.endTransaction(txId, true);
		}

		txId = obj2.startTransaction("Add Property");
		try {
			propertyList2 = obj2.getOptions("Test");
			propertyList2.setString("A2", "listA2");
		}
		finally {
			obj2.endTransaction(txId, true);
		}

	}

	@After
	public void tearDown() throws Exception {
		if (obj1 != null) {
			obj1.release(this);
		}
		if (obj2 != null) {
			obj2.release(this);
		}
	}

	private static String START = "Start";
	private static String END = "End";
	private static String UNDO_STATE_CHANGE1 = "UndoRedo1";
	private static String UNDO_STATE_CHANGE2 = "UndoRedo2";

	class MyListener implements TransactionListener {

		private List<String> events = new ArrayList<>();
		private Transaction lastTransaction;
		private DomainObjectAdapterDB obj;

		MyListener(DomainObjectAdapterDB obj) {
			this.obj = obj;
			obj.addTransactionListener(this);
		}

		@Override
		public synchronized void transactionEnded(DomainObjectAdapterDB domainObj) {
			assertEquals(obj, domainObj);
			events.add(END);
		}

		@Override
		public synchronized void transactionStarted(DomainObjectAdapterDB domainObj,
				Transaction tx) {
			assertEquals(obj, domainObj);
			events.add(START);
			lastTransaction = tx;
		}

		@Override
		public void undoRedoOccurred(DomainObjectAdapterDB domainObj) {
			// not used

		}

		@Override
		public void undoStackChanged(DomainObjectAdapterDB domainObj) {
			String event = null;
			if ("obj1".equals(domainObj.getName())) {
				event = UNDO_STATE_CHANGE1;
			}
			if ("obj2".equals(domainObj.getName())) {
				event = UNDO_STATE_CHANGE2;
			}
			events.add(event);
		}

		String[] getEvents() {
			waitForPostedSwingRunnables();
			synchronized (this) {
				String[] a = new String[events.size()];
				events.toArray(a);
				events.clear();
				return a;
			}
		}

		Transaction getLastTransaction() {
			waitForPostedSwingRunnables();
			synchronized (this) {
				return lastTransaction;
			}
		}

	}

	@Test
	public void testAddSynchronizedDomainObject() throws IOException {

		assertNull(obj1.getCurrentTransaction());
		assertNull(obj2.getCurrentTransaction());

		assertEquals(1, obj1.getUndoStackDepth());
		assertEquals(1, obj2.getUndoStackDepth());

		assertTrue(obj1.canUndo());
		assertTrue(obj2.canUndo());
		assertFalse(obj1.canRedo());
		assertFalse(obj2.canRedo());

		Transaction tx = obj1Listener.getLastTransaction();
		obj1Listener.getEvents();
		assertNotNull(tx);

		tx = obj2Listener.getLastTransaction();
		obj2Listener.getEvents();
		assertNotNull(tx);

		assertNull(obj1.getSynchronizedDomainObjects());
		assertNull(obj2.getSynchronizedDomainObjects());

		try {
			obj1.addSynchronizedDomainObject(obj2);
		}
		catch (LockException e) {
			e.printStackTrace();
			Assert.fail(e.getMessage());
		}

		DomainObject[] synchronizedDomainObjects = obj1.getSynchronizedDomainObjects();
		assertNotNull(synchronizedDomainObjects);
		assertEquals(2, synchronizedDomainObjects.length);
		assertEquals(obj1, synchronizedDomainObjects[0]);
		assertEquals(obj2, synchronizedDomainObjects[1]);

		assertArrayEquals(synchronizedDomainObjects, obj2.getSynchronizedDomainObjects());

		assertEquals(0, obj1.getUndoStackDepth());
		assertEquals(0, obj2.getUndoStackDepth());

		assertFalse(obj1.canUndo());
		assertFalse(obj2.canUndo());
		assertFalse(obj1.canRedo());
		assertFalse(obj2.canRedo());

		String[] events1 = obj1Listener.getEvents();
		assertEquals(UNDO_STATE_CHANGE1, events1[events1.length - 1]);

		String[] events2 = obj2Listener.getEvents();
		assertEquals(UNDO_STATE_CHANGE2, events2[events2.length - 1]);

		// Test rollback (non-committed) transaction

		int txId1 = obj1.startTransaction("Test1");
		try {

			assertNotNull(obj2.getCurrentTransaction());

			propertyList1.setString("A1.B1", "TestB1");

			events1 = obj1Listener.getEvents();
			events2 = obj2Listener.getEvents();
			assertTrue(Arrays.equals(new String[] { START, UNDO_STATE_CHANGE1 }, events1));
			assertTrue(Arrays.equals(new String[] { START, UNDO_STATE_CHANGE2 }, events2));

			int txId2 = obj2.startTransaction("Test2");
			try {
				propertyList2.setString("A2.B2", "TestB2");

				events1 = obj1Listener.getEvents();
				events2 = obj2Listener.getEvents();
				assertTrue(Arrays.equals(new String[] { START, UNDO_STATE_CHANGE1 }, events1));
				assertTrue(Arrays.equals(new String[] { START, UNDO_STATE_CHANGE2 }, events2));
			}
			finally {
				obj2.endTransaction(txId2, true);
			}

			events1 = obj1Listener.getEvents();
			events2 = obj2Listener.getEvents();
			assertTrue(Arrays.equals(new String[] {}, events1));
			assertTrue(Arrays.equals(new String[] {}, events2));

			assertEquals("TestB1", propertyList1.getString("A1.B1", "NULL"));
			assertEquals("TestB2", propertyList2.getString("A2.B2", "NULL"));

		}
		finally {
			obj1.endTransaction(txId1, false);
		}

		// obj2 rollback causes obj2 to rollback
		assertEquals("NULL", propertyList1.getString("A1.B1", "NULL"));
		assertEquals("NULL", propertyList2.getString("A2.B2", "NULL"));

		assertNull(obj1.getCurrentTransaction());

		assertEquals(0, obj1.getUndoStackDepth());
		assertEquals(0, obj2.getUndoStackDepth());

		assertFalse(obj1.canUndo());
		assertFalse(obj2.canUndo());
		assertFalse(obj1.canRedo());
		assertFalse(obj2.canRedo());

		events1 = obj1Listener.getEvents();
		events2 = obj2Listener.getEvents();
		assertTrue(Arrays.equals(new String[] { END, UNDO_STATE_CHANGE1 }, events1));
		assertTrue(Arrays.equals(new String[] { END, UNDO_STATE_CHANGE2 }, events2));

		// Test committed transaction

		txId1 = obj1.startTransaction("Test1");
		try {

			assertNotNull(obj2.getCurrentTransaction());

			propertyList1.setString("A1.B1", "TestB1");

			events1 = obj1Listener.getEvents();
			events2 = obj2Listener.getEvents();
			assertTrue(Arrays.equals(new String[] { START, UNDO_STATE_CHANGE1 }, events1));
			assertTrue(Arrays.equals(new String[] { START, UNDO_STATE_CHANGE2 }, events2));

			int txId2 = obj2.startTransaction("Test2");
			try {
				propertyList2.setString("A2.B2", "TestB2");

				events1 = obj1Listener.getEvents();
				events2 = obj2Listener.getEvents();
				assertTrue(Arrays.equals(new String[] { START, UNDO_STATE_CHANGE1 }, events1));
				assertTrue(Arrays.equals(new String[] { START, UNDO_STATE_CHANGE2 }, events2));
			}
			finally {
				obj2.endTransaction(txId2, true);
			}

			events1 = obj1Listener.getEvents();
			events2 = obj2Listener.getEvents();
			assertTrue(Arrays.equals(new String[] {}, events1));
			assertTrue(Arrays.equals(new String[] {}, events2));

			assertEquals("TestB1", propertyList1.getString("A1.B1", "NULL"));
			assertEquals("TestB2", propertyList2.getString("A2.B2", "NULL"));

		}
		finally {
			obj1.endTransaction(txId1, true);
		}

		assertEquals("TestB1", propertyList1.getString("A1.B1", "NULL"));
		assertEquals("TestB2", propertyList2.getString("A2.B2", "NULL"));

		assertNull(obj1.getCurrentTransaction());

		assertEquals(1, obj1.getUndoStackDepth());
		assertEquals(1, obj2.getUndoStackDepth());

		assertTrue(obj1.canUndo());
		assertTrue(obj2.canUndo());
		assertFalse(obj1.canRedo());
		assertFalse(obj2.canRedo());

		events1 = obj1Listener.getEvents();
		events2 = obj2Listener.getEvents();
		assertTrue(Arrays.equals(new String[] { END, UNDO_STATE_CHANGE1 }, events1));
		assertTrue(Arrays.equals(new String[] { END, UNDO_STATE_CHANGE2 }, events2));

		assertEquals("obj1: Test1\nobj2: Test2", obj1.getUndoName());
		assertEquals("obj1: Test1\nobj2: Test2", obj2.getUndoName());
		assertEquals("", obj1.getRedoName());
		assertEquals("", obj2.getRedoName());

		obj1.undo();

		assertFalse(obj1.canUndo());
		assertFalse(obj2.canUndo());
		assertTrue(obj1.canRedo());
		assertTrue(obj2.canRedo());

		events1 = obj1Listener.getEvents();
		events2 = obj2Listener.getEvents();
		assertTrue(Arrays.equals(new String[] { UNDO_STATE_CHANGE1 }, events1));
		assertTrue(Arrays.equals(new String[] { UNDO_STATE_CHANGE2 }, events2));

		assertEquals("NULL", propertyList1.getString("A1.B1", "NULL"));
		assertEquals("NULL", propertyList2.getString("A2.B2", "NULL"));

		assertEquals("", obj1.getUndoName());
		assertEquals("", obj2.getUndoName());
		assertEquals("obj1: Test1\nobj2: Test2", obj1.getRedoName());
		assertEquals("obj1: Test1\nobj2: Test2", obj2.getRedoName());

		obj1.redo();

		assertTrue(obj1.canUndo());
		assertTrue(obj2.canUndo());
		assertFalse(obj1.canRedo());
		assertFalse(obj2.canRedo());

		events1 = obj1Listener.getEvents();
		events2 = obj2Listener.getEvents();
		assertTrue(Arrays.equals(new String[] { UNDO_STATE_CHANGE1 }, events1));
		assertTrue(Arrays.equals(new String[] { UNDO_STATE_CHANGE2 }, events2));

		assertEquals("TestB1", propertyList1.getString("A1.B1", "NULL"));
		assertEquals("TestB2", propertyList2.getString("A2.B2", "NULL"));

		try {
			obj1.releaseSynchronizedDomainObject();
		}
		catch (LockException e) {
			e.printStackTrace();
			Assert.fail();
		}

		assertEquals(0, obj1.getUndoStackDepth());
		assertEquals(0, obj2.getUndoStackDepth());

		assertFalse(obj1.canUndo());
		assertFalse(obj2.canUndo());
		assertFalse(obj1.canRedo());
		assertFalse(obj2.canRedo());

		events1 = obj1Listener.getEvents();
		events2 = obj2Listener.getEvents();
		assertTrue(Arrays.equals(new String[] { UNDO_STATE_CHANGE1 }, events1));
		assertTrue(Arrays.equals(new String[] { UNDO_STATE_CHANGE2 }, events2));

		assertEquals("TestB1", propertyList1.getString("A1.B1", "NULL"));
		assertEquals("TestB2", propertyList2.getString("A2.B2", "NULL"));

		// Independent transactions

		txId1 = obj1.startTransaction("Test1");
		try {

			assertNull(obj2.getCurrentTransaction());

			propertyList1.setString("A1.C1", "TestC1");

			events1 = obj1Listener.getEvents();
			events2 = obj2Listener.getEvents();
			assertTrue(Arrays.equals(new String[] { START, UNDO_STATE_CHANGE1 }, events1));
			assertTrue(Arrays.equals(new String[] {}, events2));

			int txId2 = obj2.startTransaction("Test2");
			try {
				propertyList2.setString("A2.C2", "TestC2");

				events1 = obj1Listener.getEvents();
				events2 = obj2Listener.getEvents();
				assertTrue(Arrays.equals(new String[] {}, events1));
				assertTrue(Arrays.equals(new String[] { START, UNDO_STATE_CHANGE2 }, events2));
			}
			finally {
				obj2.endTransaction(txId2, true);
			}

			events1 = obj1Listener.getEvents();
			events2 = obj2Listener.getEvents();
			assertTrue(Arrays.equals(new String[] {}, events1));
			assertTrue(Arrays.equals(new String[] { END, UNDO_STATE_CHANGE2 }, events2));

			assertEquals("TestC1", propertyList1.getString("A1.C1", "NULL"));
			assertEquals("TestC2", propertyList2.getString("A2.C2", "NULL"));

		}
		finally {
			obj1.endTransaction(txId1, false);
		}

		assertEquals("NULL", propertyList1.getString("A1.C1", "NULL"));
		assertEquals("TestC2", propertyList2.getString("A2.C2", "NULL"));

		assertNull(obj1.getCurrentTransaction());

		assertEquals(0, obj1.getUndoStackDepth());
		assertEquals(1, obj2.getUndoStackDepth());

		assertFalse(obj1.canUndo());
		assertTrue(obj2.canUndo());
		assertFalse(obj1.canRedo());
		assertFalse(obj2.canRedo());

		events1 = obj1Listener.getEvents();
		events2 = obj2Listener.getEvents();
		assertTrue(Arrays.equals(new String[] { END, UNDO_STATE_CHANGE1 }, events1));
		assertTrue(Arrays.equals(new String[] {}, events2));

		assertEquals("", obj1.getUndoName());
		assertEquals("obj2: Test2", obj2.getUndoName());
		assertEquals("", obj1.getRedoName());
		assertEquals("", obj2.getRedoName());

	}

	@Test
	public void testCloseSeparation() {

		try {
			obj1.addSynchronizedDomainObject(obj2);
		}
		catch (LockException e) {
			e.printStackTrace();
			Assert.fail(e.getMessage());
		}

		String[] events1 = obj1Listener.getEvents();
		assertEquals(UNDO_STATE_CHANGE1, events1[events1.length - 1]);

		String[] events2 = obj2Listener.getEvents();
		assertEquals(UNDO_STATE_CHANGE2, events2[events2.length - 1]);

		obj1.release(this);
		obj1 = null;

		events2 = obj2Listener.getEvents();
		assertEquals(UNDO_STATE_CHANGE2, events2[events2.length - 1]);

		assertNull(obj2.getSynchronizedDomainObjects());

		int txId2 = obj2.startTransaction("Test2");
		try {
			propertyList2.setString("A2.C2", "TestC2");

			events2 = obj2Listener.getEvents();
			assertTrue(Arrays.equals(new String[] { START, UNDO_STATE_CHANGE2 }, events2));
		}
		finally {
			obj2.endTransaction(txId2, true);
		}

		events2 = obj2Listener.getEvents();
		assertTrue(Arrays.equals(new String[] { END, UNDO_STATE_CHANGE2 }, events2));

		assertEquals("TestC2", propertyList2.getString("A2.C2", "NULL"));
	}

}
