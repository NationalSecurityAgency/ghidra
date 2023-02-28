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
package ghidra.trace.database.module;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Collection;

import org.junit.*;

import db.Transaction;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.modules.TraceConflictedMappingException;
import ghidra.trace.model.modules.TraceStaticMapping;

public class DBTraceStaticMappingManagerTest extends AbstractGhidraHeadlessIntegrationTest {

	ToyDBTraceBuilder tb;
	DBTraceStaticMappingManager staticMappingManager;

	@Before
	public void setUpStaticMappingManagerTest() throws IOException {
		tb = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");
		staticMappingManager = tb.trace.getStaticMappingManager();
	}

	@After
	public void tearDownStaticMappingManagerTest() {
		tb.close();
	}

	@Test
	public void testAddAndGet() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			staticMappingManager.add(tb.range(0xdeadbeef, 0xdeadbeef + 99), Lifespan.span(2, 5),
				new URL("ghidra://static"), "DEADBEEF");
		}

		DBTraceStaticMapping found = staticMappingManager.findContaining(tb.addr(0xdeadbeef), 2);
		assertEquals(tb.addr(0xdeadbeef), found.getMinTraceAddress());
		assertEquals(100, found.getLength());
		assertEquals(2, found.getStartSnap());
		assertEquals(5, found.getEndSnap());
		assertEquals(new URL("ghidra://static"), found.getStaticProgramURL());
		assertEquals("DEADBEEF", found.getStaticAddress());

		assertEquals(found, staticMappingManager.findContaining(tb.addr(0xdeadbeef + 99), 2));
		assertEquals(found, staticMappingManager.findContaining(tb.addr(0xdeadbeef + 99), 5));
		assertEquals(found, staticMappingManager.findContaining(tb.addr(0xdeadbeef), 5));

		assertNull(staticMappingManager.findContaining(tb.addr(0xdeadbeef - 1), 2));
		assertNull(staticMappingManager.findContaining(tb.addr(0xdeadbeef + 100), 2));
		assertNull(staticMappingManager.findContaining(tb.addr(0xdeadbeef), 1));
		assertNull(staticMappingManager.findContaining(tb.addr(0xdeadbeef), 6));
	}

	@Test
	public void testAddAndEnumerate() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			staticMappingManager.add(tb.range(0xdeadbeef, 0xdeadbeef + 99),
				Lifespan.span(2, 4),
				new URL("ghidra://static"), "DEADBEEF");
		}

		Collection<? extends TraceStaticMapping> all = staticMappingManager.getAllEntries();
		assertEquals(1, all.size());
	}

	@Test
	public void testAddRemoveAndEnumerate() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			staticMappingManager.add(tb.range(0xdeadbeef, 0xdeadbeef + 99),
				Lifespan.span(2, 4),
				new URL("ghidra://static"), "DEADBEEF");
			staticMappingManager.add(tb.range(0xdeadbeef, 0xdeadbeef + 99),
				Lifespan.span(7, 9),
				new URL("ghidra://static"), "DEADBEEF");

			assertEquals(2, staticMappingManager.getAllEntries().size());

			for (TraceStaticMapping m : staticMappingManager.getAllEntries()) {
				m.delete();
			}
		}

		assertEquals(0, staticMappingManager.getAllEntries().size());
	}

	@Test
	public void testOverlapCausesException() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			staticMappingManager.add(tb.range(0xdeadbeef, 0xdeadbeef + 99),
				Lifespan.span(2, 4),
				new URL("ghidra://static"), "DEADBEEF");
			staticMappingManager.add(tb.range(0xdeadbeef + 80, 0xdeadbeef + 179),
				Lifespan.span(2, 4), new URL("ghidra://static"), "DEADBEEF");
			fail();
		}
		catch (TraceConflictedMappingException e) {
			// pass
		}
	}

	@Test
	public void testOverlapAgreeingAccepted() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			staticMappingManager.add(tb.range(0xdeadbeef, 0xdeadbeef + 99),
				Lifespan.span(2, 4),
				new URL("ghidra://static"), "DEADBEEF");
			staticMappingManager.add(tb.range(0xdeadbeef + 80, 0xdeadbeef + 179),
				Lifespan.span(2, 4), new URL("ghidra://static"), "DEADBF3F");
		}
	}

	@Test
	public void testTouchingProceedingIsNotOverlapping() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			staticMappingManager.add(tb.range(0xdeadbeef, 0xdeadbeef + 99),
				Lifespan.span(2, 4),
				new URL("ghidra://static"), "DEADBEEF");
			staticMappingManager.add(tb.range(0xdeadbeef + 100, 0xdeadbeef + 199),
				Lifespan.span(2, 4), new URL("ghidra://static"), "DEADBEEF");
		}
	}

	@SuppressWarnings("hiding")
	@Test
	public void testSaveAndLoad() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			staticMappingManager.add(tb.range(0xdeadbeef, 0xdeadbeef + 99), Lifespan.span(2, 5),
				new URL("ghidra://static"), "DEADBEEF");
		}

		File tmp = tb.save();
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder(tmp)) {
			DBTraceStaticMappingManager staticMappingManager = b.trace.getStaticMappingManager();
			DBTraceStaticMapping found =
				staticMappingManager.findContaining(b.addr(0xdeadbeef), 2);
			assertEquals(b.addr(0xdeadbeef), found.getMinTraceAddress());
			assertEquals(100, found.getLength());
			assertEquals(2, found.getStartSnap());
			assertEquals(5, found.getEndSnap());
			assertEquals(new URL("ghidra://static"), found.getStaticProgramURL());
			assertEquals("DEADBEEF", found.getStaticAddress());
		}
	}

	@Test
	public void testAddButAbortedStillEmpty() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			staticMappingManager.add(tb.range(0xdeadbeef, 0xdeadbeef + 99),
				Lifespan.span(2, 4),
				new URL("ghidra://static"), "DEADBEEF");
			tx.abort();
		}

		assertEquals(0, staticMappingManager.getAllEntries().size());
	}

	@Test
	public void testAddThenUndo() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			staticMappingManager.add(tb.range(0xdeadbeef, 0xdeadbeef + 99),
				Lifespan.span(2, 4),
				new URL("ghidra://static"), "DEADBEEF");
		}
		tb.trace.undo();

		assertEquals(0, staticMappingManager.getAllEntries().size());
	}

	@Test
	public void testAddThenRemoveThenUndo() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			staticMappingManager.add(tb.range(0xdeadbeef, 0xdeadbeef + 99),
				Lifespan.span(2, 4),
				new URL("ghidra://static"), "DEADBEEF");
		}
		assertEquals(1, staticMappingManager.getAllEntries().size());
		try (Transaction tx = tb.startTransaction()) {
			for (TraceStaticMapping m : staticMappingManager.getAllEntries()) {
				m.delete();
			}
		}
		assertEquals(0, staticMappingManager.getAllEntries().size());
		tb.trace.undo();
		assertEquals(1, staticMappingManager.getAllEntries().size());
	}
}
