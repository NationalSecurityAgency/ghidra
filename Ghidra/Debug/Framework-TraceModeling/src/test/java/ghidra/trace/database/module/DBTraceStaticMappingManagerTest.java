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

import com.google.common.collect.Range;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.modules.TraceConflictedMappingException;
import ghidra.trace.model.modules.TraceStaticMapping;
import ghidra.util.database.UndoableTransaction;

public class DBTraceStaticMappingManagerTest extends AbstractGhidraHeadlessIntegrationTest {

	ToyDBTraceBuilder b;
	DBTraceStaticMappingManager staticMappingManager;

	@Before
	public void setUpStaticMappingManagerTest() throws IOException {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");
		staticMappingManager = b.trace.getStaticMappingManager();
	}

	@After
	public void tearDownStaticMappingManagerTest() {
		b.close();
	}

	@Test
	public void testAddAndGet() throws Exception {
		try (UndoableTransaction tid = b.startTransaction()) {
			staticMappingManager.add(b.range(0xdeadbeef, 0xdeadbeef + 99), Range.closed(2L, 5L),
				new URL("ghidra://static"), "DEADBEEF");
		}

		DBTraceStaticMapping found = staticMappingManager.findContaining(b.addr(0xdeadbeef), 2);
		assertEquals(b.addr(0xdeadbeef), found.getMinTraceAddress());
		assertEquals(100, found.getLength());
		assertEquals(2, found.getStartSnap());
		assertEquals(5, found.getEndSnap());
		assertEquals(new URL("ghidra://static"), found.getStaticProgramURL());
		assertEquals("DEADBEEF", found.getStaticAddress());

		assertEquals(found, staticMappingManager.findContaining(b.addr(0xdeadbeef + 99), 2));
		assertEquals(found, staticMappingManager.findContaining(b.addr(0xdeadbeef + 99), 5));
		assertEquals(found, staticMappingManager.findContaining(b.addr(0xdeadbeef), 5));

		assertNull(staticMappingManager.findContaining(b.addr(0xdeadbeef - 1), 2));
		assertNull(staticMappingManager.findContaining(b.addr(0xdeadbeef + 100), 2));
		assertNull(staticMappingManager.findContaining(b.addr(0xdeadbeef), 1));
		assertNull(staticMappingManager.findContaining(b.addr(0xdeadbeef), 6));
	}

	@Test
	public void testAddAndEnumerate() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(b.trace, "Testing", true)) {
			staticMappingManager.add(b.range(0xdeadbeef, 0xdeadbeef + 99), Range.closedOpen(2L, 5L),
				new URL("ghidra://static"), "DEADBEEF");
		}

		Collection<? extends TraceStaticMapping> all = staticMappingManager.getAllEntries();
		assertEquals(1, all.size());
	}

	@Test
	public void testAddRemoveAndEnumerate() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(b.trace, "Testing", true)) {
			staticMappingManager.add(b.range(0xdeadbeef, 0xdeadbeef + 99), Range.closedOpen(2L, 5L),
				new URL("ghidra://static"), "DEADBEEF");
			staticMappingManager.add(b.range(0xdeadbeef, 0xdeadbeef + 99),
				Range.closedOpen(7L, 10L),
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
		try (UndoableTransaction tid = UndoableTransaction.start(b.trace, "Testing", true)) {
			staticMappingManager.add(b.range(0xdeadbeef, 0xdeadbeef + 99), Range.closedOpen(2L, 5L),
				new URL("ghidra://static"), "DEADBEEF");
			staticMappingManager.add(b.range(0xdeadbeef + 80, 0xdeadbeef + 179),
				Range.closedOpen(2L, 5L), new URL("ghidra://static"), "DEADBEEF");
			fail();
		}
		catch (TraceConflictedMappingException e) {
			// pass
		}
	}

	@Test
	public void testOverlapAgreeingAccepted() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(b.trace, "Testing", true)) {
			staticMappingManager.add(b.range(0xdeadbeef, 0xdeadbeef + 99), Range.closedOpen(2L, 5L),
				new URL("ghidra://static"), "DEADBEEF");
			staticMappingManager.add(b.range(0xdeadbeef + 80, 0xdeadbeef + 179),
				Range.closedOpen(2L, 5L), new URL("ghidra://static"), "DEADBF3F");
		}
	}

	@Test
	public void testTouchingProceedingIsNotOverlapping() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(b.trace, "Testing", true)) {
			staticMappingManager.add(b.range(0xdeadbeef, 0xdeadbeef + 99), Range.closedOpen(2L, 5L),
				new URL("ghidra://static"), "DEADBEEF");
			staticMappingManager.add(b.range(0xdeadbeef + 100, 0xdeadbeef + 199),
				Range.closedOpen(2L, 5L), new URL("ghidra://static"), "DEADBEEF");
		}
	}

	@SuppressWarnings("hiding")
	@Test
	public void testSaveAndLoad() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(b.trace, "Testing", true)) {
			staticMappingManager.add(b.range(0xdeadbeef, 0xdeadbeef + 99), Range.closed(2L, 5L),
				new URL("ghidra://static"), "DEADBEEF");
		}

		File tmp = b.save();
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
		try (UndoableTransaction tid = UndoableTransaction.start(b.trace, "Testing", true)) {
			staticMappingManager.add(b.range(0xdeadbeef, 0xdeadbeef + 99), Range.closedOpen(2L, 5L),
				new URL("ghidra://static"), "DEADBEEF");
			tid.abort();
		}

		assertEquals(0, staticMappingManager.getAllEntries().size());
	}

	@Test
	public void testAddThenUndo() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(b.trace, "Testing", true)) {
			staticMappingManager.add(b.range(0xdeadbeef, 0xdeadbeef + 99), Range.closedOpen(2L, 5L),
				new URL("ghidra://static"), "DEADBEEF");
		}
		b.trace.undo();

		assertEquals(0, staticMappingManager.getAllEntries().size());
	}

	@Test
	public void testAddThenRemoveThenUndo() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(b.trace, "Testing", true)) {
			staticMappingManager.add(b.range(0xdeadbeef, 0xdeadbeef + 99), Range.closedOpen(2L, 5L),
				new URL("ghidra://static"), "DEADBEEF");
		}
		assertEquals(1, staticMappingManager.getAllEntries().size());
		try (UndoableTransaction tid = UndoableTransaction.start(b.trace, "Testing", true)) {
			for (TraceStaticMapping m : staticMappingManager.getAllEntries()) {
				m.delete();
			}
		}
		assertEquals(0, staticMappingManager.getAllEntries().size());
		b.trace.undo();
		assertEquals(1, staticMappingManager.getAllEntries().size());
	}
}
