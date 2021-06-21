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
package ghidra.trace.database.symbol;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.junit.*;

import com.google.common.collect.Range;

import ghidra.lifecycle.Unfinished;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.symbol.TraceLabelSymbol;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.*;

public class DBTraceSymbolManagerTest extends AbstractGhidraHeadlessIntegrationTest
		implements Unfinished {
	protected ToyDBTraceBuilder b;
	protected DBTraceSymbolManager manager;

	@Before
	public void setUpTraceSymbolManagerTest() throws IOException {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:harvard");
		manager = b.trace.getSymbolManager();
	}

	@After
	public void tearDownSymbolReferenceManagerTest() {
		b.close();
	}

	@Test
	public void testGlobalNamespaceExists() {
		assertEquals(0, GlobalNamespace.GLOBAL_NAMESPACE_ID);
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		assertNotNull(global);
		assertEquals(GlobalNamespace.GLOBAL_NAMESPACE_NAME, global.getName());
		assertEquals(GlobalNamespace.GLOBAL_NAMESPACE_ID, global.getID());
	}

	interface NamedCreator {
		void create(String name) throws Exception;
	}

	interface Temperametal {
		void run() throws Exception;
	}

	static final String[] INVALID_NAMES = new String[] { null, "", "I have spaces!",
		"I\thave\ttabs!", "I\nhave\nlines!", "I\rhave\rreturns!" };

	protected void assertRejectsInvalid(NamedCreator creator) throws Exception {
		for (String name : INVALID_NAMES) {
			try {
				creator.create(name);
				fail();
			}
			catch (InvalidInputException e) {
				// pass
			}
		}
	}

	protected void assertRejectsDefault(Temperametal r) throws Exception {
		try {
			r.run();
			fail();
		}
		catch (IllegalArgumentException e) {
			// pass
		}
	}

	protected void assertRejectsDuplicate(Temperametal r) throws Exception {
		try {
			r.run();
			fail();
		}
		catch (DuplicateNameException e) {
			// pass
		}
	}

	@Test
	public void testAddLabels() throws Exception {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceThread thread = b.getOrAddThread("Thread1", 0);

			manager.labels()
					.create(0, null, b.addr(0x4000), "myLabel", global,
						SourceType.USER_DEFINED);
			manager.labels()
					.create(0, thread, b.language.getRegister("r4").getAddress(),
						"myRegisterLabel", global, SourceType.USER_DEFINED);
			assertEquals(2, manager.labelStore.getRecordCount());

			assertRejectsInvalid(name -> manager.labels()
					.create(0, null, b.addr(0x4001), name,
						global, SourceType.USER_DEFINED));
			assertRejectsDefault(() -> manager.labels()
					.create(0, null, b.addr(0x4001), "myLabel",
						global, SourceType.DEFAULT));
			assertEquals(2, manager.labelStore.getRecordCount());

			// Accepts duplicates
			manager.labels()
					.create(0, null, b.addr(0x4001), "myLabel", global,
						SourceType.USER_DEFINED);
			// TODO: What happens if same name, address, and parent?
			assertEquals(3, manager.labelStore.getRecordCount());
		}
	}

	@Test
	public void testAddNamespaces() throws Exception {
		DBTraceNamespaceSymbol top;
		DBTraceNamespaceSymbol a;
		try (UndoableTransaction tid = b.startTransaction()) {
			top = manager.namespaces()
					.add("top", manager.getGlobalNamespace(),
						SourceType.USER_DEFINED);
			assertEquals(2, manager.namespaceStore.getRecordCount()); // + global
			a = manager.namespaces().add("a", top, SourceType.USER_DEFINED);
			assertEquals(3, manager.namespaceStore.getRecordCount());

			assertRejectsInvalid(
				name -> manager.namespaces().add(name, top, SourceType.USER_DEFINED));
			assertRejectsDefault(() -> manager.namespaces().add("b", top, SourceType.DEFAULT));
			assertRejectsDuplicate(
				() -> manager.namespaces().add("a", top, SourceType.USER_DEFINED));
			assertRejectsDuplicate(() -> manager.classes().add("a", top, SourceType.USER_DEFINED));

			assertEquals(3, manager.namespaceStore.getRecordCount());
			assertEquals(0, manager.classStore.getRecordCount());
		}
		assertEquals("top", top.name);
		assertSame(top.parent, manager.getGlobalNamespace());

		assertEquals("a", a.name);
		assertSame(a.parent, top);
	}

	@Test
	public void testAddClasses() throws Exception {
		DBTraceClassSymbol classA;
		DBTraceClassSymbol nested;
		try (UndoableTransaction tid = b.startTransaction()) {
			classA =
				manager.classes().add("A", manager.getGlobalNamespace(), SourceType.USER_DEFINED);
			assertEquals(1, manager.classStore.getRecordCount());
			nested = manager.classes().add("Nested", classA, SourceType.USER_DEFINED);
			assertEquals(2, manager.classStore.getRecordCount());

			assertRejectsInvalid(
				name -> manager.classes().add(name, classA, SourceType.USER_DEFINED));
			assertRejectsDefault(() -> manager.classes().add("B", classA, SourceType.DEFAULT));
			assertRejectsDuplicate(
				() -> manager.classes().add("Nested", classA, SourceType.USER_DEFINED));
			assertRejectsDuplicate(
				() -> manager.namespaces().add("Nested", classA, SourceType.USER_DEFINED));

			assertEquals(2, manager.classStore.getRecordCount());
			assertEquals(1, manager.namespaceStore.getRecordCount());
		}
		assertEquals("A", classA.name);
		assertSame(classA.parent, manager.getGlobalNamespace());

		assertEquals("Nested", nested.name);
		assertSame(nested.parent, classA);
	}

	@Test
	public void testGetTrace() {
		assertEquals(b.trace, manager.getTrace());
	}

	@Test
	public void testGetSymbolByID()
			throws DuplicateNameException, InvalidInputException, IllegalArgumentException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		assertSame(global, manager.getSymbolByID(GlobalNamespace.GLOBAL_NAMESPACE_ID));

		DBTraceNamespaceSymbol nsA;
		DBTraceClassSymbol clsA;
		TraceLabelSymbol lab1;
		TraceLabelSymbol lab2;
		try (UndoableTransaction tid = b.startTransaction()) {
			nsA = manager.namespaces().add("a", global, SourceType.USER_DEFINED);
			clsA = manager.classes().add("A", nsA, SourceType.USER_DEFINED);
			lab1 = manager.labels()
					.create(0, null, b.addr(0x4000), "LAB1", nsA,
						SourceType.USER_DEFINED);
			lab2 = manager.labels()
					.create(0, null, b.addr(0x4001), "LAB2", clsA,
						SourceType.USER_DEFINED);
		}

		assertNull(manager.getSymbolByID(-1));
		assertSame(nsA, manager.getSymbolByID(nsA.getID()));
		assertSame(clsA, manager.getSymbolByID(clsA.getID()));
		assertSame(lab1, manager.getSymbolByID(lab1.getID()));
		assertSame(lab2, manager.getSymbolByID(lab2.getID()));
	}

	@Test
	public void testLabelsGetManager() {
		assertEquals(manager, manager.labels().getManager());
	}

	@Test
	public void testGetAllAndSize()
			throws InvalidInputException, DuplicateNameException, IllegalArgumentException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		DBTraceNamespaceSymbol nsA;
		DBTraceClassSymbol clsA;
		TraceLabelSymbol lab1;
		TraceLabelSymbol lab2;
		try (UndoableTransaction tid = b.startTransaction()) {
			nsA = manager.namespaces().add("a", global, SourceType.USER_DEFINED);
			clsA = manager.classes().add("A", nsA, SourceType.USER_DEFINED);
			lab1 = manager.labels()
					.create(0, null, b.addr(0x4000), "LAB1", nsA,
						SourceType.USER_DEFINED);
			lab2 = manager.labels()
					.create(0, null, b.addr(0x4001), "LAB2", clsA,
						SourceType.USER_DEFINED);
		}

		// TODO: Test with dynamicSymbols
		assertEquals(Set.of(lab1, lab2), new HashSet<>(manager.labels().getAll(false)));
		assertEquals(2, manager.labels().size(false));
		assertEquals(Set.of(nsA), new HashSet<>(manager.namespaces().getAll(false)));
		assertEquals(1, manager.namespaces().size(false));
		assertEquals(Set.of(clsA), new HashSet<>(manager.classes().getAll(false)));
		assertEquals(1, manager.classes().size(false));
		// TODO: Remaining types

		assertEquals(Set.of(nsA, clsA), new HashSet<>(manager.allNamespaces().getAll(false)));
		assertEquals(2, manager.allNamespaces().size(false));
		assertEquals(Set.of(lab1, lab2), new HashSet<>(manager.labelsAndFunctions().getAll(false)));
		assertEquals(2, manager.labelsAndFunctions().size(false));
		assertEquals(Set.of(nsA, clsA),
			new HashSet<>(manager.notLabelsNorFunctions().getAll(false)));
		assertEquals(2, manager.notLabelsNorFunctions().size(false));
		// TODO: Remaining composites
		assertEquals(Set.of(nsA, clsA, lab1, lab2),
			new HashSet<>(manager.allSymbols().getAll(false)));
		assertEquals(4, manager.allSymbols().size(false));
	}

	@Test
	public void testGetChildrenNamed()
			throws DuplicateNameException, InvalidInputException, IllegalArgumentException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		DBTraceNamespaceSymbol nsA;
		DBTraceClassSymbol clsA;
		TraceLabelSymbol lab1;
		TraceLabelSymbol lab2;
		try (UndoableTransaction tid = b.startTransaction()) {
			nsA = manager.namespaces().add("a", global, SourceType.USER_DEFINED);
			clsA = manager.classes().add("A", nsA, SourceType.USER_DEFINED);
			lab1 = manager.labels()
					.create(0, null, b.addr(0x4000), "LAB1", nsA,
						SourceType.USER_DEFINED);
			lab2 = manager.labels()
					.create(0, null, b.addr(0x4001), "LAB2", clsA,
						SourceType.USER_DEFINED);
		}

		assertEquals(Set.of(nsA),
			new HashSet<>(manager.allSymbols().getChildrenNamed("a", global)));
		assertEquals(Set.of(clsA), new HashSet<>(manager.classes().getChildrenNamed("A", nsA)));
		assertEquals(clsA, manager.classes().getChildNamed("A", nsA));
		assertEquals(Set.of(lab1), new HashSet<>(manager.labels().getChildrenNamed("LAB1", nsA)));
		assertEquals(Set.of(lab2),
			new HashSet<>(manager.labelsAndFunctions().getChildrenNamed("LAB2", clsA)));
		assertEquals(Set.of(), new HashSet<>(manager.labels().getChildrenNamed("LAB2", nsA)));
	}

	@Test
	public void testGetChildren()
			throws DuplicateNameException, InvalidInputException, IllegalArgumentException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		DBTraceNamespaceSymbol nsA;
		DBTraceClassSymbol clsA;
		TraceLabelSymbol lab1;
		TraceLabelSymbol lab2;
		try (UndoableTransaction tid = b.startTransaction()) {
			nsA = manager.namespaces().add("a", global, SourceType.USER_DEFINED);
			clsA = manager.classes().add("A", nsA, SourceType.USER_DEFINED);
			lab1 = manager.labels()
					.create(0, null, b.addr(0x4000), "LAB1", nsA,
						SourceType.USER_DEFINED);
			lab2 = manager.labels()
					.create(0, null, b.addr(0x4001), "LAB2", clsA,
						SourceType.USER_DEFINED);
		}
		assertEquals(Set.of(nsA), new HashSet<>(global.getChildren()));
		assertEquals(Set.of(clsA, lab1), new HashSet<>(nsA.getChildren()));
		assertEquals(Set.of(lab2), new HashSet<>(clsA.getChildren()));
		assertEquals(Set.of(), new HashSet<>(manager.classes().getChildren(clsA)));
	}

	@Test
	public void testGetGlobalsNamed()
			throws DuplicateNameException, InvalidInputException, IllegalArgumentException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		DBTraceNamespaceSymbol nsA;
		DBTraceClassSymbol clsA;
		try (UndoableTransaction tid = b.startTransaction()) {
			nsA = manager.namespaces().add("a", global, SourceType.USER_DEFINED);
			clsA = manager.classes().add("A", nsA, SourceType.USER_DEFINED);
			manager.labels().create(0, null, b.addr(0x4000), "LAB1", nsA, SourceType.USER_DEFINED);
			manager.labels().create(0, null, b.addr(0x4001), "LAB2", clsA, SourceType.USER_DEFINED);
		}

		assertEquals(Set.of(nsA), new HashSet<>(manager.namespaces().getGlobalsNamed("a")));
		assertEquals(Set.of(), new HashSet<>(manager.classes().getGlobalsNamed("a")));
		assertEquals(Set.of(), new HashSet<>(manager.allNamespaces().getGlobalsNamed("b")));
		// clsA not global
		assertEquals(Set.of(), new HashSet<>(manager.allNamespaces().getGlobalsNamed("A")));
	}

	@Test
	public void testGetGlobals()
			throws DuplicateNameException, InvalidInputException, IllegalArgumentException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		DBTraceNamespaceSymbol nsA;
		DBTraceClassSymbol clsA;
		try (UndoableTransaction tid = b.startTransaction()) {
			nsA = manager.namespaces().add("a", global, SourceType.USER_DEFINED);
			clsA = manager.classes().add("A", nsA, SourceType.USER_DEFINED);
			manager.labels().create(0, null, b.addr(0x4000), "LAB1", nsA, SourceType.USER_DEFINED);
			manager.labels().create(0, null, b.addr(0x4001), "LAB2", clsA, SourceType.USER_DEFINED);
		}

		assertEquals(Set.of(nsA), new HashSet<>(manager.namespaces().getGlobals()));
		assertEquals(Set.of(), new HashSet<>(manager.classes().getGlobals()));
		assertEquals(Set.of(nsA), new HashSet<>(manager.allNamespaces().getGlobals()));
	}

	@Test
	public void testGetNamed()
			throws DuplicateNameException, InvalidInputException, IllegalArgumentException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		DBTraceNamespaceSymbol nsA;
		DBTraceClassSymbol clsA;
		TraceLabelSymbol lab1;
		TraceLabelSymbol lab2;
		try (UndoableTransaction tid = b.startTransaction()) {
			nsA = manager.namespaces().add("a", global, SourceType.USER_DEFINED);
			clsA = manager.classes().add("A", nsA, SourceType.USER_DEFINED);
			lab1 = manager.labels()
					.create(0, null, b.addr(0x4000), "LAB1", nsA,
						SourceType.USER_DEFINED);
			lab2 = manager.labels()
					.create(0, null, b.addr(0x4001), "LAB2", clsA,
						SourceType.USER_DEFINED);
		}
		assertEquals(Set.of(lab1), new HashSet<>(manager.labels().getNamed("LAB1")));
		assertEquals(Set.of(lab2), new HashSet<>(manager.allSymbols().getNamed("LAB2")));
	}

	@Test
	public void testGetWithMatchingName()
			throws DuplicateNameException, InvalidInputException, IllegalArgumentException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		DBTraceNamespaceSymbol nsA;
		DBTraceClassSymbol clsA;
		TraceLabelSymbol lab1;
		TraceLabelSymbol lab2;
		try (UndoableTransaction tid = b.startTransaction()) {
			nsA = manager.namespaces().add("a", global, SourceType.USER_DEFINED);
			clsA = manager.classes().add("A", nsA, SourceType.USER_DEFINED);
			lab1 = manager.labels()
					.create(0, null, b.addr(0x4000), "LAB1", nsA,
						SourceType.USER_DEFINED);
			lab2 = manager.labels()
					.create(0, null, b.addr(0x4001), "lab2", clsA,
						SourceType.USER_DEFINED);
		}
		assertEquals(Set.of(lab1),
			new HashSet<>(manager.labelsAndFunctions().getWithMatchingName("LAB?", true)));
		assertEquals(Set.of(lab1, lab2),
			new HashSet<>(manager.labelsAndFunctions().getWithMatchingName("LAB?", false)));
	}

	@Test
	public void testGetChildWithNameAt()
			throws DuplicateNameException, InvalidInputException, IllegalArgumentException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		DBTraceThread thread;
		DBTraceNamespaceSymbol nsA;
		DBTraceClassSymbol clsA;
		TraceLabelSymbol lab1;
		TraceLabelSymbol lab2;
		TraceLabelSymbol lab3;
		TraceLabelSymbol lab4;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread1", 0);
			nsA = manager.namespaces().add("a", global, SourceType.USER_DEFINED);
			clsA = manager.classes().add("A", nsA, SourceType.USER_DEFINED);
			lab1 = manager.labels()
					.create(4, null, b.addr(0x4000), "LAB1", nsA,
						SourceType.USER_DEFINED);
			lab2 = manager.labels()
					.create(0, null, b.addr(0x4001), "lab2", clsA,
						SourceType.USER_DEFINED);
			lab3 = manager.labels()
					.create(0, null, b.addr(0x4001), "lab3", clsA,
						SourceType.USER_DEFINED);
			lab4 = manager.labels()
					.create(0, thread, b.language.getRegister("r4").getAddress(),
						"lab4", nsA, SourceType.USER_DEFINED);
		}
		assertEquals(lab1,
			manager.labels().getChildWithNameAt("LAB1", 4, null, b.addr(0x4000), nsA));
		assertNull(manager.functions().getChildWithNameAt("LAB1", 4, null, b.addr(0x4000), nsA));
		assertNull(manager.labels().getChildWithNameAt("LAB2", 4, null, b.addr(0x4000), nsA));
		assertNull(manager.labels().getChildWithNameAt("LAB1", 0, null, b.addr(0x4000), nsA));
		assertNull(manager.labels()
				.getChildWithNameAt("LAB1", 4, thread,
					b.language.getRegister("r4").getAddress(), nsA));
		assertNull(manager.labels().getChildWithNameAt("LAB1", 4, null, b.addr(0x4001), nsA));
		assertNull(
			manager.labelsAndFunctions().getChildWithNameAt("LAB1", 4, null, b.addr(0x4000), clsA));

		assertEquals(lab2,
			manager.labelsAndFunctions().getChildWithNameAt("lab2", 4, null, b.addr(0x4001), clsA));
		assertEquals(lab3,
			manager.labelsAndFunctions().getChildWithNameAt("lab3", 4, null, b.addr(0x4001), clsA));
		assertEquals(lab4, manager.labelsAndFunctions()
				.getChildWithNameAt("lab4", 0, thread,
					b.language.getRegister("r4").getAddress(), nsA));
	}

	@Test
	public void testGetGlobalWithNameAt() throws InvalidInputException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		TraceLabelSymbol lab1;
		try (UndoableTransaction tid = b.startTransaction()) {
			lab1 = manager.labels()
					.create(4, null, b.addr(0x4000), "LAB1", global,
						SourceType.USER_DEFINED);
		}
		assertEquals(lab1,
			manager.labelsAndFunctions().getGlobalWithNameAt("LAB1", 4, null, b.addr(0x4000)));
		assertEquals(lab1, manager.labels().getGlobalWithNameAt("LAB1", 4, null, b.addr(0x4000)));
	}

	@Test
	public void testGetIntersecting()
			throws DuplicateNameException, InvalidInputException, IllegalArgumentException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		DBTraceThread thread;
		DBTraceNamespaceSymbol nsA;
		DBTraceClassSymbol clsA;
		TraceLabelSymbol lab1;
		TraceLabelSymbol lab2;
		TraceLabelSymbol lab3;
		TraceLabelSymbol lab4;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread1", 0);
			nsA = manager.namespaces().add("a", global, SourceType.USER_DEFINED);
			clsA = manager.classes().add("A", nsA, SourceType.USER_DEFINED);
			lab1 = manager.labels()
					.create(4, null, b.addr(0x4000), "LAB1", nsA,
						SourceType.USER_DEFINED);
			lab2 = manager.labels()
					.create(0, null, b.addr(0x4001), "lab2", clsA,
						SourceType.USER_DEFINED);
			lab3 = manager.labels()
					.create(0, null, b.addr(0x4001), "lab3", clsA,
						SourceType.USER_DEFINED);
			lab4 = manager.labels()
					.create(0, thread, b.language.getRegister("r4").getAddress(),
						"lab4", nsA, SourceType.USER_DEFINED);
		}
		// TODO: Test that functions are properly excluded from labels()
		// once I have a means of adding them.
		assertEquals(Set.of(),
			new HashSet<>(manager.labelsAndFunctions()
					.getIntersecting(Range.closed(0L, 0L), null,
						b.range(0x0000, 0x4000), false, true)));
		assertEquals(Set.of(lab1, lab2, lab3),
			new HashSet<>(manager.labels()
					.getIntersecting(Range.atLeast(0L), null,
						b.range(0x4000, 0x4001), false, true)));
		assertEquals(Set.of(lab4),
			new HashSet<>(manager.labels()
					.getIntersecting(Range.atLeast(0L), thread,
						TraceRegisterUtils.rangeForRegister(b.language.getRegister("r4")), false,
						true)));
		assertEquals(Set.of(), new HashSet<>(manager.labels()
				.getIntersecting(Range.atLeast(0L),
					null, b.drng(0x4000, 0x4001), false, true)));

		// TODO: Test ordering is by address
	}

	@Test
	public void testGetAndHasAt()
			throws DuplicateNameException, InvalidInputException, IllegalArgumentException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		DBTraceNamespaceSymbol nsA;
		DBTraceClassSymbol clsA;
		TraceLabelSymbol lab1;
		TraceLabelSymbol lab2;
		TraceLabelSymbol lab3;
		try (UndoableTransaction tid = b.startTransaction()) {
			nsA = manager.namespaces().add("a", global, SourceType.USER_DEFINED);
			clsA = manager.classes().add("A", nsA, SourceType.USER_DEFINED);
			lab1 = manager.labels()
					.create(4, null, b.addr(0x4000), "LAB1", nsA,
						SourceType.USER_DEFINED);
			lab2 = manager.labels()
					.create(0, null, b.addr(0x4001), "lab2", clsA,
						SourceType.USER_DEFINED);
			lab3 = manager.labels()
					.create(0, null, b.addr(0x4001), "lab3", clsA,
						SourceType.USER_DEFINED);
		}

		assertEquals(Set.of(lab1),
			new HashSet<>(manager.labels().getAt(4, null, b.addr(0x4000), false)));
		assertEquals(Set.of(lab2, lab3),
			new HashSet<>(manager.labelsAndFunctions().getAt(4, null, b.addr(0x4001), false)));
		// TODO: Test ordering by setPrimary

		assertFalse(manager.labels().hasAt(0, null, b.addr(0x4000), false));
		assertTrue(manager.labels().hasAt(4, null, b.addr(0x4000), false));
	}

	@Test
	public void testDelete()
			throws DuplicateNameException, InvalidInputException, IllegalArgumentException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		DBTraceThread thread;
		DBTraceNamespaceSymbol nsA;
		DBTraceClassSymbol clsA;
		TraceLabelSymbol lab2;
		TraceLabelSymbol lab3;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread1", 0);
			nsA = manager.namespaces().add("a", global, SourceType.USER_DEFINED);
			clsA = manager.classes().add("A", nsA, SourceType.USER_DEFINED);
			manager.labels().create(4, null, b.addr(0x4000), "LAB1", nsA, SourceType.USER_DEFINED);
			lab2 = manager.labels()
					.create(0, null, b.addr(0x4001), "lab2", clsA,
						SourceType.USER_DEFINED);
			lab3 = manager.labels()
					.create(0, null, b.addr(0x4001), "lab3", clsA,
						SourceType.USER_DEFINED);
			manager.labels()
					.create(0, thread, b.language.getRegister("r4").getAddress(), "lab4",
						nsA, SourceType.USER_DEFINED);
		}

		try (UndoableTransaction tid = b.startTransaction()) {
			lab3.delete();
			assertEquals(Set.of(lab2), new HashSet<>(manager.allSymbols().getChildren(clsA)));

			nsA.delete();
			assertEquals(Set.of(), new HashSet<>(manager.allSymbols().getAll(false)));
		}
	}

	@Test
	public void testSaveAndLoad() throws DuplicateNameException, InvalidInputException,
			IllegalArgumentException, CancelledException, IOException, VersionException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		DBTraceThread thread;
		DBTraceNamespaceSymbol nsA;
		DBTraceClassSymbol clsA;
		TraceLabelSymbol lab1;
		TraceLabelSymbol lab2;
		TraceLabelSymbol lab3;
		TraceLabelSymbol lab4;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread1", 0);
			nsA = manager.namespaces().add("a", global, SourceType.USER_DEFINED);
			clsA = manager.classes().add("A", nsA, SourceType.USER_DEFINED);
			lab1 = manager.labels()
					.create(4, null, b.addr(0x4000), "LAB1", nsA,
						SourceType.USER_DEFINED);
			lab2 = manager.labels()
					.create(0, null, b.addr(0x4001), "lab2", clsA,
						SourceType.USER_DEFINED);
			lab3 = manager.labels()
					.create(0, null, b.addr(0x4001), "lab3", clsA,
						SourceType.USER_DEFINED);
			lab4 = manager.labels()
					.create(0, thread, b.language.getRegister("r4").getAddress(),
						"lab4", nsA, SourceType.USER_DEFINED);
		}

		File saved = b.save();
		try (@SuppressWarnings("hiding") // I want to hide it
		ToyDBTraceBuilder b = new ToyDBTraceBuilder(saved)) {
			@SuppressWarnings("hiding")
			DBTraceSymbolManager manager = b.trace.getSymbolManager();
			thread = b.trace.getThreadManager().getThreadsByPath("Thread1").iterator().next();
			assertEquals(Set.of(nsA, clsA, lab1, lab2, lab3, lab4),
				new HashSet<>(manager.allSymbols().getAll(false)));
			assertEquals(Set.of(lab2, lab3),
				new HashSet<>(manager.labels().getAt(0, null, b.addr(0x4001), false)));
			assertEquals(Set.of(lab4), new HashSet<>(manager.labels()
					.getAt(0, thread,
						b.language.getRegister("r4").getAddress(), false)));
		}
	}

	@Test
	public void testUndoThenRedo() throws DuplicateNameException, InvalidInputException,
			IllegalArgumentException, IOException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		DBTraceThread thread;
		DBTraceNamespaceSymbol nsA;
		DBTraceClassSymbol clsA;
		TraceLabelSymbol lab1;
		TraceLabelSymbol lab2;
		TraceLabelSymbol lab3;
		TraceLabelSymbol lab4;
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread1", 0);
			nsA = manager.namespaces().add("a", global, SourceType.USER_DEFINED);
			clsA = manager.classes().add("A", nsA, SourceType.USER_DEFINED);
			lab1 = manager.labels()
					.create(4, null, b.addr(0x4000), "LAB1", nsA,
						SourceType.USER_DEFINED);
			lab2 = manager.labels()
					.create(0, null, b.addr(0x4001), "lab2", clsA,
						SourceType.USER_DEFINED);
			lab3 = manager.labels()
					.create(0, null, b.addr(0x4001), "lab3", clsA,
						SourceType.USER_DEFINED);
			lab4 = manager.labels()
					.create(0, thread, b.language.getRegister("r4").getAddress(),
						"lab4", nsA, SourceType.USER_DEFINED);
		}

		b.trace.undo();

		assertNotNull(manager.checkIsMine((Namespace) manager.getGlobalNamespace()));

		assertEquals(Set.of(), new HashSet<>(manager.allSymbols().getAll(false)));

		b.trace.redo();

		thread = b.getOrAddThread("Thread1", 0);

		assertEquals(Set.of(nsA, clsA, lab1, lab2, lab3, lab4),
			new HashSet<>(manager.allSymbols().getAll(false)));
		assertEquals(Set.of(lab2, lab3),
			new HashSet<>(manager.labels().getAt(0, null, b.addr(0x4001), false)));
		assertEquals(Set.of(lab4), new HashSet<>(
			manager.labels().getAt(0, thread, b.language.getRegister("r4").getAddress(), false)));
	}
}
