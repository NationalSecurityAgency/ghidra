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

import static ghidra.lifecycle.Unfinished.TODO;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.*;

import org.junit.*;

import com.google.common.collect.Range;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.util.database.UndoableTransaction;

public class DBTraceModuleManagerTest extends AbstractGhidraHeadlessIntegrationTest {

	ToyDBTraceBuilder b;
	DBTraceModuleManager moduleManager;

	@Before
	public void setUpModuleManagerTest() throws Exception {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");
		moduleManager = b.trace.getModuleManager();
	}

	@After
	public void tearDownModuleManagerTest() {
		b.close();
	}

	@Test
	public void testAddModule() throws Exception {
		try (UndoableTransaction tid = b.startTransaction()) {
			moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			moduleManager.addLoadedModule("second", "second",
				b.range(0x7f400000, 0x7f60002f), 0);
		}
	}

	@Test
	public void testAddSections() throws Exception {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceModule mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			mod1.addSection(".text", b.range(0x00401000, 0x00401f9f));
			mod1.addSection(".data", b.range(0x00600000, 0x0060002f));

			moduleManager.addModule("second", "second",
				b.range(0x7f400000, 0x7f60002f), Range.closed(0L, 10L));
		}
	}

	@Test
	public void testGetAllModules() throws Exception {
		assertEquals(Set.of(), new HashSet<>(moduleManager.getAllModules()));

		TraceModule mod1;
		TraceModule mod2;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			mod1.addSection(".text", b.range(0x00401000, 0x00401f9f));
			mod1.addSection(".data", b.range(0x00600000, 0x0060002f));

			mod2 = moduleManager.addModule("second", "second",
				b.range(0x7f400000, 0x7f60002f), Range.closed(0L, 10L));
		}
		assertEquals(Set.of(mod1, mod2), new HashSet<>(moduleManager.getAllModules()));
	}

	@Test
	public void testGetModulesByPath() throws Exception {
		assertEquals(Set.of(), new HashSet<>(moduleManager.getModulesByPath("first")));

		TraceModule mod1;
		TraceModule mod2;
		TraceModule mod3;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			mod1.addSection(".text", b.range(0x00401000, 0x00401f9f));
			mod1.addSection(".data", b.range(0x00600000, 0x0060002f));

			mod2 = moduleManager.addModule("second", "second",
				b.range(0x7e400000, 0x7e60002f), Range.closed(0L, 10L));
			mod3 = moduleManager.addModule("second", "second",
				b.range(0x7f400000, 0x7f60002f), Range.closed(11L, 20L));
		}
		assertEquals(Set.of(mod1), new HashSet<>(moduleManager.getModulesByPath("first")));
		assertEquals(Set.of(mod2, mod3), new HashSet<>(moduleManager.getModulesByPath("second")));
	}

	@Test
	public void testModuleGetTrace() throws Exception {
		TraceModule mod1;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
		}
		assertEquals(b.trace, mod1.getTrace());
	}

	@Test
	public void testModuleSetGetName() throws Exception {
		TraceModule mod1;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			assertEquals("first", mod1.getName());

			mod1.setName("FIRST");
			assertEquals("FIRST", mod1.getName());
		}
	}

	@Test
	public void testModuleSetGetBase() throws Exception {
		// TODO: Should adjusting the base shift the sections?
		TraceModule mod1;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			assertEquals(b.addr(0x00400000), mod1.getBase());

			mod1.setBase(b.addr(0x00400100)); // Cannot exceed current max
			assertEquals(b.addr(0x00400100), mod1.getBase());
		}
	}

	@Test
	public void testModuleSetGetLifespan() throws Exception {
		TraceModule mod1;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			assertEquals(Range.closed(0L, 10L), mod1.getLifespan());
			assertEquals(0, mod1.getLoadedSnap());
			assertEquals(10, mod1.getUnloadedSnap());

			mod1.setLifespan(Range.closed(1L, 11L));
			assertEquals(Range.closed(1L, 11L), mod1.getLifespan());
			assertEquals(1, mod1.getLoadedSnap());
			assertEquals(11, mod1.getUnloadedSnap());

			mod1.setLoadedSnap(2);
			assertEquals(Range.closed(2L, 11L), mod1.getLifespan());
			mod1.setUnloadedSnap(4);
			assertEquals(Range.closed(2L, 4L), mod1.getLifespan());
		}
	}

	@Test
	public void testModuleGetSections() throws Exception {
		TraceModule mod1;
		TraceModule mod2;
		TraceSection s1text;
		TraceSection s1data;
		TraceSection s2text;
		TraceSection s2data;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			s1text = mod1.addSection("first[.text]", b.range(0x00401000, 0x00401f9f));
			s1data = mod1.addSection("first[.data]", b.range(0x00600000, 0x0060002f));

			mod2 = moduleManager.addModule("second", "second",
				b.range(0x7e400000, 0x7e60002f), Range.closed(0L, 10L));
			s2text = mod2.addSection("second[.text]", b.range(0x7f401000, 0x7f401fa0));
			s2data = mod2.addSection("second[.data]", b.range(0x7f600000, 0x7f60002f));
		}
		assertEquals(Set.of(s1text, s1data), new HashSet<>(mod1.getSections()));
		assertEquals(Set.of(s2text, s2data), new HashSet<>(mod2.getSections()));
	}

	@Test
	public void testModuleGetSectionByName() throws Exception {
		TraceModule mod1;
		TraceModule mod2;
		TraceSection s1text;
		TraceSection s1data;
		TraceSection s2text;
		TraceSection s2data;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			s1text = mod1.addSection("first[.text]", ".text", b.range(0x00401000, 0x00401f9f));
			s1data = mod1.addSection("first[.data]", ".data", b.range(0x00600000, 0x0060002f));

			mod2 = moduleManager.addModule("second", "second",
				b.range(0x7f400000, 0x7f60002f), Range.closed(0L, 10L));
			s2text = mod2.addSection("second[.text]", ".text", b.range(0x7f401000, 0x7f401f9f));
			s2data = mod2.addSection("second[.data]", ".data", b.range(0x7f600000, 0x7f60002f));
		}
		assertEquals(s1text, mod1.getSectionByName(".text"));
		assertEquals(s1data, mod1.getSectionByName(".data"));
		assertEquals(s2text, mod2.getSectionByName(".text"));
		assertEquals(s2data, mod2.getSectionByName(".data"));
	}

	@Test
	public void testModuleDelete() throws Exception {
		TraceModule mod1;
		TraceModule mod2;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			mod1.addSection(".text", b.range(0x00401000, 0x00401f9f));
			mod1.addSection(".data", b.range(0x00600000, 0x0060002f));

			mod2 = moduleManager.addModule("second", "second",
				b.range(0x7f400000, 0x7f60002f), Range.closed(0L, 10L));
		}

		try (UndoableTransaction tid = b.startTransaction()) {
			mod1.delete();
		}

		assertEquals(Set.of(mod2), new HashSet<>(moduleManager.getAllModules()));
	}

	@Test
	public void testSectionGetModule() throws Exception {
		TraceModule mod1;
		TraceSection s1text;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			s1text = mod1.addSection(".text", b.range(0x00401000, 0x00401f9f));
		}

		assertEquals(mod1, s1text.getModule());
	}

	@Test
	public void testSectionSetGetName() throws Exception {
		TraceModule mod1;
		TraceSection s1text;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			s1text = mod1.addSection(".text", b.range(0x00401000, 0x00401f9f));

			assertEquals(".text", s1text.getName());
			s1text.setName("_TEXT");
			assertEquals("_TEXT", s1text.getName());
		}
	}

	@Test
	public void testSectionGetRange() throws Exception {
		TraceModule mod1;
		TraceSection s1text;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			s1text = mod1.addSection(".text", b.range(0x00401000, 0x00401f9f));
		}

		assertEquals(b.range(0x00401000, 0x00401f9f), s1text.getRange());
		assertEquals(b.addr(0x00401000), s1text.getStart());
		assertEquals(b.addr(0x00401f9f), s1text.getEnd());
	}

	protected <T> T assertOne(Collection<T> col) {
		assertEquals(1, col.size());
		return col.iterator().next();
	}

	@Test
	@SuppressWarnings("hiding") // I want to hide them, to avoid mistaken ref to them
	public void testSaveThenLoad() throws Exception {
		TraceModule mod1;
		TraceModule mod2;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			mod1.addSection(".text", b.range(0x00401000, 0x00401f9f));
			mod1.addSection(".data", b.range(0x00600000, 0x0060002f));

			mod2 = moduleManager.addModule("second", "second",
				b.range(0x7f400000, 0x7f60002f), Range.closed(1L, 11L));
		}

		File tmp = b.save();
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder(tmp)) {
			DBTraceModuleManager moduleManager = b.trace.getModuleManager();

			mod1 = assertOne(moduleManager.getModulesByPath("first"));
			mod2 = assertOne(moduleManager.getModulesByPath("second"));
			TraceSection s1text = mod1.getSectionByName(".text");
			TraceSection s1data = mod1.getSectionByName(".data");

			assertEquals(b.addr(0x00400000), mod1.getBase());
			assertEquals(Range.closed(0L, 10L), mod1.getLifespan());
			assertEquals(b.addr(0x7f400000), mod2.getBase());
			assertEquals(Range.closed(1L, 11L), mod2.getLifespan());
			assertEquals(b.range(0x00401000, 0x00401f9f), s1text.getRange());
			assertEquals(b.range(0x00600000, 0x0060002f), s1data.getRange());
		}
	}

	@Test
	@Ignore("GP-479")
	public void testUndoIdentitiesPreserved() throws Exception {
		TraceModule mod1;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			mod1.addSection(".text", b.range(0x00401000, 0x00401f9f));
			mod1.addSection(".data", b.range(0x00600000, 0x0060002f));
		}

		try (UndoableTransaction tid = b.startTransaction()) {
			moduleManager.addModule("second", "second",
				b.range(0x7f400000, 0x7f60002f), Range.closed(1L, 11L));
		}

		b.trace.undo();

		assertEquals(mod1, assertOne(moduleManager.getModulesByPath("first")));
		TODO(); // TODO: mod1 should still be identical to that in database
		assertTrue(moduleManager.getModulesByPath("second").isEmpty());
	}

	@Test
	public void testUndoThenRedo() throws Exception {
		TraceModule mod1;
		TraceModule mod2;
		try (UndoableTransaction tid = b.startTransaction()) {
			mod1 = moduleManager.addModule("first", "first",
				b.range(0x00400000, 0x0060002f), Range.closed(0L, 10L));
			mod1.addSection(".text", b.range(0x00401000, 0x00401f9f));
			mod1.addSection(".data", b.range(0x00600000, 0x0060002f));

			mod2 = moduleManager.addModule("second", "second",
				b.range(0x7f400000, 0x7f60002f), Range.closed(1L, 11L));
		}

		b.trace.undo();
		assertEquals(Set.of(), new HashSet<>(moduleManager.getAllModules()));

		b.trace.redo();

		// NOTE: Because undo actually removes them, module identity may not be preserved
		mod1 = assertOne(moduleManager.getModulesByPath("first"));
		mod2 = assertOne(moduleManager.getModulesByPath("second"));
		TraceSection s1text = mod1.getSectionByName(".text");
		TraceSection s1data = mod1.getSectionByName(".data");

		assertEquals(b.addr(0x00400000), mod1.getBase());
		assertEquals(Range.closed(0L, 10L), mod1.getLifespan());
		assertEquals(b.addr(0x7f400000), mod2.getBase());
		assertEquals(Range.closed(1L, 11L), mod2.getLifespan());
		assertEquals(b.range(0x00401000, 0x00401f9f), s1text.getRange());
		assertEquals(b.range(0x00600000, 0x0060002f), s1data.getRange());
	}
}
