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
import java.util.*;

import org.junit.*;

import db.Transaction;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;
import ghidra.trace.model.target.schema.XmlSchemaContext;

public class DBTraceModuleManagerTest extends AbstractGhidraHeadlessIntegrationTest {

	public static final String XML_CTX = """
			<context>
			    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
			        <attribute name='Modules' schema='ModuleContainer' />
			    </schema>
			    <schema name='ModuleContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <element schema='Module' />
			    </schema>
			    <schema name='Module' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Module' />
			        <attribute name='Sections' schema='SectionContainer' />
			    </schema>
			    <schema name='SectionContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <element schema='Section' />
			    </schema>
			    <schema name='Section' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Section' />
			    </schema>
			</context>
			""";

	ToyDBTraceBuilder b;
	DBTraceModuleManager moduleManager;

	@Before
	public void setUpModuleManagerTest() throws Exception {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");

		try (Transaction tx = b.startTransaction()) {
			XmlSchemaContext ctx = XmlSchemaContext.deserialize(XML_CTX);
			b.trace.getObjectManager().createRootObject(ctx.getSchema(new SchemaName("Session")));
		}

		moduleManager = b.trace.getModuleManager();
	}

	@After
	public void tearDownModuleManagerTest() {
		b.close();
	}

	@Test
	public void testAddModule() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			moduleManager.addLoadedModule("Modules[second]", "second",
				b.range(0x7f400000, 0x7f60002f), 0);
		}
	}

	@Test
	public void testAddSections() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			TraceModule mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			mod1.addSection(0, "Modules[first].Sections[.text]", b.range(0x00401000, 0x00401f9f));
			mod1.addSection(0, "Modules[first].Sections[.data]", b.range(0x00600000, 0x0060002f));

			moduleManager.addModule("Modules[second]", "second",
				b.range(0x7f400000, 0x7f60002f), Lifespan.span(0, 10));
		}
	}

	@Test
	public void testGetAllModules() throws Exception {
		assertEquals(Set.of(), new HashSet<>(moduleManager.getAllModules()));

		TraceModule mod1;
		TraceModule mod2;
		try (Transaction tx = b.startTransaction()) {
			mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			mod1.addSection(0, "Modules[first].Sections[.text]", b.range(0x00401000, 0x00401f9f));
			mod1.addSection(0, "Modules[first].Sections[.data]", b.range(0x00600000, 0x0060002f));

			mod2 = moduleManager.addModule("Modules[second]", "second",
				b.range(0x7f400000, 0x7f60002f), Lifespan.span(0, 10));
		}
		assertEquals(Set.of(mod1, mod2), new HashSet<>(moduleManager.getAllModules()));
	}

	@Test
	public void testGetModulesByPath() throws Exception {
		assertEquals(Set.of(), new HashSet<>(moduleManager.getModulesByPath("first")));

		TraceModule mod1;
		TraceModule mod2;
		TraceModule mod3;
		try (Transaction tx = b.startTransaction()) {
			mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			mod1.addSection(0, "Modules[first].Sections[.text]", b.range(0x00401000, 0x00401f9f));
			mod1.addSection(0, "Modules[first].Sections[.data]", b.range(0x00600000, 0x0060002f));

			mod2 = moduleManager.addModule("Modules[second]", "second",
				b.range(0x7e400000, 0x7e60002f), Lifespan.span(0, 10));
			mod3 = moduleManager.addModule("Modules[second]", "second",
				b.range(0x7f400000, 0x7f60002f), Lifespan.span(11, 20));
		}
		assertEquals(Set.of(mod1), new HashSet<>(moduleManager.getModulesByPath("Modules[first]")));
		assertEquals(Set.copyOf(List.of(mod2, mod3)), // Same in object mode
			Set.copyOf(moduleManager.getModulesByPath("Modules[second]")));
	}

	@Test
	public void testModuleGetTrace() throws Exception {
		TraceModule mod1;
		try (Transaction tx = b.startTransaction()) {
			mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
		}
		assertEquals(b.trace, mod1.getTrace());
	}

	@Test
	public void testModuleSetGetName() throws Exception {
		TraceModule mod1;
		try (Transaction tx = b.startTransaction()) {
			mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			assertEquals("first", mod1.getName(0));

			mod1.setName(0, "FIRST");
			assertEquals("FIRST", mod1.getName(0));
		}
	}

	@Test
	public void testModuleSetGetBase() throws Exception {
		// TODO: Should adjusting the base shift the sections?
		TraceModule mod1;
		try (Transaction tx = b.startTransaction()) {
			mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			assertEquals(b.addr(0x00400000), mod1.getBase(0));

			mod1.setBase(0, b.addr(0x00400100)); // Cannot exceed current max
			assertEquals(b.addr(0x00400100), mod1.getBase(0));
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
		try (Transaction tx = b.startTransaction()) {
			mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			s1text = mod1.addSection(0, "Modules[first].Sections[.text]",
				b.range(0x00401000, 0x00401f9f));
			s1data = mod1.addSection(0, "Modules[first].Sections[.data]",
				b.range(0x00600000, 0x0060002f));

			mod2 = moduleManager.addModule("Modules[second]", "second",
				b.range(0x7e400000, 0x7e60002f), Lifespan.span(0, 10));
			s2text = mod2.addSection(0, "Modules[second].Sections[.text]",
				b.range(0x7f401000, 0x7f401fa0));
			s2data = mod2.addSection(0, "Modules[second].Sections[.data]",
				b.range(0x7f600000, 0x7f60002f));
		}
		assertEquals(Set.of(s1text, s1data), new HashSet<>(mod1.getSections(0)));
		assertEquals(Set.of(s2text, s2data), new HashSet<>(mod2.getSections(0)));
	}

	@Test
	public void testModuleGetSectionByName() throws Exception {
		TraceModule mod1;
		TraceModule mod2;
		TraceSection s1text;
		TraceSection s1data;
		TraceSection s2text;
		TraceSection s2data;
		try (Transaction tx = b.startTransaction()) {
			mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			s1text = mod1.addSection(0, "Modules[first].Sections[.text]", ".text",
				b.range(0x00401000, 0x00401f9f));
			s1data = mod1.addSection(0, "Modules[first].Sections[.data]", ".data",
				b.range(0x00600000, 0x0060002f));

			mod2 = moduleManager.addModule("Modules[second]", "second",
				b.range(0x7f400000, 0x7f60002f), Lifespan.span(0, 10));
			s2text = mod2.addSection(0, "Modules[second].Sections[.text]", ".text",
				b.range(0x7f401000, 0x7f401f9f));
			s2data = mod2.addSection(0, "Modules[second].Sections[.data]", ".data",
				b.range(0x7f600000, 0x7f60002f));
		}
		assertEquals(s1text, mod1.getSectionByName(0, ".text"));
		assertEquals(s1data, mod1.getSectionByName(0, ".data"));
		assertEquals(s2text, mod2.getSectionByName(0, ".text"));
		assertEquals(s2data, mod2.getSectionByName(0, ".data"));
	}

	@Test
	public void testModuleDelete() throws Exception {
		TraceModule mod1;
		TraceModule mod2;
		try (Transaction tx = b.startTransaction()) {
			mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			mod1.addSection(0, "Modules[first].Sections[.text]", b.range(0x00401000, 0x00401f9f));
			mod1.addSection(0, "Modules[first].Sections[.data]", b.range(0x00600000, 0x0060002f));

			mod2 = moduleManager.addModule("Modules[second]", "second",
				b.range(0x7f400000, 0x7f60002f), Lifespan.span(0, 10));
		}

		try (Transaction tx = b.startTransaction()) {
			mod1.delete();
		}

		assertEquals(Set.of(mod2), new HashSet<>(moduleManager.getAllModules()));
	}

	@Test
	public void testSectionGetModule() throws Exception {
		TraceModule mod1;
		TraceSection s1text;
		try (Transaction tx = b.startTransaction()) {
			mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			s1text =
				mod1.addSection(0, "Modules[first].Sections[.text]",
					b.range(0x00401000, 0x00401f9f));
		}

		assertEquals(mod1, s1text.getModule());
	}

	@Test
	public void testSectionSetGetName() throws Exception {
		TraceModule mod1;
		TraceSection s1text;
		try (Transaction tx = b.startTransaction()) {
			mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			s1text = mod1.addSection(0, "Modules[first].Sections[.text]", ".text",
				b.range(0x00401000, 0x00401f9f));

			assertEquals(".text", s1text.getName(0));
			s1text.setName(0, "_TEXT");
			assertEquals("_TEXT", s1text.getName(0));
		}
	}

	@Test
	public void testSectionGetRange() throws Exception {
		TraceModule mod1;
		TraceSection s1text;
		try (Transaction tx = b.startTransaction()) {
			mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			s1text = mod1.addSection(0, "Modules[first].Sections[.text]", ".text",
				b.range(0x00401000, 0x00401f9f));
		}

		assertEquals(b.range(0x00401000, 0x00401f9f), s1text.getRange(0));
		assertEquals(b.addr(0x00401000), s1text.getStart(0));
		assertEquals(b.addr(0x00401f9f), s1text.getEnd(0));
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
		try (Transaction tx = b.startTransaction()) {
			mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			mod1.addSection(0, "Modules[first].Sections[.text]", ".text",
				b.range(0x00401000, 0x00401f9f));
			mod1.addSection(0, "Modules[first].Sections[.data]", ".data",
				b.range(0x00600000, 0x0060002f));

			mod2 = moduleManager.addModule("Modules[second]", "second",
				b.range(0x7f400000, 0x7f60002f), Lifespan.span(1, 11));
		}

		File tmp = b.save();
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder(tmp)) {
			DBTraceModuleManager moduleManager = b.trace.getModuleManager();

			mod1 = assertOne(moduleManager.getModulesByPath("Modules[first]"));
			mod2 = assertOne(moduleManager.getModulesByPath("Modules[second]"));
			TraceSection s1text = mod1.getSectionByName(0, ".text");
			TraceSection s1data = mod1.getSectionByName(0, ".data");

			assertEquals(b.addr(0x00400000), mod1.getBase(0));
			assertEquals(b.addr(0x7f400000), mod2.getBase(1));
			assertEquals(b.range(0x00401000, 0x00401f9f), s1text.getRange(0));
			assertEquals(b.range(0x00600000, 0x0060002f), s1data.getRange(0));
		}
	}

	@Test
	@Ignore("Write-back cache doesn't support undo")
	public void testUndoIdentitiesPreserved() throws Exception {
		TraceModule mod1;
		try (Transaction tx = b.startTransaction()) {
			mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			mod1.addSection(0, "Modules[first].Sections[.text]", b.range(0x00401000, 0x00401f9f));
			mod1.addSection(0, "Modules[first].Sections[.data]", b.range(0x00600000, 0x0060002f));
		}

		try (Transaction tx = b.startTransaction()) {
			moduleManager.addModule("Modules[second]", "second",
				b.range(0x7f400000, 0x7f60002f), Lifespan.span(1, 11));
		}

		b.trace.undo();

		assertSame(mod1, assertOne(moduleManager.getModulesByPath("Modules[first]")));
		assertTrue(moduleManager.getModulesByPath("Modules[second]").isEmpty());
	}

	@Test
	@Ignore("Write-back cache doesn't support undo")
	public void testUndoThenRedo() throws Exception {
		TraceModule mod1;
		TraceModule mod2;
		try (Transaction tx = b.startTransaction()) {
			mod1 = moduleManager.addModule("Modules[first]", "first",
				b.range(0x00400000, 0x0060002f), Lifespan.span(0, 10));
			mod1.addSection(0, "Modules[first].Sections[.text]", ".text",
				b.range(0x00401000, 0x00401f9f));
			mod1.addSection(0, "Modules[first].Sections[.data]", ".data",
				b.range(0x00600000, 0x0060002f));

			mod2 = moduleManager.addModule("Modules[second]", "second",
				b.range(0x7f400000, 0x7f60002f), Lifespan.span(1, 11));
		}

		b.trace.undo();
		assertEquals(Set.of(), new HashSet<>(moduleManager.getAllModules()));

		b.trace.redo();

		// NOTE: Because undo actually removes them, module identity may not be preserved
		mod1 = assertOne(moduleManager.getModulesByPath("Modules[first]"));
		mod2 = assertOne(moduleManager.getModulesByPath("Modules[second]"));
		TraceSection s1text = mod1.getSectionByName(0, ".text");
		TraceSection s1data = mod1.getSectionByName(0, ".data");

		assertEquals(b.addr(0x00400000), mod1.getBase(0));
		assertEquals(b.addr(0x7f400000), mod2.getBase(0));
		assertEquals(b.range(0x00401000, 0x00401f9f), s1text.getRange(0));
		assertEquals(b.range(0x00600000, 0x0060002f), s1data.getRange(0));
	}
}
