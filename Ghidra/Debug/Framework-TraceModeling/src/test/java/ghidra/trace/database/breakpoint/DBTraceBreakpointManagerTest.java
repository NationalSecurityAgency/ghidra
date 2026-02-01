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
package ghidra.trace.database.breakpoint;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.*;

import java.util.List;
import java.util.Set;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.*;

import db.Transaction;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.breakpoint.TraceBreakpointLocation;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;
import ghidra.trace.model.target.schema.XmlSchemaContext;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceBreakpointManagerTest extends AbstractGhidraHeadlessIntegrationTest {

	public static final String XML_CTX = """
			<context>
			    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
			        <interface name='Process' />
			        <attribute name='Threads' schema='ThreadContainer' />
			        <attribute name='Breakpoints' schema='BreakpointContainer' />
			    </schema>
			    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <element schema='Thread' />
			    </schema>
			    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Thread' />
			    </schema>
			    <schema name='BreakpointContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <element schema='Breakpoint' />
			    </schema>
			    <schema name='Breakpoint' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='BreakpointSpec' />
			        <interface name='BreakpointLocation' />
			    </schema>
			</context>
			""";

	ToyDBTraceBuilder b;
	DBTraceBreakpointManager breakpointManager;

	TraceThread thread;
	TraceBreakpointLocation breakMain;
	TraceBreakpointLocation breakVarA;
	TraceBreakpointLocation breakVarB;

	@Before
	public void setUpBreakpointManagerTest() throws Exception {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");

		try (Transaction tx = b.startTransaction()) {
			XmlSchemaContext ctx = XmlSchemaContext.deserialize(XML_CTX);
			b.trace.getObjectManager().createRootObject(ctx.getSchema(new SchemaName("Session")));
		}

		breakpointManager = b.trace.getBreakpointManager();
	}

	@After
	public void tearDownBreakpointManagerTest() throws Exception {
		b.close();
	}

	@Test
	public void testAddBreakpoint() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			breakpointManager.addBreakpoint("Breakpoints[0]", Lifespan.span(0, 10),
				b.addr(0x00400000),
				Set.of(), Set.of(TraceBreakpointKind.SW_EXECUTE), true, "main");
		}

		try (Transaction tx = b.startTransaction()) {
			breakpointManager.addBreakpoint("Breakpoints[0]", Lifespan.span(0, 10),
				b.range(0x00400000, 0x00400003), Set.of(), Set.of(), false, "duplicate");
		}
		catch (DuplicateNameException e) {
			// pass
		}

		assertEquals(1, breakpointManager.getBreakpointLocationsByPath("Breakpoints[0]").size());
	}

	protected void addBreakpoints() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			thread = b.getOrAddThread("Threads[1]", 0);
			// NB. threads parameter is deprecated by object mode.
			// For table mode, ensure the answer is the same as object mode
			breakMain = breakpointManager.addBreakpoint("Breakpoints[0]", Lifespan.span(0, 10),
				b.addr(0x00400000),
				Set.of(thread), Set.of(TraceBreakpointKind.SW_EXECUTE), true, "main");
			breakVarA = breakpointManager.addBreakpoint("Breakpoints[1]", Lifespan.span(0, 10),
				b.range(0x00600010, 0x00600013),
				Set.of(thread), Set.of(TraceBreakpointKind.WRITE), false, "varA");
			breakVarB = breakpointManager.addBreakpoint("Breakpoints[1]", Lifespan.span(11, 20),
				b.range(0x00600020, 0x00600023),
				Set.of(thread), Set.of(TraceBreakpointKind.WRITE), false, "varB");
		}
	}

	@Test
	public void testGetAllBreakpoints() throws Exception {
		addBreakpoints();
		// breakVarA == breakVarB in object mode
		assertEquals(Set.copyOf(List.of(breakMain, breakVarA, breakVarB)),
			Set.copyOf(breakpointManager.getAllBreakpointLocations()));
	}

	@Test
	public void testBreakpointsByPath() throws Exception {
		addBreakpoints();
		assertEquals(Set.of(breakMain),
			Set.copyOf(breakpointManager.getBreakpointLocationsByPath("Breakpoints[0]")));
		assertEquals(Set.copyOf(List.of(breakVarA, breakVarB)), // Same breakpoint in object mode
			Set.copyOf(breakpointManager.getBreakpointLocationsByPath("Breakpoints[1]")));
	}

	@Test
	public void testBreakpointPlacedByPath() throws Exception {
		addBreakpoints();
		assertEquals(breakVarA, breakpointManager.getPlacedBreakpointByPath(0, "Breakpoints[1]"));
		assertEquals(breakVarB, breakpointManager.getPlacedBreakpointByPath(11, "Breakpoints[1]"));
	}

	@Test
	public void testBreakpointsAt() throws Exception {
		addBreakpoints();
		assertEquals(Set.of(breakMain),
			Set.copyOf(breakpointManager.getBreakpointsAt(0, b.addr(0x00400000))));
		assertEquals(Set.of(breakVarA),
			Set.copyOf(breakpointManager.getBreakpointsAt(0, b.addr(0x00600010))));
	}

	@Test
	public void testBreakpointsIntersecting() throws Exception {
		addBreakpoints();
		assertEquals(Set.of(breakMain, breakVarA),
			Set.copyOf(breakpointManager.getBreakpointsIntersecting(Lifespan.at(0),
				b.range(0x00400000, 0x00600010))));
		assertEquals(Set.of(breakMain),
			Set.copyOf(breakpointManager.getBreakpointsIntersecting(Lifespan.at(0),
				b.range(0x00400000, 0x00400010))));
		assertEquals(Set.of(breakVarA),
			Set.copyOf(breakpointManager.getBreakpointsIntersecting(Lifespan.at(0),
				b.range(0x00600000, 0x00600010))));
	}

	@Test
	public void testGetTrace() throws Exception {
		addBreakpoints();
		assertEquals(b.trace, breakMain.getTrace());
	}

	@Test
	public void testGetPath() throws Exception {
		addBreakpoints();
		assertEquals("Breakpoints[0]", breakMain.getPath());
	}

	@Test
	public void testSetGetName() throws Exception {
		addBreakpoints();
		assertEquals("Breakpoints[0]", breakMain.getName(0));
		try (Transaction tx = b.startTransaction()) {
			breakMain.setName(0, "bpt 0");
			assertEquals("bpt 0", breakMain.getName(0));
		}
		assertEquals("bpt 0", breakMain.getName(0));
	}

	@Test
	@Deprecated
	public void testGetThreads() throws Exception {
		addBreakpoints();
		assertEquals(Set.of(thread), Set.copyOf(breakMain.getThreads(0)));
		assertEquals(Set.of(thread), Set.copyOf(breakVarA.getThreads(0)));
		assertEquals(Set.of(thread), Set.copyOf(breakVarB.getThreads(0)));
	}

	@Test
	public void testGetRange() throws Exception {
		addBreakpoints();
		assertEquals(b.addr(0x00400000), breakMain.getMinAddress(0));
		assertEquals(b.addr(0x00400000), breakMain.getMaxAddress(0));
		assertEquals(b.range(0x00400000, 0x00400000), breakMain.getRange(0));
		assertEquals(1, breakMain.getLength(0));
	}

	@Test
	public void testSetIsEnabled() throws Exception {
		addBreakpoints();
		assertTrue(breakMain.isEnabled(0));
		try (Transaction tx = b.startTransaction()) {
			breakMain.setEnabled(0, false);
			assertFalse(breakMain.isEnabled(0));
		}
		assertFalse(breakMain.isEnabled(0));
		try (Transaction tx = b.startTransaction()) {
			breakMain.setEnabled(0, true);
			assertTrue(breakMain.isEnabled(0));
		}
		assertTrue(breakMain.isEnabled(0));
	}

	@Test
	public void testSetGetKinds() throws Exception {
		addBreakpoints();
		assertEquals(Set.of(TraceBreakpointKind.SW_EXECUTE), Set.copyOf(breakMain.getKinds(0)));
		try (Transaction tx = b.startTransaction()) {
			breakMain.getSpecification().setKinds(0, Set.of(TraceBreakpointKind.HW_EXECUTE));
			assertEquals(Set.of(TraceBreakpointKind.HW_EXECUTE), Set.copyOf(breakMain.getKinds(0)));
		}
		assertEquals(Set.of(TraceBreakpointKind.HW_EXECUTE), Set.copyOf(breakMain.getKinds(0)));
	}

	@Test
	public void testSetGetComment() throws Exception {
		addBreakpoints();
		assertEquals("main", breakMain.getComment(0));
		try (Transaction tx = b.startTransaction()) {
			breakMain.setComment(0, "WinMain");
			assertEquals("WinMain", breakMain.getComment(0));
		}
		assertEquals("WinMain", breakMain.getComment(0));
	}

	protected static class InvalidBreakpointMatcher extends BaseMatcher<TraceBreakpointLocation> {
		private final long snap;

		public InvalidBreakpointMatcher(long snap) {
			this.snap = snap;
		}

		@Override
		public boolean matches(Object actual) {
			return actual == null ||
				actual instanceof TraceBreakpointLocation bpt && !bpt.isValid(snap);
		}

		@Override
		public void describeTo(Description description) {
			description.appendText("An invalid or null breakpoint");
		}
	}

	protected static InvalidBreakpointMatcher invalidBreakpoint(long snap) {
		return new InvalidBreakpointMatcher(snap);
	}

	@Test
	public void testDelete() throws Exception {
		addBreakpoints();
		assertEquals(breakMain, breakpointManager.getPlacedBreakpointByPath(0, "Breakpoints[0]"));
		try (Transaction tx = b.startTransaction()) {
			breakMain.delete();
			assertThat(breakpointManager.getPlacedBreakpointByPath(0, "Breakpoints[0]"),
				invalidBreakpoint(0));
		}
		assertThat(breakpointManager.getPlacedBreakpointByPath(0, "Breakpoints[0]"),
			invalidBreakpoint(0));
	}
}
