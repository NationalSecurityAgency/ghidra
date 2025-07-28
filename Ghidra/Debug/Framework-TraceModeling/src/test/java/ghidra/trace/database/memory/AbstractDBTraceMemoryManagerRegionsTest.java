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
package ghidra.trace.database.memory;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.*;

import java.util.Set;

import org.hamcrest.*;
import org.junit.*;

import db.Transaction;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;
import ghidra.trace.model.target.schema.XmlSchemaContext;
import ghidra.trace.util.LanguageTestWatcher;

public abstract class AbstractDBTraceMemoryManagerRegionsTest
		extends AbstractGhidraHeadlessIntegrationTest {

	public static final String XML_CTX = """
			<context>
			    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
			        <attribute name='Regions' schema='RegionContainer' />
			    </schema>
			    <schema name='RegionContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <element schema='Region' />
			    </schema>
			    <schema name='Region' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='MemoryRegion' />
			    </schema>
			</context>
			""";

	protected ToyDBTraceBuilder b;
	protected DBTraceMemoryManager memory;

	@Rule
	public LanguageTestWatcher testLanguage =
		new LanguageTestWatcher(getLanguageID().getIdAsString());

	protected abstract LanguageID getLanguageID();

	@Before
	public void setUp() throws Exception {
		b = new ToyDBTraceBuilder("Testing", testLanguage.getLanguage());

		try (Transaction tx = b.startTransaction()) {
			b.trace.getTimeManager().createSnapshot("Initialize");
			XmlSchemaContext ctx = XmlSchemaContext.deserialize(XML_CTX);
			b.trace.getObjectManager().createRootObject(ctx.getSchema(new SchemaName("Session")));
		}

		memory = b.trace.getMemoryManager();
	}

	@After
	public void tearDown() {
		b.close();
	}

	@Test
	public void testAddRegion() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			memory.addRegion("Regions[0x1000]", Lifespan.nowOn(0), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}
	}

	@Test
	public void testGetAllRegions() throws Exception {
		assertEquals(Set.of(), Set.copyOf(memory.getAllRegions()));

		TraceMemoryRegion region;
		try (Transaction tx = b.startTransaction()) {
			region = memory.addRegion("Regions[0x1000]", Lifespan.nowOn(0), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		assertEquals(Set.of(region), Set.copyOf(memory.getAllRegions()));
	}

	protected static class InvalidRegionMatcher extends BaseMatcher<TraceMemoryRegion> {
		private final long snap;

		public InvalidRegionMatcher(long snap) {
			this.snap = snap;
		}

		@Override
		public boolean matches(Object actual) {
			return actual == null ||
				actual instanceof TraceMemoryRegion region && !region.isValid(snap);
		}

		@Override
		public void describeTo(Description description) {
			description.appendText("An invalid or null region");
		}
	}

	protected static InvalidRegionMatcher invalidRegion(long snap) {
		return new InvalidRegionMatcher(snap);
	}

	@Test
	public void testGetLiveRegionByPath() throws Exception {
		assertNull(memory.getLiveRegionByPath(0, "Regions[0x1000]"));

		TraceMemoryRegion region;
		try (Transaction tx = b.startTransaction()) {
			region = memory.addRegion("Regions[0x1000]", Lifespan.nowOn(0), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		assertEquals(region, memory.getLiveRegionByPath(0, "Regions[0x1000]"));
		assertThat(memory.getLiveRegionByPath(0, "Regions[0x1001]"), invalidRegion(0));
		assertThat(memory.getLiveRegionByPath(-1, "Regions[0x1000]"), invalidRegion(-1));
	}

	@Test
	public void testGetRegionContaining() throws Exception {
		assertNull(memory.getRegionContaining(0, b.addr(0x1000)));

		TraceMemoryRegion region;
		try (Transaction tx = b.startTransaction()) {
			region = memory.addRegion("Regions[0x1000]", Lifespan.nowOn(0), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		assertEquals(region, memory.getRegionContaining(0, b.addr(0x1000)));
		assertEquals(region, memory.getRegionContaining(0, b.addr(0x1fff)));
		assertNull(memory.getRegionContaining(-1, b.addr(0x1000)));
		assertNull(memory.getRegionContaining(0, b.addr(0x0fff)));
		assertNull(memory.getRegionContaining(0, b.addr(0x2000)));
	}

	@Test
	public void testRegionsIntersecting() throws Exception {
		assertEquals(Set.of(), Set.copyOf(
			memory.getRegionsIntersecting(Lifespan.span(0, 10), b.range(0x1800, 0x27ff))));

		TraceMemoryRegion region;
		try (Transaction tx = b.startTransaction()) {
			region = memory.addRegion("Regions[0x1000]", Lifespan.nowOn(0), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		assertEquals(Set.of(region), Set.copyOf(
			memory.getRegionsIntersecting(Lifespan.span(0, 10), b.range(0x1800, 0x27ff))));
		assertEquals(Set.of(), Set.copyOf(
			memory.getRegionsIntersecting(Lifespan.span(-10, -1), b.range(0x1800, 0x27ff))));
		assertEquals(Set.of(), Set.copyOf(
			memory.getRegionsIntersecting(Lifespan.span(0, 10), b.range(0x2000, 0x27ff))));
	}

	@Test
	public void testGetRegionsAtSnap() throws Exception {
		assertEquals(Set.of(), Set.copyOf(memory.getRegionsAtSnap(0)));

		TraceMemoryRegion region;
		try (Transaction tx = b.startTransaction()) {
			region = memory.addRegion("Regions[0x1000]", Lifespan.nowOn(0), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		assertEquals(Set.of(region), Set.copyOf(memory.getRegionsAtSnap(0)));
		assertEquals(Set.of(), Set.copyOf(memory.getRegionsAtSnap(-1)));
	}

	@Test
	public void testGetRegionsAddressSet() throws Exception {
		assertEquals(b.set(), memory.getRegionsAddressSet(0));

		try (Transaction tx = b.startTransaction()) {
			memory.addRegion("Regions[0x1000]", Lifespan.nowOn(0), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		assertEquals(b.set(b.range(0x1000, 0x1fff)),
			new AddressSet(memory.getRegionsAddressSet(0)));
		assertEquals(b.set(), new AddressSet(memory.getRegionsAddressSet(-1)));
	}

	@Test
	public void testGetRegionsAddressSetWith() throws Exception {
		assertEquals(b.set(), memory.getRegionsAddressSetWith(0, r -> true));

		try (Transaction tx = b.startTransaction()) {
			memory.addRegion("Regions[0x1000]", Lifespan.nowOn(0), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		assertEquals(b.set(b.range(0x1000, 0x1fff)),
			new AddressSet(memory.getRegionsAddressSetWith(0, r -> true)));
		assertEquals(b.set(), new AddressSet(memory.getRegionsAddressSetWith(-1, r -> true)));
		assertEquals(b.set(), new AddressSet(memory.getRegionsAddressSetWith(0, r -> false)));
	}
}
