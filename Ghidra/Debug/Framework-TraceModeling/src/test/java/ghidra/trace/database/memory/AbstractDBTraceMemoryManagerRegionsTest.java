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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.util.Set;

import org.junit.*;

import com.google.common.collect.Range;

import ghidra.program.model.lang.LanguageID;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.util.LanguageTestWatcher;
import ghidra.util.database.UndoableTransaction;

public abstract class AbstractDBTraceMemoryManagerRegionsTest
		extends AbstractGhidraHeadlessIntegrationTest {
	protected ToyDBTraceBuilder b;
	protected DBTraceMemoryManager memory;

	@Rule
	public LanguageTestWatcher testLanguage =
		new LanguageTestWatcher(getLanguageID().getIdAsString());

	protected abstract LanguageID getLanguageID();

	@Before
	public void setUp() throws IOException {
		b = new ToyDBTraceBuilder("Testing", testLanguage.getLanguage());
		try (UndoableTransaction tid = b.startTransaction()) {
			b.trace.getTimeManager().createSnapshot("Initialize");
		}
		memory = b.trace.getMemoryManager();
	}

	@After
	public void tearDown() {
		b.close();
	}

	@Test
	public void testAddRegion() throws Exception {
		try (UndoableTransaction tid = b.startTransaction()) {
			memory.addRegion("Regions[0x1000]", Range.atLeast(0L), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}
	}

	@Test
	public void testGetAllRegions() throws Exception {
		assertEquals(Set.of(), Set.copyOf(memory.getAllRegions()));

		TraceMemoryRegion region;
		try (UndoableTransaction tid = b.startTransaction()) {
			region = memory.addRegion("Regions[0x1000]", Range.atLeast(0L), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		assertEquals(Set.of(region), Set.copyOf(memory.getAllRegions()));
	}

	@Test
	public void testGetLiveRegionByPath() throws Exception {
		assertNull(memory.getLiveRegionByPath(0L, "Regions[0x1000]"));

		TraceMemoryRegion region;
		try (UndoableTransaction tid = b.startTransaction()) {
			region = memory.addRegion("Regions[0x1000]", Range.atLeast(0L), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		assertEquals(region, memory.getLiveRegionByPath(0L, "Regions[0x1000]"));
		assertNull(memory.getLiveRegionByPath(0L, "Regions[0x1001]"));
		assertNull(memory.getLiveRegionByPath(-1L, "Regions[0x1000]"));
	}

	@Test
	public void testGetRegionContaining() throws Exception {
		assertNull(memory.getRegionContaining(0, b.addr(0x1000)));

		TraceMemoryRegion region;
		try (UndoableTransaction tid = b.startTransaction()) {
			region = memory.addRegion("Regions[0x1000]", Range.atLeast(0L), b.range(0x1000, 0x1fff),
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
			memory.getRegionsIntersecting(Range.closed(0L, 10L), b.range(0x1800, 0x27ff))));

		TraceMemoryRegion region;
		try (UndoableTransaction tid = b.startTransaction()) {
			region = memory.addRegion("Regions[0x1000]", Range.atLeast(0L), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		assertEquals(Set.of(region), Set.copyOf(
			memory.getRegionsIntersecting(Range.closed(0L, 10L), b.range(0x1800, 0x27ff))));
		assertEquals(Set.of(), Set.copyOf(
			memory.getRegionsIntersecting(Range.closed(-10L, -1L), b.range(0x1800, 0x27ff))));
		assertEquals(Set.of(), Set.copyOf(
			memory.getRegionsIntersecting(Range.closed(0L, 10L), b.range(0x2000, 0x27ff))));
	}

	@Test
	public void testGetRegionsAtSnap() throws Exception {
		assertEquals(Set.of(), Set.copyOf(memory.getRegionsAtSnap(0)));

		TraceMemoryRegion region;
		try (UndoableTransaction tid = b.startTransaction()) {
			region = memory.addRegion("Regions[0x1000]", Range.atLeast(0L), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		assertEquals(Set.of(region), Set.copyOf(memory.getRegionsAtSnap(0)));
		assertEquals(Set.of(), Set.copyOf(memory.getRegionsAtSnap(-1)));
	}

	@Test
	public void testGetRegionsAddressSet() throws Exception {
		assertEquals(b.set(), memory.getRegionsAddressSet(0));

		try (UndoableTransaction tid = b.startTransaction()) {
			memory.addRegion("Regions[0x1000]", Range.atLeast(0L), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		assertEquals(b.set(b.range(0x1000, 0x1fff)), memory.getRegionsAddressSet(0));
		assertEquals(b.set(), memory.getRegionsAddressSet(-1));
	}

	@Test
	public void testGetRegionsAddressSetWith() throws Exception {
		assertEquals(b.set(), memory.getRegionsAddressSetWith(0, r -> true));

		try (UndoableTransaction tid = b.startTransaction()) {
			memory.addRegion("Regions[0x1000]", Range.atLeast(0L), b.range(0x1000, 0x1fff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		assertEquals(b.set(b.range(0x1000, 0x1fff)), memory.getRegionsAddressSetWith(0, r -> true));
		assertEquals(b.set(), memory.getRegionsAddressSetWith(-1, r -> true));
		assertEquals(b.set(), memory.getRegionsAddressSetWith(0, r -> false));
	}
}
