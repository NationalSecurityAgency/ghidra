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

import static org.junit.Assert.*;

import java.util.Set;

import org.junit.*;

import com.google.common.collect.Range;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceBreakpointManagerTest extends AbstractGhidraHeadlessIntegrationTest {

	ToyDBTraceBuilder b;
	DBTraceBreakpointManager breakpointManager;

	TraceThread thread;
	TraceBreakpoint breakMain;
	TraceBreakpoint breakVarA;
	TraceBreakpoint breakVarB;

	@Before
	public void setUpBreakpointManagerTest() throws Exception {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");
		breakpointManager = b.trace.getBreakpointManager();
	}

	@After
	public void tearDownBreakpointManagerTest() throws Exception {
		b.close();
	}

	@Test
	public void testAddBreakpoint() throws Exception {
		try (UndoableTransaction tid = b.startTransaction()) {
			breakpointManager.addBreakpoint("Breaks[0]", Range.closed(0L, 10L), b.addr(0x00400000),
				Set.of(), Set.of(TraceBreakpointKind.SW_EXECUTE), true, "main");
		}

		try (UndoableTransaction tid = b.startTransaction()) {
			breakpointManager.addBreakpoint("Breaks[0]", Range.closed(0L, 10L),
				b.range(0x00400000, 0x00400003), Set.of(), Set.of(), false, "duplicate");
		}
		catch (DuplicateNameException e) {
			// pass
		}

		assertEquals(1, breakpointManager.getBreakpointsByPath("Breaks[0]").size());
	}

	protected void addBreakpoints() throws Exception {
		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread1", 0);
			breakMain = breakpointManager.addBreakpoint("Breaks[0]", Range.closed(0L, 10L),
				b.addr(0x00400000),
				Set.of(), Set.of(TraceBreakpointKind.SW_EXECUTE), true, "main");
			breakVarA = breakpointManager.addBreakpoint("Breaks[1]", Range.closed(0L, 10L),
				b.range(0x00600010, 0x00600013),
				Set.of(), Set.of(TraceBreakpointKind.WRITE), false, "varA");
			breakVarB = breakpointManager.addBreakpoint("Breaks[1]", Range.closed(11L, 20L),
				b.range(0x00600020, 0x00600023),
				Set.of(thread), Set.of(TraceBreakpointKind.WRITE), false, "varB");
		}
	}

	@Test
	public void testGetAllBreakpoints() throws Exception {
		addBreakpoints();
		assertEquals(Set.of(breakMain, breakVarA, breakVarB),
			Set.copyOf(breakpointManager.getAllBreakpoints()));
	}

	@Test
	public void testBreakpointsByPath() throws Exception {
		addBreakpoints();
		assertEquals(Set.of(breakMain),
			Set.copyOf(breakpointManager.getBreakpointsByPath("Breaks[0]")));
		assertEquals(Set.of(breakVarA, breakVarB),
			Set.copyOf(breakpointManager.getBreakpointsByPath("Breaks[1]")));
	}

	@Test
	public void testBreakpointPlacedByPath() throws Exception {
		addBreakpoints();
		assertEquals(breakVarA, breakpointManager.getPlacedBreakpointByPath(0, "Breaks[1]"));
		assertEquals(breakVarB, breakpointManager.getPlacedBreakpointByPath(11, "Breaks[1]"));
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
			Set.copyOf(breakpointManager.getBreakpointsIntersecting(Range.singleton(0L),
				b.range(0x00400000, 0x00600010))));
		assertEquals(Set.of(breakMain),
			Set.copyOf(breakpointManager.getBreakpointsIntersecting(Range.singleton(0L),
				b.range(0x00400000, 0x00400010))));
		assertEquals(Set.of(breakVarA),
			Set.copyOf(breakpointManager.getBreakpointsIntersecting(Range.singleton(0L),
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
		assertEquals("Breaks[0]", breakMain.getPath());
	}

	@Test
	public void testSetGetName() throws Exception {
		addBreakpoints();
		assertEquals("Breaks[0]", breakMain.getName());
		try (UndoableTransaction tid = b.startTransaction()) {
			breakMain.setName("bpt 0");
			assertEquals("bpt 0", breakMain.getName());
		}
		assertEquals("bpt 0", breakMain.getName());
	}

	@Test
	public void testGetThreads() throws Exception {
		addBreakpoints();
		assertEquals(Set.of(), Set.copyOf(breakMain.getThreads()));
		assertEquals(Set.of(thread), Set.copyOf(breakVarB.getThreads()));
	}

	@Test
	public void testGetRange() throws Exception {
		addBreakpoints();
		assertEquals(b.addr(0x00400000), breakMain.getMinAddress());
		assertEquals(b.addr(0x00400000), breakMain.getMaxAddress());
		assertEquals(b.range(0x00400000, 0x00400000), breakMain.getRange());
		assertEquals(1, breakMain.getLength());
	}

	@Test
	public void testGetLifespan() throws Exception {
		addBreakpoints();
		assertEquals(0, breakMain.getPlacedSnap());
		assertEquals(10, breakMain.getClearedSnap());
		assertEquals(Range.closed(0L, 10L), breakMain.getLifespan());
	}

	@Test
	public void testSetCleared() throws Exception {
		addBreakpoints();
		try (UndoableTransaction tid = b.startTransaction()) {
			breakMain.setClearedSnap(5);
			assertEquals(5, breakMain.getClearedSnap());
		}
		assertEquals(0, breakMain.getPlacedSnap());
		assertEquals(5, breakMain.getClearedSnap());
		assertEquals(Range.closed(0L, 5L), breakMain.getLifespan());
	}

	@Test
	public void testSplitAndSet() throws Exception {
		addBreakpoints();

		TraceBreakpoint disMain;
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceBreakpoint oopsMain =
				breakMain.splitAndSet(0, true, Set.of(TraceBreakpointKind.HW_EXECUTE));
			assertSame(breakMain, oopsMain);
			disMain =
				breakMain.splitAndSet(6, false, Set.of(TraceBreakpointKind.HW_EXECUTE));
			assertNotSame(breakMain, disMain);
			TraceBreakpoint sameDis =
				disMain.splitAndSet(8, false, Set.of(TraceBreakpointKind.HW_EXECUTE));
			assertSame(disMain, sameDis);
		}

		assertTrue(breakMain.isEnabled());
		assertEquals(Set.of(TraceBreakpointKind.HW_EXECUTE), Set.copyOf(breakMain.getKinds()));

		assertFalse(disMain.isEnabled());
		assertEquals(Set.of(TraceBreakpointKind.HW_EXECUTE), Set.copyOf(disMain.getKinds()));
	}

	@Test
	public void testSetIsEnabled() throws Exception {
		addBreakpoints();
		assertTrue(breakMain.isEnabled());
		try (UndoableTransaction tid = b.startTransaction()) {
			breakMain.setEnabled(false);
			assertFalse(breakMain.isEnabled());
		}
		assertFalse(breakMain.isEnabled());
		try (UndoableTransaction tid = b.startTransaction()) {
			breakMain.setEnabled(true);
			assertTrue(breakMain.isEnabled());
		}
		assertTrue(breakMain.isEnabled());
	}

	@Test
	public void testSetGetKinds() throws Exception {
		addBreakpoints();
		assertEquals(Set.of(TraceBreakpointKind.SW_EXECUTE), Set.copyOf(breakMain.getKinds()));
		try (UndoableTransaction tid = b.startTransaction()) {
			breakMain.setKinds(Set.of(TraceBreakpointKind.HW_EXECUTE));
			assertEquals(Set.of(TraceBreakpointKind.HW_EXECUTE), Set.copyOf(breakMain.getKinds()));
		}
		assertEquals(Set.of(TraceBreakpointKind.HW_EXECUTE), Set.copyOf(breakMain.getKinds()));
	}

	@Test
	public void testSetGetComment() throws Exception {
		addBreakpoints();
		assertEquals("main", breakMain.getComment());
		try (UndoableTransaction tid = b.startTransaction()) {
			breakMain.setComment("WinMain");
			assertEquals("WinMain", breakMain.getComment());
		}
		assertEquals("WinMain", breakMain.getComment());
	}

	@Test
	public void testDelete() throws Exception {
		addBreakpoints();
		assertEquals(Set.of(breakMain),
			Set.copyOf(breakpointManager.getBreakpointsByPath("Breaks[0]")));
		try (UndoableTransaction tid = b.startTransaction()) {
			breakMain.delete();
			assertEquals(Set.of(), Set.copyOf(breakpointManager.getBreakpointsByPath("Breaks[0]")));
		}
		assertEquals(Set.of(), Set.copyOf(breakpointManager.getBreakpointsByPath("Breaks[0]")));
	}
}
