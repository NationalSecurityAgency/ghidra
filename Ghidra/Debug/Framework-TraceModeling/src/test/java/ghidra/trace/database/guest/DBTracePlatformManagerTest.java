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
package ghidra.trace.database.guest;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.*;

import org.junit.*;

import db.Transaction;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.util.task.ConsoleTaskMonitor;

public class DBTracePlatformManagerTest extends AbstractGhidraHeadlessIntegrationTest {
	protected ToyDBTraceBuilder b;
	protected DBTracePlatformManager manager;

	@Before
	public void setUpLanguageManagerTest() throws IOException {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");
		manager = b.trace.getPlatformManager();
	}

	@After
	public void tearDownLanguageManagerTest() {
		b.close();
	}

	@Test
	public void testGetHostPlatform() throws Throwable {
		TracePlatform host = b.trace.getPlatformManager().getHostPlatform();
		assertEquals("Toy:BE:64:default", host.getLanguage().getLanguageID().getIdAsString());
		assertEquals("default", host.getCompilerSpec().getCompilerSpecID().getIdAsString());
	}

	@Test
	public void testAddGuestPlatform() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(0, manager.languageStore.getRecordCount());
			assertEquals(0, manager.platformStore.getRecordCount());
			manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			assertEquals(1, manager.languageStore.getRecordCount());
			assertEquals(1, manager.platformStore.getRecordCount());
		}
	}

	@Test
	public void testAddGuestPlatformHostCompilerErr() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			manager.addGuestPlatform(b.getLanguage("Toy:BE:64:default").getDefaultCompilerSpec());
			fail();
		}
		catch (IllegalArgumentException e) {
			// pass, pending consistency check
		}

		assertEquals(0, manager.languageStore.getRecordCount());
		assertEquals(0, manager.platformStore.getRecordCount());
		assertTrue(manager.getGuestPlatforms().isEmpty());
	}

	@Test
	public void testAddGuestPlatformHostLanguage() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(0, manager.languageStore.getRecordCount());
			assertEquals(0, manager.platformStore.getRecordCount());
			manager.addGuestPlatform(b.getCompiler("Toy:BE:64:default", "long8"));
			assertEquals(0, manager.languageStore.getRecordCount());
			assertEquals(1, manager.platformStore.getRecordCount());
		}
	}

	@Test
	public void testGetGuestPlatforms() throws Throwable {
		DBTraceGuestPlatform guest;
		try (Transaction tx = b.startTransaction()) {
			assertTrue(manager.getGuestPlatforms().isEmpty());
			guest = manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
		}

		assertEquals(Set.of(guest), new HashSet<>(manager.getGuestPlatforms()));
	}

	@Test
	public void testAddPlatformThenUndo() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
		}

		b.trace.undo();

		assertTrue(manager.getGuestPlatforms().isEmpty());
	}

	@Test
	public void testAddPlatformThenSaveAndLoad() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
		}

		File saved = b.save();

		try (ToyDBTraceBuilder r = new ToyDBTraceBuilder(saved)) {
			Collection<TraceGuestPlatform> guestPlatforms =
				r.trace.getPlatformManager().getGuestPlatforms();
			assertEquals(1, guestPlatforms.size());
			TraceGuestPlatform platform = guestPlatforms.iterator().next();
			assertEquals("x86:LE:32:default",
				platform.getLanguage().getLanguageID().getIdAsString());
			assertEquals("gcc", platform.getCompilerSpec().getCompilerSpecID().getIdAsString());
		}
	}

	@Test
	public void testDeleteGuestPlatform() throws Throwable {
		DBTraceGuestPlatform guest;
		try (Transaction tx = b.startTransaction()) {
			guest = manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
		}

		try (Transaction tx = b.startTransaction()) {
			guest.delete(new ConsoleTaskMonitor());
		}

		assertEquals(0, manager.platformStore.getRecordCount());
		assertTrue(manager.platformsByCompiler.isEmpty());
	}

	@Test
	public void testAddMappedRange() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			DBTraceGuestPlatform guest =
				manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));

			assertEquals(0, manager.rangeMappingStore.getRecordCount());
			guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
			assertEquals(1, manager.rangeMappingStore.getRecordCount());

			try { // Collides in host space
				guest.addMappedRange(b.addr(0x01000080), b.addr(guest, 0x04000000), 0x1000);
				fail();
			}
			catch (IllegalArgumentException e) {
				// pass
			}

			try { // Collides in guest space
				guest.addMappedRange(b.addr(0x03000000), b.addr(guest, 0x02000800), 0x1000);
				fail();
			}
			catch (IllegalArgumentException e) {
				// pass
			}
		}
	}

	@Test
	public void testGetHostAndGuestAddressSet() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			DBTraceGuestPlatform guest =
				manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			assertEquals(b.set(), guest.getHostAddressSet());

			guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
			assertEquals(b.set(b.range(0x01000000, 0x01000fff)), guest.getHostAddressSet());
			assertEquals(b.set(b.range(guest, 0x02000000, 0x02000fff)), guest.getGuestAddressSet());
		}
	}

	@Test
	public void testMapHostToGuest() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			DBTraceGuestPlatform guest =
				manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);

			assertNull(guest.mapHostToGuest(b.addr(0x00000000)));
			assertNull(guest.mapHostToGuest(b.addr(0x00ffffff)));
			assertEquals(b.addr(guest, 0x02000000), guest.mapHostToGuest(b.addr(0x01000000)));
			assertEquals(b.addr(guest, 0x02000800), guest.mapHostToGuest(b.addr(0x01000800)));
			assertEquals(b.addr(guest, 0x02000fff), guest.mapHostToGuest(b.addr(0x01000fff)));
			assertNull(guest.mapHostToGuest(b.addr(0x01001000)));
		}
	}

	@Test
	public void testMapGuestToHost() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			DBTraceGuestPlatform guest =
				manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);

			assertNull(guest.mapGuestToHost(b.addr(0x00000000)));
			assertNull(guest.mapGuestToHost(b.addr(0x01ffffff)));
			assertEquals(b.addr(0x01000000), guest.mapGuestToHost(b.addr(guest, 0x02000000)));
			assertEquals(b.addr(0x01000800), guest.mapGuestToHost(b.addr(guest, 0x02000800)));
			assertEquals(b.addr(0x01000fff), guest.mapGuestToHost(b.addr(guest, 0x02000fff)));
			assertNull(guest.mapGuestToHost(b.addr(0x02001000)));
		}
	}

	@Test
	public void testAddMappedRangeThenSaveAndLoad() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			DBTraceGuestPlatform guest =
				manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
		}

		File saved = b.save();

		try (ToyDBTraceBuilder r = new ToyDBTraceBuilder(saved)) {
			TraceGuestPlatform guest =
				r.trace.getPlatformManager().getGuestPlatforms().iterator().next();
			assertEquals(b.addr(guest, 0x02000800), guest.mapHostToGuest(b.addr(0x01000800)));
		}
	}

	@Test
	public void testMappedRangeGetHostLanguage() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			DBTraceGuestPlatform guest =
				manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			DBTraceGuestPlatformMappedRange range =
				guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
			assertEquals("Toy:BE:64:default",
				range.getHostPlatform().getLanguage().getLanguageID().getIdAsString());
		}
	}

	@Test
	public void testMappedRangeGetHostRange() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			DBTraceGuestPlatform guest =
				manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			DBTraceGuestPlatformMappedRange range =
				guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
			assertEquals(b.range(0x01000000, 0x01000fff), range.getHostRange());
		}
	}

	@Test
	public void testMappedRangeGetGuestPlatform() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			DBTraceGuestPlatform guest =
				manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			DBTraceGuestPlatformMappedRange range =
				guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
			assertEquals(guest, range.getGuestPlatform());
		}
	}

	@Test
	public void testMappedRangeGetGuestRange() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			DBTraceGuestPlatform guest =
				manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			DBTraceGuestPlatformMappedRange range =
				guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
			assertEquals(b.range(guest, 0x02000000, 0x02000fff), range.getGuestRange());
		}
	}

	@Test
	public void testDeleteMappedRange() throws Throwable {
		try (Transaction tx = b.startTransaction()) {
			DBTraceGuestPlatform guest =
				manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			DBTraceGuestPlatformMappedRange range =
				guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
			assertNotNull(guest.mapHostToGuest(b.addr(0x01000800))); // Sanity check
			assertNotNull(guest.mapGuestToHost(b.addr(guest, 0x02000800))); // Sanity check
			range.delete(new ConsoleTaskMonitor());

			assertEquals(b.set(), guest.getHostAddressSet());
			assertEquals(b.set(), guest.getGuestAddressSet());
			assertNull(guest.mapHostToGuest(b.addr(0x01000800)));
			assertNull(guest.mapGuestToHost(b.addr(guest, 0x02000800)));

			// Just check that it succeeds:
			guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
		}
	}

	@Test
	public void testDeleteMappedRangeThenUndo() throws Throwable {
		DBTraceGuestPlatform guest;
		DBTraceGuestPlatformMappedRange range;
		try (Transaction tx = b.startTransaction()) {
			guest = manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			range = guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
			assertNotNull(guest.mapHostToGuest(b.addr(0x01000800))); // Sanity check
			assertNotNull(guest.mapGuestToHost(b.addr(guest, 0x02000800))); // Sanity check
		}

		try (Transaction tx = b.startTransaction()) {
			range.delete(new ConsoleTaskMonitor());
			assertNull(guest.mapHostToGuest(b.addr(0x01000800))); // Sanity check
			assertNull(guest.mapGuestToHost(b.addr(guest, 0x02000800))); // Sanity check
		}

		b.trace.undo();

		guest =
			(DBTraceGuestPlatform) manager.getPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
		assertNotNull(guest.mapHostToGuest(b.addr(0x01000800)));
		assertNotNull(guest.mapGuestToHost(b.addr(guest, 0x02000800)));
	}

	@Test
	public void testDeleteGuestPlatformDeletesMappedRanges() throws Throwable {
		// TODO: Check that it also deletes code units
		DBTraceGuestPlatform guest;
		try (Transaction tx = b.startTransaction()) {
			guest = manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
		}

		try (Transaction tx = b.startTransaction()) {
			guest.delete(new ConsoleTaskMonitor());
			assertEquals(0, manager.rangeMappingStore.getRecordCount());
		}
	}

	@Test
	public void testDeleteGuestPlatformThenUndo() throws Throwable {
		// TODO: Check that it also deletes code units
		DBTraceGuestPlatform guest;
		try (Transaction tx = b.startTransaction()) {
			guest = manager.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
		}

		try (Transaction tx = b.startTransaction()) {
			guest.delete(new ConsoleTaskMonitor());
		}

		b.trace.undo();

		guest =
			(DBTraceGuestPlatform) manager.getPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
		assertEquals(b.addr(guest, 0x02000800), guest.mapHostToGuest(b.addr(0x01000800)));
	}
}
