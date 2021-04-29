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
package ghidra.trace.database.language;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.*;

import org.junit.*;

import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.language.TraceGuestLanguage;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.ConsoleTaskMonitor;

public class DBTraceLanguageManagerTest extends AbstractGhidraHeadlessIntegrationTest {
	protected ToyDBTraceBuilder b;
	protected DBTraceLanguageManager manager;

	@Before
	public void setUpLanguageManagerTest() throws IOException {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");
		manager = b.trace.getLanguageManager();
	}

	@After
	public void tearDownLanguageManagerTest() {
		b.close();
	}

	@Test
	public void testGetBaseLanguage() {
		assertEquals("Toy:BE:64:default",
			manager.getBaseLanguage().getLanguageID().getIdAsString());
	}

	@Test
	public void testAddGuestLangauge() throws LanguageNotFoundException {
		try (UndoableTransaction tid = b.startTransaction()) {
			assertEquals(0, manager.languageStore.getRecordCount());
			manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
			assertEquals(1, manager.languageStore.getRecordCount());

			try { // Cannot add base language as guest
				manager.addGuestLanguage(b.getLanguage("Toy:BE:64:default"));
				fail();
			}
			catch (IllegalArgumentException e) {
				// pass
			}
		}
	}

	@Test
	public void testGetGuestLanguages() throws LanguageNotFoundException {
		DBTraceGuestLanguage guest;
		try (UndoableTransaction tid = b.startTransaction()) {
			assertTrue(manager.getGuestLanguages().isEmpty());
			guest = manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
		}

		assertEquals(Set.of(guest), new HashSet<>(manager.getGuestLanguages()));
	}

	@Test
	public void testAddLanguageThenUndo() throws IOException {
		try (UndoableTransaction tid = b.startTransaction()) {
			manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
		}

		b.trace.undo();

		assertTrue(manager.getGuestLanguages().isEmpty());
	}

	@Test
	public void testAddLanguageThenSaveAndLoad()
			throws CancelledException, IOException, VersionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
		}

		File saved = b.save();

		try (ToyDBTraceBuilder r = new ToyDBTraceBuilder(saved)) {
			Collection<TraceGuestLanguage> guestLanguages =
				r.trace.getLanguageManager().getGuestLanguages();
			assertEquals(1, guestLanguages.size());
			assertEquals("x86:LE:32:default",
				guestLanguages.iterator().next().getLanguage().getLanguageID().getIdAsString());
		}
	}

	@Test
	public void testDeleteGuestLanguage() throws LanguageNotFoundException, CancelledException {
		DBTraceGuestLanguage guest;
		try (UndoableTransaction tid = b.startTransaction()) {
			guest = manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
		}

		try (UndoableTransaction tid = b.startTransaction()) {
			guest.delete(new ConsoleTaskMonitor());
		}

		assertEquals(0, manager.languageStore.getRecordCount());
		assertTrue(manager.entriesByLanguage.isEmpty());
	}

	@Test
	public void testAddMappedRange() throws LanguageNotFoundException, AddressOverflowException {
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceGuestLanguage guest =
				manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));

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
	public void testGetHostAndGuestAddressSet()
			throws LanguageNotFoundException, AddressOverflowException {
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceGuestLanguage guest =
				manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
			assertEquals(b.set(), guest.getHostAddressSet());

			guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
			assertEquals(b.set(b.range(0x01000000, 0x01000fff)), guest.getHostAddressSet());
			assertEquals(b.set(b.range(guest, 0x02000000, 0x02000fff)), guest.getGuestAddressSet());
		}
	}

	@Test
	public void testMapHostToGuest() throws LanguageNotFoundException, AddressOverflowException {
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceGuestLanguage guest =
				manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
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
	public void testMapGuestToHost() throws LanguageNotFoundException, AddressOverflowException {
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceGuestLanguage guest =
				manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
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
	public void testAddMappedRangeThenSaveAndLoad()
			throws AddressOverflowException, CancelledException, IOException, VersionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceGuestLanguage guest =
				manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
			guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
		}

		File saved = b.save();

		try (ToyDBTraceBuilder r = new ToyDBTraceBuilder(saved)) {
			TraceGuestLanguage guest =
				r.trace.getLanguageManager().getGuestLanguages().iterator().next();
			assertEquals(b.addr(guest, 0x02000800), guest.mapHostToGuest(b.addr(0x01000800)));
		}
	}

	@Test
	public void testMappedRangeGetHostLanguage()
			throws LanguageNotFoundException, AddressOverflowException {
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceGuestLanguage guest =
				manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
			DBTraceGuestLanguageMappedRange range =
				guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
			assertEquals("Toy:BE:64:default",
				range.getHostLanguage().getLanguageID().getIdAsString());
		}
	}

	@Test
	public void testMappedRangeGetHostRange()
			throws LanguageNotFoundException, AddressOverflowException {
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceGuestLanguage guest =
				manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
			DBTraceGuestLanguageMappedRange range =
				guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
			assertEquals(b.range(0x01000000, 0x01000fff), range.getHostRange());
		}
	}

	@Test
	public void testMappedRangeGetGuestLanguage()
			throws LanguageNotFoundException, AddressOverflowException {
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceGuestLanguage guest =
				manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
			DBTraceGuestLanguageMappedRange range =
				guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
			assertEquals("x86:LE:32:default",
				range.getGuestLanguage().getLanguageID().getIdAsString());
		}
	}

	@Test
	public void testMappedRangeGetGuestRange()
			throws LanguageNotFoundException, AddressOverflowException {
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceGuestLanguage guest =
				manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
			DBTraceGuestLanguageMappedRange range =
				guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
			assertEquals(b.range(guest, 0x02000000, 0x02000fff), range.getGuestRange());
		}
	}

	@Test
	public void testDeleteMappedRange()
			throws LanguageNotFoundException, AddressOverflowException, CancelledException {
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceGuestLanguage guest =
				manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
			DBTraceGuestLanguageMappedRange range =
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
	public void testDeleteMappedRangeThenUndo()
			throws AddressOverflowException, IOException, CancelledException {
		DBTraceGuestLanguage guest;
		DBTraceGuestLanguageMappedRange range;
		try (UndoableTransaction tid = b.startTransaction()) {
			guest = manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
			range = guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
			assertNotNull(guest.mapHostToGuest(b.addr(0x01000800))); // Sanity check
			assertNotNull(guest.mapGuestToHost(b.addr(guest, 0x02000800))); // Sanity check
		}

		try (UndoableTransaction tid = b.startTransaction()) {
			range.delete(new ConsoleTaskMonitor());
			assertNull(guest.mapHostToGuest(b.addr(0x01000800))); // Sanity check
			assertNull(guest.mapGuestToHost(b.addr(guest, 0x02000800))); // Sanity check
		}

		b.trace.undo();

		guest = manager.getGuestLanguage(b.getLanguage("x86:LE:32:default"));

		assertNotNull(guest.mapHostToGuest(b.addr(0x01000800)));
		assertNotNull(guest.mapGuestToHost(b.addr(guest, 0x02000800)));
	}

	@Test
	public void testDeleteGuestLanguageDeletesMappedRanges()
			throws LanguageNotFoundException, AddressOverflowException, CancelledException {
		// TODO: Check that it also deletes code units
		DBTraceGuestLanguage guest;
		try (UndoableTransaction tid = b.startTransaction()) {
			guest = manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
			guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
		}

		try (UndoableTransaction tid = b.startTransaction()) {
			guest.delete(new ConsoleTaskMonitor());
			assertEquals(0, manager.rangeMappingStore.getRecordCount());
		}
	}

	@Test
	public void testDeleteGuestLanguageThenUndo()
			throws AddressOverflowException, CancelledException, IOException {
		// TODO: Check that it also deletes code units
		DBTraceGuestLanguage guest;
		try (UndoableTransaction tid = b.startTransaction()) {
			guest = manager.addGuestLanguage(b.getLanguage("x86:LE:32:default"));
			guest.addMappedRange(b.addr(0x01000000), b.addr(guest, 0x02000000), 0x1000);
		}

		try (UndoableTransaction tid = b.startTransaction()) {
			guest.delete(new ConsoleTaskMonitor());
		}

		b.trace.undo();

		guest = manager.getGuestLanguage(b.getLanguage("x86:LE:32:default"));
		assertEquals(b.addr(guest, 0x02000800), guest.mapHostToGuest(b.addr(0x01000800)));
	}
}
