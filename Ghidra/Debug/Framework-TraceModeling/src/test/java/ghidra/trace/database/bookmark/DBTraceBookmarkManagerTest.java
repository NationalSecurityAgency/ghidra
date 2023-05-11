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
package ghidra.trace.database.bookmark;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.junit.*;

import db.Transaction;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.thread.TraceThread;

public class DBTraceBookmarkManagerTest extends AbstractGhidraHeadlessIntegrationTest {
	protected ToyDBTraceBuilder b;
	protected DBTraceBookmarkManager manager;

	@Before
	public void setUpBookmarkManagerTest() throws IOException {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");
		manager = b.trace.getBookmarkManager();
	}

	@After
	public void tearDownBookmarkManagerTest() {
		b.close();
	}

	@Test
	public void testDefineBookmarkType() {
		assertNull(manager.getBookmarkType("Test Type"));
		assertEquals(Set.of(), new HashSet<>(manager.getDefinedBookmarkTypes()));
		DBTraceBookmarkType type = b.getOrAddBookmarkType("Test Type");
		assertSame(type, manager.getBookmarkType("Test Type"));
		assertEquals(Set.of(type), new HashSet<>(manager.getDefinedBookmarkTypes()));
	}

	@Test
	public void testGetBookmarkById() {
		DBTraceBookmark bm = manager.getBookmark(0);
		assertNull(bm);

		try (Transaction tx = b.startTransaction()) {
			bm = b.addBookmark(0, 0, "Test Type", "Cat1", "Test comment");
		}
		long id = bm.getId();

		DBTraceBookmark found = manager.getBookmark(id);
		assertSame(bm, found);
	}

	@Test
	public void testDeleteBookmark() {
		DBTraceBookmark bm;
		try (Transaction tx = b.startTransaction()) {
			bm = b.addBookmark(0, 0, "Test Type", "Cat1", "Test comment");
		}
		long id = bm.getId();

		try (Transaction tx = b.startTransaction()) {
			bm.delete();
		}
		DBTraceBookmark found = manager.getBookmark(id);
		assertNull(found);
	}

	@Test
	public void testGetRegisterBookmarkById() throws Exception {
		// TODO: Should I check that bookmarks in register spaces are enclosed by the corresponding thread's lifespan?
		DBTraceBookmark bm;
		try (Transaction tx = b.startTransaction()) {
			bm = b.addRegisterBookmark(0, "Thread1", "r4", "Test Type", "Cat1", "Test comment");
		}
		long id = bm.getId();

		DBTraceBookmark found = manager.getBookmark(id);
		assertSame(bm, found);
	}

	@Test
	public void testGetCategoriesForType() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			TraceThread thread = b.trace.getThreadManager().createThread("Thread1", 0);
			DBTraceBookmarkSpace rSpace = manager.getBookmarkRegisterSpace(thread, true);

			DBTraceBookmarkType type = b.getOrAddBookmarkType("Test Type");
			assertEquals(Set.of(), type.getCategories());
			assertEquals(Set.of(), manager.getCategoriesForType(type));
			assertEquals(Set.of(), rSpace.getCategoriesForType(type));

			b.addBookmark(0, 0, "Test Type", "Cat1", "First");
			assertEquals(Set.of("Cat1"), type.getCategories());
			assertEquals(Set.of("Cat1"), manager.getCategoriesForType(type));
			assertEquals(Set.of(), rSpace.getCategoriesForType(type));

			b.addRegisterBookmark(0, "Thread1", "r4", "Test Type", "Cat2", "Second");
			assertEquals(Set.of("Cat1", "Cat2"), type.getCategories());
			assertEquals(Set.of("Cat1"), manager.getCategoriesForType(type));
			assertEquals(Set.of("Cat2"), rSpace.getCategoriesForType(type));
		}
	}

	@Test
	public void testGetBookmarksForType() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			DBTraceBookmarkType type = b.getOrAddBookmarkType("Test Type");
			assertFalse(type.hasBookmarks());
			assertEquals(0, type.countBookmarks());

			DBTraceBookmark bm1 = b.addBookmark(0, 0, "Test Type", "Cat1", "First");
			assertTrue(type.hasBookmarks());
			assertEquals(1, type.countBookmarks());
			assertEquals(Set.of(bm1), new HashSet<>(type.getBookmarks()));

			DBTraceBookmark bm2 =
				b.addRegisterBookmark(0, "Thread1", "r4", "Test Type", "Cat2", "Second");
			assertTrue(type.hasBookmarks());
			assertEquals(2, type.countBookmarks());
			assertEquals(Set.of(bm1, bm2), new HashSet<>(type.getBookmarks()));
		}
	}

	protected <E> Set<E> toSet(Iterable<E> it) {
		Set<E> result = new HashSet<>();
		it.iterator().forEachRemaining(result::add);
		return result;
	}

	@Test
	public void testGetAllBookmarks() {
		try (Transaction tx = b.startTransaction()) {
			DBTraceBookmark bm1 = b.addBookmark(0, 0, "Test Type", "Cat1", "First");
			DBTraceBookmark bm2 = b.addBookmark(1, 4, "Test Type", "Cat2", "Second");

			assertEquals(Set.of(bm1, bm2), new HashSet<>(manager.getAllBookmarks()));
		}
	}

	@Test
	public void testGetBookmarksAt() {
		try (Transaction tx = b.startTransaction()) {
			DBTraceBookmark bm1 = b.addBookmark(0, 0, "Test Type", "Cat1", "First");
			DBTraceBookmark bm2 = b.addBookmark(1, 4, "Test Type", "Cat2", "Second");

			assertEquals(Set.of(), toSet(manager.getBookmarksAt(0, b.addr(1))));
			assertEquals(Set.of(bm1), toSet(manager.getBookmarksAt(0, b.addr(0))));
			assertEquals(Set.of(bm2), toSet(manager.getBookmarksAt(1, b.addr(4))));
		}
	}

	@Test
	public void testGetBookmarksEnclosed() {
		try (Transaction tx = b.startTransaction()) {
			DBTraceBookmark bm1 = b.addBookmark(0, 0, "Test Type", "Cat1", "First");
			DBTraceBookmark bm2 = b.addBookmark(1, 4, "Test Type", "Cat2", "Second");

			assertEquals(Set.of(),
				toSet(manager.getBookmarksEnclosed(Lifespan.span(0, 10), b.range(0, 0x10))));
			assertEquals(Set.of(bm1),
				toSet(manager.getBookmarksEnclosed(Lifespan.nowOn(0), b.range(0, 3))));
			assertEquals(Set.of(bm2),
				toSet(manager.getBookmarksEnclosed(Lifespan.nowOn(0), b.range(2, 5))));
			assertEquals(Set.of(bm1, bm2),
				toSet(manager.getBookmarksEnclosed(Lifespan.nowOn(0), b.range(0, 0x10))));
		}
	}

	@Test
	public void testGetBookmarksIntersecting() {
		try (Transaction tx = b.startTransaction()) {
			DBTraceBookmark bm1 = b.addBookmark(0, 0, "Test Type", "Cat1", "First");
			DBTraceBookmark bm2 = b.addBookmark(1, 4, "Test Type", "Cat2", "Second");

			assertEquals(Set.of(),
				toSet(manager.getBookmarksIntersecting(Lifespan.span(2, 4), b.range(1, 3))));
			assertEquals(Set.of(bm1),
				toSet(manager.getBookmarksIntersecting(Lifespan.span(0, 0), b.range(0, 0x10))));
			assertEquals(Set.of(bm2),
				toSet(manager.getBookmarksIntersecting(Lifespan.span(0, 10), b.range(2, 5))));
			assertEquals(Set.of(bm1, bm2),
				toSet(manager.getBookmarksIntersecting(Lifespan.span(0, 10), b.range(0, 0x10))));
		}
	}
}
