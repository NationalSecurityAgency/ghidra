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
package ghidra.app.plugin.core.bookmark;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Iterator;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.GhidraLocationGenerator;
import ghidra.app.SampleLocationGenerator;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ToyProgramBuilder;

public class BookmarkDeleteCmdTest extends AbstractGhidraHeadedIntegrationTest {

	private Program notepad;
	private BookmarkManager bookmarkManager;
	private GhidraLocationGenerator locationGenerator;

	public BookmarkDeleteCmdTest() {
		super();
	}

    @Before
    public void setUp() throws Exception {
		notepad = buildProgram();
		bookmarkManager = notepad.getBookmarkManager();
		locationGenerator = new SampleLocationGenerator(notepad);
	}

	private Program buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("Test", true, ProgramBuilder._TOY);
		builder.createMemory("test1", "0x1001000", 0x2000);
		return builder.getProgram();
	}

	private Address[] createBookmarks(ProgramLocation[] locs) {

		Address[] addrs = new Address[locs.length];
		for (int i = 0; i < locs.length; i++) {
			Address addr = locs[i].getAddress();
			BookmarkEditCmd cmd = new BookmarkEditCmd(addr, "Type" + i, "Cat" + i, "Cmt" + i);
			applyCmd(notepad, cmd);
			addrs[i] = addr;
		}
		System.out.println("Created " + addrs.length + " Bookmarks");
		return addrs;
	}

	private ArrayList<Bookmark> getBookmarks(BookmarkManager mgr) {
		ArrayList<Bookmark> list = new ArrayList<Bookmark>();
		Iterator<Bookmark> it = mgr.getBookmarksIterator();
		while (it.hasNext()) {
			list.add(it.next());
		}
		return list;
	}

	private ArrayList<Bookmark> getBookmarks(BookmarkManager mgr, String type) {
		ArrayList<Bookmark> list = new ArrayList<Bookmark>();
		Iterator<Bookmark> it = mgr.getBookmarksIterator(type);
		while (it.hasNext()) {
			list.add(it.next());
		}
		return list;
	}

@Test
    public void testDeleteBookmarkOnAddr() throws Exception {
		int origTypeCnt = bookmarkManager.getBookmarkTypes().length;

		ProgramLocation[] locations = locationGenerator.getProgramLocations();
		Address[] addrs = createBookmarks(locations);

		assertEquals(origTypeCnt + addrs.length, bookmarkManager.getBookmarkTypes().length);
		int bmCnt = getBookmarks(bookmarkManager).size();

		// Bogus delete
		BookmarkDeleteCmd deleteCmd = new BookmarkDeleteCmd(addrs[0], "Type1", "Cat1");
		applyCmd(notepad, deleteCmd);

		// Bookmark not at specified address
		ArrayList<Bookmark> list = getBookmarks(bookmarkManager, "Type1");
		assertEquals(1, list.size());

		list = getBookmarks(bookmarkManager, "Type0");
		assertEquals(1, list.size());

		Bookmark[] bookmarks = bookmarkManager.getBookmarks(addrs[0]);
		assertEquals(1, bookmarks.length);

		// Delete bookmark at addrs[1]
		deleteCmd = new BookmarkDeleteCmd(addrs[1], "Type1", "Cat1");
		applyCmd(notepad, deleteCmd);

		list = getBookmarks(bookmarkManager, "Type1");
		assertEquals(0, list.size());

		list = getBookmarks(bookmarkManager, "Type0");
		assertEquals(1, list.size());

		bookmarks = bookmarkManager.getBookmarks(addrs[1]);
		assertEquals(0, bookmarks.length);

		bookmarks = bookmarkManager.getBookmarks(addrs[0]);
		assertEquals(1, bookmarks.length);

		// Delete bookmark at addrs[0]
		deleteCmd = new BookmarkDeleteCmd(addrs[0]);
		applyCmd(notepad, deleteCmd);

		System.out.println(bookmarkManager.getBookmarkCount());

		list = getBookmarks(bookmarkManager, "Type0");
		assertEquals(0, list.size());

		bookmarks = bookmarkManager.getBookmarks(addrs[0]);
		assertEquals(0, bookmarks.length);

		assertEquals(bmCnt - 2, getBookmarks(bookmarkManager).size());
	}

@Test
    public void testDeleteBookmarkOnType() throws Exception {

		int origTypeCnt = bookmarkManager.getBookmarkTypes().length;

		ProgramLocation[] locations = locationGenerator.getProgramLocations();
		Address[] addrs = createBookmarks(locations);

		assertEquals(origTypeCnt + addrs.length, bookmarkManager.getBookmarkTypes().length);
		int bmCnt = getBookmarks(bookmarkManager).size();

		// Bookmark not at specified address
		ArrayList<Bookmark> list = getBookmarks(bookmarkManager, "Type0");
		assertEquals(1, list.size());

		// Delete bookmark
		BookmarkDeleteCmd deleteCmd = new BookmarkDeleteCmd("Type0");
		applyCmd(notepad, deleteCmd);

		list = getBookmarks(bookmarkManager, "Type1");
		assertEquals(1, list.size());

		list = getBookmarks(bookmarkManager, "Type0");
		assertEquals(0, list.size());

		Bookmark[] bookmarks = bookmarkManager.getBookmarks(addrs[0]);
		assertEquals(0, bookmarks.length);

		assertEquals(origTypeCnt + addrs.length, bookmarkManager.getBookmarkTypes().length);
		assertEquals(bmCnt - 1, getBookmarks(bookmarkManager).size());
	}

@Test
    public void testDeleteBookmarkOnTypeCategory() throws Exception {

		int origTypeCnt = bookmarkManager.getBookmarkTypes().length;

		ProgramLocation[] locations = locationGenerator.getProgramLocations();
		Address[] addrs = createBookmarks(locations);

		assertEquals(origTypeCnt + addrs.length, bookmarkManager.getBookmarkTypes().length);
		int bmCnt = getBookmarks(bookmarkManager).size();

		// Bookmark not at specified address
		ArrayList<Bookmark> list = getBookmarks(bookmarkManager, "Type0");
		assertEquals(1, list.size());

		// Bogus delete
		BookmarkDeleteCmd deleteCmd = new BookmarkDeleteCmd("Type0", "Cat1");
		applyCmd(notepad, deleteCmd);

		list = getBookmarks(bookmarkManager, "Type0");
		assertEquals(1, list.size());

		Bookmark[] bookmarks = bookmarkManager.getBookmarks(addrs[0]);
		assertEquals(1, bookmarks.length);

		// Delete bookmark
		deleteCmd = new BookmarkDeleteCmd("Type0", "Cat0");
		applyCmd(notepad, deleteCmd);

		list = getBookmarks(bookmarkManager, "Type0");
		assertEquals(0, list.size());

		bookmarks = bookmarkManager.getBookmarks(addrs[0]);
		assertEquals(0, bookmarks.length);

		assertEquals(bmCnt - 1, getBookmarks(bookmarkManager).size());
	}

@Test
    public void testDeleteBookmarkOnAddrSet() throws Exception {

		int origTypeCnt = bookmarkManager.getBookmarkTypes().length;

		ProgramLocation[] locations = locationGenerator.getProgramLocations();
		Address[] addrs = createBookmarks(locations);

		assertEquals(origTypeCnt + addrs.length, bookmarkManager.getBookmarkTypes().length);
		int bmCnt = getBookmarks(bookmarkManager).size();

		AddressSet set = new AddressSet(addrs[0], addrs[0]);

		// Bogus delete
		BookmarkDeleteCmd deleteCmd = new BookmarkDeleteCmd(set, "Type1", "Cat1");
		applyCmd(notepad, deleteCmd);

		// Bookmark not at specified address
		ArrayList<Bookmark> list = getBookmarks(bookmarkManager, "Type1");
		assertEquals(1, list.size());

		list = getBookmarks(bookmarkManager, "Type0");
		assertEquals(1, list.size());

		Bookmark[] bookmarks = bookmarkManager.getBookmarks(addrs[0]);
		assertEquals(1, bookmarks.length);

		assertEquals(bmCnt, getBookmarks(bookmarkManager).size());

		// Delete bookmark at addrs[1]
		deleteCmd =
			new BookmarkDeleteCmd(notepad.getAddressFactory().getAddressSet(), "Type1", "Cat1");
		applyCmd(notepad, deleteCmd);

		list = getBookmarks(bookmarkManager, "Type1");
		assertEquals(0, list.size());

		list = getBookmarks(bookmarkManager, "Type0");
		assertEquals(1, list.size());

		bookmarks = bookmarkManager.getBookmarks(addrs[1]);
		assertEquals(0, bookmarks.length);

		assertEquals(bmCnt - 1, getBookmarks(bookmarkManager).size());

		// Delete all remaining bookmarks
		deleteCmd = new BookmarkDeleteCmd(notepad.getAddressFactory().getAddressSet());
		applyCmd(notepad, deleteCmd);

		assertEquals(0, getBookmarks(bookmarkManager).size());
	}

}
