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

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.GhidraLocationGenerator;
import ghidra.app.SampleLocationGenerator;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class BookmarkEditCmdTest extends AbstractGhidraHeadedIntegrationTest {

	private Program notepad;
	private BookmarkManager bookmarkManager;
	private GhidraLocationGenerator locationGenerator;
	private ProgramBuilder builder;

	public BookmarkEditCmdTest() {
		super();
	}

    @Before
    public void setUp() throws Exception {
		notepad = buildProgram();
		bookmarkManager = notepad.getBookmarkManager();
		locationGenerator = new SampleLocationGenerator(notepad);

	}

	private Program buildProgram() throws Exception {
		builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory("test1", "0x1001000", 0x2000);
		return builder.getProgram();
	}

	private Address[] createBookmarks(ProgramLocation[] locs) {

		CompoundCmd compoundCmd = new CompoundCmd("Create Bookmarks");

		Address[] addrs = new Address[locs.length];
		for (int i = 0; i < locs.length; i++) {
			Address addr = locs[i].getAddress();
			BookmarkEditCmd cmd = new BookmarkEditCmd(addr, "Type" + i, "Cat" + i, "Cmt" + i);
			compoundCmd.add(cmd);
			addrs[i] = addr;
		}
		applyCmd(notepad, compoundCmd);
		System.out.println("Created " + addrs.length + " Bookmarks");
		return addrs;
	}

	private int getAddressIndex(Address[] addrs, Address addr) throws NoSuchElementException {
		for (int i = 0; i < addrs.length; i++) {
			if (addrs[i] != null && addrs[i].equals(addr))
				return i;
		}
		throw new NoSuchElementException();
	}

	private ArrayList<Bookmark> getBookmarks(BookmarkManager mgr) {
		ArrayList<Bookmark> list = new ArrayList<Bookmark>();
		Iterator<Bookmark> it = mgr.getBookmarksIterator();
		while (it.hasNext()) {
			list.add(it.next());
		}
		return list;
	}

@Test
    public void testCreateBookmarkOnAddr() throws Exception {

		int origTypeCnt = bookmarkManager.getBookmarkTypes().length;
		ArrayList<Bookmark> originalList = getBookmarks(bookmarkManager);

		Address[] addrs = createBookmarks(locationGenerator.getProgramLocations());

		assertEquals(origTypeCnt + addrs.length, bookmarkManager.getBookmarkTypes().length);

		ArrayList<Bookmark> list = getBookmarks(bookmarkManager);
		assertEquals(originalList.size() + addrs.length, list.size());
		Iterator<Bookmark> iter = list.iterator();
		while (iter.hasNext()) {
			Bookmark bm = iter.next();
			if (originalList.contains(bm))
				continue;// skip old bookmarks	
			int ix = getAddressIndex(addrs, bm.getAddress());
			addrs[ix] = null;
			assertEquals("Type" + ix, bm.getTypeString());
			assertEquals("Cat" + ix, bm.getCategory());
			assertEquals("Cmt" + ix, bm.getComment());
		}

	}

@Test
    public void testCreateBookmarkOnAddrSet() throws Exception {

		AddressSet set = new AddressSet();
		set.add(builder.addr("0x1001000"), builder.addr("0x10010010"));
		set.add(builder.addr("0x1002000"), builder.addr("0x10020010"));
		set.add(builder.addr("0x1003000"), builder.addr("0x10030010"));
		set.add(builder.addr("0x1004000"), builder.addr("0x10040010"));

		BookmarkEditCmd cmd = new BookmarkEditCmd(set, "Type0", "Cat0", "Cmt0");
		applyCmd(notepad, cmd);

		AddressRangeIterator iter = set.getAddressRanges();
		int cnt = 0;
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			++cnt;

			Bookmark bm = bookmarkManager.getBookmark(range.getMinAddress(), "Type0", "Cat0");
			assertNotNull(bm);
			assertEquals("Cmt0", bm.getComment());
		}

		assertEquals(cnt, bookmarkManager.getBookmarkCount("Type0"));
	}

@Test
    public void testEditBookmark() throws Exception {

		Address[] addrs = createBookmarks(locationGenerator.getProgramLocations());
		int bmCnt = getBookmarks(bookmarkManager).size();

		Bookmark bm = bookmarkManager.getBookmark(addrs[0], "Type0", "Cat0");
		assertNotNull(bm);

		BookmarkEditCmd cmd = new BookmarkEditCmd(bm, "CatX", "CmtX");
		applyCmd(notepad, cmd);

		assertEquals(bmCnt, getBookmarks(bookmarkManager).size());

		assertNull(bookmarkManager.getBookmark(addrs[0], "Type0", "Cat0"));

		bm = bookmarkManager.getBookmark(addrs[0], "Type0", "CatX");
		assertNotNull(bm);
		assertEquals("CatX", bm.getCategory());
		assertEquals("CmtX", bm.getComment());
	}

@Test
    public void testCreateBookmarkOnAddrWithUndo() throws Exception {

		int origTypeCnt = bookmarkManager.getBookmarkTypes().length;
		ArrayList<Bookmark> originalList = getBookmarks(bookmarkManager);
		int originalCnt = originalList.size();

		Address[] addrs = createBookmarks(locationGenerator.getProgramLocations());

		assertEquals(origTypeCnt + addrs.length, bookmarkManager.getBookmarkTypes().length);

		notepad.undo();

		assertEquals(originalCnt, bookmarkManager.getBookmarkCount());

	}

}
