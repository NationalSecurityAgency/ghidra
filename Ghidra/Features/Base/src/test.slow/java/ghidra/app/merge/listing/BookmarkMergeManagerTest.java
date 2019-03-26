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
package ghidra.app.merge.listing;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class BookmarkMergeManagerTest extends AbstractListingMergeManagerTest {

	// 10028b1 no bookmark
	// 1001978, 100248f, 1002f01, 10031ee Analysis bookmark w/ category="Found Code"

	/**
	 * 
	 * @param arg0
	 */
	public BookmarkMergeManagerTest() {
		super();
	}

@Test
    public void testAddLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr = addr(program, "0x10028b1");
					bookMgr.setBookmark(addr, BookmarkType.INFO, "Cat1",
						"Test bookmark @ 0x10028b1");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		checkBookmark("0x10028b1", BookmarkType.INFO, "Cat1", "Test bookmark @ 0x10028b1");
	}

@Test
    public void testAddMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr = addr(program, "0x10028b1");
					bookMgr.setBookmark(addr, BookmarkType.INFO, "Cat1",
						"Test bookmark @ 0x10028b1");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		checkBookmark("0x10028b1", BookmarkType.INFO, "Cat1", "Test bookmark @ 0x10028b1");
	}

@Test
    public void testAddSame() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr = addr(program, "0x10028b1");
					bookMgr.setBookmark(addr, BookmarkType.INFO, "Cat1",
						"Test bookmark @ 0x10028b1");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr = addr(program, "0x10028b1");
					bookMgr.setBookmark(addr, BookmarkType.INFO, "Cat1",
						"Test bookmark @ 0x10028b1");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		checkBookmark("0x10028b1", BookmarkType.INFO, "Cat1", "Test bookmark @ 0x10028b1");
	}

@Test
    public void testAddDiffPickLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr = addr(program, "0x10028b1");
					bookMgr.setBookmark(addr, BookmarkType.INFO, "Cat1",
						"Test bookmark @ 0x10028b1");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr = addr(program, "0x10028b1");
					bookMgr.setBookmark(addr, BookmarkType.INFO, "Cat1", "My Cat1 bookmark.");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseBookmark("0x10028b1", KEEP_LATEST, false);
		waitForMergeCompletion();

		checkBookmark("0x10028b1", BookmarkType.INFO, "Cat1", "Test bookmark @ 0x10028b1");
	}

@Test
    public void testAddDiffPickMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr = addr(program, "0x10028b1");
					bookMgr.setBookmark(addr, BookmarkType.INFO, "Cat1",
						"Test bookmark @ 0x10028b1");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr = addr(program, "0x10028b1");
					bookMgr.setBookmark(addr, BookmarkType.INFO, "Cat1", "My Cat1 bookmark.");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseBookmark("0x10028b1", KEEP_MY, false);
		waitForMergeCompletion();

		checkBookmark("0x10028b1", BookmarkType.INFO, "Cat1", "My Cat1 bookmark.");
	}

@Test
    public void testChangeLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr;
					Bookmark[] bookmarks;

					// new category
					addr = addr(program, "0x1001978");
					bookmarks = bookMgr.getBookmarks(addr, BookmarkType.ANALYSIS);
					bookmarks[0].set("NewCat", bookmarks[0].getComment());

					// new comment
					addr = addr(program, "0x100248f");
					bookmarks = bookMgr.getBookmarks(addr, BookmarkType.ANALYSIS);
					bookmarks[0].set(bookmarks[0].getCategory(), "This is a new analysis comment.");

					// new category and comment
					addr = addr(program, "0x1002f01");
					bookmarks = bookMgr.getBookmarks(addr, BookmarkType.ANALYSIS);
					bookmarks[0].set("NewCat", "This is a new analysis comment.");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		checkBookmark("0x1001978", BookmarkType.ANALYSIS, "NewCat",
			"Found code from operand reference");
		checkBookmark("0x100248f", BookmarkType.ANALYSIS, "Found Code",
			"This is a new analysis comment.");
		checkBookmark("0x1002f01", BookmarkType.ANALYSIS, "NewCat",
			"This is a new analysis comment.");
	}

@Test
    public void testChangeMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr;
					Bookmark[] bookmarks;

					// new category
					addr = addr(program, "0x1001978");
					bookmarks = bookMgr.getBookmarks(addr, BookmarkType.ANALYSIS);
					bookmarks[0].set("NewCat", bookmarks[0].getComment());

					// new comment
					addr = addr(program, "0x100248f");
					bookmarks = bookMgr.getBookmarks(addr, BookmarkType.ANALYSIS);
					bookmarks[0].set(bookmarks[0].getCategory(), "This is a new analysis comment.");

					// new category and comment
					addr = addr(program, "0x1002f01");
					bookmarks = bookMgr.getBookmarks(addr, BookmarkType.ANALYSIS);
					bookmarks[0].set("NewCat", "This is a new analysis comment.");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		checkBookmark("0x1001978", BookmarkType.ANALYSIS, "NewCat",
			"Found code from operand reference");
		checkBookmark("0x100248f", BookmarkType.ANALYSIS, "Found Code",
			"This is a new analysis comment.");
		checkBookmark("0x1002f01", BookmarkType.ANALYSIS, "NewCat",
			"This is a new analysis comment.");
	}

@Test
    public void testChangeSame() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr;
					Bookmark[] bookmarks;

					// new category
					addr = addr(program, "0x1001978");
					bookmarks = bookMgr.getBookmarks(addr, BookmarkType.ANALYSIS);
					bookmarks[0].set("NewCat", bookmarks[0].getComment());

					// new comment
					addr = addr(program, "0x100248f");
					bookmarks = bookMgr.getBookmarks(addr, BookmarkType.ANALYSIS);
					bookmarks[0].set(bookmarks[0].getCategory(), "This is a new analysis comment.");

					// new category and comment
					addr = addr(program, "0x1002f01");
					bookmarks = bookMgr.getBookmarks(addr, BookmarkType.ANALYSIS);
					bookmarks[0].set("NewCat", "This is a new analysis comment.");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr;
					Bookmark[] bookmarks;

					// new category
					addr = addr(program, "0x1001978");
					bookmarks = bookMgr.getBookmarks(addr, BookmarkType.ANALYSIS);
					bookmarks[0].set("NewCat", bookmarks[0].getComment());

					// new comment
					addr = addr(program, "0x100248f");
					bookmarks = bookMgr.getBookmarks(addr, BookmarkType.ANALYSIS);
					bookmarks[0].set(bookmarks[0].getCategory(), "This is a new analysis comment.");

					// new category and comment
					addr = addr(program, "0x1002f01");
					bookmarks = bookMgr.getBookmarks(addr, BookmarkType.ANALYSIS);
					bookmarks[0].set("NewCat", "This is a new analysis comment.");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		checkBookmark("0x1001978", BookmarkType.ANALYSIS, "NewCat",
			"Found code from operand reference");
		checkBookmark("0x100248f", BookmarkType.ANALYSIS, "Found Code",
			"This is a new analysis comment.");
		checkBookmark("0x1002f01", BookmarkType.ANALYSIS, "NewCat",
			"This is a new analysis comment.");
	}

@Test
    public void testChangeDiff() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					bookMgr.setBookmark(addr(program, "0x1001978"), BookmarkType.ANALYSIS,
						"Found Code", "Latest bookmark @ 0x1001978");
					bookMgr.setBookmark(addr(program, "0x100248f"), BookmarkType.ANALYSIS,
						"Found Code", "Latest bookmark @ 0x100248f");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					bookMgr.setBookmark(addr(program, "0x1001978"), BookmarkType.ANALYSIS,
						"Found Code", "My bookmark @ 0x1001978");
					bookMgr.setBookmark(addr(program, "0x100248f"), BookmarkType.ANALYSIS,
						"Found Code", "My bookmark @ 0x100248f");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseBookmark("0x1001978", KEEP_LATEST, false);
		chooseBookmark("0x100248f", KEEP_MY, false);
		waitForMergeCompletion();

		checkBookmark("0x1001978", BookmarkType.ANALYSIS, "Found Code",
			"Latest bookmark @ 0x1001978");
		checkBookmark("0x100248f", BookmarkType.ANALYSIS, "Found Code", "My bookmark @ 0x100248f");
	}

@Test
    public void testRemoveLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Bookmark[] bookmarks;
					bookmarks =
						bookMgr.getBookmarks(addr(program, "0x1001978"), BookmarkType.ANALYSIS);
					bookMgr.removeBookmark(bookmarks[0]);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		BookmarkManager bookMgr = resultProgram.getBookmarkManager();
		Bookmark[] bookmarks;
		bookmarks = bookMgr.getBookmarks(addr("0x1001978"));
		assertEquals(0, bookmarks.length);
	}

@Test
    public void testRemoveMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Bookmark[] bookmarks;
					bookmarks =
						bookMgr.getBookmarks(addr(program, "0x1001978"), BookmarkType.ANALYSIS);
					bookMgr.removeBookmark(bookmarks[0]);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		BookmarkManager bookMgr = resultProgram.getBookmarkManager();
		Bookmark[] bookmarks;
		bookmarks = bookMgr.getBookmarks(addr("0x1001978"));
		assertEquals(0, bookmarks.length);
	}

@Test
    public void testRemoveSame() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Bookmark[] bookmarks;
					bookmarks =
						bookMgr.getBookmarks(addr(program, "0x1001978"), BookmarkType.ANALYSIS);
					bookMgr.removeBookmark(bookmarks[0]);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Bookmark[] bookmarks;
					bookmarks =
						bookMgr.getBookmarks(addr(program, "0x1001978"), BookmarkType.ANALYSIS);
					bookMgr.removeBookmark(bookmarks[0]);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		BookmarkManager bookMgr = resultProgram.getBookmarkManager();
		Bookmark[] bookmarks;
		bookmarks = bookMgr.getBookmarks(addr("0x1001978"));
		assertEquals(0, bookmarks.length);
	}

@Test
    public void testChangeLatestRemoveMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					bookMgr.setBookmark(addr(program, "0x1001978"), BookmarkType.ANALYSIS,
						"Found Code", "Latest bookmark @ 0x1001978");
					bookMgr.setBookmark(addr(program, "0x100248f"), BookmarkType.ANALYSIS,
						"Found Code", "Latest bookmark @ 0x100248f");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Bookmark[] bookmarks;
					bookmarks =
						bookMgr.getBookmarks(addr(program, "0x1001978"), BookmarkType.ANALYSIS);
					bookMgr.removeBookmark(bookmarks[0]);
					bookmarks =
						bookMgr.getBookmarks(addr(program, "0x100248f"), BookmarkType.ANALYSIS);
					bookMgr.removeBookmark(bookmarks[0]);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseBookmark("0x1001978", KEEP_LATEST, false);
		chooseBookmark("0x100248f", KEEP_MY, false);
		waitForMergeCompletion();

		checkBookmark("0x1001978", BookmarkType.ANALYSIS, "Found Code",
			"Latest bookmark @ 0x1001978");
		noBookmark("0x100248f", BookmarkType.ANALYSIS, "Found Code");
	}

@Test
    public void testChangeMyRemoveLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Bookmark[] bookmarks;
					bookmarks =
						bookMgr.getBookmarks(addr(program, "0x1001978"), BookmarkType.ANALYSIS);
					bookMgr.removeBookmark(bookmarks[0]);
					bookmarks =
						bookMgr.getBookmarks(addr(program, "0x100248f"), BookmarkType.ANALYSIS);
					bookMgr.removeBookmark(bookmarks[0]);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					bookMgr.setBookmark(addr(program, "0x1001978"), BookmarkType.ANALYSIS,
						"Found Code", "My bookmark @ 0x1001978");
					bookMgr.setBookmark(addr(program, "0x100248f"), BookmarkType.ANALYSIS,
						"Found Code", "My bookmark @ 0x100248f");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseBookmark("0x1001978", KEEP_LATEST, false);
		chooseBookmark("0x100248f", KEEP_MY, false);
		waitForMergeCompletion();

		noBookmark("0x1001978", BookmarkType.ANALYSIS, "Found Code");
		checkBookmark("0x100248f", BookmarkType.ANALYSIS, "Found Code", "My bookmark @ 0x100248f");
	}

	private void setupUseForAll() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Bookmark[] bookmarks;
					bookmarks =
						bookMgr.getBookmarks(addr(program, "0x1001978"), BookmarkType.ANALYSIS);
					bookMgr.removeBookmark(bookmarks[0]);
					bookmarks =
						bookMgr.getBookmarks(addr(program, "0x100248f"), BookmarkType.ANALYSIS);
					bookMgr.removeBookmark(bookmarks[0]);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					bookMgr.setBookmark(addr(program, "0x1001978"), BookmarkType.ANALYSIS,
						"Found Code", "My bookmark @ 0x1001978");
					bookMgr.setBookmark(addr(program, "0x100248f"), BookmarkType.ANALYSIS,
						"Found Code", "My bookmark @ 0x100248f");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	}

@Test
    public void testChangeMyRemoveLatestUseForAllPickLatest() throws Exception {
		setupUseForAll();

		executeMerge(ASK_USER);
		chooseBookmark("0x1001978", KEEP_LATEST, true);
//		chooseBookmark("0x100248f", KEEP_LATEST, false); // Use For All will handle this.
		waitForMergeCompletion();

		noBookmark("0x1001978", BookmarkType.ANALYSIS, "Found Code");
		noBookmark("0x100248f", BookmarkType.ANALYSIS, "Found Code");
	}

@Test
    public void testChangeMyRemoveLatestUseForAllPickMy() throws Exception {
		setupUseForAll();

		executeMerge(ASK_USER);
		chooseBookmark("0x1001978", KEEP_MY, true);
//		chooseBookmark("0x100248f", KEEP_MY, false); // Use For All will handle this.
		waitForMergeCompletion();

		checkBookmark("0x1001978", BookmarkType.ANALYSIS, "Found Code", "My bookmark @ 0x1001978");
		checkBookmark("0x100248f", BookmarkType.ANALYSIS, "Found Code", "My bookmark @ 0x100248f");
	}
}
