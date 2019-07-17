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

import ghidra.app.merge.ProgramMultiUserMergeManager;
import ghidra.program.database.MergeProgram;
import ghidra.program.database.MergeProgramModifier;
import ghidra.program.model.listing.*;

/**
 * Test the merge of Note Bookmarks in the versioned program's listing.
 */
public class BookmarkMergerNoteTest extends AbstractListingMergeManagerTest {

	// 1002306 Note MyCat
	// 100230b Note P1Category
	// 100230c Note 
	// 1002312 Note 
	// 1002318 Note Test
	// 100231d Note Test
	// 1002323 Note cat

	public BookmarkMergerNoteTest() {
		super();
	}

	@Override
	protected ProgramMultiUserMergeManager createMergeManager(ProgramChangeSet resultChangeSet,
			ProgramChangeSet myChangeSet) {

		// NOTE: this makes the tests faster.  If you need visual debugging, then make this true
		boolean showListingPanels = false;

		ProgramMultiUserMergeManager mergeManger =
			new ProgramMultiUserMergeManager(resultProgram, myProgram, originalProgram,
				latestProgram, resultChangeSet, myChangeSet, showListingPanels);

		return mergeManger;
	}

	@Test
	public void testAddLatest() throws Exception {

		final String address = "0x100";

		mtf.initialize("DiffTestPgm1", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram program) {
				program.setBookmark(address, BookmarkType.NOTE, "Cat1",
					"Test bookmark @ " + address);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		checkBookmark(address, BookmarkType.NOTE, "Cat1", "Test bookmark @ " + address);
	}

	@Test
	public void testAddMy() throws Exception {
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyPrivate(MergeProgram program) {
				program.setBookmark(address, BookmarkType.NOTE, "Cat1",
					"Test bookmark @ " + address);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		checkBookmark(address, BookmarkType.NOTE, "Cat1", "Test bookmark @ " + address);
	}

	@Test
	public void testAddSame() throws Exception {

		final String address = "0x100";

		mtf.initialize("DiffTestPgm1", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram program) {
				program.setBookmark(address, BookmarkType.NOTE, "Cat1",
					"Test bookmark @ " + address);
			}

			@Override
			public void modifyPrivate(MergeProgram program) {
				program.setBookmark(address, BookmarkType.NOTE, "Cat1",
					"Test bookmark @ " + address);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		checkBookmark(address, BookmarkType.NOTE, "Cat1", "Test bookmark @ " + address);
	}

	@Test
	public void testAddDiffPickLatest() throws Exception {

		final String address1 = "0x101";
		final String address2 = "0x102";
		final String address3 = "0x103";
		final String address4 = "0x104";

		mtf.initialize("DiffTestPgm1", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram program) {
				program.setBookmark(address1, BookmarkType.NOTE, "Cat1",
					"Test bookmark @ " + address1);
				program.setBookmark(address2, BookmarkType.NOTE, "Cat1",
					"Test bookmark @ " + address2);
				program.setBookmark(address3, BookmarkType.NOTE, "Cat1",
					"Latest Test bookmark @ " + address3);
				program.setBookmark(address4, BookmarkType.NOTE, "Cat1",
					"Latest Test bookmark @ " + address4);
			}

			@Override
			public void modifyPrivate(MergeProgram program) {
				program.setBookmark(address1, BookmarkType.NOTE, "Cat1", "My Cat1 bookmark.");
				program.setBookmark(address2, BookmarkType.NOTE, "Test",
					"Test bookmark @ " + address2);
				program.setBookmark(address3, BookmarkType.NOTE, "Cat1",
					"My Test bookmark @ " + address3);
				program.setBookmark(address4, BookmarkType.NOTE, "Test",
					"My Test bookmark @ " + address4);
			}
		});

		executeMerge(ASK_USER);
		chooseBookmark(address1, KEEP_LATEST, false);
		chooseBookmark(address2, KEEP_LATEST, false);
		chooseBookmark(address3, KEEP_LATEST, false);
		chooseBookmark(address4, KEEP_LATEST, false);
		waitForMergeCompletion();

		checkBookmark(address1, BookmarkType.NOTE, "Cat1", "Test bookmark @ " + address1);
		checkBookmark(address2, BookmarkType.NOTE, "Cat1", "Test bookmark @ " + address2);
		checkBookmark(address3, BookmarkType.NOTE, "Cat1", "Latest Test bookmark @ " + address3);
		checkBookmark(address4, BookmarkType.NOTE, "Cat1", "Latest Test bookmark @ " + address4);
	}

	@Test
	public void testAddDiffPickMy() throws Exception {

		final String address1 = "0x100";
		final String address2 = "0x110";
		final String address3 = "0x120";
		final String address4 = "0x130";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram program) throws Exception {
				program.setBookmark(address1, BookmarkType.NOTE, "Cat1",
					"Test bookmark @" + address1);
				program.setBookmark(address2, BookmarkType.NOTE, "Cat1",
					"Test bookmark @ " + address2);
				program.setBookmark(address3, BookmarkType.NOTE, "Cat1",
					"Latest Test @ " + address3);
				program.setBookmark(address4, BookmarkType.NOTE, "Cat1",
					"Latest Test @ " + address4);
			}

			@Override
			public void modifyPrivate(MergeProgram program) throws Exception {
				program.setBookmark(address1, BookmarkType.NOTE, "Cat1", "My Cat1 bookmark.");
				program.setBookmark(address2, BookmarkType.NOTE, "Test",
					"Test bookmark @ " + address2);
				program.setBookmark(address3, BookmarkType.NOTE, "Cat1",
					"My Test bookmark @ " + address3);
				program.setBookmark(address4, BookmarkType.NOTE, "Test",
					"My Test bookmark @ " + address4);
			}
		});

		executeMerge(ASK_USER);
		chooseBookmark(address1, KEEP_MY, false);
		chooseBookmark(address2, KEEP_MY, false);
		chooseBookmark(address3, KEEP_MY, false);
		chooseBookmark(address4, KEEP_MY, false);
		waitForMergeCompletion();

		checkBookmark(address1, BookmarkType.NOTE, "Cat1", "My Cat1 bookmark.");
		checkBookmark(address2, BookmarkType.NOTE, "Test", "Test bookmark @ " + address2);
		checkBookmark(address3, BookmarkType.NOTE, "Cat1", "My Test bookmark @ " + address3);
		checkBookmark(address4, BookmarkType.NOTE, "Test", "My Test bookmark @ " + address4);
	}

	@Test
	public void testChangeLatest() throws Exception {
		final String address1 = "0x100";
		final String address2 = "0x110";
		final String address3 = "0x120";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);

				program.setBookmark(address1, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address1);
				program.setBookmark(address2, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address2);
				program.setBookmark(address3, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address3);
			}

			@Override
			public void modifyLatest(MergeProgram program) throws Exception {
				program.updateBookmark(address1, BookmarkType.ANALYSIS, "NewCat", null);
				program.updateBookmark(address2, BookmarkType.ANALYSIS, null,
					"This is a new analysis comment.");
				program.updateBookmark(address3, BookmarkType.ANALYSIS, "NewCat",
					"This is a new analysis comment.");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		checkBookmark(address1, BookmarkType.ANALYSIS, "NewCat", "Original bookmark @ " + address1);
		checkBookmark(address2, BookmarkType.ANALYSIS, "Found Code",
			"This is a new analysis comment.");
		checkBookmark(address3, BookmarkType.ANALYSIS, "NewCat", "This is a new analysis comment.");
	}

	@Test
	public void testChangeMy() throws Exception {
		final String address1 = "0x100";
		final String address2 = "0x110";
		final String address3 = "0x120";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);

				program.setBookmark(address1, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address1);
				program.setBookmark(address2, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address2);
				program.setBookmark(address3, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address3);
			}

			@Override
			public void modifyPrivate(MergeProgram program) throws Exception {
				program.updateBookmark(address1, BookmarkType.ANALYSIS, "NewCat", null);
				program.updateBookmark(address2, BookmarkType.ANALYSIS, null,
					"This is a new analysis comment.");
				program.updateBookmark(address3, BookmarkType.ANALYSIS, "NewCat",
					"This is a new analysis comment.");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		checkBookmark(address1, BookmarkType.ANALYSIS, "NewCat", "Original bookmark @ " + address1);
		checkBookmark(address2, BookmarkType.ANALYSIS, "Found Code",
			"This is a new analysis comment.");
		checkBookmark(address3, BookmarkType.ANALYSIS, "NewCat", "This is a new analysis comment.");
	}

	@Test
	public void testChangeSame() throws Exception {

		final String address1 = "0x100";
		final String address2 = "0x110";
		final String address3 = "0x120";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);

				program.setBookmark(address1, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address1);
				program.setBookmark(address2, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address2);
				program.setBookmark(address3, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address3);
			}

			@Override
			public void modifyLatest(MergeProgram program) throws Exception {
				program.updateBookmark(address1, BookmarkType.ANALYSIS, "NewCat", null);
				program.updateBookmark(address2, BookmarkType.ANALYSIS, null,
					"This is a new analysis comment.");
				program.updateBookmark(address3, BookmarkType.ANALYSIS, "NewCat",
					"This is a new analysis comment.");
			}

			@Override
			public void modifyPrivate(MergeProgram program) throws Exception {
				program.updateBookmark(address1, BookmarkType.ANALYSIS, "NewCat", null);
				program.updateBookmark(address2, BookmarkType.ANALYSIS, null,
					"This is a new analysis comment.");
				program.updateBookmark(address3, BookmarkType.ANALYSIS, "NewCat",
					"This is a new analysis comment.");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		checkBookmark(address1, BookmarkType.ANALYSIS, "NewCat", "Original bookmark @ " + address1);
		checkBookmark(address2, BookmarkType.ANALYSIS, "Found Code",
			"This is a new analysis comment.");
		checkBookmark(address3, BookmarkType.ANALYSIS, "NewCat", "This is a new analysis comment.");
	}

	@Test
	public void testChangeDiff() throws Exception {

		final String address1 = "0x100";
		final String address2 = "0x110";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);

				program.setBookmark(address1, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address1);
				program.setBookmark(address2, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address2);
			}

			@Override
			public void modifyLatest(MergeProgram program) throws Exception {
				program.setBookmark(address1, BookmarkType.ANALYSIS, "Found Code",
					"Latest bookmark @ " + address1);
				program.setBookmark(address2, BookmarkType.ANALYSIS, "Found Code",
					"Latest bookmark @ " + address2);
			}

			@Override
			public void modifyPrivate(MergeProgram program) throws Exception {
				program.setBookmark(address1, BookmarkType.ANALYSIS, "Found Code",
					"My bookmark @ " + address1);
				program.setBookmark(address2, BookmarkType.ANALYSIS, "Found Code",
					"My bookmark @ " + address2);
			}
		});

		executeMerge(ASK_USER);
		chooseBookmark(address1, KEEP_LATEST, false);
		chooseBookmark(address2, KEEP_MY, false);
		waitForMergeCompletion();

		checkBookmark(address1, BookmarkType.ANALYSIS, "Found Code",
			"Latest bookmark @ " + address1);
		checkBookmark(address2, BookmarkType.ANALYSIS, "Found Code", "My bookmark @ " + address2);
	}

	@Test
	public void testRemoveLatest() throws Exception {

		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);

				program.setBookmark(address, BookmarkType.NOTE, "Cat1", "Test");
			}

			@Override
			public void modifyLatest(MergeProgram program) throws Exception {
				program.removeBookmark(address, BookmarkType.NOTE);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		BookmarkManager bookMgr = resultProgram.getBookmarkManager();
		Bookmark[] bookmarks;
		bookmarks = bookMgr.getBookmarks(addr(address));
		assertEquals(0, bookmarks.length);
	}

	@Test
	public void testRemoveMy() throws Exception {

		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);

				program.setBookmark(address, BookmarkType.ANALYSIS, "Cat1", "Test");
			}

			@Override
			public void modifyPrivate(MergeProgram program) throws Exception {
				program.removeBookmark(address, BookmarkType.ANALYSIS);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		BookmarkManager bookMgr = resultProgram.getBookmarkManager();
		Bookmark[] bookmarks;
		bookmarks = bookMgr.getBookmarks(addr(address));
		assertEquals(0, bookmarks.length);
	}

	@Test
	public void testRemoveSame() throws Exception {

		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);

				program.setBookmark(address, BookmarkType.ANALYSIS, "Cat1", "Test");
			}

			@Override
			public void modifyLatest(MergeProgram program) throws Exception {
				program.removeBookmark(address, BookmarkType.ANALYSIS);
			}

			@Override
			public void modifyPrivate(MergeProgram program) throws Exception {
				program.removeBookmark(address, BookmarkType.ANALYSIS);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		BookmarkManager bookMgr = resultProgram.getBookmarkManager();
		Bookmark[] bookmarks;
		bookmarks = bookMgr.getBookmarks(addr(address));
		assertEquals(0, bookmarks.length);
	}

	@Test
	public void testChangeLatestRemoveMy() throws Exception {

		final String address1 = "0x100";
		final String address2 = "0x110";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);

				program.setBookmark(address1, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address1);
				program.setBookmark(address2, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address2);
			}

			@Override
			public void modifyLatest(MergeProgram program) throws Exception {
				program.setBookmark(address1, BookmarkType.ANALYSIS, "Found Code",
					"Latest bookmark @ " + address1);
				program.setBookmark(address2, BookmarkType.ANALYSIS, "Found Code",
					"Latest bookmark @ " + address2);
			}

			@Override
			public void modifyPrivate(MergeProgram program) throws Exception {
				program.removeBookmark(address1, BookmarkType.ANALYSIS);
				program.removeBookmark(address2, BookmarkType.ANALYSIS);
			}
		});

		executeMerge(ASK_USER);
		chooseBookmark(address1, KEEP_LATEST, false);
		chooseBookmark(address2, KEEP_MY, false);
		waitForMergeCompletion();

		checkBookmark(address1, BookmarkType.ANALYSIS, "Found Code",
			"Latest bookmark @ " + address1);
		noBookmark(address2, BookmarkType.ANALYSIS, "Found Code");
	}

	@Test
	public void testChangeMyRemoveLatest() throws Exception {

		final String address1 = "0x100";
		final String address2 = "0x110";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);

				program.setBookmark(address1, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address1);
				program.setBookmark(address2, BookmarkType.ANALYSIS, "Found Code",
					"Original bookmark @ " + address2);
			}

			@Override
			public void modifyLatest(MergeProgram program) throws Exception {
				program.removeBookmark(address1, BookmarkType.ANALYSIS);
				program.removeBookmark(address2, BookmarkType.ANALYSIS);
			}

			@Override
			public void modifyPrivate(MergeProgram program) throws Exception {
				program.setBookmark(address1, BookmarkType.ANALYSIS, "Found Code",
					"My bookmark @ " + address1);
				program.setBookmark(address2, BookmarkType.ANALYSIS, "Found Code",
					"My bookmark @ " + address2);
			}
		});

		executeMerge(ASK_USER);
		chooseBookmark(address1, KEEP_LATEST, false);
		chooseBookmark(address2, KEEP_MY, false);
		waitForMergeCompletion();

		noBookmark(address1, BookmarkType.ANALYSIS, "Found Code");
		checkBookmark(address2, BookmarkType.ANALYSIS, "Found Code", "My bookmark @ " + address2);
	}
}
