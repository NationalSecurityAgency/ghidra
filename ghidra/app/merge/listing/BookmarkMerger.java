/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.app.merge.util.ConflictUtility;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramConflictException;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Hashtable;

import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

/**
 * Class for merging bookmark changes. This class can merge non-conflicting
 * bookmark changes that were made to the checked out version. It can determine
 * where there are conflicts between the latest checked in version and my
 * checked out version. It can then manually merge the conflicting bookmarks.
 * <br>Important: This class is intended to be used only for a single program 
 * version merge. It should be constructed, followed by an autoMerge(), and lastly
 * each address with a conflict should have mergeConflicts() called on it.
 */
class BookmarkMerger extends AbstractListingMerger {

	final static String BOOKMARKS_PHASE = "Bookmarks";
	private VerticalChoicesPanel conflictPanel;
	private String type;
	private String category;

	private BookmarkManager originalBookmarkMgr;
	private BookmarkManager latestBookmarkMgr;
	private BookmarkManager myBookmarkMgr;

	private AddressSet conflictSet;
	private Hashtable<Address, ArrayList<BookmarkUid>> conflicts;
	private AddressSet resolvedSet;
	private int bookmarkChoice = ASK_USER;

	/**
	 * Constructs a comments merger.
	 * @param listingMergeMgr the listing merge manager that owns this merger.
	 */
	BookmarkMerger(ListingMergeManager listingMergeMgr) {
		super(listingMergeMgr);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.AbstractListingMerger#init()
	 */
	@Override
	public void init() {
		super.init();
		originalBookmarkMgr = originalPgm.getBookmarkManager();
		latestBookmarkMgr = latestPgm.getBookmarkManager();
		myBookmarkMgr = myPgm.getBookmarkManager();

		conflictSet = new AddressSet();
		resolvedSet = new AddressSet();
		conflicts = new Hashtable<Address, ArrayList<BookmarkUid>>();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictType()
	 */
	@Override
	public String getConflictType() {
		return "Bookmark";
	}

	@Override
	public boolean apply() {
		conflictOption = conflictPanel.getSelectedOptions();

		// If the "Use For All" check box is selected 
		// then save the option chosen for this conflict type.
		if (conflictPanel.getUseForAll()) {
			bookmarkChoice = conflictOption;
		}

		return super.apply();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#determineConflicts(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void autoMerge(int progressMin, int progressMax, TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {

		initializeAutoMerge("Auto-merging Bookmarks and determining conflicts.", progressMin,
			progressMax, monitor);

		// Inspect each bookmark where my changes occurred.
		AddressIterator iterator = listingMergeMgr.mySet.getAddresses(true);
		totalChanges = listingMergeMgr.mySet.getNumAddresses();

		while (iterator.hasNext()) {
			Address addr = iterator.next();
			incrementProgress(1);

			// Check the Original Bookmarks
			Bookmark[] bookmarks = originalBookmarkMgr.getBookmarks(addr);
			for (int i = 0; i < bookmarks.length; i++) {
				checkOriginalBookmark(monitor, addr, bookmarks[i]);
			}
			//Check any bookmarks that were added to MY program at the address.
			bookmarks = myBookmarkMgr.getBookmarks(addr);
			for (int i = 0; i < bookmarks.length; i++) {
				checkAddedBookmark(monitor, addr, bookmarks[i]);
			}
		}
		updateProgress(100, "Done auto-merging Bookmarks and determining conflicts.");
	}

	private void checkOriginalBookmark(TaskMonitor monitor, Address addr, Bookmark currentBookmark)
			throws CancelledException {
		if (currentBookmark.getTypeString() == BookmarkType.NOTE) {
			checkOriginalNoteBookmark(monitor, addr, currentBookmark);
		}
		else {
			checkOriginalNonNoteBookmark(monitor, addr, currentBookmark);
		}
	}

	private void checkOriginalNoteBookmark(TaskMonitor monitor, Address addr,
			Bookmark currentBookmark) throws CancelledException {
		String originalType = currentBookmark.getTypeString();
		String originalCategory = currentBookmark.getCategory();
		String originalComment = currentBookmark.getComment();
		// We only allow one NOTE bookmark.
		Bookmark[] my = myBookmarkMgr.getBookmarks(addr, originalType);
		if (my.length > 1) {
			throw new AssertException(
				"Error in CHECKED OUT program - Shouldn't be multiple notes at a single address. Address=" +
					addr.toString());
		}
		Bookmark[] latest = latestBookmarkMgr.getBookmarks(addr, originalType);
		if (latest.length > 1) {
			throw new AssertException(
				"Error in LATEST checked in program - Shouldn't be multiple notes at a single address. Address=" +
					addr.toString());
		}

		if (my.length == 0) {
			// Deleted in MY
			if (latest.length == 1) {
				String latestCategory = latest[0].getCategory();
				String latestComment = latest[0].getComment();
				if (!originalCategory.equals(latestCategory) ||
					!originalComment.equals(latestComment)) {
					// MY deleted and LATEST changed, so conflict.
					addConflict(addr, originalType, null);
				}
				else {
					// MY deleted and LATEST didn't.
					merge(addr, originalType, null, KEEP_MY, monitor);
				}
			}
		}
		else if (my.length == 1) {
			String myCategory = my[0].getCategory();
			String myComment = my[0].getComment();
			if (!originalCategory.equals(myCategory) ||
				!originalComment.equals(myComment)) {
				// Changed in MY
				if (latest.length == 0) {
					// MY changed and LATEST deleted, so conflict.
					addConflict(addr, originalType, null);
				}
				else if (latest.length == 1) {
					String latestCategory = latest[0].getCategory();
					String latestComment = latest[0].getComment();
					if ((!originalCategory.equals(latestCategory) || !originalComment.equals(latestComment)) &&
						(!myCategory.equals(latestCategory) || !myComment.equals(latestComment))) {
						// MY changed and LATEST changed differently
						addConflict(addr, originalType, null);
					}
					else {
						// MY changed and LATEST didn't.
						merge(addr, originalType, null, KEEP_MY, monitor);
					}
				}
			}
		}
	}

	private void checkOriginalNonNoteBookmark(TaskMonitor monitor, Address addr,
			Bookmark currentBookmark) throws CancelledException {
		String originalType = currentBookmark.getTypeString();
		String originalCategory = currentBookmark.getCategory();
		String originalComment = currentBookmark.getComment();
		// Non-NOTE type.
		Bookmark my = myBookmarkMgr.getBookmark(addr, originalType, originalCategory);
		Bookmark latest =
			latestBookmarkMgr.getBookmark(addr, originalType, originalCategory);

		if (my == null) {
			// Deleted in MY
			if (latest != null) {
				String latestComment = latest.getComment();
				if (!originalComment.equals(latestComment)) {
					// MY deleted and LATEST changed, so conflict.
					addConflict(addr, originalType, originalCategory);
				}
				else {
					// MY deleted and LATEST didn't.
					merge(addr, originalType, originalCategory, KEEP_MY, monitor);
				}
			}
		}
		else {
			String myComment = my.getComment();
			if (!originalComment.equals(myComment)) {
				// Changed in MY
				if (latest == null) {
					// MY changed and LATEST deleted, so conflict.
					addConflict(addr, originalType, originalCategory);
				}
				else {
					String latestComment = latest.getComment();
					if (!originalComment.equals(latestComment) &&
						!myComment.equals(latestComment)) {
						// MY changed and LATEST changed differently
						addConflict(addr, originalType, originalCategory);
					}
					else {
						// MY changed and LATEST didn't.
						merge(addr, originalType, originalCategory, KEEP_MY, monitor);
					}
				}
			}
		}
	}

	private void checkAddedBookmark(TaskMonitor monitor, Address addr, Bookmark currentBookmark)
			throws CancelledException {
		if (currentBookmark.getTypeString().equals(BookmarkType.NOTE)) {
			checkAddedNoteBookmark(monitor, addr, currentBookmark);
		}
		else {
			checkAddedNonNoteBookmark(monitor, addr, currentBookmark);
		}
	}

	private void checkAddedNoteBookmark(TaskMonitor monitor, Address addr, Bookmark currentBookmark)
			throws CancelledException {
		String myType = currentBookmark.getTypeString();
		String myCategory = currentBookmark.getCategory();
		String myComment = currentBookmark.getComment();
		// We only allow one NOTE bookmark.
		Bookmark[] original = originalBookmarkMgr.getBookmarks(addr, myType);
		if (original.length > 1) {
			throw new AssertException(
				"Error in CHECKED OUT program - Shouldn't be multiple notes at a single address. Address=" +
					addr.toString());
		}
		if (original.length == 0) {
			// MY added this bookmark
			Bookmark[] latest = latestBookmarkMgr.getBookmarks(addr, myType);
			if (latest.length > 1) {
				throw new AssertException(
					"Error in LATEST checked in program - Shouldn't be multiple notes at a single address. Address=" +
						addr.toString());
			}
			else if (latest.length == 0) {
				// MY added
				merge(addr, myType, null, KEEP_MY, monitor);
			}
			else if (latest.length == 1) {
				String latestCategory = latest[0].getCategory();
				String latestComment = latest[0].getComment();
				if (!myCategory.equals(latestCategory) ||
					!myComment.equals(latestComment)) {
					// MY & LATEST added different NOTEs, so conflict.
					addConflict(addr, myType, null);
				}
			}
		}
	}

	private void checkAddedNonNoteBookmark(TaskMonitor monitor, Address addr, Bookmark currentBookmark)
			throws CancelledException {
		String myType = currentBookmark.getTypeString();
		String myCategory = currentBookmark.getCategory();
		String myComment = currentBookmark.getComment();
		// Non-NOTE type
		Bookmark original = originalBookmarkMgr.getBookmark(addr, myType, myCategory);
		if (original == null) {
			// MY added this bookmark
			Bookmark latest = latestBookmarkMgr.getBookmark(addr, myType, myCategory);
			if (latest == null) {
				// MY added
				merge(addr, myType, myCategory, KEEP_MY, monitor);
			}
			else {
				String latestComment = latest.getComment();
				if (!myComment.equals(latestComment)) {
					// MY & LATEST added same bookmark w/ different comments, so conflict.
					addConflict(addr, myType, myCategory);
				}
			}
		}
	}

	private void addConflict(Address address, String bookmarkType, String bookmarkCategory) {
		ArrayList<BookmarkUid> list = conflicts.get(address);
		if (list == null) {
			list = new ArrayList<BookmarkUid>(1);
			conflicts.put(address, list);
		}
		list.add(new BookmarkUid(address, bookmarkType, bookmarkCategory));
		conflictSet.addRange(address, address);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#hasConflict(ghidra.program.model.address.Address)
	 */
	@Override
	public boolean hasConflict(Address addr) {
		return conflictSet.contains(addr);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictCount(ghidra.program.model.address.Address)
	 */
	@Override
	public int getConflictCount(Address addr) {
		ArrayList<BookmarkUid> list = conflicts.get(addr);
		if (list == null) {
			return 0;
		}
		return list.size();
	}

	VerticalChoicesPanel getConflictsPanel(Address address, String bookmarkType,
			String bookmarkCategory, ChangeListener changeListener) {
		if (conflictPanel == null) {
			conflictPanel = new VerticalChoicesPanel();
			currentConflictPanel = conflictPanel;
			conflictPanel.setTitle(getConflictType());
		}
		else {
			conflictPanel.clear();
		}
		Bookmark original;
		Bookmark latest;
		Bookmark my;
		if (bookmarkType.equals(BookmarkType.NOTE)) {
			Bookmark[] originalMarks = originalBookmarkMgr.getBookmarks(address, bookmarkType);
			original = (originalMarks.length > 0) ? originalMarks[0] : null;
			Bookmark[] latestMarks = latestBookmarkMgr.getBookmarks(address, bookmarkType);
			latest = (latestMarks.length > 0) ? latestMarks[0] : null;
			Bookmark[] myMarks = myBookmarkMgr.getBookmarks(address, bookmarkType);
			my = (myMarks.length > 0) ? myMarks[0] : null;
		}
		else {
			original = originalBookmarkMgr.getBookmark(address, bookmarkType, bookmarkCategory);
			latest = latestBookmarkMgr.getBookmark(address, bookmarkType, bookmarkCategory);
			my = myBookmarkMgr.getBookmark(address, bookmarkType, bookmarkCategory);
		}

		String text = "Bookmark conflict @ address :" + ConflictUtility.getAddressString(address);
		conflictPanel.setHeader(text);
		conflictPanel.setRowHeader(getBookmarkInfo(-1, null));
		conflictPanel.addRadioButtonRow(getBookmarkInfo(LATEST, latest), LATEST_BUTTON_NAME,
			KEEP_LATEST, changeListener);
		conflictPanel.addRadioButtonRow(getBookmarkInfo(MY, my), CHECKED_OUT_BUTTON_NAME, KEEP_MY,
			changeListener);
		conflictPanel.addInfoRow(getBookmarkInfo(ORIGINAL, original));
		return conflictPanel;
	}

	/**
	 * Gets a standardized array of strings that represent the bookmark information for 
	 * each column of a bookmark info row that will be presented in a table format.
	 * @param version the program version that provided the bookmark.
	 * @param bookmark the bookmark having its information presented.
	 * @return the standardized bookmark information.
	 */
	private String[] getBookmarkInfo(int version, Bookmark bookmark) {
		String[] info = new String[] { "", "", "", "" };
		if (version == LATEST) {
			info[0] = getChoice(LATEST_TITLE, bookmark);
		}
		else if (version == MY) {
			info[0] = getChoice(MY_TITLE, bookmark);
		}
		else if (version == ORIGINAL) {
			info[0] = " '" + ORIGINAL_TITLE + "' version";
		}
		else {
			return new String[] { "Option", "Type", "Category", "Description" };
		}
		if (bookmark != null) {
			info[1] = bookmark.getTypeString();
			info[2] = bookmark.getCategory();
			info[3] = bookmark.getComment();
		}
		return info;
	}

	/** Gets a standard string to display for the version info of the bookmark info.
	 * Provides different strings depending on whether the bookmark is null
	 * indicating it was removed or not null indicating the user can choose to keep it.
	 * @param version the program version that provided the bookmark.
	 * @param bookmark the bookmark having its information presented.
	 * @returnthe version information string.
	 */
	private String getChoice(String version, Bookmark bookmark) {
		if (bookmark == null) {
			return "Remove as in '" + version + "' version";
		}
		return "Keep '" + version + "' version";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#mergeConflicts(ghidra.app.merge.tool.ListingMergePanel, ghidra.program.model.address.Address, int, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void mergeConflicts(ListingMergePanel listingPanel, Address addr,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException,
			MemoryAccessException {
		monitor.setMessage("Resolving Bookmark conflicts.");
		if (!hasConflict(addr)) {
			return;
		}
		// At address get the BookmarkUid ArrayList for each conflict.
		boolean askUser = chosenConflictOption == ASK_USER;
		ArrayList<BookmarkUid> list = conflicts.get(addr);
		int size = list.size();
		for (int i = 0; i < size; i++) {
			BookmarkUid bmuid = list.get(i);
			// If we have a bookmark choice then a "Use For All" has already occurred.
			if ((bookmarkChoice == ASK_USER) && askUser && mergeManager != null) {
				showMergePanel(listingPanel, bmuid.address, bmuid.bookmarkType,
					bmuid.bookmarkCategory, monitor);
				monitor.checkCanceled();
			}
			else {
				int optionToUse =
					(bookmarkChoice == ASK_USER) ? chosenConflictOption : bookmarkChoice;
				merge(bmuid.address, bmuid.bookmarkType, bmuid.bookmarkCategory, optionToUse,
					monitor);
			}
		}
		resolvedSet.addRange(addr, addr);
	}

	private void merge(Address address, String bookmarkType, String bookmarkCategory,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException {
		if ((chosenConflictOption & KEEP_ORIGINAL) != 0) {
			listingMergeMgr.mergeOriginal.mergeBookmark(address, bookmarkType, bookmarkCategory,
				monitor);
		}
		else if ((chosenConflictOption & KEEP_LATEST) != 0) {
			listingMergeMgr.mergeLatest.mergeBookmark(address, bookmarkType, bookmarkCategory,
				monitor);
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			listingMergeMgr.mergeMy.mergeBookmark(address, bookmarkType, bookmarkCategory, monitor);
		}
	}

	private void showMergePanel(final ListingMergePanel listingPanel, final Address addr,
			final String bookmarkType, final String bookmarkCategory, TaskMonitor monitor) {
		this.currentAddress = addr;
		this.type = bookmarkType;
		this.category = bookmarkCategory;
		this.currentMonitor = monitor;
		try {
			final ChangeListener changeListener = new BookmarkMergeChangeListener();
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					VerticalChoicesPanel panel =
						getConflictsPanel(BookmarkMerger.this.currentAddress,
							BookmarkMerger.this.type, BookmarkMerger.this.category, changeListener);

					boolean useForAll = (bookmarkChoice != ASK_USER);
					conflictPanel.setUseForAll(useForAll);
					conflictPanel.setConflictType("Bookmark");

					listingPanel.setBottomComponent(panel);
				}
			});
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					Address addressToPaint = BookmarkMerger.this.currentAddress;
					listingPanel.clearAllBackgrounds();
					listingPanel.paintAllBackgrounds(new AddressSet(addressToPaint, addressToPaint));
				}
			});
		}
		catch (InterruptedException e) {
		}
		catch (InvocationTargetException e) {
		}
		if (mergeManager != null) {
			mergeManager.setApplyEnabled(false);
			mergeManager.showListingMergePanel(currentAddress);
		}
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflicts()
	 */
	@Override
	public AddressSetView getConflicts() {
		return this.conflictSet;
	}

	private final class BookmarkMergeChangeListener implements ChangeListener {
		@Override
		public void stateChanged(ChangeEvent e) {
			conflictOption = conflictPanel.getSelectedOptions();
			if (conflictOption == ASK_USER) {
				if (mergeManager != null) {
					mergeManager.setApplyEnabled(false);
				}
				return;
			}
			if (mergeManager != null) {
				mergeManager.clearStatusText();
			}
			try {
				merge(BookmarkMerger.this.currentAddress, BookmarkMerger.this.type,
					BookmarkMerger.this.category, conflictOption, currentMonitor);
			}
			catch (CancelledException e1) {
				cancel();
				return;
			}
			if (mergeManager != null) {
				mergeManager.setApplyEnabled(true);
			}
		}
	}

	private class BookmarkUid {
		Address address;
		String bookmarkType;
		String bookmarkCategory;

		BookmarkUid(Address addr, String bookmarkType, String bookmarkCategory) {
			this.address = addr;
			this.bookmarkType = bookmarkType;
			this.bookmarkCategory = bookmarkCategory;
		}
	}

}
