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

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

import java.util.Collections;
import java.util.List;

/**
 * Command to delete some number of bookmarks.
 * The bookmarks to delete can be specified by:
 *     an array of bookmarks
 *     an address set to delete all bookmarks within
 *     by type of bookmark
 *     by category of bookmark
 */
public class BookmarkDeleteCmd implements Command {

	private List<Bookmark> bookmarks;
	private String type;
	private String category;
	private AddressSetView addrSet;
	private String presentationName = "Delete Bookmark(s)";

	private BookmarkDeleteCmd(List<Bookmark> bookmarks, AddressSetView set, String type,
			String category) {
		this.bookmarks = bookmarks;
		this.addrSet = set;
		this.type = type;
		this.category = category;
	}

	/**
	 * Delete a Bookmark.
	 * @param bookmark the bookmark to be deleted
	 */
	public BookmarkDeleteCmd(Bookmark bookmark) {
		this(Collections.singletonList(bookmark), null, null, null);
		if (bookmark == null)
			throw new IllegalArgumentException();
		presentationName = "Delete Bookmark";
	}

	/**
	 * Delete an array of Bookmarks.
	 * @param bookmarks the array of bookmarks to be deleted.
	 */
	public BookmarkDeleteCmd(List<Bookmark> bookmarks) {
		this(bookmarks, null, null, null);
		if (bookmarks == null)
			throw new IllegalArgumentException();
		presentationName = "Delete Bookmark(s)";
	}

	/**
	 * Deletes all bookmarks at the given address
	 * @param addr that address at which to delete all bookmarks
	 */
	public BookmarkDeleteCmd(Address addr) {
		this(null, new AddressSet(addr, addr), null, null);
		presentationName = "Delete Bookmarks at " + addr;
	}

	/**
	 * Deletes all bookmarks at the given address with the given type
	 * @param addr the address at which to delete bookmarks of the given type.
	 * @param type the type of bookmark to delete at the given address
	 */
	public BookmarkDeleteCmd(Address addr, String type) {
		this(null, new AddressSet(addr, addr), type, null);
		presentationName = "Delete " + type + " Bookmarks at " + addr;
	}

	/**
	 * Deletes all bookmarks at the given address with the given type and category
	 * @param addr the address at which to delete bookmarks of the given type and category
	 * @param type the type of bookmark to delete at the given address
	 * @param category the category of the bookmark to delete at the given address
	 */
	public BookmarkDeleteCmd(Address addr, String type, String category) {
		this(null, new AddressSet(addr, addr), type, category);
		presentationName = "Delete " + type + ", " + category + " Bookmark at " + addr;
	}

	/**
	 * Deletes all bookmarks in the given address set
	 * @param set set of addresses at which to delete all bookmarks
	 */
	public BookmarkDeleteCmd(AddressSetView set) {
		this(null, set, null, null);
		presentationName = "Delete Bookmarks over address range";
	}

	/**
	 * Deletes all bookmarks in the given address set that have the given type
	 * @param set set of addresses at which to delete all bookmarks
	 * @param type the type of bookmark to delete at the given address
	 */
	public BookmarkDeleteCmd(AddressSetView set, String type) {
		this(null, set, type, null);
		presentationName = "Delete " + type + " Bookmarks over address range";
	}

	/**
	 * Deletes all bookmarks at the given address that have the given type and category
	 * @param set set of addresses at which to delete all bookmarks
	 * @param type the type of bookmark to delete at the given address
	 * @param category the category of the bookmark to delete at the given address
	 */
	public BookmarkDeleteCmd(AddressSetView set, String type, String category) {
		this(null, set, type, category);
		presentationName = "Delete " + type + ", " + category + " Bookmarks over address range";
	}

	/**
	 * Deletes all bookmarks of the given type.
	 * @param type the type of bookmarks to delete
	 */
	public BookmarkDeleteCmd(String type) {
		this(null, null, type, null);
		if (type == null)
			throw new IllegalArgumentException();
		presentationName = "Delete all " + type + " Bookmarks";
	}

	/**
	 * Deletes all bookmarks of the given type and category.
	 * @param type the type of bookmarks to delete
	 * @param category the category of bookmarks to delete.
	 */
	public BookmarkDeleteCmd(String type, String category) {
		this(null, null, type, category);
		if (type == null)
			throw new IllegalArgumentException();
		presentationName = "Delete all Bookmarks of type " + type + " and category " + category;
	}

	/**
	 * The name of the edit action.
	 */
	public String getPresentationName() {
		return presentationName;
	}

	@Override
	public boolean applyTo(DomainObject obj) {

		BookmarkManager mgr = ((Program) obj).getBookmarkManager();

		if (bookmarks != null) {
			deleteBookmarks(mgr, bookmarks);
		}
		else if (addrSet != null) {
			if (type != null) {
				if (category != null) {
					deleteBookmarks(mgr, addrSet, type, category);
				}
				else {
					deleteBookmarks(mgr, addrSet, type);
				}
			}
			else {
				deleteBookmarks(mgr, addrSet);
			}
		}
		else {
			if (category != null) {
				deleteBookmarks(mgr, type, category);
			}
			else {
				deleteBookmarks(mgr, type);
			}
		}
		return true;
	}

	private void deleteBookmarks(BookmarkManager mgr, List<Bookmark> marks) {
		for (Bookmark bookmark : marks) {
			mgr.removeBookmark(bookmark);
		}
	}

	private void deleteBookmarks(BookmarkManager mgr, String theType) {
		mgr.removeBookmarks(theType);
	}

	private void deleteBookmarks(BookmarkManager mgr, String theType, String theCategory) {
		try {
			mgr.removeBookmarks(theType, theCategory, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			// can't happen--dummy monitor
		}
	}

	private void deleteBookmarks(BookmarkManager mgr, AddressSetView set) {
		try {
			mgr.removeBookmarks(set, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			// can't happen--dummy monitor
		}
	}

	private void deleteBookmarks(BookmarkManager mgr, AddressSetView set, String theType) {
		try {
			mgr.removeBookmarks(set, theType, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			// can't happen--dummy monitor
		}
	}

	private void deleteBookmarks(BookmarkManager mgr, AddressSetView set, String theType,
			String theCategory) {
		try {
			mgr.removeBookmarks(set, theType, theCategory, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			// can't happen--dummy monitor
		}
	}

	@Override
	public String getStatusMsg() {
		return null;
	}

	@Override
	public String getName() {
		return presentationName;
	}

}
