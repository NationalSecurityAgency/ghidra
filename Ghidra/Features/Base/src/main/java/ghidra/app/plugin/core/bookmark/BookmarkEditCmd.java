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

/**
 * Command to set a Bookmark(s) at a location or range of locations.
 * The location to create the bookmark(s) can be set by:
 *      1) by address set where the bookmark is placed at the first address
 *         in each range in the address set
 *      2) at a given address
 *      3) by the information contained in a Bookmark
 */
public class BookmarkEditCmd implements Command {

	private String category;
	private String comment;

	private Bookmark bookmark;

	private AddressSetView set;
	private Address addr;
	private String type;

	private String presentationName;

	/**
	 * Edit a Bookmark. When editing a bookmark, all fields are used except the address
	 * which is determined by the first address within each range of the set.
	 * @param set list of bookmark addresses.
	 * @param type the bookmark type.
	 * @param category the bookmark category.
	 * @param comment the bookmark comment.
	 */
	public BookmarkEditCmd(AddressSetView set, String type, String category, String comment) {
		this.type = type;
		this.category = category;
		this.comment = comment;
		this.set = set;
		if (set == null || set.isEmpty() || type == null || type.length() == 0)
			throw new IllegalArgumentException();
		presentationName = "Add " + type + " Bookmark(s)";
	}

	/**
	 * Edit a Bookmark. When editing a bookmark, all fields are used except the address
	 * which is provided by the addrs parameter.
	 * @param addr the bookmark address.
	 * @param type the bookmark type.
	 * @param category the bookmark category.
	 * @param comment the bookmark comment.
	 */
	public BookmarkEditCmd(Address addr, String type, String category, String comment) {
		this.type = type;
		this.category = category;
		this.comment = comment;
		this.addr = addr;
		if (addr == null || type == null || type.length() == 0)
			throw new IllegalArgumentException();
		presentationName = "Add " + type + " Bookmark";
	}

	public BookmarkEditCmd(Bookmark bookmark, String category, String comment) {
		this.bookmark = bookmark;
		this.category = category;
		this.comment = comment;
		if (bookmark == null)
			throw new IllegalArgumentException();
		presentationName = "Edit " + bookmark.getTypeString() + " Bookmark";
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

		if (bookmark != null) {
			bookmark.set(category, comment);
		}
		else if (addr != null) {
			mgr.setBookmark(addr, type, category, comment);
		}
		else {
			AddressRangeIterator rangeIter = set.getAddressRanges();
			while (rangeIter.hasNext()) {
				Address minAddr = rangeIter.next().getMinAddress();
				mgr.setBookmark(minAddr, type, category, comment);
			}
		}
		return true;
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
