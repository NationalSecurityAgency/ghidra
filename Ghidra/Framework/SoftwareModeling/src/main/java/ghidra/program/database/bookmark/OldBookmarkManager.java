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
package ghidra.program.database.bookmark;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.*;
import ghidra.util.exception.DuplicateNameException;

import java.util.*;

import db.DBRecord;

/**
 * Interface to manage bookmarks on a program.
 */
class OldBookmarkManager {

	public static final String OLD_BOOKMARK_PROPERTY = "Bookmarks";

	private static final String BASE_PROPERTY_NAME = OLD_BOOKMARK_PROPERTY;
	private static final EmptyAddressIterator emptyAddressIterator = new EmptyAddressIterator();

	private Program program;
	private PropertyMapManager propertyMgr;

	private HashMap<String, DBRecord> bookmarkTypes = new HashMap<String, DBRecord>();  // maps type to record

//	private ArrayList bookmarks = new ArrayList();
//	private LongIntHashedList bookmarkAddrIndex = new LongIntHashedList();

	/**
	 * Constructs a new bookmark manager.
	 */
	OldBookmarkManager(ProgramDB program) {
		this.program = program;
		propertyMgr = program.getUsrPropertyManager();

		// Create type records
		String[] types = getTypes();
		for (int i = 0; i < types.length; i++) {
			DBRecord rec = BookmarkTypeDBAdapter.SCHEMA.createRecord(i);
			rec.setString(BookmarkTypeDBAdapter.TYPE_NAME_COL, types[i]);
			bookmarkTypes.put(types[i], rec);
		}
	}

	/**
	 * Get the bookmark type associated with the specified property name.
	 * @param propertyName
	 * @return bookmark type or null if property name is not recognized.
	 */
	private static String getBookmarkType(String propertyName) {
		if (propertyName == null) {
			return null;
		}
		if (propertyName.startsWith(BASE_PROPERTY_NAME)) {
			int baseLen = BASE_PROPERTY_NAME.length();
			if (propertyName.length() == baseLen) {
				return BookmarkType.NOTE;
			}
			return propertyName.substring(baseLen);
		}
		return null;
	}

	/**
	 * Get the bookmark property name for a specified bookmark type.
	 * @param bookmarkType
	 * @return property used to store bookmarks or null if a
	 * null type was specified.
	 */
	private static String getPropertyName(String bookmarkType) {
		if (bookmarkType == null) {
			return null;
		}
		if (BookmarkType.NOTE.equals(bookmarkType)) {
			return BASE_PROPERTY_NAME;
		}
		return BASE_PROPERTY_NAME + bookmarkType;
	}

	private ObjectPropertyMap getMap(String type, boolean create) {
		String property = getPropertyName(type);
		ObjectPropertyMap map = null;
		map = propertyMgr.getObjectPropertyMap(property);
		if (map == null) {
			if (create) {
				try {
					map = propertyMgr.createObjectPropertyMap(property, OldBookmark.class);
				}
				catch (DuplicateNameException e) {
					throw new RuntimeException("Unexpected Error");
				}
			}
		}
		return map;
	}

	/**
	 * Return all the Bookmark types currenly in use.
	 */
	private String[] getTypes() {
		ArrayList<String> list = new ArrayList<String>();
		Iterator<String> iter = propertyMgr.propertyManagers();
		while (iter.hasNext()) {
			String property = iter.next();
			String type = getBookmarkType(property);
			if (type != null && !list.contains(type)) {
				try {
					propertyMgr.getObjectPropertyMap(property);
					list.add(type);
				}
				catch (TypeMismatchException e) {
				}
			}
		}
		String[] types = new String[list.size()];
		list.toArray(types);
		return types;
	}

	/**
	 * Get number of bookmarks for the specified type
	 * @param type
	 * @return bookmark count
	 */
	int getBookmarkCount(String type) {
		return propertyMgr.getObjectPropertyMap(getPropertyName(type)).getSize();
	}

	/**
	 * Remove all bookmarks of the specific type from the program.
	 * Caller is responsible for the transaction which incorporates this program change.
	 * @param type bookmark type
	 */
	void removeAllBookmarks(String type) {
		propertyMgr.removePropertyMap(getPropertyName(type));
	}

	/**
	 * Get a specific bookmark type at the specified address.
	 * @param addr program address
	 * @param type bookmark type
	 * @return bookmark or null if not found.
	 */
	OldBookmark getBookmark(Address addr, String type) {
		OldBookmark bookmark = null;
		ObjectPropertyMap map = getMap(type, false);
		if (map != null) {
			bookmark = (OldBookmark) map.getObject(addr);
			if (bookmark != null) {
				bookmark.setContext(program, type);
			}
		}
		return bookmark;
	}

	/**
	 * Get addresses at which bookmarks of the specified type exist.
	 * @param type bookmark type
	 * @return address iterator
	 */
	AddressIterator getBookmarkAddresses(String type) {
		ObjectPropertyMap map = getMap(type, false);
		if (map != null) {
			return map.getPropertyIterator();
		}
		return emptyAddressIterator;
	}

	/**
	 * Returns array of bookmark type records
	 */
	public DBRecord[] getTypeRecords() {
		Collection<DBRecord> c = bookmarkTypes.values();
		DBRecord[] recs = new DBRecord[c.size()];
		c.toArray(recs);
		return recs;
	}

}

class EmptyAddressIterator implements AddressIterator {

	/*
	 * @see ghidra.program.model.address.AddressIterator#next()
	 */
	@Override
	public Address next() {
		return null;
	}

	/*
	 * @see ghidra.program.model.address.AddressIterator#hasNext()
	 */
	@Override
	public boolean hasNext() {
		return false;
	}

	/*
	 * @see ghidra.program.model.address.AddressIterator#hasPrevious()
	 */
	public boolean hasPrevious() {
		return false;
	}

	/*
	 * @see ghidra.program.model.address.AddressIterator#previous()
	 */
	public Address previous() {
		return null;
	}

	/**
	 * @see java.util.Iterator#remove()
	 */
	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<Address> iterator() {
		return this;
	}
}
