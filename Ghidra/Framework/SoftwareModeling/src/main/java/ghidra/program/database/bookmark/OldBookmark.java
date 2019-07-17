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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

/**
 * 
 */
public class OldBookmark implements Saveable {

//TODO: This class and its constructors should not be public

	private String type;
	private String category;
	private String comment;
	private Address addr;
	private String addrString;

	/**
	 * Constructs a copy of a Bookmark at a new address.
	 * @param info
	 * @param addr
	 */
	OldBookmark(OldBookmark info, Address addr) {
		this.type = info.getType();
		this.addr = addr;
		this.category = info.getCategory();
		this.comment = info.getComment();
	}

	/**
	 * Constructs a Bookmark.
	 * @param type
	 * @param category
	 * @param comment
	 * @param addr
	 */
	public OldBookmark(String type, String category, String comment, Address addr) {
		if (addr == null) {
			throw new IllegalArgumentException("Bookmark address required");
		}
		this.type = type != null ? type : BookmarkType.NOTE;
		this.category = category;
		this.comment = comment;
		this.addr = addr;
	}

	/**
	 * Constructs a Note Bookmark (required for Saveable property objects).
	 * Contains no address.
	 */
	public OldBookmark() {
		type = "";
		category = "";
		comment = "";
	}

	void setContext(Program program, String type) {
		this.type = type;
		if (addrString != null) {
			addr = program.parseAddress(addrString)[0];
			addrString = null;
		}
	}

	public String getType() {
		return type;
	}

	public String getCategory() {
		return category;
	}

	public void setCategory(String category) {
		this.category = category;
	}

	public String getComment() {
		return comment;
	}

	public void setComment(String comment) {
		this.comment = comment;
	}

	/**
	 * Get the address of this bookmark info.
	 * 
	 * @return Address
	 */
	public Address getAddress() {
		return addr;
	}

	/**
	 * Return true if this object is the same as obj.
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (this == obj) {
			return true;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		OldBookmark bookmark = (OldBookmark) obj;
		boolean addrsEqual = false;
		if (addr == null || bookmark.addr == null) {
			if (!addrString.equals(bookmark.addrString)) {
				return false;
			}
			addrsEqual = true;
		}
		else {
			if (addr.getClass() != bookmark.addr.getClass()) {
				return false;
			}
			addrsEqual = addr.equals(bookmark.addr);
		}

		return comment.equals(bookmark.comment) && category.equals(bookmark.category) &&
			type.equals(bookmark.type) && addrsEqual;
	}

	/**
	 * @see Saveable#restore(ObjectStorage)
	 */
	@Override
	public void restore(ObjectStorage objStorage) {
		category = objStorage.getString();
		comment = objStorage.getString();
		addrString = objStorage.getString();
	}

	/**
	 * @see Saveable#save(ObjectStorage)
	 */
	@Override
	public void save(ObjectStorage objStorage) {
		objStorage.putString(category);
		objStorage.putString(comment);
		if (addr != null) {
			addrString = addr.toString();
		}
		objStorage.putString(addrString);
	}

	@Override
	public Class<?>[] getObjectStorageFields() {
		return new Class<?>[] { String.class, String.class, String.class };
	}

	/*
	 * @see ghidra.util.Saveable#getSchemaVersion()
	 */
	@Override
	public int getSchemaVersion() {
		return 0;
	}

	/*
	 * @see ghidra.util.Saveable#isUpgradeable(int)
	 */
	@Override
	public boolean isUpgradeable(int oldSchemaVersion) {
		return false;
	}

	/*
	 * @see ghidra.util.Saveable#upgrade(ghidra.util.ObjectStorage, int, ghidra.util.ObjectStorage)
	 */
	@Override
	public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion,
			ObjectStorage currentObjStorage) {

		return false;
	}

	@Override
	public boolean isPrivate() {
		return false;
	}
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return category + "/" + comment;
	}

}
