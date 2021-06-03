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

import db.DBRecord;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;

/**
 * 
 */
public class BookmarkDB extends DatabaseObject implements Bookmark {

	private BookmarkDBManager mgr;
	private DBRecord record;

	BookmarkDB(BookmarkDBManager mgr, DBObjectCache<BookmarkDB> cache, DBRecord record) {
		super(cache, record.getKey());
		this.mgr = mgr;
		this.record = record;
	}

	@Override
	public String toString() {
		return getTypeString() + " - " + getCategory() + " - " + getComment() + " - " +
			getAddress();
	}

	/**
	 * Update associated record
	 * @param rec
	 */
	void setRecord(DBRecord rec) {
		if (rec.getKey() != key) {
			throw new IllegalArgumentException("Key mismatch");
		}
		record = rec;
	}

	@Override
	public long getId() {
		return key;
	}

	@Override
	public Address getAddress() {
		checkIsValid();
		return mgr.getAddress(record.getLongValue(BookmarkDBAdapter.ADDRESS_COL));
	}

	/**
	 * Returns bookmark type or null if type has been removed.
	 */
	@Override
	public BookmarkType getType() {
		return mgr.getBookmarkType((int) (key >> BookmarkDBAdapterV3.TYPE_ID_OFFSET));
	}

	@Override
	public String getTypeString() {
		return getType().getTypeString();
	}

	@Override
	public String getCategory() {
		return record.getString(BookmarkDBAdapter.CATEGORY_COL);
	}

	public void setComment(String comment) {
		checkDeleted();
		if (comment == null)
			comment = "";

		if (!comment.equals(record.getString(BookmarkDBAdapter.COMMENT_COL))) {
			record.setString(BookmarkDBAdapter.COMMENT_COL, comment);
			mgr.bookmarkChanged(this);
		}
	}

	@Override
	public String getComment() {
		return record.getString(BookmarkDBAdapter.COMMENT_COL);
	}

	@Override
	public void set(String category, String comment) {
		checkDeleted();

		if (category == null)
			category = "";
		if (comment == null)
			comment = "";
		if (!comment.equals(record.getString(BookmarkDBAdapter.COMMENT_COL)) ||
			!category.equals(record.getString(BookmarkDBAdapter.CATEGORY_COL))) {

			record.setString(BookmarkDBAdapter.CATEGORY_COL, category);
			record.setString(BookmarkDBAdapter.COMMENT_COL, comment);
			mgr.bookmarkChanged(this);
		}
	}

	@Override
	protected boolean refresh() {
		return refresh(null);
	}

	@Override
	protected boolean refresh(DBRecord rec) {
		if (rec == null) {
			rec = mgr.getRecord(key);
		}
		if (rec == null) {
			return false;
		}
		record = rec;
		return true;
	}

	/**
	 * Returns record associated with this bookmark or
	 * null if bookmark has been deleted.
	 */
	DBRecord getRecord() {
		return checkIsValid() ? record : null;
	}

	/*
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return (int) key;
	}

	/* (non-Javadoc)
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(Bookmark otherBm) {
		int rc = getAddress().compareTo(otherBm.getAddress());
		if (rc != 0) {
			return rc;
		}
		rc = getTypeString().compareTo(otherBm.getTypeString());
		if (rc != 0) {
			return rc;
		}
		rc = getCategory().compareTo(otherBm.getCategory());
		if (rc != 0) {
			return rc;
		}
		return getComment().compareTo(otherBm.getComment());
	}

}
