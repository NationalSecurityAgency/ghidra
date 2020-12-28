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
package ghidra.trace.database.bookmark;

import com.google.common.collect.Range;

import db.DBRecord;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Bookmark;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.Trace.TraceBookmarkChangeType;
import ghidra.trace.model.bookmark.TraceBookmark;
import ghidra.trace.model.bookmark.TraceBookmarkType;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceBookmark extends AbstractDBTraceAddressSnapRangePropertyMapData<DBTraceBookmark>
		implements TraceBookmark {
	protected static final String TABLE_NAME = "Bookmarks";

	static final String TYPE_COLUMN_NAME = "Type";
	static final String CATEGORY_COLUMN_NAME = "Category";
	static final String COMMENT_COLUMN_NAME = "Comment";

	@DBAnnotatedColumn(TYPE_COLUMN_NAME)
	static DBObjectColumn TYPE_COLUMN;
	@DBAnnotatedColumn(CATEGORY_COLUMN_NAME)
	static DBObjectColumn CATEGORY_COLUMN;
	@DBAnnotatedColumn(COMMENT_COLUMN_NAME)
	static DBObjectColumn COMMENT_COLUMN;

	static String tableName(AddressSpace space, long threadKey, int frameLevel) {
		return DBTraceUtils.tableName(TABLE_NAME, space, threadKey, frameLevel);
	}

	@DBAnnotatedField(column = TYPE_COLUMN_NAME, indexed = true)
	private String typeName;
	@DBAnnotatedField(column = CATEGORY_COLUMN_NAME)
	private String category;
	@DBAnnotatedField(column = COMMENT_COLUMN_NAME)
	private String comment;

	protected final DBTraceBookmarkSpace space;

	public DBTraceBookmark(DBTraceBookmarkSpace space,
			DBTraceAddressSnapRangePropertyMapTree<DBTraceBookmark, ?> tree,
			DBCachedObjectStore<?> store, DBRecord record) {
		super(tree, store, record);
		this.space = space;
	}

	@Override
	protected void setRecordValue(DBTraceBookmark value) {
		// Meh. The manager will populate the data
	}

	@Override
	protected DBTraceBookmark getRecordValue() {
		return this;
	}

	void set(String typeName, String category, String comment) {
		this.typeName = typeName;
		this.category = category;
		this.comment = comment;
		update(TYPE_COLUMN, CATEGORY_COLUMN, COMMENT_COLUMN);
	}

	@Override
	public void setLifespan(Range<Long> lifespan) {
		doSetLifespan(lifespan);
	}

	@Override
	public DBTrace getTrace() {
		return space.trace;
	}

	@Override
	public DBTraceThread getThread() {
		return space.getThread();
	}

	@Override
	public long getId() {
		return DBTraceBookmarkManager.packId(key, space);
	}

	@Override
	public Address getAddress() {
		return range.getMinAddress();
	}

	@Override
	public TraceBookmarkType getType() {
		return space.manager.getOrDefineBookmarkType(typeName);
	}

	@Override
	public String getTypeString() {
		return typeName;
	}

	@Override
	public String getCategory() {
		return category;
	}

	@Override
	public String getComment() {
		return comment;
	}

	@Override
	public void set(String category, String comment) {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			this.category = category;
			this.comment = comment;
			update(CATEGORY_COLUMN, COMMENT_COLUMN);
		}
		space.trace.setChanged(
			new TraceChangeRecord<>(TraceBookmarkChangeType.CHANGED, space, this));
	}

	@Override
	public void delete() {
		space.bookmarkMapSpace.deleteData(this);
		space.trace.setChanged(
			new TraceChangeRecord<>(TraceBookmarkChangeType.DELETED, space, this));
	}

	@Override
	public int compareTo(Bookmark o) {
		if (!(o instanceof TraceBookmark)) {
			throw new IllegalArgumentException(
				"Can compare only to another " + TraceBookmark.class.getSimpleName());
		}
		TraceBookmark that = (TraceBookmark) o;
		int result;
		result = DBTraceUtils.compareRanges(this.getLifespan(), that.getLifespan());
		if (result != 0) {
			return result;
		}
		result = this.getAddress().compareTo(that.getAddress());
		if (result != 0) {
			return result;
		}
		result = this.getTypeString().compareTo(that.getTypeString());
		if (result != 0) {
			return result;
		}
		result = this.getComment().compareTo(that.getComment());
		if (result != 0) {
			return result;
		}
		return 0;
	}

	@Override
	public String toString() {
		return "<TraceBookmark: " + typeName + "(" + category + "): " + comment + ">";
	}
}
