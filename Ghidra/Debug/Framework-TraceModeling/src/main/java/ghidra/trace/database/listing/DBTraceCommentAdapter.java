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
package ghidra.trace.database.listing;

import java.io.IOException;
import java.util.concurrent.locks.ReadWriteLock;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.Range;

import db.DBHandle;
import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.CodeUnit;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.listing.DBTraceCommentAdapter.DBTraceCommentEntry;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMap;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.DBTraceSpaceKey;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.Trace.TraceCommentChangeType;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceCommentAdapter
		extends DBTraceAddressSnapRangePropertyMap<DBTraceCommentEntry, DBTraceCommentEntry> {
	protected static final String[] EMPTY_STRING_ARRAY = new String[] {};
	protected static final int MIN_COMMENT_TYPE = CodeUnit.EOL_COMMENT;
	protected static final int MAX_COMMENT_TYPE = CodeUnit.REPEATABLE_COMMENT;

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBTraceCommentEntry
			extends AbstractDBTraceAddressSnapRangePropertyMapData<DBTraceCommentEntry> {
		static final String TYPE_COLUMN_NAME = "Type";
		static final String COMMENT_COLUMN_NAME = "Comment";

		@DBAnnotatedColumn(TYPE_COLUMN_NAME)
		static DBObjectColumn TYPE_COLUMN;
		@DBAnnotatedColumn(COMMENT_COLUMN_NAME)
		static DBObjectColumn COMMENT_COLUMN;

		@DBAnnotatedField(column = TYPE_COLUMN_NAME)
		byte type;
		@DBAnnotatedField(column = COMMENT_COLUMN_NAME)
		String comment;

		public DBTraceCommentEntry(
				DBTraceAddressSnapRangePropertyMapTree<DBTraceCommentEntry, ?> tree,
				DBCachedObjectStore<?> store, DBRecord record) {
			super(tree, store, record);
		}

		@Override
		protected void setRecordValue(DBTraceCommentEntry value) {
			// Nothing: record is value
		}

		@Override
		protected DBTraceCommentEntry getRecordValue() {
			return this;
		}

		void set(byte type, String comment) {
			this.type = type;
			this.comment = comment;
			update(TYPE_COLUMN, COMMENT_COLUMN);
		}

		void setLifespan(Range<Long> lifespan) {
			super.doSetLifespan(lifespan);
		}

		public int getType() {
			return type;
		}
	}

	public DBTraceCommentAdapter(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager) throws IOException, VersionException {
		super("Comments", dbh, openMode, lock, monitor, baseLanguage, trace, threadManager,
			DBTraceCommentEntry.class, DBTraceCommentEntry::new);
	}

	protected void makeWay(DBTraceCommentEntry entry, Range<Long> span) {
		DBTraceUtils.makeWay(entry, span, (e, s) -> e.setLifespan(s), e -> deleteData(e));
	}

	public void setComment(Range<Long> lifespan, Address address, int commentType, String comment) {
		if (commentType < MIN_COMMENT_TYPE || commentType > MAX_COMMENT_TYPE) {
			throw new IllegalArgumentException("commentType");
		}
		String oldValue = null;
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			for (DBTraceCommentEntry entry : reduce(TraceAddressSnapRangeQuery.intersecting(
				new AddressRangeImpl(address, address), lifespan)).values()) {
				if (entry.type == commentType) {
					if (lifespan.hasLowerBound() &&
						entry.getLifespan().contains(lifespan.lowerEndpoint())) {
						oldValue = entry.comment;
					}
					makeWay(entry, lifespan);
				}
			}
			if (comment != null) {
				DBTraceCommentEntry entry = put(address, lifespan, null);
				entry.set((byte) commentType, comment);
			}
		}
		trace.setChanged(new TraceChangeRecord<TraceAddressSnapRange, String>(
			TraceCommentChangeType.byType(commentType),
			DBTraceSpaceKey.create(address.getAddressSpace(), null, 0),
			new ImmutableTraceAddressSnapRange(address, lifespan),
			oldValue, comment));
	}

	public static String commentFromArray(String[] comment) {
		return comment == null || comment.length == 0 ? null : StringUtils.join(comment, '\n');
	}

	public static String[] arrayFromComment(String comment) {
		return comment == null || comment.length() == 0 ? EMPTY_STRING_ARRAY : comment.split("\n");
	}

	public String getComment(long snap, Address address, int commentType) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (DBTraceCommentEntry entry : reduce(
				TraceAddressSnapRangeQuery.at(address, snap)).values()) {
				if (entry.type != commentType) {
					continue;
				}
				return entry.comment;
			}
			return null;
		}
	}

	/**
	 * TODO: Document me
	 * 
	 * @param span
	 * @param range
	 * @param commentType a comment type to clear, or {@link CodeUnit#NO_COMMENT} to clear all.
	 */
	public void clearComments(Range<Long> span, AddressRange range, int commentType) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			for (DBTraceCommentEntry entry : reduce(
				TraceAddressSnapRangeQuery.intersecting(range, span)).values()) {
				if (commentType == CodeUnit.NO_COMMENT || entry.type == commentType) {
					makeWay(entry, span);
				}
			}
		}
	}

	@Override
	public DBTraceCommentEntry put(TraceAddressSnapRange shape, DBTraceCommentEntry value) {
		assert shape.getRange().getLength() == 1;
		return super.put(shape, value);
	}
}
