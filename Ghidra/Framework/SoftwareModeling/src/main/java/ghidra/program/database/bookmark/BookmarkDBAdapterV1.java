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

import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.util.exception.VersionException;

import java.io.IOException;
import java.util.*;

import db.*;

/**
 * 
 */
class BookmarkDBAdapterV1 extends BookmarkDBAdapter {

	static final int VERSION = 1;

	static final int V1_ADDRESS_COL = 0;
	static final int V1_TYPE_ID_COL = 1;
	static final int V1_TYPE_CATEGORY_COL = 2; // mangled column to improve indexing
	static final int V1_COMMENT_COL = 3;

//	private static final Schema SCHEMA = new Schema(VERSION,"ID", 
//							new Class[] {LongField.class, LongField.class, 
//										 StringField.class, StringField.class},
//							new String[] {"Address", "Type ID", "Type ID/Category", "Comment"});

//	private static int[] INDEXED_COLUMNS = new int[] { V1_ADDRESS_COL, V1_TYPE_ID_COL, V1_TYPE_CATEGORY_COL };

	protected Table table;
	protected AddressMap addrMap;

	/**
	 * Constructor (used by BookmarkDBAdapterV2)
	 */
	BookmarkDBAdapterV1() {
	}

	/**
	 * Constructor (Read-Only access)
	 * @param dbHandle
	 * @throws VersionException
	 */
	BookmarkDBAdapterV1(DBHandle dbHandle, AddressMap addrMap) throws VersionException {
		this.addrMap = addrMap.getOldAddressMap();
		table = dbHandle.getTable(BOOKMARK_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + BOOKMARK_TABLE_NAME);
		}
		else if (table.getSchema().getVersion() != VERSION) {
			throw new VersionException("Expected version " + VERSION + " for table " +
				BOOKMARK_TABLE_NAME + " but got " + table.getSchema().getVersion());
		}
	}

	@Override
	AddressSetView getBookmarkAddresses(int typeId) throws IOException {
		AddressSet set = new AddressSet();
		RecordIterator recordIter = getRecordsByType(typeId);
		while (recordIter.hasNext()) {
			DBRecord rec = recordIter.next();
			Address addr = addrMap.decodeAddress(rec.getLongValue(V1_ADDRESS_COL));
			set.addRange(addr, addr);
		}
		return set;
	}

	@Override
	String[] getCategories(int typeId) throws IOException {
		HashSet<String> set = new HashSet<String>();
		Field fv = new LongField(typeId);
		RecordIterator recordIter = table.indexIterator(V1_TYPE_ID_COL, fv, fv, true);
		while (recordIter.hasNext()) {
			DBRecord rec = recordIter.next();
			String cat = demangleTypeCategory(rec.getString(V1_TYPE_CATEGORY_COL));
			set.add(cat);
		}
		String[] categories = new String[set.size()];
		set.toArray(categories);
		Arrays.sort(categories);
		return categories;
	}

	@Override
	DBRecord getRecord(long id) throws IOException {
		return convertV1Record(table.getRecord(id));
	}

	private static DBRecord convertV1Record(DBRecord record) {
		long key = record.getLongValue(V1_TYPE_ID_COL) << 48 | (record.getKey() & 0xffffffffL);
		DBRecord rec = BookmarkDBAdapter.SCHEMA.createRecord(key);
		rec.setLongValue(BookmarkDBAdapter.ADDRESS_COL, record.getLongValue(V1_ADDRESS_COL));
		rec.setString(BookmarkDBAdapter.CATEGORY_COL,
			demangleTypeCategory(record.getString(V1_TYPE_CATEGORY_COL)));
		rec.setString(BookmarkDBAdapter.COMMENT_COL, record.getString(V1_COMMENT_COL));

		return rec;
	}

	@Override
	RecordIterator getRecordsByType(int typeId) throws IOException {
		return new V1ConvertedRecordIterator(table.iterator());
	}

	@Override
	RecordIterator getRecordsByTypeAndCategory(int typeId, String category) throws IOException {
		RecordIterator recordIter;
		if (category == null) {
			Field fv = new LongField(typeId);
			recordIter = table.indexIterator(V1_TYPE_ID_COL, fv, fv, true);
		}
		else {
			Field fv = new StringField(mangleTypeCategory(typeId, category));
			recordIter = table.indexIterator(V1_TYPE_CATEGORY_COL, fv, fv, true);
		}
		return new V1ConvertedRecordIterator(recordIter);
	}

	@Override
	int getBookmarkCount(int typeId) {
		int cnt = 0;
		try {
			Field f = new LongField(typeId);
			RecordIterator it = table.indexIterator(V1_TYPE_ID_COL, f, f, true);
			while (it.hasNext()) {
				it.next();
				cnt++;
			}
		}
		catch (IOException e) {
			// return 0
		}
		return cnt;
	}

	@Override
	int getBookmarkCount() {
		return table.getRecordCount();
	}

	@Override
	RecordIterator getRecordsByTypeAtAddress(int typeId, long address) throws IOException {
		return getRecordsByTypeForAddressRange(typeId, address, address);
	}

	@Override
	RecordIterator getRecordsByTypeStartingAtAddress(int typeID, long startAddress, boolean forward)
			throws IOException {
		throw new UnsupportedOperationException(); // they tell me that this class is too old to care
	}

	@Override
	RecordIterator getRecordsByTypeForAddressRange(int typeId, long startAddr, long endAddr)
			throws IOException {
		return new BatchRecordIterator(typeId, startAddr, endAddr);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class BatchRecordIterator implements RecordIterator {
		private ListIterator<DBRecord> iter;

		BatchRecordIterator(int typeId, long start, long end) throws IOException {
			ArrayList<DBRecord> list = new ArrayList<DBRecord>();
			Field sf = new LongField(start);
			Field ef = new LongField(end);
			RecordIterator recIter = table.indexIterator(V1_ADDRESS_COL, sf, ef, true);
			while (recIter.hasNext()) {
				list.add(convertV1Record(recIter.next()));
			}
			iter = list.listIterator();
		}

		@Override
		public boolean hasNext() throws IOException {
			return iter.hasNext();
		}

		@Override
		public boolean hasPrevious() throws IOException {
			return iter.hasPrevious();
		}

		@Override
		public DBRecord next() throws IOException {
			return iter.next();
		}

		@Override
		public DBRecord previous() throws IOException {
			return iter.previous();
		}

		@Override
		public boolean delete() throws IOException {
			throw new UnsupportedOperationException();
		}
	}

	private static class V1ConvertedRecordIterator extends ConvertedRecordIterator {

		V1ConvertedRecordIterator(RecordIterator originalIterator) {
			super(originalIterator, false);
		}

		@Override
		protected DBRecord convertRecord(DBRecord record) {
			return convertV1Record(record);
		}
	}
}
