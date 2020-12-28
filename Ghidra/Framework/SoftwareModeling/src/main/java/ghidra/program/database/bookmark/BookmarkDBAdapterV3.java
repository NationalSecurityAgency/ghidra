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

import java.io.IOException;
import java.util.HashSet;

import db.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.program.model.address.*;
import ghidra.util.exception.VersionException;

public class BookmarkDBAdapterV3 extends BookmarkDBAdapter {

	static final int TYPE_ID_OFFSET = 48;

	static final int V3_ADDRESS_COL = 0;
	static final int V3_CATEGORY_COL = 1;
	static final int V3_COMMENT_COL = 2;

	static final int VERSION = 3;
	static final Schema V3_SCHEMA = new Schema(VERSION, "ID",
		new Field[] { LongField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE },
		new String[] { "Address", "Category", "Comment" });

	static int[] INDEXED_COLUMNS = new int[] { V3_ADDRESS_COL, V3_CATEGORY_COL };

	private DBHandle dbHandle;
	private Table[] tables;
	private AddressMap addressMap;

	public BookmarkDBAdapterV3(DBHandle handle, boolean create, int[] typeIDs, AddressMap addrMap)
			throws VersionException, IOException {
		this.addressMap = addrMap;
		dbHandle = handle;
		if (typeIDs.length > 0) {
			tables = new Table[typeIDs[typeIDs.length - 1] + 1];
		}
		else {
			tables = new Table[0];
		}
		if (create) {
			for (int i = 0; i < typeIDs.length; i++) {
				int id = typeIDs[i];
				tables[id] =
					handle.createTable(BOOKMARK_TABLE_NAME + id, V3_SCHEMA, INDEXED_COLUMNS);
			}
		}
		else {
			Table bmt = handle.getTable(BOOKMARK_TABLE_NAME);
			if (bmt != null && bmt.getRecordCount() != 0) {
				// Previous version improperly upgraded and left this empty table behind empty
				throw new VersionException(true);
			}
			if (handle.getTable(BookmarkTypeDBAdapter.TABLE_NAME) == null) {
				// Indicates use of Bookmark Properties
				throw new VersionException(true);
			}
			else if (typeIDs.length != 0) {
				for (int i = 0; i < typeIDs.length; i++) {
					int id = typeIDs[i];
					tables[id] = handle.getTable(BOOKMARK_TABLE_NAME + id);
				}
				boolean noTables = (tables[typeIDs[0]] == null);
				int version = noTables ? -1 : tables[typeIDs[0]].getSchema().getVersion();
				for (int i = 1; i < typeIDs.length; i++) {
					int id = typeIDs[i];
					if (noTables) {
						if (tables[id] != null) {
							throw new IOException("Missing bookmark table");
						}
					}
					else if (tables[id].getSchema().getVersion() != version) {
						throw new IOException("Inconsistent bookmark table versions");
					}
				}
				if (noTables) {
					throw new VersionException(true);
				}
				else if (version != VERSION) {
					throw new VersionException(false);
				}
			}
		}
	}

	private Table getTable(long id) {
		int tableID = (int) (id >> TYPE_ID_OFFSET);
		if (tableID >= tables.length) {
			return null;
		}
		return tables[tableID];
	}

	@Override
	DBRecord getRecord(long id) throws IOException {
		Table table = getTable(id);
		if (table == null) {
			return null;
		}
		return table.getRecord(id);
	}

	@Override
	RecordIterator getRecordsByTypeAndCategory(int typeID, String category) throws IOException {
		Field field = new StringField(category);
		return getIndexIterator(typeID, V3_CATEGORY_COL, field, field);
	}

	private RecordIterator getAddressIndexIterator(int typeID, Field fieldStart, boolean forward)
			throws IOException {
		if (!hasTable(typeID)) {
			return new EmptyRecordIterator();
		}

		return forward ? tables[typeID].indexIteratorBefore(V3_ADDRESS_COL, fieldStart)
				: tables[typeID].indexIteratorAfter(V3_ADDRESS_COL, fieldStart);
	}

	private RecordIterator getIndexIterator(int typeID, int columnIndex, Field fieldStart,
			Field fieldEnd) throws IOException {
		if (!hasTable(typeID)) {
			return new EmptyRecordIterator();
		}

		return tables[typeID].indexIterator(columnIndex, fieldStart, fieldEnd, true);
	}

	private RecordIterator getIterator(int typeID) throws IOException {
		if (!hasTable(typeID)) {
			return new EmptyRecordIterator();
		}

		return tables[typeID].iterator();
	}

	@Override
	RecordIterator getRecordsByType(int typeID) throws IOException {
		return getIterator(typeID);
	}

	@Override
	String[] getCategories(int typeID) throws IOException {
		HashSet<String> set = new HashSet<String>();
		RecordIterator it = getIterator(typeID);
// TODO: This is very inefficient but is just as fast as using the index iterator
// Employing a separate category table would be faster
		while (it.hasNext()) {
			DBRecord rec = it.next();
			String cat = rec.getString(V3_CATEGORY_COL);
			if (cat != null && cat.length() != 0) {
				set.add(cat);
			}
		}
		String[] strings = new String[set.size()];
		return set.toArray(strings);
	}

	@Override
	AddressSetView getBookmarkAddresses(int typeID) throws IOException {
		AddressSet set = new AddressSet();
		RecordIterator recordIter = getRecordsByType(typeID);
		while (recordIter.hasNext()) {
			DBRecord rec = recordIter.next();
			Address addr = addressMap.decodeAddress(rec.getLongValue(V3_ADDRESS_COL));
			set.addRange(addr, addr);
		}
		return set;
	}

	@Override
	int getBookmarkCount(int typeID) {
		if (!hasTable(typeID)) {
			return 0;
		}
		return tables[typeID].getRecordCount();
	}

	@Override
	int getBookmarkCount() {
		int cnt = 0;
		for (int i = 0; i < tables.length; i++) {
			cnt += getBookmarkCount(i);
		}
		return cnt;
	}

	@Override
	DBRecord createBookmark(int typeID, String category, long index, String comment)
			throws IOException {
		if (!hasTable(typeID)) {
			return null;
		}

		Table table = tables[typeID];
		long nextId = table.getKey() + 1;
		long id = ((long) typeID << TYPE_ID_OFFSET) | nextId;

		DBRecord rec = V3_SCHEMA.createRecord(id);
		rec.setLongValue(V3_ADDRESS_COL, index);
		rec.setString(V3_CATEGORY_COL, category);
		rec.setString(V3_COMMENT_COL, comment);
		table.putRecord(rec);
		return rec;
	}

	@Override
	void deleteRecord(long id) throws IOException {
		Table table = getTable(id);
		table.deleteRecord(id);
	}

	@Override
	void updateRecord(DBRecord rec) throws IOException {
		Table table = getTable(rec.getKey());
		table.putRecord(rec);
	}

	@Override
	RecordIterator getRecordsByTypeAtAddress(int typeID, long address) throws IOException {
		Field field = new LongField(address);
		return getIndexIterator(typeID, V3_ADDRESS_COL, field, field);
	}

	@Override
	RecordIterator getRecordsByTypeStartingAtAddress(int typeID, long startAddress, boolean forward)
			throws IOException {
		Field start = new LongField(startAddress);
		return getAddressIndexIterator(typeID, start, forward);
	}

	@Override
	RecordIterator getRecordsByTypeForAddressRange(int typeID, long startAddr, long endAddr)
			throws IOException {
		Field start = new LongField(startAddr);
		Field end = new LongField(endAddr);
		return getIndexIterator(typeID, V3_ADDRESS_COL, start, end);
	}

	@Override
	void addType(int typeID) throws IOException {
		if (typeID >= tables.length) {
			Table[] newTables = new Table[typeID + 1];
			System.arraycopy(tables, 0, newTables, 0, tables.length);
			tables = newTables;
		}
		if (tables[typeID] == null) {
			tables[typeID] = dbHandle.getTable(BOOKMARK_TABLE_NAME + typeID);
			if (tables[typeID] == null) {
				tables[typeID] =
					dbHandle.createTable(BOOKMARK_TABLE_NAME + typeID, V3_SCHEMA, INDEXED_COLUMNS);
			}
		}
	}

	@Override
	void deleteType(int typeID) throws IOException {
		if (tables[typeID] != null) {
			dbHandle.deleteTable(BOOKMARK_TABLE_NAME + typeID);
			tables[typeID] = null;
		}
	}

	@Override
	public boolean hasTable(int typeID) {
		if (typeID < 0 || typeID >= tables.length) {
			return false;
		}
		return tables[typeID] != null;
	}

	@Override
	Table getTable(int typeID) {
		if (typeID < 0 || typeID >= tables.length) {
			return null;
		}
		return tables[typeID];
	}

	@Override
	void reloadTables() {
		for (int i = 0; i < tables.length; i++) {
			tables[i] = dbHandle.getTable(BOOKMARK_TABLE_NAME + i);
		}
	}
}
