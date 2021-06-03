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

import db.*;
import ghidra.util.exception.VersionException;

abstract class BookmarkTypeDBAdapter {

	static final String TABLE_NAME = "Bookmark Types";

	static final int TYPE_NAME_COL = 0;

	static final Schema SCHEMA =
		new Schema(0, "ID", new Field[] { StringField.INSTANCE }, new String[] { "Name" });

	static BookmarkTypeDBAdapter getAdapter(DBHandle dbHandle, int openMode)
			throws VersionException, IOException {
		if (openMode == DBConstants.CREATE) {
			return new BookmarkTypeDBAdapterV0(dbHandle, true);
		}

		try {
			return new BookmarkTypeDBAdapterV0(dbHandle, false);
		}
		catch (VersionException e) {
			if (openMode == DBConstants.UPDATE) {
				throw e;
			}
			BookmarkTypeDBAdapter adapter = findReadOnlyAdapter(dbHandle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(dbHandle, adapter);
			}
			return adapter;
		}
	}

	@SuppressWarnings("unused")
	private static BookmarkTypeDBAdapter findReadOnlyAdapter(DBHandle dbHandle)
			throws VersionException, IOException {
		return new BookmarkTypeDBAdapterNoTable(dbHandle);
	}

	private static BookmarkTypeDBAdapter upgrade(DBHandle dbHandle,
			BookmarkTypeDBAdapter oldAdapter) throws VersionException, IOException {
		return new BookmarkTypeDBAdapterV0(dbHandle, true);
	}

	/**
	 * Allocate a new bookmark type
	 * @param typeId type id
	 * @param type type string
	 * @throws IOException
	 */
	void addType(int typeID, String type) throws IOException {
		throw new UnsupportedOperationException("Bookmarks are read-only and may not be added");
	}

	/**
	 * Delete a bookmark type
	 * @param typeId type ID
	 * @throws IOException
	 */
	void deleteRecord(long typeId) throws IOException {
		throw new UnsupportedOperationException("Bookmarks are read-only and may not be deleted");
	}

	/**
	 * Get all bookmark type records.
	 * @return array of records
	 * @throws IOException
	 */
	abstract DBRecord[] getRecords() throws IOException;

	public int[] getTypeIds() throws IOException {
		DBRecord[] typeRecords = getRecords();
		int[] ids = new int[typeRecords.length];
		for (int i = 0; i < typeRecords.length; i++) {
			DBRecord rec = typeRecords[i];
			ids[i] = (int) rec.getKey();
		}
		return ids;
	}
}
