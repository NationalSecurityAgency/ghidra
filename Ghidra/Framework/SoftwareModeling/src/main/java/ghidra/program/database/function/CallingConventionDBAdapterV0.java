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
package ghidra.program.database.function;

import java.io.IOException;

import db.*;
import ghidra.util.exception.VersionException;

/**
 * Version 0 implementation for the calling conventions tables adapter.
 * 
 */
class CallingConventionDBAdapterV0 extends CallingConventionDBAdapter {

	static final String CALLING_CONVENTION_TABLE_NAME = "Calling Conventions";

	// Calling Convention Columns
	// Key field is the Calling convention ID, which is a Byte field.
	static final int V0_CALLING_CONVENTION_NAME_COL = 0;

	static final Schema V0_CALLING_CONVENTION_SCHEMA = new Schema(0, ByteField.INSTANCE, "ID",
		new Field[] { StringField.INSTANCE }, new String[] { "Name" });

	private Table callingConventionTable;

	/**
	 * Constructor
	 * 
	 */
	public CallingConventionDBAdapterV0(DBHandle handle, boolean create)
			throws VersionException, IOException {

		if (create) {
			// No additional indexed fields.
			callingConventionTable = handle.createTable(CALLING_CONVENTION_TABLE_NAME,
				V0_CALLING_CONVENTION_SCHEMA, new int[] {});
		}
		else {
			callingConventionTable = handle.getTable(CALLING_CONVENTION_TABLE_NAME);
			if (callingConventionTable == null) {
				throw new VersionException(true);
			}
			if (callingConventionTable.getSchema().getVersion() != 0) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	public DBRecord createCallingConventionRecord(String name) throws IOException {
		byte key = getFirstAvailableKey();
		DBRecord record = V0_CALLING_CONVENTION_SCHEMA.createRecord(new ByteField(key));
		record.setString(V0_CALLING_CONVENTION_NAME_COL, name);
		callingConventionTable.putRecord(record);
		return record;
	}

	/**
	 * Get the first unused key value. Remember 0 is reserved for unknown and 1 for default.
	 * @return the first available key. This is a number for 2 to 255.
	 * @throws IOException if there are no more available keys.
	 */
	private byte getFirstAvailableKey() throws IOException {
		byte key = 2;
		for (; key < 256; key++) {
			DBRecord record = getCallingConventionRecord(key);
			if (record == null) {
				return key;
			}
		}
		if (key >= 256) {
			throw new IOException("No more keys available for calling conventions.");
		}
		return key;
	}

	@Override
	public DBRecord getCallingConventionRecord(byte callingConventionID) throws IOException {
		return callingConventionTable.getRecord(new ByteField(callingConventionID));
	}

	@Override
	public DBRecord getCallingConventionRecord(String name) throws IOException {
		RecordIterator iterator = callingConventionTable.iterator();
		while (iterator.hasNext()) {
			DBRecord record = iterator.next();
			String callingConventionName = record.getString(V0_CALLING_CONVENTION_NAME_COL);
			if (callingConventionName.equals(name)) {
				return record;
			}
		}
		return null;
	}

}
