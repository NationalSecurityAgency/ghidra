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
package ghidra.program.database.data;

import db.DBRecord;

/**
 * DatabaseObject for a Default settings record.
 * 
 * 
 */
class SettingsDB {
	private DBRecord record;

	/**
	 * Constructor
	 * @param cache
	 * @param record
	 */
	SettingsDB(DBRecord record) {
		this.record = record;
	}

	String getName() {
		return record.getString(SettingsDBAdapter.SETTINGS_NAME_COL);
	}

	Long getLongValue() {

		Long lvalue = null;
		if (getStringValue() == null && getByteValue() == null) {
			long l = record.getLongValue(SettingsDBAdapter.SETTINGS_LONG_VALUE_COL);
			lvalue = new Long(l);
		}
		return lvalue;
	}

	String getStringValue() {
		return record.getString(SettingsDBAdapter.SETTINGS_STRING_VALUE_COL);
	}

	byte[] getByteValue() {
		return record.getBinaryData(SettingsDBAdapter.SETTINGS_BYTE_VALUE_COL);
	}

	Object getValue() {
		Object obj = getStringValue();
		if (obj != null) {
			return obj;
		}
		obj = getByteValue();
		if (obj != null) {
			return obj;
		}
		return getLongValue();
	}
}
