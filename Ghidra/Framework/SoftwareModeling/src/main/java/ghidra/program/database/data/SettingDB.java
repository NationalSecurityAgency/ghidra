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
 * Setting DBRecord wrapper for cache use
 */
class SettingDB {

	private String name;
	private DBRecord record;

	/**
	 * Construction setting object
	 * @param record setting record
	 * @param name setting name
	 */
	SettingDB(DBRecord record, String name) {
		this.record = record;
		this.name = name;
	}

	String getName() {
		return name;
	}

	Long getLongValue() {
		Long lvalue = null;
		if (getStringValue() == null) {
			lvalue = record.getLongValue(SettingsDBAdapter.SETTINGS_LONG_VALUE_COL);
		}
		return lvalue;
	}

	String getStringValue() {
		return record.getString(SettingsDBAdapter.SETTINGS_STRING_VALUE_COL);
	}

	Object getValue() {
		Object obj = getStringValue();
		if (obj != null) {
			return obj;
		}
		return record.getLongValue(SettingsDBAdapter.SETTINGS_LONG_VALUE_COL);
	}

	long getKey() {
		return record.getKey();
	}

	DBRecord getRecord() {
		return record;
	}
}
