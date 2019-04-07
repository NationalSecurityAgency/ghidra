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
package ghidra.feature.fid.db;

import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;

/**
 * A string record in the FID database.
 */
public class StringRecord extends DatabaseObject {
	/**
	 * The value of the string.
	 */
	private final String value;

	/**
	 * Constructor with the primary key and the string value.
	 * @param cache StringRecord object cache
	 * @param key primary key
	 * @param value the string value
	 */
	public StringRecord(DBObjectCache<StringRecord> cache, long key, String value) {
		super(cache, key);
		this.value = value;
	}

	/**
	 * Returns the value of the string.
	 * @return the value of the string
	 */
	public String getValue() {
		return value;
	}

	/**
	 * Never need to refresh...this database object is immutable.
	 */
	@Override
	protected boolean refresh() {
		return false;
	}
}
