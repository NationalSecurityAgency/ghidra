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
package ghidra.feature.vt.api.db;

import static ghidra.feature.vt.api.db.VTMatchTagDBAdapter.ColumnDescription.TAG_NAME_COL;

import java.io.IOException;

import db.DBRecord;
import ghidra.feature.vt.api.main.VTMatchTag;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;

/**
 * The database object for a user defined tag on a version tracking match.
 */
public class VTMatchTagDB extends DatabaseObject implements VTMatchTag {

	private VTSessionDB sessionDB;
	private DBRecord record;

	VTMatchTagDB(VTSessionDB sessionDB, DBObjectCache<VTMatchTagDB> cache, DBRecord record) {
		super(cache, record.getKey());
		this.sessionDB = sessionDB;
		this.record = record;
	}

	@Override
	public String toString() {
		return getName();
	}

	/**
	 * Update associated record
	 * @param rec the new record information
	 */
	void setRecord(DBRecord rec) {
		if (rec.getKey() != key) {
			throw new IllegalArgumentException("Key mismatch");
		}
		record = rec;
	}

	@Override
	protected boolean refresh() {
		DBRecord rec = null;
		try {
			rec = sessionDB.getTagRecord(key);
		}
		catch (IOException e) {
			sessionDB.dbError(e);
		}
		if (rec == null) {
			return false;
		}
		record = rec;
		return true;
	}

	/**
	 * Returns record associated with this match tag or
	 * null if the match tag has been deleted.
	 */
	DBRecord getRecord() {
		return checkIsValid() ? record : null;
	}

	@Override
	public String getName() {
		return record.getString(TAG_NAME_COL.column());
	}

	public int compareTo(VTMatchTag otherTag) {
		return getName().compareTo(otherTag.getName());
	}

	@Override
	public int hashCode() {
		return getName().hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (obj == null) {
			return false;
		}

		if (!(obj instanceof VTMatchTag)) {
			return false;
		}

		VTMatchTag other = (VTMatchTag) obj;
		return getName().equals(other.getName());
	}

}
