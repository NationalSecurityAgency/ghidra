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

import static ghidra.feature.fid.db.FunctionsTable.*;

import db.DBRecord;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.util.NumericUtilities;

/**
 * Represents a function record in the FID database.
 */
public class FunctionRecord extends DatabaseObject implements FidHashQuad {
	public final static int HAS_TERMINATOR_FLAG = 1;
	public final static int AUTO_PASS_FLAG = 2;
	public final static int AUTO_FAIL_FLAG = 4;
	public final static int FORCE_SPECIFIC_FLAG = 8;
	public final static int FORCE_RELATION_FLAG = 16;

	/**
	 * All values are stored in the record instead of memoized.
	 */
	final DBRecord record;
	/**
	 * Need a reference to the FidDb because all strings are stored
	 * via foreign key (considerable duplication of string values).
	 */
	final FidDB fidDb;

	/**
	 * Package private constructor, to be called from FunctionsTable exclusively.
	 * @param fid database (for string references)
	 * @param cache FunctionRecord object cache
	 * @param record record for this function
	 */
	FunctionRecord(FidDB fid, DBObjectCache<FunctionRecord> cache, DBRecord record) {
		super(cache, record.getKey());
		this.record = record;
		this.fidDb = fid;
	}

	/**
	 * @return database that owns this record
	 */
	public FidDB getFidDb() {
		return fidDb;
	}

	/**
	 * Returns the full hash size.
	 */
	@Override
	public short getCodeUnitSize() {
		return record.getShortValue(CODE_UNIT_SIZE_COL);
	}

	/**
	 * Returns the full hash.
	 */
	@Override
	public long getFullHash() {
		return record.getLongValue(FULL_HASH_COL);
	}

	/**
	 * Returns the specific hash additional size.
	 */
	@Override
	public byte getSpecificHashAdditionalSize() {
		return record.getByteValue(SPECIFIC_HASH_ADDITIONAL_SIZE_COL);
	}

	/**
	 * Returns the specific hash.
	 */
	@Override
	public long getSpecificHash() {
		return record.getLongValue(SPECIFIC_HASH_COL);
	}

	/**
	 * Returns the name.
	 * @return the name
	 */
	public String getName() {
		StringRecord lookupString =
			fidDb.getStringsTable().lookupString(record.getLongValue(NAME_ID_COL));
		if (lookupString != null) {
			return lookupString.getValue();
		}
		return null;
	}

	/**
	 * Returns the entry point (memory address).
	 * @return the entry point
	 */
	public long getEntryPoint() {
		return record.getLongValue(ENTRY_POINT_COL);
	}

	/**
	 * Returns the domain path in the project upon library creation.
	 * @return the domain path
	 */
	public String getDomainPath() {
		StringRecord lookupString =
			fidDb.getStringsTable().lookupString(record.getLongValue(DOMAIN_PATH_ID_COL));
		if (lookupString != null) {
			return lookupString.getValue();
		}
		return null;
	}

	/**
	 * Returns whether auto-analysis found a terminator within the flow of the function body.
	 * @return whether it has a terminator
	 */
	public boolean hasTerminator() {
		byte val = record.getByteValue(FLAGS_COL);
		return ((val & HAS_TERMINATOR_FLAG) != 0);
	}

	/**
	 * @return true if this function should automatically pass the code unit threshold
	 */
	public boolean autoPass() {
		byte val = record.getByteValue(FLAGS_COL);
		return ((val & AUTO_PASS_FLAG) != 0);
	}

	/**
	 * @return true if this function should automatically fail the code unit threshold
	 */
	public boolean autoFail() {
		byte val = record.getByteValue(FLAGS_COL);
		return ((val & AUTO_FAIL_FLAG) != 0);
	}

	/**
	 * @return true if this record can only be matched if the specific hash matches
	 */
	public boolean isForceSpecific() {
		byte val = record.getByteValue(FLAGS_COL);
		return ((val & FORCE_SPECIFIC_FLAG) != 0);
	}

	/**
	 * @return true if this record can only be matched if one of the functions parent/child
	 *         relations also matches
	 */
	public boolean isForceRelation() {
		byte val = record.getByteValue(FLAGS_COL);
		return ((val & FORCE_RELATION_FLAG) != 0);
	}
	/**
	 * Returns the record id (primary key).
	 * @return the record id
	 */
	public long getID() {
		return record.getKey();
	}

	/**
	 * Overridden toString to help debugging.
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(NumericUtilities.toHexString(getID()));
		sb.append(" - ");
		sb.append(getName());
		sb.append(" (");
		sb.append(NumericUtilities.toHexString(getLibraryID()));
		sb.append(")");
		return sb.toString();
	}

	/**
	 * Overridden hashCode to support collections.
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (getID() ^ (getID() >>> 32));
		return result;
	}

	/**
	 * Overridden equals to support collections.
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		FunctionRecord other = (FunctionRecord) obj;
		if (getID() != other.getID()) {
			return false;
		}
		return true;
	}

	/**
	 * Returns the library id for this function.
	 * @return the library id
	 */
	public long getLibraryID() {
		return record.getLongValue(LIBRARY_ID_COL);
	}

	/**
	 * Never need to refresh...this database object is immutable.
	 */
	@Override
	protected boolean refresh() {
		return false;
	}
}
