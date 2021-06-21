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
import java.util.Objects;

import db.DBRecord;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.listing.FunctionTag;

/**
 * Database object for {@link FunctionTagAdapter} objects. 
 */
public class FunctionTagDB extends DatabaseObject implements FunctionTag {

	private FunctionTagManagerDB mgr;
	private DBRecord record;

	public FunctionTagDB(FunctionTagManagerDB mgr, DBObjectCache<FunctionTagDB> cache,
			DBRecord record) {
		super(cache, record.getKey());
		this.mgr = mgr;
		this.record = record;
	}

	@Override
	public long getId() {
		return key;
	}

	@Override
	public void setComment(String comment) {
		mgr.lock.acquire();
		try {
			checkDeleted();

			if (comment == null) {
				comment = "";
			}

			String oldValue = record.getString(FunctionTagAdapter.COMMENT_COL);
			if (!comment.equals(oldValue)) {
				record.setString(FunctionTagAdapter.COMMENT_COL, comment);
				mgr.updateFunctionTag(this, oldValue, comment);
			}

		}
		catch (IOException e) {
			mgr.dbError(e);
		}
		finally {
			mgr.lock.release();
		}
	}

	@Override
	public void setName(String name) {
		mgr.lock.acquire();
		try {
			checkDeleted();

			if (name == null) {
				name = "";
			}

			String oldValue = record.getString(FunctionTagAdapter.NAME_COL);
			if (!name.equals(oldValue)) {
				record.setString(FunctionTagAdapter.NAME_COL, name);
				mgr.updateFunctionTag(this, oldValue, name);
			}
		}
		catch (IOException e) {
			mgr.dbError(e);
		}
		finally {
			mgr.lock.release();
		}
	}

	@Override
	public String getComment() {
		mgr.lock.acquire();
		try {
			checkIsValid();
			return record.getString(FunctionTagAdapter.COMMENT_COL);
		}
		finally {
			mgr.lock.release();
		}
	}

	@Override
	public String getName() {
		mgr.lock.acquire();
		try {
			checkIsValid();
			return record.getString(FunctionTagAdapter.NAME_COL);
		}
		finally {
			mgr.lock.release();
		}
	}

	/**
	 * Get tag record
	 * @return record
	 */
	DBRecord getRecord() {
		return record;
	}

	@Override
	protected boolean refresh() {

		// Call refresh with a null value to force the record
		// to be refreshed using whatever is in the database.
		return refresh(null);
	}

	@Override
	protected boolean refresh(DBRecord rec) {

		// As per the description of this function, if the record passed-in
		// is null, use whatever is in the database.
		if (rec == null) {
			try {
				rec = mgr.getTagRecord(key);
			}
			catch (IOException e) {
				mgr.dbError(e);
			}
		}

		// If still null, then nothing to do.
		if (rec == null) {
			return false;
		}

		// If here, then just use whatever was passed in.
		record = rec;
		return true;
	}

	@Override
	public void delete() {
		mgr.lock.acquire();
		try {
			if (checkIsValid()) {
				mgr.doDeleteTag(this);
			}
		}
		catch (IOException e) {
			mgr.dbError(e);
		}
		finally {
			mgr.lock.release();
		}
	}

	@Override
	public int compareTo(FunctionTag otherTag) {
		int rc = getName().compareToIgnoreCase(otherTag.getName());
		if (rc != 0) {
			return rc;
		}
		return getComment().compareToIgnoreCase(otherTag.getComment());
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((getComment() == null) ? 0 : getComment().hashCode());
		result = prime * result + ((getName() == null) ? 0 : getName().hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof FunctionTag)) {
			return false;
		}

		FunctionTag other = (FunctionTag) obj;
		if (!Objects.equals(getComment(), other.getComment())) {
			return false;
		}

		if (!Objects.equals(getName(), other.getName())) {
			return false;
		}

		return true;
	}

	@Override
	public String toString() {
		return getName();
	}
}
