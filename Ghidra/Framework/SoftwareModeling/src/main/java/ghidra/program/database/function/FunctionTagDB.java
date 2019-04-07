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

import db.Record;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.listing.FunctionTag;

/**
 * Database object for {@link FunctionTagAdapter} objects. 
 */
public class FunctionTagDB extends DatabaseObject implements FunctionTag {

	private FunctionTagManagerDB mgr;
	private Record record;

	public FunctionTagDB(FunctionTagManagerDB mgr, DBObjectCache<FunctionTagDB> cache,
			Record record) {
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
	
			if (comment == null)
				comment = "";
	
			if (!comment.equals(record.getString(FunctionTagAdapter.COMMENT_COL))) {
				record.setString(FunctionTagAdapter.COMMENT_COL, comment);
				mgr.updateFunctionTag(this);
			}
			
		} catch (IOException e) {
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
	
			if (name == null)
				name = "";
	
			if (!name.equals(record.getString(FunctionTagAdapter.NAME_COL))) {
				record.setString(FunctionTagAdapter.NAME_COL, name);
				mgr.updateFunctionTag(this);
			}
		} catch (IOException e) {
			mgr.dbError(e);
		} finally {
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
	Record getRecord() {
		return record;
	}

	@Override
	protected boolean refresh() {

		// Call refresh with a null value to force the record
		// to be refreshed using whatever is in the database.
		return refresh(null);
	}

	@Override
	protected boolean refresh(Record rec) {

		// As per the description of this function, if the record passed-in
		// is null, use whatever is in the database.
		if (rec == null) {
			try {
				rec = mgr.getFunctionTagAdapter().getRecord(key);
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
	public int hashCode() {
		return (int) key;
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
	public boolean equals(Object obj) {
		if ((obj == null) || (!(obj instanceof FunctionTag))) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		FunctionTag tag = (FunctionTag) obj;
		if (!getName().equals(tag.getName())) {
			return false;
		}
		if (!getComment().equals(tag.getComment())) {
			return false;
		}
		return true;
	}

	@Override
	public void delete() {
		mgr.lock.acquire();
		try {
			if (checkIsValid()) {
				mgr.doDeleteTag(this);
			}
		} catch (IOException e) {
			mgr.dbError(e);
		}
		finally {
			mgr.lock.release();
		}
	}
}

