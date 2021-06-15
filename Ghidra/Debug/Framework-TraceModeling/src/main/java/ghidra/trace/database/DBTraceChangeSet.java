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
package ghidra.trace.database;

import java.io.IOException;

import db.DBHandle;
import ghidra.framework.data.DomainObjectDBChangeSet;
import ghidra.trace.model.TraceChangeSet;

public class DBTraceChangeSet implements TraceChangeSet, DomainObjectDBChangeSet {

	@Override
	public void read(DBHandle dbh) throws IOException {
		// TODO Auto-generated method stub

	}

	@Override
	public void write(DBHandle dbh, boolean isRecoverySave) throws IOException {
		// TODO Auto-generated method stub

	}

	@Override
	public void clearUndo(boolean isCheckedOut) {
		// TODO Auto-generated method stub

	}

	@Override
	public void undo() {
		// TODO Auto-generated method stub

	}

	@Override
	public void redo() {
		// TODO Auto-generated method stub

	}

	@Override
	public void setMaxUndos(int maxUndos) {
		// TODO Auto-generated method stub

	}

	@Override
	public void clearUndo() {
		// TODO Auto-generated method stub

	}

	@Override
	public void startTransaction() {
		// TODO Auto-generated method stub

	}

	@Override
	public void endTransaction(boolean commit) {
		// TODO Auto-generated method stub

	}

	@Override
	public void dataTypeChanged(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public void dataTypeAdded(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public long[] getDataTypeChanges() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long[] getDataTypeAdditions() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void categoryChanged(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public void categoryAdded(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public long[] getCategoryChanges() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long[] getCategoryAdditions() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void sourceArchiveChanged(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public void sourceArchiveAdded(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public long[] getSourceArchiveChanges() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long[] getSourceArchiveAdditions() {
		// TODO Auto-generated method stub
		return null;
	}
}
