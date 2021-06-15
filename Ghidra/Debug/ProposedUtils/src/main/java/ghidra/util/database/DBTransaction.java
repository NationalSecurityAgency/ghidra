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
package ghidra.util.database;

import java.io.IOException;

import db.DBHandle;

public class DBTransaction implements AutoCloseable {
	public static DBTransaction start(DBHandle handle, boolean commitByDefault) {
		long tid = handle.startTransaction();
		return new DBTransaction(handle, tid, commitByDefault);
	}

	private final DBHandle handle;
	private final long tid;

	private boolean commit;
	private boolean open = true;

	private DBTransaction(DBHandle handle, long tid, boolean commitByDefault) {
		this.handle = handle;
		this.tid = tid;
		this.commit = commitByDefault;
	}

	public void abort() throws IOException {
		open = false;
		handle.endTransaction(tid, false);
	}

	public void commit() throws IOException {
		open = false;
		handle.endTransaction(tid, true);
	}

	@Override
	public void close() throws IOException {
		if (open) {
			handle.endTransaction(tid, commit);
		}
	}
}
