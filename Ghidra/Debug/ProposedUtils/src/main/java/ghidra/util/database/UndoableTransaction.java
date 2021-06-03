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

import javax.help.UnsupportedOperationException;

import ghidra.framework.model.AbortedTransactionListener;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.util.Msg;

public interface UndoableTransaction extends AutoCloseable {
	public static UndoableTransaction start(UndoableDomainObject domainObject, String description,
			boolean commitByDefault) {
		int tid = domainObject.startTransaction(description);
		return new DomainObjectUndoableTransaction(domainObject, tid, commitByDefault);
	}

	public static UndoableTransaction start(UndoableDomainObject domainObject, String description,
			AbortedTransactionListener listener, boolean commitByDefault) {
		int tid = domainObject.startTransaction(description, listener);
		return new DomainObjectUndoableTransaction(domainObject, tid, commitByDefault);
	}

	public static UndoableTransaction start(DataTypeManager dataTypeManager, String description,
			boolean commitByDefault) {
		int tid = dataTypeManager.startTransaction(description);
		return new DataTypeManagerUndoableTransaction(dataTypeManager, tid, commitByDefault);
	}

	public static UndoableTransaction start(ProgramUserData userData) {
		int tid = userData.startTransaction();
		return new ProgramUserDataUndoableTransaction(userData, tid);
	}

	abstract class AbstractUndoableTransaction implements UndoableTransaction {
		protected final int transactionID;

		private boolean commit;
		private boolean open = true;

		private AbstractUndoableTransaction(int transactionID, boolean commitByDefault) {
			this.transactionID = transactionID;
			this.commit = commitByDefault;
		}

		abstract void endTransaction(@SuppressWarnings("hiding") boolean commit);

		@Override
		public void abort() {
			if (open) {
				open = false;
				endTransaction(false);
			}
		}

		@Override
		public void commit() {
			if (open) {
				open = false;
				endTransaction(true);
			}
		}

		@Override
		public void close() {
			if (open) {
				endTransaction(commit);
			}
		}
	}

	class DomainObjectUndoableTransaction extends AbstractUndoableTransaction {
		private final UndoableDomainObject domainObject;

		private DomainObjectUndoableTransaction(UndoableDomainObject domainObject, int tid,
				boolean commitByDefault) {
			super(tid, commitByDefault);
			this.domainObject = domainObject;
		}

		@Override
		void endTransaction(boolean commit) {
			if (!commit) {
				Msg.debug(this, "Aborting transaction");
			}
			domainObject.endTransaction(transactionID, commit);
		}
	}

	class DataTypeManagerUndoableTransaction extends AbstractUndoableTransaction {
		private final DataTypeManager dataTypeManager;

		private DataTypeManagerUndoableTransaction(DataTypeManager dataTypeManager, int tid,
				boolean commitByDefault) {
			super(tid, commitByDefault);
			this.dataTypeManager = dataTypeManager;
		}

		@Override
		void endTransaction(boolean commit) {
			dataTypeManager.endTransaction(transactionID, commit);
		}
	}

	class ProgramUserDataUndoableTransaction extends AbstractUndoableTransaction {
		private final ProgramUserData userData;

		private ProgramUserDataUndoableTransaction(ProgramUserData userData, int tid) {
			super(tid, true);
			this.userData = userData;
		}

		@Override
		public void abort() {
			throw new UnsupportedOperationException();
		}

		@Override
		void endTransaction(boolean commit) {
			userData.endTransaction(transactionID);
		}
	}

	void commit();

	void abort();

	@Override
	void close();
}
