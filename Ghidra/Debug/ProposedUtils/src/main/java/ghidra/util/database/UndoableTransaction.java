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

import javax.help.UnsupportedOperationException;

import db.DBHandle;
import db.NoTransactionException;
import db.util.ErrorHandler;
import ghidra.framework.model.AbortedTransactionListener;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.util.Msg;

/**
 * Provides syntax for opening a database transaction using a try-with-resources block
 *
 * <p>
 * For example, using {@link UndoableDomainObject#startTransaction(String)} directly:
 * 
 * <pre>
 * int txid = program.startTransaction("Do a thing");
 * try {
 * 	// ... Do that thing
 * }
 * finally {
 * 	program.endTransaction(txid, true);
 * }
 * </pre>
 * 
 * <p>
 * Can be expressed using an undoable transaction instead:
 * 
 * <pre>
 * try (UndoableTransaction txid = UndoableTransaction.start(program, "Do a thing", true)) {
 * 	// ... Do that thing
 * }
 * </pre>
 */
public interface UndoableTransaction extends AutoCloseable {
	/**
	 * Open a transaction directly on a database handle
	 * 
	 * @param handle the handle
	 * @param errHandler a handler for database errors, usually the domain object
	 * @return the transaction handle
	 */
	public static UndoableTransaction start(DBHandle handle, ErrorHandler errHandler) {
		long tid = handle.startTransaction();
		return new DBHandleUndoableTransaction(handle, tid, errHandler);
	}

	/**
	 * Open a transaction on a domain object
	 * 
	 * @param domainObject the domain object
	 * @param description a description of the change
	 * @return the transaction handle
	 */
	public static UndoableTransaction start(UndoableDomainObject domainObject, String description) {
		int tid = domainObject.startTransaction(description);
		return new DomainObjectUndoableTransaction(domainObject, tid);
	}

	/**
	 * Open a transaction on a domain object
	 * 
	 * <p>
	 * Even if this transaction is committed, if a sub-transaction is aborted, this transaction
	 * could become aborted, too. The listener can be used to detect this situation.
	 * 
	 * @param domainObject the domain object
	 * @param description a description of the change
	 * @param listener a listener for aborted transactions
	 * @param commitByDefault true to commit at the end of the block
	 * @return the transaction handle
	 */
	public static UndoableTransaction start(UndoableDomainObject domainObject, String description,
			AbortedTransactionListener listener) {
		int tid = domainObject.startTransaction(description, listener);
		return new DomainObjectUndoableTransaction(domainObject, tid);
	}

	/**
	 * Open a transaction on a data type manager
	 * 
	 * @param dataTypeManager the data type manager
	 * @param description a description of the change
	 * @param commitByDefault true to commit at the end of the block
	 * @return the transaction handle
	 */
	public static UndoableTransaction start(DataTypeManager dataTypeManager, String description) {
		int tid = dataTypeManager.startTransaction(description);
		return new DataTypeManagerUndoableTransaction(dataTypeManager, tid);
	}

	/**
	 * Open a transaction on program user data
	 * 
	 * @param userData the user data
	 * @return the transaction handle
	 */
	public static UndoableTransaction start(ProgramUserData userData) {
		int tid = userData.startTransaction();
		return new ProgramUserDataUndoableTransaction(userData, tid);
	}

	abstract class AbstractUndoableTransaction implements UndoableTransaction {

		private boolean commit = true;
		private boolean open = true;

		protected AbstractUndoableTransaction() {
		}

		abstract void endTransaction(@SuppressWarnings("hiding") boolean commit);

		@Override
		public void abortOnClose() {
			commit = false;
		}

		@Override
		public void commitOnClose() {
			commit = true;
		}

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
				open = false;
				endTransaction(commit);
			}
		}
	}

	abstract class AbstractLongUndoableTransaction extends AbstractUndoableTransaction {
		final long transactionID;

		public AbstractLongUndoableTransaction(long transactionID) {
			super();
			this.transactionID = transactionID;
		}
	}

	abstract class AbstractIntUndoableTransaction extends AbstractUndoableTransaction {
		final int transactionID;

		public AbstractIntUndoableTransaction(int transactionID) {
			super();
			this.transactionID = transactionID;
		}
	}

	class DBHandleUndoableTransaction extends AbstractLongUndoableTransaction {
		private final DBHandle handle;
		private final ErrorHandler errHandler;

		public DBHandleUndoableTransaction(DBHandle handle, long transactionID,
				ErrorHandler errHandler) {
			super(transactionID);
			this.handle = handle;
			this.errHandler = errHandler;
		}

		@Override
		void endTransaction(boolean commit) {
			if (!commit) {
				Msg.debug(this, "Aborting transaction");
			}
			try {
				handle.endTransaction(transactionID, commit);
			}
			catch (IOException e) {
				errHandler.dbError(e);
			}
		}
	}

	class DomainObjectUndoableTransaction extends AbstractIntUndoableTransaction {
		private final UndoableDomainObject domainObject;

		private DomainObjectUndoableTransaction(UndoableDomainObject domainObject, int tid) {
			super(tid);
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

	class DataTypeManagerUndoableTransaction extends AbstractIntUndoableTransaction {
		private final DataTypeManager dataTypeManager;

		private DataTypeManagerUndoableTransaction(DataTypeManager dataTypeManager, int tid) {
			super(tid);
			this.dataTypeManager = dataTypeManager;
		}

		@Override
		void endTransaction(boolean commit) {
			dataTypeManager.endTransaction(transactionID, commit);
		}
	}

	class ProgramUserDataUndoableTransaction extends AbstractIntUndoableTransaction {
		private final ProgramUserData userData;

		private ProgramUserDataUndoableTransaction(ProgramUserData userData, int tid) {
			super(tid);
			this.userData = userData;
		}

		@Override
		public void abortOnClose() {
			throw new UnsupportedOperationException();
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

	/**
	 * Set this transaction to commit when closed
	 * 
	 * <p>
	 * This is the default behavior. If an error occurs, or when the end of the try block is
	 * reached, the transaction will be committed. The user is expected to undo unwanted
	 * transactions, including those committed with an error. It could be the results are still
	 * mostly correct. Additionally, aborting a transaction can roll back other concurrent
	 * transactions.
	 */
	void commitOnClose();

	/**
	 * Set this transaction to abort by when closed
	 * 
	 * <p>
	 * Ordinarily, if an error occurs, the transaction is committed as is. The user is expected to
	 * undo unwanted transactions. Calling this method will cause the transaction to be aborted
	 * instead. <b>WARNING:</b> Aborting this transaction may abort other concurrent transactions.
	 * Use with extreme care. <b>NOTE:</b> Use of this method requires that the transaction be
	 * explicitly committed using {@link #commit()}. When this transaction is closed, if it hasn't
	 * been committed, it will be aborted.
	 */
	void abortOnClose();

	/**
	 * Commit the transaction and close it immediately
	 * 
	 * <p>
	 * Note that attempting to make changes after this call will likely result in a
	 * {@link NoTransactionException}.
	 */
	void commit();

	/**
	 * Abort the transaction and close it immediately
	 * 
	 * <p>
	 * Note that attempting to make changes after this call will likely result in a
	 * {@link NoTransactionException}. <b>WARNING:</b> Aborting this transaction may abort other
	 * concurrent transactions. Use with extreme care.
	 */
	void abort();

	@Override
	void close();
}
