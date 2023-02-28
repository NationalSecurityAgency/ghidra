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
package db;

/**
 * Provides syntax for opening a database transaction using a try-with-resources block
 *
 * <p>
 * For example, using {@link DBHandle#startTransaction()} directly:
 * 
 * <pre>
 * int txid = dbHandle.startTransaction();
 * try {
 * 	// ... Do something
 * }
 * finally {
 * 	program.endTransaction(txid, true);
 * }
 * </pre>
 * 
 * <p>
 * Can be expressed using an an {@link Transaction} instead:
 * 
 * <pre>
 * try (Transaction tx = dbHandle.openTransaction(dbErrorHandler)) {
 * 	// ... Do something
 * }
 * </pre>
 */
public abstract class Transaction implements AutoCloseable {

	private boolean commit = true;
	private boolean open = true;

	protected Transaction() {
	}

	/**
	 * End this transaction if currently active.  
	 * @param commit true if changes shuold be commited, false if all changes in this transaction
	 * shuold be discarded (i.e., rollback).  If this is a "sub-transaction" and commit is false,
	 * the larger transaction will rollback upon completion.  
	 * @return true if changes have been commited or false if nothing to commit or commit parameter 
	 * was specified as false.
	 */
	abstract protected boolean endTransaction(@SuppressWarnings("hiding") boolean commit);

	/**
	 * Determine if this is a sub-transaction to a larger transaction.  If true is returned the 
	 * larger transaction will not complete until all sub-transactions have ended.  The larger
	 * transaction will rollback upon completion if any of the sub-transactions do not commit.
	 * @return true if this is a sub-transaction, else false.
	 */
	public boolean isSubTransaction() {
		return false;
	}

	/**
	 * Mark transaction for rollback/non-commit upon closing.  A subsequent invocation of 
	 * {@link #commitOnClose()} will alter this state prior to closing.
	 */
	public void abortOnClose() {
		commit = false;
	}

	/**
	 * Mark transaction for commit upon closing.  This state is assumed by default.  A subsequent 
	 * invocation of {@link #abortOnClose()} will alter this state prior to closing.
	 */
	public void commitOnClose() {
		commit = true;
	}

	/**
	 * Mark transaction for rollback/non-commit and end transaction if active.
	 */
	public void abort() {
		if (open) {
			open = false;
			endTransaction(false);
		}
	}

	/**
	 * Mark transaction for commit and end transaction if active.
	 */
	public void commit() {
		if (open) {
			open = false;
			endTransaction(true);
		}
	}

	/**
	 * End this transaction if active using the current commit state.
	 * See {@link #commitOnClose()}, {@link #abortOnClose()}.
	 */
	@Override
	public void close() {
		if (open) {
			open = false;
			endTransaction(commit);
		}
	}
	
}
