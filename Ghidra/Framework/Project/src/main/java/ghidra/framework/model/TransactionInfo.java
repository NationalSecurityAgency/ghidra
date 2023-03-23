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
package ghidra.framework.model;

import java.util.ArrayList;

public interface TransactionInfo {

	public enum Status {
		NOT_DONE, COMMITTED, ABORTED, NOT_DONE_BUT_ABORTED;
	}

	public long getID();

	/**
	 * Returns the description of this transaction.
	 * @return the description of this transaction
	 */
	public String getDescription();

	/**
	 * Returns the list of open sub-transactions that are contained
	 * inside this transaction.
	 * @return the list of open sub-transactions
	 */
	public ArrayList<String> getOpenSubTransactions();

	/**
	 * Get the status of the corresponding transaction.
	 * @return status
	 */
	public Status getStatus();

	/**
	 * Determine if the corresponding transaction, and all of its sub-transactions, has been 
	 * comitted to the underlying database.
	 * @return true if the corresponding transaction has been comitted, else false.
	 */
	public boolean hasCommittedDBTransaction();

}
