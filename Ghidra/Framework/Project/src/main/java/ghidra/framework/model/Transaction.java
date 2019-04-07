/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

public interface Transaction {

	public static final int NOT_DONE = 0;
	public static final int COMMITTED = 1;
	public static final int ABORTED = 2;
	public static final int NOT_DONE_BUT_ABORTED = 3;

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

	public int getStatus();

	/**
	 * Returns true if this fully committed transaction has a corresponding 
	 * database transaction/checkpoint.
	 */
	public boolean hasCommittedDBTransaction();

}
