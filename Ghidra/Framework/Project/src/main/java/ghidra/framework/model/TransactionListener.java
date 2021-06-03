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

import ghidra.framework.data.DomainObjectAdapterDB;

/**
 * An interface for listening to transactions
 */
public interface TransactionListener {
	/**
	 * Invoked when a transaction is started.
	 * @param domainObj the domain object where the transaction was started
	 * @param tx the transaction that was started
	 */
	void transactionStarted(DomainObjectAdapterDB domainObj, Transaction tx);

	/**
	 * Invoked when a transaction is ended.
	 * @param domainObj the domain object where the transaction was ended
	 */
	void transactionEnded(DomainObjectAdapterDB domainObj);

	/**
	 * Invoked when the stack of available undo/redo's has changed.
	 * @param domainObj the affected domain object
	 */
	void undoStackChanged(DomainObjectAdapterDB domainObj);

	/**
	 * Notification that undo or redo has occurred.
	 * @param domainObj the affected domain object
	 */
	void undoRedoOccurred(DomainObjectAdapterDB domainObj);
}
