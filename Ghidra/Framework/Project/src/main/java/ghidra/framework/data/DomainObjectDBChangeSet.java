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
package ghidra.framework.data;

import db.DBChangeSet;

/**
 * <code>DomainObjectDBChangeSet</code> extends <code>DBChangeSet</code> 
 * providing methods which facilitate transaction synchronization with the domain object's DBHandle.
 */
public interface DomainObjectDBChangeSet extends DBChangeSet {
	/**
	 * Resets the change sets after a save.
	 */
	void clearUndo(boolean isCheckedOut);

	/**
	 * Undo the last change data transaction
	 */
	void undo();

	/**
	 * Redo the change data transaction associated the last Undo.
	 */
	void redo();

	/**
	 * Set the undo/redo stack depth
	 * @param maxUndos the maximum numbder of undo
	 */
	void setMaxUndos(int maxUndos);

	/**
	 * Clears the undo/redo stack.
	 */
	void clearUndo();

	/**
	 * Start change data transaction.
	 */
	void startTransaction();

	/**
	 * End change data transaction.
	 * @param commit if true transaction data is committed, 
	 *               otherwise transaction data is discarded
	 */
	void endTransaction(boolean commit);
}
