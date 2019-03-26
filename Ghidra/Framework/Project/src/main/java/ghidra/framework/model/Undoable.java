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


import java.io.IOException;

/**
 * Objects that implement Undoable have the ability to "remember" some number
 * of stable states that are created as operations are performed upon them.  The
 * object then provides methods for "undoing" to a previous state or "redoing" to
 * a later state.
 */
public interface Undoable {

	/**
	 * Returns true if there is a previous state to "undo" to.
	 */
	boolean canUndo();

	/**
	 * Returns true if there is a later state to "redo" to.
	 */
	boolean canRedo();

	/**
	 * Clear all undoable/redoable transactions
	 */
	public void clearUndo();

	/**
	 * Returns to the previous state.  Normally, this will cause the current state
	 * to appear on the "redo" stack.  This method will do nothing if there are
	 * no previous states to "undo".
	 * @throws IOException if an IO error occurs
	 */
	void undo() throws IOException;

	/**
	 * Returns to a latter state that exists because of an undo.  Normally, this
	 * will cause the current state to appear on the "undo" stack.  This method
	 * will do nothing if there are no latter states to "redo".
	 * @throws IOException if an IO error occurs
	 */
	void redo() throws IOException;

	/**
	 * Returns a description of the chanage that would be "undone".
	 */
	String getUndoName();

	/**
	 * Returns a description of the change that would be "redone".
	 */
	String getRedoName();

	/**
	 * Adds the given transaction listener to this domain object
	 * @param listener the new transaction listener to add
	 */
	public void addTransactionListener(TransactionListener listener);

	/**
	 * Removes the given transaction listener from this domain object.
	 * @param listener the transaction listener to remove
	 */
	public void removeTransactionListener(TransactionListener listener);

}
