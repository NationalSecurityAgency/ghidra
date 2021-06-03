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
package docking.widgets.fieldpanel;

import java.awt.Dimension;
import java.math.BigInteger;

import docking.widgets.fieldpanel.listener.LayoutModelListener;

/**
 * The Big Layout Model interface.  Objects that implement this interface can be dispayed
 * using a BigFieldPanel.
 */

public interface LayoutModel {

	/**
	 * Returns true if every index returns a non-null layout and all the layouts
	 * are the same height.
	 */
	boolean isUniform();

	/**
	 * Returns the width of the largest possible layout.
	 */
	public Dimension getPreferredViewSize();

	/**
	 * Returns the total number of indexes.
	 */
	public BigInteger getNumIndexes();

	/**
	 * Returns the closest larger index in the model that has a non-null layout.
	 * @param index for which to find the next index with a non-null layout.
	 * @return returns the closest larger index in the model that has a non-null layout.
	 */
	public BigInteger getIndexAfter(BigInteger index);

	/**
	 * Returns the closest smaller index in the model that has a non-null layout.
	 * @param index for which to find the previous index with a non-null layout.
	 * @return returns the closest smaller index in the model that has a non-null layout.
	 */
	public BigInteger getIndexBefore(BigInteger index);

	/**
	 * Returns a layout for the given index.
	 * @param index the index of the layout to retrieve.
	 */
	public Layout getLayout(BigInteger index);

	/**
	 * Returns an iterator that walks all the Layout items in this model.
	 * 
	 * @return new iterator
	 */
	public default LayoutModelIterator iterator() {
		return new LayoutModelIterator(this);
	}

	/**
	 * Returns an iterator that walks all the Layout items in this model, starting at the
	 * specified index.
	 * 
	 * @param startIndex start index in the model to beginning iterating
	 * @return new iterator
	 */
	public default LayoutModelIterator iterator(BigInteger startIndex) {
		return new LayoutModelIterator(this, startIndex);
	}

	/**
	 * Adds a LayoutModelListener to be notified when changes occur.
	 * @param listener the LayoutModelListener to add.
	 */
	public void addLayoutModelListener(LayoutModelListener listener);

	/**
	 * Removes a LayoutModelListener to be notified when changes occur.
	 * @param listener the LayoutModelListener to remove.
	 */
	public void removeLayoutModelListener(LayoutModelListener listener);

	/**
	 * Returns true if the model knows about changes that haven't yet been told to the 
	 * LayoutModelListeners.
	 */
	public void flushChanges();
}
