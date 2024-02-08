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
package docking.widgets.indexedscrollpane;

import java.math.BigInteger;

/**
 * Interface for scrolling a FieldPanel or container of a group of FieldPanels which displays
 * a list of displayable items (layouts)
 */
public interface IndexedScrollable {

	/**
	 * Returns the number individually addressable items displayed.
	 * @return the number individually addressable items displayed
	 */
	public BigInteger getIndexCount();

	/**
	 * Returns true if all the items are the same vertical size.
	 * @return true if all the items are the same vertical size
	 */
	public boolean isUniformIndex();

	/**
	 * Returns the height of the n'th item.
	 * @param index the index of the time to get height for
	 * @return the height of the n'th item.
	 */
	public int getHeight(BigInteger index);

	/**
	 * Makes the item at the given index be visible on the screen at the given vertical offset
	 * @param index the index of the item to show
	 * @param verticalOffset the number of pixels from the top of the screen to show the item
	 */
	public void showIndex(BigInteger index, int verticalOffset);

	/**
	 * Returns the index of the next non-null item. Not all indexes have items. Some items span
	 * multiple indexes
	 * @param index the index to start searching for the next non-null item
	 * @return the index of the next non-null item, or -1 if there is none
	 */
	public BigInteger getIndexAfter(BigInteger index);

	/**
	 * Returns the index of the previous non-null item. Not all indexes have items. Some items span
	 * multiple indexes
	 * @param index the index to start searching backwards for the previous non-null item
	 * @return the index of the previous non-null item, or -1 if there is none
	 */
	public BigInteger getIndexBefore(BigInteger index);

	/**
	 * Scrolls the displayed items up by the height of one line of text
	 */
	public void scrollLineUp();

	/**
	 * Scrolls the displayed items down by the height of one line of text
	 */
	public void scrollLineDown();

	/**
	 * Scrolls the displayed items up by the height of one screen of text
	 */
	public void scrollPageUp();

	/**
	 * Scrolls the displayed items down by the height of one screen of text
	 */
	public void scrollPageDown();

	/**
	 * Adds a listener to be notified when the view is scrolled in any way.
	 * @param listener the listener to be notified when the visible items change
	 */
	public void addIndexScrollListener(IndexScrollListener listener);

	/**
	 * Removes the given listener from those to be notified when the view changes.
	 * @param listener the listener to remove
	 */
	public void removeIndexScrollListener(IndexScrollListener listener);

	/**
	 * Notify the scrollable that the mouse wheel was moved.
	 * @param preciseWheelRotation the amount of rotation of the wheel
	 * @param isHorizontal true if the rotation was horizontal, false for vertical
	 */
	public void mouseWheelMoved(double preciseWheelRotation, boolean isHorizontal);

}
