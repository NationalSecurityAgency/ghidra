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
package ghidra.util.prop;

import ghidra.util.datastruct.RedBlackLongKeySet;

import java.io.Serializable;


/**
 * PropertyPageIndex is used to find the property pages before and
 *   after a given property page.
 */
class PropertyPageIndex implements Serializable {
	private RedBlackLongKeySet rbtree;

	public PropertyPageIndex() {
		rbtree = new RedBlackLongKeySet();
	}

	/**
	 * Get the ID of the page after pageID.
	 */
	public long getNext(long pageID) {
        return rbtree.getNext(pageID);
	}

	/**
	 * Get the number of pages in the table.
	 */
	public int getNumPages() {
		return rbtree.size();
	}

	/**
	 * Get the ID of the page before pageID.
	 */
	public long getPrevious(long pageID) {
        return rbtree.getPrevious(pageID);
	}

	/**
	 * Return whether the pageID exists in the table.
	 */
	public boolean hasPage(long pageID) {
		return rbtree.containsKey(pageID);
	}

	/**
	 * Add the given pageID to the table.
	 */
	public void add(long pageID) {
		rbtree.put(pageID);
	}

	/**
	 * Remove pageID from the table.
	 * @return true if the pageID was removed
	 */
	public boolean remove(long pageID) {
		return rbtree.remove(pageID);
	}
}

