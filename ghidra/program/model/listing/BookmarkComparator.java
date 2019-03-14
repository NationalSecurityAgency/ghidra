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
package ghidra.program.model.listing;

import java.util.Comparator;

/**
 * Provides an ordering for bookmarks.
 */
public class BookmarkComparator implements Comparator<Bookmark> {

	/**
	 * Comparator for bookmarks.
	 * @param bm1 first bookmark
	 * @param bm2 second bookmark
     * @return a negative integer, zero, or a positive integer as the
     * 	       first argument is less than, equal to, or greater than the
     *	       second. 
	 */
	public int compare(Bookmark bm1, Bookmark bm2) {
		String bt1 = bm1.getTypeString();
		String bt2 = bm2.getTypeString();
		String bc1 = bm1.getCategory();
		String bc2 = bm2.getCategory();
		int typeCompare = bt1.compareTo(bt2);
		if (typeCompare == 0) {
			return bc1.compareTo(bc2);
		}
		return typeCompare;
	}
}
