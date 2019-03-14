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
 * Provides an ordering for bookmark types.
 */
public class BookmarkTypeComparator implements Comparator<BookmarkType> {

	/**
	 * Comparator for bookmark types.
	 * @param bt1 first bookmark type
	 * @param bt2 second bookmark type
     * @return a negative integer, zero, or a positive integer as the
     * 	       first argument is less than, equal to, or greater than the
     *	       second. 
	 */
	public int compare(BookmarkType bt1, BookmarkType bt2) {
		return bt1.getTypeString().compareTo(bt2.getTypeString());
	}

}
