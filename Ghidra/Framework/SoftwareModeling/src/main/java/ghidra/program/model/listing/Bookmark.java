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

import ghidra.program.model.address.Address;

/**
 * Interface for bookmarks.  Bookmarks are locations that are marked within the program so
 * that they can be easily found.
 */
public interface Bookmark extends Comparable<Bookmark> {

	/**
	 * Returns the id of the bookmark.
	 */
	long getId();

	/**
	 * Returns address at which this bookmark is applied.
	 */
	Address getAddress();
	
	/**
	 * Returns bookmark type object.
	 */
	BookmarkType getType();
	
	/**
	 * Returns bookmark type as a string
	 */
	String getTypeString();
	
	/**
	 * Returns bookmark category
	 */
	String getCategory();

	/**
	 * Returns bookmark comment
	 */
	String getComment();
	
	/**
	 * Set the category and comment associated with a bookmark.
	 * @param category category
	 * @param comment single line comment
	 */
	void set(String category, String comment);
}
