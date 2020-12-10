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
package ghidra.trace.model.bookmark;

import java.util.Collection;
import java.util.Set;

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

public interface TraceBookmarkOperations {
	/**
	 * Get all the categories used for a given type
	 * 
	 * @param type the bookmark type
	 * @return the set of categories
	 */
	Set<String> getCategoriesForType(TraceBookmarkType type);

	/**
	 * Add a bookmark at the given location.
	 * 
	 * The category need not be created explicitly beforehand. It will be created implicitly if it
	 * does not already exist.
	 * 
	 * @param lifespan the span of snaps to bookmark
	 * @param address the address to bookmark
	 * @param type the type of the bookmark
	 * @param category a category for the bookmark
	 * @param comment a comment to add to the bookmark
	 * @return the new bookmark
	 */
	TraceBookmark addBookmark(Range<Long> lifespan, Address address, TraceBookmarkType type,
			String category, String comment);

	Collection<? extends TraceBookmark> getAllBookmarks();

	Iterable<? extends TraceBookmark> getBookmarksAt(long snap, Address address);

	Iterable<? extends TraceBookmark> getBookmarksEnclosed(Range<Long> lifespan,
			AddressRange range);

	Iterable<? extends TraceBookmark> getBookmarksIntersecting(Range<Long> lifespan,
			AddressRange range);
}
