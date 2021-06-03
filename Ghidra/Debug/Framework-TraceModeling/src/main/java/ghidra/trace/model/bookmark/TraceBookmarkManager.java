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

import java.awt.Color;
import java.util.Collection;

import javax.swing.ImageIcon;

import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;

public interface TraceBookmarkManager extends TraceBookmarkOperations {
	TraceBookmarkSpace getBookmarkSpace(AddressSpace space, boolean createIfAbsent);

	TraceBookmarkRegisterSpace getBookmarkRegisterSpace(TraceThread thread, boolean createIfAbsent);

	TraceBookmarkRegisterSpace getBookmarkRegisterSpace(TraceStackFrame frame,
			boolean createIfAbsent);

	/**
	 * Define (or redefine) a bookmark type.
	 * 
	 * Bookmark type metadata are not stored in the database. To customize these things, a plugin
	 * must call this method for every opened program
	 * 
	 * @param name a name to uniquely identify the type
	 * @param icon an icon for displaying the mark (usually in the listing margin)
	 * @param color a color for displaying the mark (usually in the listing background)
	 * @param priority a priority to determine which mark is displayed when multiple are present at
	 *            the same location
	 * @return the newly-defined type
	 */
	TraceBookmarkType defineBookmarkType(String name, ImageIcon icon, Color color, int priority);

	/**
	 * Get the defined bookmark types.
	 * 
	 * @return the types
	 */
	Collection<? extends TraceBookmarkType> getDefinedBookmarkTypes();

	TraceBookmarkType getBookmarkType(String name);

	TraceBookmark getBookmark(long id);

	Collection<? extends TraceBookmark> getBookmarksAdded(long from, long to);

	Collection<? extends TraceBookmark> getBookmarksRemoved(long from, long to);
}
