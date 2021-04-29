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

import ghidra.program.model.listing.BookmarkType;

public interface TraceBookmarkType extends BookmarkType {
	void setIcon(ImageIcon icon);

	void setMarkerColor(Color color);

	void setMarkerPriority(int priority);

	Collection<String> getCategories();

	int countBookmarks();

	Collection<TraceBookmark> getBookmarks();
}
