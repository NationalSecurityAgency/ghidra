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
package ghidra.trace.database.bookmark;

import java.awt.Color;
import java.util.*;

import javax.swing.ImageIcon;

import ghidra.trace.model.bookmark.TraceBookmark;
import ghidra.trace.model.bookmark.TraceBookmarkType;
import ghidra.util.LockHold;

public class DBTraceBookmarkType implements TraceBookmarkType {
	static int nextId = 1;

	static synchronized int nextId() {
		return nextId++;
	}

	protected final DBTraceBookmarkManager manager;
	protected final String name;
	protected ImageIcon icon;
	protected Color color;
	protected int priority;

	protected final int id = nextId();
	protected final Collection<TraceBookmark> bookmarkView;

	public DBTraceBookmarkType(DBTraceBookmarkManager manager, String name, ImageIcon icon,
			Color color, int priority) {
		this.manager = manager;
		this.name = name;
		this.icon = icon;
		this.color = color;
		this.priority = priority;

		// TODO: Can I forego the wrapper and just cast? It should already be unmodifiable.
		this.bookmarkView = Collections.unmodifiableCollection(manager.getBookmarksByType(name));
	}

	public DBTraceBookmarkType(DBTraceBookmarkManager manager, String name) {
		this(manager, name, null, null, -1);
	}

	@Override
	public String getTypeString() {
		return name;
	}

	@Override
	public ImageIcon getIcon() {
		return icon;
	}

	@Override
	public Color getMarkerColor() {
		return color;
	}

	@Override
	public int getMarkerPriority() {
		return priority;
	}

	@Override
	public int getTypeId() {
		return id;
	}

	@Override
	public void setIcon(ImageIcon icon) {
		this.icon = icon;
	}

	@Override
	public void setMarkerColor(Color color) {
		this.color = color;
	}

	@Override
	public void setMarkerPriority(int priority) {
		this.priority = priority;
	}

	@Override
	public Collection<String> getCategories() {
		try (LockHold hold = LockHold.lock(manager.getLock().readLock())) {
			Set<String> result = new HashSet<>();
			for (TraceBookmark bm : bookmarkView) {
				result.add(bm.getCategory());
			}
			return result;
		}
	}

	@Override
	public boolean hasBookmarks() {
		return !bookmarkView.isEmpty();
	}

	@Override
	public int countBookmarks() {
		return bookmarkView.size();
	}

	@Override
	public Collection<TraceBookmark> getBookmarks() {
		return bookmarkView;
	}
}
