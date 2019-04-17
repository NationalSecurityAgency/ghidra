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
package ghidra.app.plugin.core.bookmark;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

/**
 * Command to delete a number of bookmarks.
 */
public class BookmarkDeleteBackgroundCmd extends BackgroundCommand {

	private Bookmark[] bookmarks;

	/**
	 * Delete an array of Bookmarks.
	 * @param bookmarks the array of bookmarks to be deleted.
	 */
	public BookmarkDeleteBackgroundCmd(Bookmark[] bookmarks) {
		super("Delete Bookmarks", true, true, false);
		this.bookmarks = bookmarks;
	}

	/**
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		BookmarkManager mgr = ((Program) obj).getBookmarkManager();
		monitor.initialize(bookmarks.length);
		for (int i = 0; i < bookmarks.length; i++) {
			if (monitor.isCancelled()) {
				return true;
			}
			Bookmark bm = bookmarks[i];
			mgr.removeBookmark(bm);
			monitor.setProgress(i);
		}
		return true;
	}
}
