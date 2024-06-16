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
package sarif.export.bkmk;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.listing.Bookmark;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.BookmarksSarifMgr;

public class SarifBookmarkWriter extends AbstractExtWriter {
	
	private List<Bookmark> bookmarks = new ArrayList<>();

	public SarifBookmarkWriter(List<Bookmark> target, Writer baseWriter) throws IOException {
		super(baseWriter);
		bookmarks = target;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genBookmarks(monitor);
		root.add("bookmarks", objects);
	}

	private void genBookmarks(TaskMonitor monitor) throws CancelledException, IOException{
		monitor.initialize(bookmarks.size());
		for (Bookmark b : bookmarks) {
			ExtBookmark isf = new ExtBookmark(b);
			SarifObject sarif = new SarifObject(BookmarksSarifMgr.SUBKEY, BookmarksSarifMgr.KEY, getTree(isf), b.getAddress(), b.getAddress());
			objects.add(getTree(sarif));
			monitor.increment();
		}
	}
}
