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
package sarif.managers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.bkmk.SarifBookmarkWriter;

public class BookmarksSarifMgr extends SarifMgr {

	public static String KEY = "BOOKMARKS";
	public static String SUBKEY = "Bookmark";

	private BookmarkManager bookmarkMgr;

	public BookmarksSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
		this.bookmarkMgr = program.getBookmarkManager();
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////
	
	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor monitor)
			throws AddressFormatException, CancelledException {
		processBookmark(result, options == null || options.isOverwriteBookmarkConflicts());
		return true;
	}

	private void processBookmark(Map<String, Object> result, boolean overwrite)  {

		Address addr = null;
		try {
			addr = getLocation(result);
		} catch (AddressOverflowException e1) {
			log.appendException(e1);
		}

		String type = (String) result.getOrDefault("kind", BookmarkType.NOTE);
		String category = (String) result.getOrDefault("name", "");
		String comment = (String) result.getOrDefault("comment", "");

		try {
			boolean hasExistingBookmark = bookmarkMgr.getBookmark(addr, type, category) != null;
			if (overwrite || !hasExistingBookmark) {
				bookmarkMgr.setBookmark(addr, type, category, comment);
			}
			if (!overwrite && hasExistingBookmark) {
				log.appendMsg("Conflicting '" + type + "' BOOKMARK ignored at: " + addr);
			}
		} catch (Exception e) {
			log.appendException(e);
			return;
		}

	}

	
	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	void write(JsonArray results, AddressSetView set, TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Writing BOOKMARKS ...");
		//writeBookmarks(results, set, monitor);
		
		List<Bookmark> request = new ArrayList<>();
		BookmarkType[] types = bookmarkMgr.getBookmarkTypes();
		for (int i = 0; i < types.length; i++) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			String typeStr = types[i].getTypeString();
			AddressSetView bmSet = bookmarkMgr.getBookmarkAddresses(typeStr);
			if (set != null) {
				bmSet = set.intersect(bmSet);
			}
			AddressIterator iter = bmSet.getAddresses(true);
			while (iter.hasNext()) {
				Address addr = iter.next();
				Bookmark[] bookmarks = bookmarkMgr.getBookmarks(addr, typeStr);
				for (int n = 0; n < bookmarks.length; n++) {
					request.add(bookmarks[n]);
				}
			}
		}
		
		writeAsSARIF(request, results);
	}

	public static void writeAsSARIF(List<Bookmark> request, JsonArray results)
			throws IOException {
		SarifBookmarkWriter writer = new SarifBookmarkWriter(request, null);
		new TaskLauncher(new SarifWriterTask(SUBKEY, writer, results), null);
	}

}
