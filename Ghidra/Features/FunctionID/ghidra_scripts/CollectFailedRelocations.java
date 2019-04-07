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
//Opens all programs under a chosen domain folder, scans them to see if they
//have failed relocations, collects their numeric types, and prints them out
//(also the project path to the last example of that type)
//@category FunctionID
import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

public class CollectFailedRelocations extends GhidraScript {

	FidService service;

	@Override
	protected void run() throws Exception {
		service = new FidService();

		DomainFolder folder =
			askProjectFolder("Please select a project folder to RECURSIVELY look for failed relocations:");

		ArrayList<DomainFile> programs = new ArrayList<DomainFile>();
		findPrograms(programs, folder);
		TreeMap<Integer, String> failedRelocations = findFailedRelocations(programs);
		Msg.info(this, "failed relocations:");
		for (Entry<Integer, String> entry : failedRelocations.entrySet()) {
			Msg.info(this, "    " + entry.getKey() + ": " + entry.getValue());
		}
	}

	private TreeMap<Integer, String> findFailedRelocations(ArrayList<DomainFile> programs) {
		TreeMap<Integer, String> result = new TreeMap<Integer, String>();
		for (DomainFile domainFile : programs) {
			if (monitor.isCancelled()) {
				break;
			}
			Program program = null;
			try {
				program = (Program) domainFile.getDomainObject(this, false, false, monitor);
				BookmarkManager bookmarkManager = program.getBookmarkManager();
				Iterator<Bookmark> bookmarksIterator = bookmarkManager.getBookmarksIterator();
				while (bookmarksIterator.hasNext()) {
					Bookmark bookmark = bookmarksIterator.next();
					if (bookmark == null) {
						continue;// skip deleted bookmark
					}
					String category = bookmark.getCategory();
					if (category.startsWith("Relocation_Type_")) {
						String string = category.substring(category.lastIndexOf("_") + 1);
						try {
							Integer number = Integer.parseInt(string);
							result.put(number, domainFile.getPathname());
						}
						catch (NumberFormatException ne) {
							Msg.error(this, "NFE on '" + string + "'", ne);
						}
					}
				}
			}
			catch (Exception e) {
				Msg.warn(this, "problem looking at " + domainFile.getName(), e);
			}
			finally {
				if (program != null) {
					program.release(this);
				}
			}
		}
		return result;
	}

	private void findPrograms(ArrayList<DomainFile> programs, DomainFolder folder)
			throws VersionException, CancelledException, IOException {
		DomainFile[] files = folder.getFiles();
		for (DomainFile domainFile : files) {
			if (monitor.isCancelled()) {
				return;
			}
			if (domainFile.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
				programs.add(domainFile);
			}
		}
		DomainFolder[] folders = folder.getFolders();
		for (DomainFolder domainFolder : folders) {
			if (monitor.isCancelled()) {
				return;
			}
			findPrograms(programs, domainFolder);
		}
	}
}
