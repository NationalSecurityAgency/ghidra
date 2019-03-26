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
//Opens all programs under a chosen domain folder, grabs their error count,
//then sorts in increasing error order and prints them
//@category FunctionID
import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

import java.io.IOException;
import java.util.*;

public class FindErrors extends GhidraScript {

	@Override
	protected void run() throws Exception {
		DomainFolder folder =
			askProjectFolder("Please select a project folder to RECURSIVELY look for full hash:");

		ArrayList<DomainFile> programs = new ArrayList<DomainFile>();
		findPrograms(programs, folder);
		ArrayList<Pair<DomainFile, Integer>> results = new ArrayList<Pair<DomainFile, Integer>>();
		monitor.initialize(programs.size());
		for (DomainFile domainFile : programs) {
			if (monitor.isCancelled()) {
				return;
			}
			monitor.incrementProgress(1);
			Program program = null;
			try {
				program = (Program) domainFile.getDomainObject(this, false, false, monitor);
				BookmarkManager bookmarkManager = program.getBookmarkManager();
				int errors = bookmarkManager.getBookmarkCount(BookmarkType.ERROR);
				results.add(new Pair<DomainFile, Integer>(domainFile, errors));
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

		Collections.sort(results, new Comparator<Pair<DomainFile, Integer>>() {
			@Override
			public int compare(Pair<DomainFile, Integer> o1, Pair<DomainFile, Integer> o2) {
				return o1.second - o2.second;
			}
		});

		for (Pair<DomainFile, Integer> pair : results) {
			println(pair.first.toString() + ": " + pair.second);
		}
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
