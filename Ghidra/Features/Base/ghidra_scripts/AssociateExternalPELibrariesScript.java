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
// This script will attempt to associate external libraries, that have already been imported into 
// Ghidra, with the libraries referenced in the current PE program. Once external libraries are 
// associated with an imported project library, all external library function references will be
// enabled, allowing navigation from the program to the external library functions. NOTES: The 
// script only works on Windows PE programs. The script will only work if the libraries have already  
// been imported to the project. If it finds more than one match, it will notify the user and use
// the first found match.
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.util.exception.CancelledException;

public class AssociateExternalPELibrariesScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("No open program.");
			return;
		}

		if (!currentProgram.getExecutableFormat().equals(PeLoader.PE_NAME)) {
			println("This script only works on Windows PE's.");
			return;
		}

		DomainFolder libraryFolder =
			askProjectFolder("Choose the folder where the libraries have been imported");

		DomainFile[] files = libraryFolder.getFiles();
		List<DomainFile> libraries = Arrays.asList(files);

		ExternalManager externalManager = currentProgram.getExternalManager();
		String[] externalLibraryNames = externalManager.getExternalLibraryNames();

		for (String name : externalLibraryNames) {
			monitor.checkCancelled();

			List<DomainFile> ciLibraries = getProgramsCaseInsensitive(name, libraries);
			if (ciLibraries.isEmpty()) {
				println("Cannot find associated program " + name + " in folder " +
					libraryFolder.getPathname() + ". Please import or relocate and rerun script.");
				continue;
			}
			if (ciLibraries.size() > 1) {
				println("Multiple matching programs " + name + " in folder " +
					libraryFolder.getPathname() + ". Using first found match " +
					ciLibraries.get(0).getName() + ".");
			}
			DomainFile library = ciLibraries.get(0);

			String path = library.getPathname();
			externalManager.setExternalPath(name, path, true);
			println("Successfully associated " + name);
		}

	}

	private List<DomainFile> getProgramsCaseInsensitive(String name, List<DomainFile> projectFiles)
			throws CancelledException {

		List<DomainFile> matchingFiles = new ArrayList<DomainFile>();

		for (DomainFile file : projectFiles) {
			monitor.checkCancelled();

			if (!file.getName().equalsIgnoreCase(name)) {
				continue;
			}

			if (!Program.class.isAssignableFrom(file.getDomainObjectClass())) {
				continue;
			}
			matchingFiles.add(file);
		}
		return matchingFiles;
	}
}
