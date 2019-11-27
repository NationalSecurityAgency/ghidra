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
// Opens all programs under a chosen domain folder, scans them for functions
// that match a user supplied FID hash and prints info about the matching function
//@category FunctionID
import java.io.IOException;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.plugin.HashLookupListMode;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

public class FindFunctionByHash extends GhidraScript {

	FidService service;

	@Override
	protected void run() throws Exception {
		service = new FidService();

		DomainFolder folder = askProjectFolder(
			"Please select a project folder to RECURSIVELY look for a named function:");
		String hashString = askString("Please enter function hash",
			"Please enter the (hex) function hash you're looking for:");
		long hash = NumericUtilities.parseHexLong(hashString);
		List<HashLookupListMode> choices =
			Arrays.asList(HashLookupListMode.FULL, HashLookupListMode.SPECIFIC);
		HashLookupListMode hashType = askChoice("Please choose hash type",
			"Please select the type of hash", choices, choices.get(1));

		ArrayList<DomainFile> programs = new ArrayList<>();
		findPrograms(programs, folder);
		findFunction(programs, hash, hashType);
	}

	private void findFunction(ArrayList<DomainFile> programs, long hash,
			HashLookupListMode hashType) {
		for (DomainFile domainFile : programs) {
			if (monitor.isCancelled()) {
				return;
			}
			Program program = null;
			try {
				program = (Program) domainFile.getDomainObject(this, false, false, monitor);
				FunctionManager functionManager = program.getFunctionManager();
				FunctionIterator functions = functionManager.getFunctions(true);
				for (Function function : functions) {
					if (monitor.isCancelled()) {
						return;
					}
					FidHashQuad hashQuad = service.hashFunction(function);
					if (hashQuad == null) {
						continue;
					}
					if ((hashType == HashLookupListMode.FULL && hashQuad.getFullHash() == hash) ||
						(hashType == HashLookupListMode.SPECIFIC &&
							hashQuad.getSpecificHash() == hash)) {
						println("found " + function.getName() + " at " + function.getEntryPoint() +
							" in " + domainFile.getPathname());
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
