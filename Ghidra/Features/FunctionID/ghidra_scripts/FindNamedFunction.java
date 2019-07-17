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
//Opens all programs under a chosen domain folder, scans them for functions
//that match a user supplied name, and prints info about the match.
//@category FunctionID
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

import java.io.IOException;
import java.util.ArrayList;

public class FindNamedFunction extends GhidraScript {

	FidService service;

	@Override
	protected void run() throws Exception {
		service = new FidService();

		DomainFolder folder =
			askProjectFolder("Please select a project folder to RECURSIVELY look for a named function:");
		String name =
			askString("Please enter function name",
				"Please enter the function name you're looking for:");

		ArrayList<DomainFile> programs = new ArrayList<DomainFile>();
		findPrograms(programs, folder);
		findFunction(programs, name);
	}

	private void findFunction(ArrayList<DomainFile> programs, String name) {
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
					if (function.getName().equals(name)) {
						println("found " + name + " in " + domainFile.getPathname());
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
