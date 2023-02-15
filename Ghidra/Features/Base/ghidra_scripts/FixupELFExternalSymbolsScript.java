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
// Fixes up any unresolved external symbols (for ELF binaries).
//
// The current program's "External Programs" list needs to be correct before running
// this script.
//
// This script can be run multiple times without harm, generally after updating the "External Programs"
// list.
//
//@category Symbol
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.Loaded;
import ghidra.framework.model.*;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ELFExternalSymbolResolver;
import ghidra.util.Msg;
import ghidra.util.exception.VersionException;

public class FixupELFExternalSymbolsScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (!ElfLoader.ELF_NAME.equals(currentProgram.getExecutableFormat())) {
			Msg.showError(this, null, "FixupELFExternalSymbols",
				"Current program is not an ELF program!  (" + currentProgram.getExecutableFormat() +
					")");
			return;
		}
		MessageLog messageLog = new MessageLog();
		Object consumer = new Object();
		ProjectData projectData = currentProgram.getDomainFile().getParent().getProjectData();
		List<Loaded<Program>> loadedPrograms = new ArrayList<>();

		// Add current program to list
		loadedPrograms.add(new Loaded<>(currentProgram, currentProgram.getName(),
			currentProgram.getDomainFile().getPathname()));

		// Add external libraries to list
		for (Library extLibrary : ELFExternalSymbolResolver.getLibrarySearchList(currentProgram)) {
			monitor.checkCanceled();
			String libName = extLibrary.getName();
			String libPath = extLibrary.getAssociatedProgramPath();
			if (libPath == null) {
				continue;
			}

			DomainFile libDomainFile = projectData.getFile(libPath);
			if (libDomainFile == null) {
				messageLog.appendMsg("Referenced external program not found: " + libPath);
				continue;
			}

			DomainObject libDomainObject = null;
			try {
				libDomainObject =
					libDomainFile.getDomainObject(consumer, false, false, monitor);
				if (libDomainObject instanceof Program program) {
					loadedPrograms.add(new Loaded<>(program, libName, libPath));
				}
				else {
					messageLog
							.appendMsg("Referenced external program is not a program: " + libPath);
				}
			}
			catch (IOException e) {
				// failed to open library
				messageLog.appendMsg("Failed to open library dependency project file: " +
					libDomainFile.getPathname());
			}
			catch (VersionException e) {
				messageLog.appendMsg(
					"Referenced external program requires updgrade, unable to consider symbols: " +
						libPath);
			}
		}

		// Resolve symbols
		ELFExternalSymbolResolver.fixUnresolvedExternalSymbols(loadedPrograms, messageLog, monitor);

		// Cleanup
		for (int i = 1; i < loadedPrograms.size(); i++) {
			loadedPrograms.get(i).release(consumer);
		}
		Msg.info(this, messageLog.toString());
	}

}
