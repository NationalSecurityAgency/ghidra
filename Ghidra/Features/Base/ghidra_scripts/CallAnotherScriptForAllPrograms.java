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
// Shows how to run a script on all of the programs within the current project.
// NOTE: Script will only process unversioned and checked-out files.
//@category Examples

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

import java.io.IOException;

public class CallAnotherScriptForAllPrograms extends GhidraScript {

	// The script referenced in the following line should be replaced with the script to be called
	private static String SUBSCRIPT_NAME = "AddCommentToProgramScript.java";

	@Override
	public void run() throws Exception {

		if (currentProgram != null) {
			popup("This script should be run from a tool with no open programs");
			return;
		}

		Project project = state.getProject();
		ProjectData projectData = project.getProjectData();
		DomainFolder rootFolder = projectData.getRootFolder();
		recurseProjectFolder(rootFolder);
	}

	private void recurseProjectFolder(DomainFolder domainFolder) throws CancelledException,
			IOException {
		DomainFile[] files = domainFolder.getFiles();
		for (DomainFile domainFile : files) {
			processDomainFile(domainFile);
		}
		DomainFolder[] folders = domainFolder.getFolders();
		for (DomainFolder folder : folders) {
			recurseProjectFolder(folder);
		}
	}

	private void processDomainFile(DomainFile domainFile) throws CancelledException, IOException {
		if (!ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(domainFile.getContentType())) {
			return; // skip non-Program files
		}
		if (domainFile.isVersioned() && !domainFile.isCheckedOut()) {
			println("WARNING! Skipping versioned file - not checked-out: " +
				domainFile.getPathname());
			return;
		}
		Program program = null;
		try {
			program =
				(Program) domainFile.getDomainObject(this, true /*upgrade*/,
					false /*don't recover*/, monitor);
			processProgram(program);
		}
		catch (VersionException e) {
			println("ERROR! Failed to process file due to upgrade issue: " +
				domainFile.getPathname());
		}
		finally {
			if (program != null) {
				program.release(this);
			}
		}
	}

	private void processProgram(Program program) throws CancelledException, IOException {
		/* Do you program work here */
		println("Processing: " + program.getDomainFile().getPathname());
		monitor.setMessage("Processing: " + program.getDomainFile().getName());
		int id = program.startTransaction("Batch Script Transaction");
		try {
			GhidraState newState =
				new GhidraState(state.getTool(), state.getProject(), program, null, null, null);
			runScript(SUBSCRIPT_NAME, newState);
		}
		catch (Exception e) {
			printerr("ERROR! Exception occurred while processing file: " +
				program.getDomainFile().getPathname());
			printerr("       " + e.getMessage());
			e.printStackTrace();
			return;
		}
		finally {
			program.endTransaction(id, true);
		}

		// ...save any changes
		program.save("Changes made by script: " + SUBSCRIPT_NAME, monitor);
	}
}
