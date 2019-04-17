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
//@category iOS

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.CancelledException;

public class GetSymbolForDynamicAddress extends GhidraScript {
	private Address addressToLookFor;
	private boolean foundSymbol = false;
	private List<String> programsWithAddress = new ArrayList<>();

	@Override
	public void run() throws Exception {
		try {
			addressToLookFor = askAddress("Enter Dynamic Address",
				"Please enter the address you want to find a symbol for: ");
		}
		catch (CancelledException e) {
			println("User cancelled script");
			return;
		}
		String[] parts = currentProgram.getDomainFile().getPathname().split("/");
		String firmwareVersion = parts[1];
		Project project = state.getProject();
		ProjectData projectData = project.getProjectData();
		DomainFolder rootFolder = projectData.getRootFolder();
		DomainFolder folder = rootFolder.getFolder(firmwareVersion);
		if (folder == null) {
			println("Run this script from a program under an iOS firmware directory.");
			return;
		}
		processFolder(folder);
		if (!foundSymbol) {
			printFailureExplanation();
		}
	}

	private void processFolder(DomainFolder domainFolder) {
		if (foundSymbol) {
			return;
		}
		DomainFolder[] folders = domainFolder.getFolders();
		for (DomainFolder folder : folders) {
			processFolder(folder);
		}
		DomainFile[] files = domainFolder.getFiles();
		for (DomainFile file : files) {
			processFile(file);
		}
	}

	private void processFile(DomainFile file) {
		if (foundSymbol) {
			return;
		}
		DomainObject domainObject = null;
		try {
			domainObject =
				file.getDomainObject(this, true /* upgrade */, false /* do not recover */, monitor);
			if (domainObject instanceof Program) {
				Program program = (Program) domainObject;
				processProgram(program);
			}
		}
		catch (Exception e) {
			printerr(e.getMessage());
		}
		finally {
			if (domainObject != null) {
				domainObject.release(this);
			}
		}
	}

	private void processProgram(Program program) throws Exception {
		if (foundSymbol) {
			return;
		}
		if (!program.getLanguageID().equals(currentProgram.getLanguageID())) {
			return;
		}
		Memory memory = program.getMemory();
		if (memory.contains(addressToLookFor)) {
			programsWithAddress.add(program.getName());
			Listing listing = program.getListing();
			Function function = listing.getFunctionAt(addressToLookFor);
			if (function == null) {
				return;
			}
			String functionName = function.getName();
			demangleAndCreateSymbol(functionName);

			foundSymbol = true;
		}
	}

	private void demangleAndCreateSymbol(String functionName) throws Exception {
		String demangledName = attemptToDemangle(functionName);
		if (demangledName == null) {
			demangledName = functionName;
		}
		try {
			createLabel(addressToLookFor, demangledName, true);
			println("Created symbol \"" + demangledName + "\" for address: " + addressToLookFor);
		}
		catch (Exception e) {
			printerr(e.getMessage());
			printerr(
				"Tried to create symbol \"" + demangledName + "\" for address " + addressToLookFor);
		}
	}

	private void printFailureExplanation() {
		if (programsWithAddress.size() != 0) {
			println("No function existed at the address " + addressToLookFor.toString());
			println("The programs that contain the address are: ");
			for (String name : programsWithAddress) {
				println("\t" + name);
			}
		}
		else {
			println("Didn't find any programs that contain that address");
		}
	}

	private String attemptToDemangle(String name) throws Exception {

		DemangledObject demangledObject = DemanglerUtil.demangle(name);
		if (demangledObject != null) {
			return demangledObject.getName();
		}
		return null;
	}
}
