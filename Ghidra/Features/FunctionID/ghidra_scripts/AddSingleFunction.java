
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
//Adds the function at the current address to the chosen FID library.
//@category FunctionID

import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidService;
import ghidra.feature.fid.service.FidServiceLibraryIngest;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class AddSingleFunction extends GhidraScript {

	private FidDB fidDb = null;

	@Override
	protected void run() throws Exception {

		if (currentProgram == null) {
			printerr("No current program");
			return;
		}
		if (currentAddress == null) {
			printerr("No current address (?)");
			return;
		}
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Function function = functionManager.getFunctionContaining(currentAddress);
		if (function == null) {
			printerr("No current function");
			return;
		}

		FidService service = new FidService();
		FidHashQuad hashFunction = service.hashFunction(function);
		if (hashFunction == null) {
			printerr("Function too small");
			return;
		}

		FidFileManager fidFileManager = FidFileManager.getInstance();
		List<FidFile> userFid = fidFileManager.getUserAddedFiles();
		if (userFid.isEmpty()) {
			printerr("No available FID DB");
			return;
		}
		FidFile fidFile =
			askChoice("FID database", "Choose FID database", userFid, userFid.get(0));
		try {
			fidDb = fidFile.getFidDB(true);

			List<LibraryRecord> libraries = fidDb.getAllLibraries();
			LibraryRecord library;
			if (libraries == null || libraries.isEmpty()) {
				println("No libraries found. Creating one...");

				String libraryFamilyName =
					askString("Library Family Name", "Choose Library Family Name");
				String libraryVersion = askString("Library Version", "Choose Library Version");
				String libraryVariant = askString("Library Variant", "Choose Library Variant");
				LanguageID languageId = currentProgram.getLanguageID();
				Language language = currentProgram.getLanguage();
				CompilerSpec compilerSpec = currentProgram.getCompilerSpec();
				library = fidDb.createNewLibrary(libraryFamilyName, libraryVersion, libraryVariant,
					getGhidraVersion(), languageId, language.getVersion(),
					language.getMinorVersion(), compilerSpec.getCompilerSpecID());
			}
			else {
				library =
					askChoice("FID libraries", "Choose FID library", libraries, libraries.get(0));
			}

			boolean disableNamespaceStripping =
				askYesNo("Namespace stripping",
					"Do you want to disable namespace stripping?");

			long offset = function.getEntryPoint().getOffset();

			boolean hasTerminator = FidServiceLibraryIngest.findTerminator(function, monitor);

			DomainFile domainFile = getCurrentProgram().getDomainFile();

			fidDb.createNewFunction(library, hashFunction,
				function.getName(disableNamespaceStripping), offset, domainFile.getName(),
				hasTerminator);

			fidDb.saveDatabase("Saving", monitor);
		}
		finally {
			fidDb.close();
		}
	}
}
