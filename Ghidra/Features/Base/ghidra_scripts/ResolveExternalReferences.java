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
import static generic.util.Beanify.beanify;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

public class ResolveExternalReferences extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Program program = getState().getCurrentProgram();
		ReferenceManager referenceManager = program.getReferenceManager();
		ExternalManager externalManager = program.getExternalManager();
		ReferenceIterator externalReferences = referenceManager.getExternalReferences();
		while (externalReferences.hasNext()) {
			Reference reference = externalReferences.next();
			if (reference instanceof ExternalReference) {
				ExternalReference externalReference = (ExternalReference) reference;
				ExternalLocation externalLocation = externalReference.getExternalLocation();
				String externalLibraryPath =
					externalManager.getExternalLibraryPath(externalLocation.getLibraryName());
				println(beanify(externalLocation).toString());
				println("externalLibraryPath = " + externalLibraryPath);
			}
			else {
				printerr("Asked for external references, but got: " + reference);
			}
			println("");
		}

		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator allSymbols = symbolTable.getAllSymbols(false);
		while (allSymbols.hasNext()) {
			Symbol symbol = allSymbols.next();

			if (symbol.isExternalEntryPoint()) {
				println("external entry point: " + beanify(symbol));
			}
		}
	}
}
