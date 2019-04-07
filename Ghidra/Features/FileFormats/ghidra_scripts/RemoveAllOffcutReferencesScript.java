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
//@category References

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.*;


public class RemoveAllOffcutReferencesScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		Listing listing = currentProgram.getListing();
		ReferenceManager referenceManager = currentProgram.getReferenceManager();
		AddressIterator iterator = referenceManager.getReferenceDestinationIterator(currentProgram.getMinAddress(), true);
		while (iterator.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
	 		Address address = iterator.next();
 			CodeUnit codeUnit = listing.getCodeUnitContaining(address);
 			if (codeUnit != null) {
 				if (!codeUnit.getMinAddress().equals(address)) {
 					monitor.setMessage("Removing offcut reference at "+address);
 			 		ReferenceIterator referencesTo = referenceManager.getReferencesTo(address);
 			 		while (referencesTo.hasNext()) {
 			 			if (monitor.isCancelled()) {
 							break;
 						}
 			 			Reference reference = referencesTo.next();
 			 			referenceManager.delete(reference);
 			 		}
				}
			}
		}
	}

}
