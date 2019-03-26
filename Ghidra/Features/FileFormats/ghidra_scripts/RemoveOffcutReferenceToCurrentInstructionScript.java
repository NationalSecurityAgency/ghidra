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
//Removes any offcut references to the current code unit.
//@category References

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

public class RemoveOffcutReferenceToCurrentInstructionScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		Instruction instruction = getInstructionAt(currentAddress);

		if ( instruction != null ) {
			removeReferences( instruction );
		}

		Data data = getDataAt(currentAddress);

		if ( data != null ) {
			removeReferences( data );
		}
	}

	private void removeReferences(CodeUnit codeUnit) {
		Address address = currentAddress.add( 1 );

		while ( address.compareTo( codeUnit.getMaxAddress() ) <= 0) {

			if ( monitor.isCancelled() ) {
				break;
			}

			Reference [] referencesTo = getReferencesTo(address);

			for ( Reference reference : referencesTo ) {

				if ( monitor.isCancelled() ) {
					break;
				}

				removeReference(reference);
			}

			address = address.add( 1 );
		}
	}
}
