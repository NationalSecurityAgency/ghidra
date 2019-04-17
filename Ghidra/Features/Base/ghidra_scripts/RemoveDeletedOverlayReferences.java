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
//Removes left over references from deleted overlays.
//@category Update

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;


public class RemoveDeletedOverlayReferences extends GhidraScript {

	@Override
	public void run() throws Exception {
		ReferenceManager refMgr = currentProgram.getReferenceManager();
		AddressIterator it = refMgr.getReferenceDestinationIterator(currentProgram.getMinAddress(), true);
		int totalRefs = 0;
		int totalDeletedRefs = 0;
		List<Reference> badRefs = new ArrayList<Reference>();
		while(it.hasNext()) {
			Address address = it.next();
			ReferenceIterator refIter = refMgr.getReferencesTo(address);
			while(refIter.hasNext()) {
				Reference ref = refIter.next();
				totalRefs++;
				if (ref.getFromAddress().getAddressSpace().getType() == AddressSpace.TYPE_DELETED) {
					totalDeletedRefs++;
					badRefs.add(ref);
				}
			}
		}
		for (Reference reference : badRefs) {
			refMgr.delete(reference);
		}
		this.println("total refs = "+totalRefs+",  deleted refs = "+totalDeletedRefs);
		
	}

}
