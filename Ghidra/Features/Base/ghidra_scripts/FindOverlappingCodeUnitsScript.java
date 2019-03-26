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
//Displays a list of addresses where instructions and defined data
//overlap other instructions or defined data.
//@category Search

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;

public class FindOverlappingCodeUnitsScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		AddressSet set = new AddressSet();
		Listing listing = currentProgram.getListing();
		InstructionIterator instrIter = listing.getInstructions(true);
		while (instrIter.hasNext() && !monitor.isCancelled()) {
			Instruction instr = instrIter.next();
			monitor.setMessage(instr.getMinAddress().toString());
			int length = instr.getLength();
			for (int i = 1; i < length; i++) {
				Address addr = instr.getMinAddress().add(i);
				if (listing.getInstructionAt(addr) != null ||
					listing.getDefinedDataAt(addr) != null) {
					set.addRange(addr, addr);
				}
			}
		}

		DataIterator dataIter = listing.getDefinedData(true);
		while (dataIter.hasNext() && !monitor.isCancelled()) {
			Data data = dataIter.next();
			monitor.setMessage(data.getMinAddress().toString());
			int length = data.getLength();
			for (int i = 1; i < length; i++) {
				Address addr = data.getMinAddress().add(i);
				if (listing.getInstructionAt(addr) != null ||
					listing.getDefinedDataAt(addr) != null) {
					set.add(addr);
				}
			}
		}

		if (set.getNumAddresses() == 0) {
			println("No overlapping codeunits found!");
			return;
		}

		show("Overlapping Code Units", set);
	}
}
