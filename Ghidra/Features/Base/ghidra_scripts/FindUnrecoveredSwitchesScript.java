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
//Finds Unrecovered Switches by finding all computed jumps that currently don't have any good destination references.
//
//@author
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class FindUnrecoveredSwitchesScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		InstructionIterator iIter = currentProgram.getListing().getInstructions(true);

		AddressSet set = new AddressSet();

		while (iIter.hasNext()) {
			Instruction instruction = iIter.next();
			FlowType flow = instruction.getFlowType();

			if (flow.isJump() && flow.isComputed()) {
				Reference[] refs = instruction.getReferencesFrom();
				boolean hasFlowRef = false;
				for (Reference ref : refs) {
					RefType refType = ref.getReferenceType();
					if (refType.isFlow() && !refType.isFallthrough()) {
						hasFlowRef = true;
						break;
					}
				}
				if (!hasFlowRef) {
					set.addRange(instruction.getMinAddress(), instruction.getMaxAddress());
				}
			}
		}

		Address[] addresses = new Address[set.getNumAddressRanges()];
		int i = 0;
		for (AddressRange range : set) {
			addresses[i++] = range.getMinAddress();
		}

		if (SystemUtilities.isInHeadlessMode()) {
			Msg.error(
				this,
				"POSSIBLE BAD SWITCHES: The number of possible bad switches is: " +
					set.getNumAddressRanges());
		}
		else {
			this.show(addresses);

		}

	}

}
