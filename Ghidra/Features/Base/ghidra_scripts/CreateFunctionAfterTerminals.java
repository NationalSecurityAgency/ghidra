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
//Create a function after terminal instruction

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.PartitionCodeSubModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;

public class CreateFunctionAfterTerminals extends GhidraScript {

	private int numTried;
	private int numCreated;

	@Override
	public void run() throws Exception {
		InstructionIterator instIter = currentProgram.getListing().getInstructions(true);
		while (instIter.hasNext() && !monitor.isCancelled()) {
			Instruction instruction = instIter.next();
			if (instruction.getFlowType() == RefType.TERMINATOR) {
				Address funcAddr = instruction.getMaxAddress().next();
				Function func = currentProgram.getFunctionManager().getFunctionContaining(funcAddr);
				if (func == null) {
					numTried++;
					Instruction funcBeginInstr =
						currentProgram.getListing().getInstructionAt(funcAddr);
					if (funcBeginInstr != null) {
						createFunctionNear(funcAddr);
					}
				}
			}
		}
		// Log what we did
		Address histAddr = currentProgram.getMemory().getMinAddress();
		String tmpString = "\nScript: CreateFunctionAfterTerminals()";
		tmpString = "   Found  " + numTried + " locations.  Created " + numCreated + " functions.";
	}

	protected Function createFunctionNear(Address addr) throws Exception {
		PartitionCodeSubModel partitionBlockModel = new PartitionCodeSubModel(currentProgram);
		CodeBlock[] blocks = partitionBlockModel.getCodeBlocksContaining(addr, monitor);
		if (blocks.length != 1) {
			println("*************************** Couldn't handle it at " + addr.toString());
			return null;
		}
		Address address = blocks[0].getFirstStartAddress();
		Function func = null;
		try {
			func = createFunction(address, null);
		}
		catch (Exception e) {
			println("Exception thrown creating function:\n" + e.getMessage());
		}
		if (func == null) {
			println("Tried to create Function At " + addr.toString() + " unsuccessfully");
		}
		else {
			println("Created Function At " + address.toString());
			numCreated++;
		}
		return func;
	}

}
