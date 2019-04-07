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
//Iterates over all instructions in the current program.
//@category Iteration

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;

public class IterateInstructionsScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		Instruction instruction = getFirstInstruction();

		while (true) {

			if (monitor.isCancelled()) {
				break;
			}

			if (instruction == null) {
				break;
			}

			StringBuffer buffer = new StringBuffer();

			buffer.append(instruction.getMinAddress());
			buffer.append(' ');
			buffer.append(instruction.getMnemonicString());
			buffer.append(' ');

			int nOperands = instruction.getNumOperands();

			for (int i = 0 ; i < nOperands ; ++i) {
				String operand = instruction.getDefaultOperandRepresentation(i);
				buffer.append(operand);
				buffer.append(' ');
			}

			println(buffer.toString());

			instruction = getInstructionAfter(instruction);
		}
	}

}
