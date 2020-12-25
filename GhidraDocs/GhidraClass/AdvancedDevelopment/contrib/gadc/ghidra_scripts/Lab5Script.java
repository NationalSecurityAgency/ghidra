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
//This script searches through all instructions that are
//moving a scalar into a register
//and sets an EOL comment in the form "[register] = [value]"
//@category GADC

import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

public class Lab5Script extends GhidraScript {

	@Override
	public void run() throws Exception {

		for (Instruction instruction = getFirstInstruction(); instruction != null; instruction =
			getInstructionAfter(instruction)) {
			if (monitor.isCancelled()) {
				break;
			}
			if (instruction.getNumOperands() != 2) {
				continue;
			}

			Object[] opObjects0 = instruction.getOpObjects(0);
			if (opObjects0.length != 1 || !(opObjects0[0] instanceof Register)) {
				continue;
			}

			Object[] opObjects1 = instruction.getOpObjects(1);
			if (opObjects1.length != 1 || !(opObjects1[0] instanceof Scalar)) {
				continue;
			}

			Register register = (Register) opObjects0[0];
			Scalar scalar = (Scalar) opObjects1[0];
			String comment =
				"[" + register.getName() + "]=[" + scalar.toString(16, false, false, "", "") + "]";
			setEOLComment(instruction.getMinAddress(), comment);
		}
	}
}
