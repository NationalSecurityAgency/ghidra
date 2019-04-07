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
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;

public class FindInvalidFlowType extends GhidraScript {

	@Override
	protected void run() throws Exception {

		if (currentProgram == null) {
			return;
		}

		for (Instruction instr : currentProgram.getListing().getInstructions(currentAddress.add(1),
			true)) {

			if (instr.getFlowType() == RefType.INVALID) {

				goTo(instr.getAddress());
				return;

			}

		}

		popup("Invalid FlowType not found below current point");

	}

}
