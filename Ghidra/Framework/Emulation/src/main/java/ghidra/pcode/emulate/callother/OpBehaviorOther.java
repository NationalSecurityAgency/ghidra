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
package ghidra.pcode.emulate.callother;

import ghidra.pcode.emulate.Emulate;
import ghidra.program.model.pcode.Varnode;

public interface OpBehaviorOther {

	/**
	 * Evaluate the CALLOTHER op which corresponds to this behavior.
	 * @param emu emulator which contains associated memory state
	 * @param out output varnode or null if no assignment has been
	 * made.  Implementation is responsible for updating memory 
	 * state appropriately.
	 * @param inputs input varnodes passed as parameters to this
	 * pcodeop.  The inputs[0] value corresponds to the index value of this 
	 * pcodeop and can generally be ignored.  The inputs[1] value
	 * corresponds to the first (leftmost) parameter passed to 
	 * this pcodeop within the language implementation.
	 */
	public void evaluate(Emulate emu, Varnode out, Varnode[] inputs);
}
