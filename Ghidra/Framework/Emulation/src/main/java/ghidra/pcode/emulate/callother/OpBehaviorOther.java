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
package ghidra.pcode.emulate.callother;

import ghidra.pcode.emulate.Emulate;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

@Deprecated(since = "12.1", forRemoval = true)
public interface OpBehaviorOther {

	/**
	 * Evaluate the CALLOTHER op which corresponds to this behavior.
	 * @param emu emulator which contains associated memory state
	 * @param out output varnode or null if no assignment has been
	 * made.  Implementation is responsible for updating memory 
	 * state appropriately.
	 * @param inputs input varnodes passed as parameters to this
	 * pcodeop.  The original {@link PcodeOp#CALLOTHER} first input 
	 * has been stripped (i.e., CALLOTHER index value), leaving only 
	 * the inputs that were were specified as arguments to the named
	 * pcodeop within the language spec. 
	 */
	public void evaluate(Emulate emu, Varnode out, Varnode[] inputs);
}
