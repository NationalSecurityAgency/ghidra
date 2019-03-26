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
package ghidra.pcodeCPort.slghpatexpress;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.slghsymbol.OperandSymbol;

public class OperandResolve {
	public VectorSTL<OperandSymbol> operands;
	public int base;			// Current base operand (as we traverse the pattern equation from left to right)
	public int offset;			// Bytes we have traversed from the LEFT edge of the current base
	public int cur_rightmost;	// (resulting) rightmost operand in our pattern
	public int size;			// (resulting) bytes traversed from the LEFT edge of the rightmost

	public OperandResolve(VectorSTL<OperandSymbol> ops) {
		operands = ops;
		base = -1;
		offset = 0;
		cur_rightmost = -1;
		size = 0;
	}
}

