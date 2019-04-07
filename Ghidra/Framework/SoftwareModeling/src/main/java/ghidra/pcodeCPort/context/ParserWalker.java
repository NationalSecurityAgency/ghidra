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
package ghidra.pcodeCPort.context;

import ghidra.pcodeCPort.address.Address;
import ghidra.pcodeCPort.slghsymbol.Constructor;
import ghidra.pcodeCPort.slghsymbol.OperandSymbol;
import ghidra.pcodeCPort.space.AddrSpace;

public class ParserWalker {
	// A class for walking the ParserContext
	private ParserContext const_context;
	protected ConstructState point;	// The current node being visited
	protected int depth;			// Depth of the current node
	protected int[] breadcrumb;	// Path of operands from root

	public ParserWalker(ParserContext c) {
		const_context = c;
		breadcrumb = new int[32];
	}

	public ParserContext getParserContext() {
		return const_context;
	}

	public void baseState() {
		point = const_context.base_state;
		depth = 0;
		breadcrumb[0] = 0;
	}

	public void setOutOfBandState(Constructor ct, int index, ConstructState tempstate,
			ParserWalker otherwalker) {
		// Initialize walker for future calls into getInstructionBytes assuming -ct- is the current position in the walk
		ConstructState pt = otherwalker.point;
		int curdepth = otherwalker.depth;
		while (pt.ct != ct) {
			if (curdepth <= 0) {
				return;
			}
			curdepth -= 1;
			pt = pt.parent;
		}
		OperandSymbol sym = ct.getOperand(index);
		int i = sym.getOffsetBase();
		// if i<0, i.e. the offset of the operand is constructor relative
		// its possible that the branch corresponding to the operand
		// has not been constructed yet. Context expressions are
		// evaluated BEFORE the constructors branches are created.
		// So we have to construct the offset explicitly.
		if (i < 0) {
			tempstate.offset = pt.offset + sym.getRelativeOffset();
		}
		else {
			tempstate.offset = pt.resolve.get(index).offset;
		}

		tempstate.ct = ct;
		tempstate.length = pt.length;
		point = tempstate;
		depth = 0;
		breadcrumb[0] = 0;
	}

	public boolean isState() {
		return (point != null);
	}

	public void pushOperand(int i) {
		breadcrumb[depth++] = i + 1;
		point = point.resolve.get(i);
		breadcrumb[depth] = 0;
	}

	public void popOperand() {
		point = point.parent;
		depth -= 1;
	}

	public int getOffset(int i) {
		if (i < 0) {
			return point.offset;
		}
		ConstructState op = point.resolve.get(i);
		return op.offset + op.length;
	}

	public Constructor getConstructor() {
		return point.ct;
	}

	public int getOperand() {
		return breadcrumb[depth];
	}

	public FixedHandle getParentHandle() {
		return point.hand;
	}

	public FixedHandle getFixedHandle(int i) {
		return point.resolve.get(i).hand;
	}

	public AddrSpace getCurSpace() {
		return const_context.getCurSpace();
	}

	public AddrSpace getConstSpace() {
		return const_context.getConstSpace();
	}

	public Address getAddr() {
		return const_context.getAddr();
	}

	public Address getNaddr() {
		return const_context.getNaddr();
	}

	public Address getFlowRefAddr() {
		return const_context.getFlowRefAddr();
	}

	public Address getFlowDestAddr() {
		return const_context.getFlowDestAddr();
	}

	public int getLength() {
		return const_context.getLength();
	}

	public int getInstructionBytes(int byteoff, int numbytes) {
		return const_context.getInstructionBytes(byteoff, numbytes, point.offset);
	}

	public int getContextBytes(int byteoff, int numbytes) {
		return const_context.getContextBytes(byteoff, numbytes);
	}

	public int getInstructionBits(int startbit, int size) {
		return const_context.getInstructionBits(startbit, size, point.offset);
	}

	public int getContextBits(int startbit, int size) {
		return const_context.getContextBits(startbit, size);
	}
}
