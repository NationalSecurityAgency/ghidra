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
package ghidra.app.plugin.processors.sleigh;

import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.AssertException;

/**
 * Class for walking the Sleigh Parser tree.  The nodes of the tree are the Sleigh Constructors arranged for a particular
 * instruction.  This tree is walked for various purposes:
 * <ul>
 *     <li>SleighInstructionPrototype.resolve        - initial parsing of instruction and building the tree
 *     <li>SleighInstructionPrototype.resolveHandles - filling in Varnode values for all the Constructor exports
 *     <li>PcodeEmit                                 - for weaving together p-code for an instruction
 * </ul>
 *
 */
public class ParserWalker {

	private static final int MAX_PARSE_DEPTH = 64;

	private SleighParserContext context;
	private SleighParserContext cross_context;		// If in the midst of cross-build, the context from the original instruction
	private ConstructState point;		// The current node being visited
	private int depth;					// Depth of current node within the tree
	private int breadcrumb[];			// Path of operands from the root

	public ParserWalker(SleighParserContext c) {
		context = c;
		cross_context = null;
		breadcrumb = new int[MAX_PARSE_DEPTH + 1];
	}

	/**
	 * For use with pcode cross-build 
	 * @param c context
	 * @param cross cross context
	 */
	public ParserWalker(SleighParserContext c, SleighParserContext cross) {
		this(c);
		cross_context = cross;
	}

	public SleighParserContext getParserContext() {
		return context;
	}

	/**
	 * Initialize a walk of the tree
	 */
	public void baseState() {
		point = context.getRootState();
		depth = 0;
		breadcrumb[0] = 0;
	}

	public void subTreeState(ConstructState subtree) {
		point = subtree;
		depth = 0;
		breadcrumb[0] = 0;
	}

	/**
	 * Create state suitable for parsing a just a p-code semantics snippet
	 */
	public void snippetState() {
		point = new ConstructState(null);
		depth = 0;
		breadcrumb[0] = 0;
	}

	/**
	 * Are we at the end of the tree walk
	 * @return true if there is more walk to go
	 */
	public boolean isState() {
		return (point != null);
	}

	public ConstructState getState() {
		return point;
	}

	/**
	 * Move down to a particular child of the current node.  Store what would be the next sibling to walk
	 * @param i is the index of the desired child
	 */
	public void pushOperand(int i) {
		if (depth == MAX_PARSE_DEPTH) {
			throw new AssertException("Exceeded maximum parse depth");
		}
		breadcrumb[depth++] = i + 1;
		point = point.getSubState(i);
		breadcrumb[depth] = 0;
	}

	public void allocateOperand() throws UnknownInstructionException {
		if (depth == MAX_PARSE_DEPTH) {
			throw new UnknownInstructionException("Exceeded maximum parse depth");
		}
		ConstructState opstate = new ConstructState(point);
		breadcrumb[depth++] += 1;
		point = opstate;
		breadcrumb[depth] = 0;
	}

	/**
	 * Move to the parent of the current node
	 */
	public void popOperand() {
		point = point.getParent();
		depth -= 1;
	}

	/**
	 * Find the next child that needs to be traversed
	 * @return the index of the child
	 */
	public int getOperand() {
		return breadcrumb[depth];
	}

	public FixedHandle getFixedHandle(int i) {
		return context.getFixedHandle(point.getSubState(i));
	}

	public FixedHandle getParentHandle() {
		return context.getFixedHandle(point);
	}

	/**
	 * Get the offset into the instruction for the current node (i=-1) or one of the current node's children
	 * @param i selects the desired child of the current node
	 * @return the offset (in bytes) for the selected node
	 */
	public int getOffset(int i) {
		if (i < 0)
			return point.getOffset();
		ConstructState op = point.getSubState(i);
		return op.getOffset() + op.getLength();
	}

	public void setOffset(int off) {
		point.setOffset(off);
	}

	public int getCurrentLength() {
		return point.getLength();
	}

	public void setCurrentLength(int len) {
		point.setLength(len);
	}

	/**
	 * Calculate the length of the current constructor state
	 * assuming all its operands are constructed
	 */
	public void calcCurrentLength(int minLength, int numopers) {
		minLength += point.getOffset(); // Convert relative length to absolute length
		for (int i = 0; i < numopers; ++i) {
			ConstructState subpoint = point.getSubState(i);
			int sublength = subpoint.getLength() + subpoint.getOffset();
			// Since subpoint.offset is an absolute offset
			// (relative to beginning of instruction) sublength
			// is absolute and must be compared to absolute length
			if (sublength > minLength)
				minLength = sublength;
		}
		point.setLength(minLength - point.getOffset()); // Convert back to relative length
	}

	/**
	 * @return the Constructor for the current node in the walk
	 */
	public Constructor getConstructor() {
		return point.getConstructor();
	}

	public void setConstructor(Constructor ct) {
		point.setConstructor(ct);
	}

	public Address getAddr() {
		if (cross_context != null)
			return cross_context.getAddr();
		return context.getAddr();
	}

	public Address getNaddr() {
		if (cross_context != null)
			return cross_context.getNaddr();
		return context.getNaddr();
	}

	public AddressSpace getCurSpace() {
		return context.getCurSpace();
	}

	public AddressSpace getConstSpace() {
		return context.getConstSpace();
	}

	public Address getFlowRefAddr() {
		return context.getFlowRefAddr();
	}

	public Address getFlowDestAddr() {
		return context.getFlowDestAddr();
	}

	public int getInstructionBytes(int byteoff, int numbytes) throws MemoryAccessException {
		return context.getInstructionBytes(point.getOffset(), byteoff, numbytes);
	}

	public int getContextBytes(int byteoff, int numbytes) {
		return context.getContextBytes(byteoff, numbytes);
	}

	public int getInstructionBits(int startbit, int size) throws MemoryAccessException {
		return context.getInstructionBits(point.getOffset(), startbit, size);
	}

	public int getContextBits(int startbit, int size) {
		return context.getContextBits(startbit, size);
	}

	public void setOutOfBandState(Constructor ct, int index, ConstructState tempstate,
			ParserWalker otherwalker) {
		ConstructState pt = otherwalker.point;
		int curdepth = otherwalker.depth;
		while (pt.getConstructor() != ct) {
			if (curdepth <= 0)
				return;
			curdepth -= 1;
			pt = pt.getParent();
		}
		OperandSymbol sym = ct.getOperand(index);
		int i = sym.getOffsetBase();
		// if i<0, i.e. the offset of the operand is constructor relative
		// its possible that the branch corresponding to the operand
		// has not been constructed yet. Context expressions are
		// evaluated BEFORE the constructors branches are created.
		// So we have to construct the offset explicitly.
		if (i < 0)
			tempstate.setOffset(pt.getOffset() + sym.getRelativeOffset());
		else
			tempstate.setOffset(pt.getSubState(index).getOffset());

		tempstate.setConstructor(ct);
		tempstate.setLength(pt.getLength());
		point = tempstate;
		depth = 0;
		breadcrumb[0] = 0;
	}

	public String getCurrentSubtableName() {
		if (point == null)
			return null;
		ConstructState parent = point.getParent();
		if (parent == null)
			return null;
		Constructor ct = parent.getConstructor();
		int curindex = breadcrumb[depth - 1] - 1;
		OperandSymbol operand = ct.getOperand(curindex);
		TripleSymbol sym = operand.getDefiningSymbol();
		if (sym instanceof SubtableSymbol)
			return sym.getName();
		return null;
	}
}
