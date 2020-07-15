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
package ghidra.app.plugin.processors.generic;

import java.util.ArrayList;
import java.util.Hashtable;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * 
 */

public class BinaryExpression implements OperandValue, ExpressionValue {
	public static final int INVALID_OP = -1;
	public static final int ADD = 0;
	public static final int SUB = 1;
	public static final int MUL = 2;
	public static final int DIV = 3;
	public static final int EQ = 4;
	public static final int AND = 5;

	private int spaceID;	// SpaceID of address space into which this expression returns a pointer
	private int wordSize;
//	private long wordMask;
	private AddressSpace constantSpace;
	
	private int opType;
	private ExpressionTerm left, right;

	public BinaryExpression(int op, ExpressionTerm l, ExpressionTerm r, AddressSpace c) 
		throws SledException {
		opType = op;
		left = l;
		right = r;
		wordSize = c.getSize()/8;
//		wordMask = c.getMaxOffset();
		spaceID = c.getSpaceID();
		constantSpace = c;
		switch (opType) {
			case ADD:
			case SUB:
			case MUL:
			case DIV:
			//case EQ: return r;
			case AND:
				break;
			default: throw new SledException("Unrecognized opType (" + opType + ") in Binary Expression");
		}
	}

	public void setSpace(AddressSpace space) {
		spaceID = space.getSpaceID();
		wordSize = space.getSize()/8;
//		wordMask = space.getMaxOffset();
	}

	@Override
	public int length(MemBuffer buf,int off) throws Exception {
		int leftLen = left.length(buf,off);
		int rightLen = right.length(buf, off);
		
		return (leftLen > rightLen ? leftLen : rightLen);
	}

	@Override
	public ConstructorInfo getInfo(MemBuffer buf, int off) throws Exception {
		return new ConstructorInfo(length(buf,off),0);
	}	

	@Override
	public long longValue(MemBuffer buf, int off) throws Exception {

		long l = left.longValue(buf, off);
		long r = right.longValue(buf, off);

		switch (opType) {
			case ADD: return l + r;
			case SUB: return l - r;
			case MUL: return l * r;
			case DIV: return l / r;
			//case EQ: return r;
			case AND: return l & r;
			default:					// Should never get executed
				return 0;
		}
	}

	@Override
	public String toString(MemBuffer buf, int off) throws Exception {
		long val = longValue(buf, off);
		if (val >= 0) {
			return "0x" + Long.toString(val,16);
		}
        return "-0x" + Long.toString(-val,16);
	}

	/**
	 * Method linkRelativeOffsets.
	 * @param opHash
	 */
	public void linkRelativeOffsets(Hashtable<String, Operand> opHash) {
		left.linkRelativeOffsets(opHash);
		right.linkRelativeOffsets(opHash);
	}

	@Override
	public Handle getHandle(Position position, int off) throws Exception {
		long val = /* wordMask & */ longValue(position.buffer(),off);
		Address a = constantSpace.getAddress(val);
		Varnode v = new Varnode(a,wordSize);
		return new Handle(v,spaceID,wordSize);
	}

	@Override
	public Handle getHandle(ArrayList<PcodeOp> pcode, Position position, int off) throws Exception {
		return getHandle(position,off); // a binary expression never has any associated pcode
	}

	@Override
	public void getAllHandles(ArrayList<Handle> handles,Position position,int off) throws Exception {
		handles.add(getHandle(position,off));
	}
	
	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.generic.OperandValue#toList(java.util.ArrayList, ghidra.program.model.mem.MemBuffer, int)
	 */
	@Override
	public void toList(ArrayList<Handle> list, Position position, int off) throws Exception {
		list.add(getHandle(position, off));
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.generic.OperandValue#getSize()
	 */
	@Override
	public int getSize() {
		return wordSize * 8;
	}
}
