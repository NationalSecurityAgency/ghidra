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
package ghidra.program.model.pcode;

import java.util.Iterator;

import ghidra.program.model.address.Address;

/**
 * 
 *
 * Some extra things attached to PcodeOp for ease of walking the syntax tree
 */
public class PcodeOpAST extends PcodeOp {

	private boolean bDead;					// Is this operation currently in the syntax tree
	private PcodeBlockBasic parent;		// Parent basic block
	private Iterator<PcodeOp> basiciter;					// Iterator within basic block
	private Iterator<Object> insertiter;					// Position in alive/dead list
//	private Iterator codeiter;						// Position in opcode list

	public PcodeOpAST(SequenceNumber sq, int op, int numinputs) {
		super(sq,op,numinputs,null);
		bDead = true;					// Start out dead until actually in the syntax tree
		parent = null;
		basiciter = null;
		insertiter = null;
//		codeiter = null;	
	}
	
	public PcodeOpAST(Address a, int uq, int op, int numinputs)
	{
		this(new SequenceNumber(a,uq),op,numinputs);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.pcode.PcodeOp#isDead()
	 */
	@Override
    public boolean isDead() {
		return bDead;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.pcode.PcodeOp#getParent()
	 */
	@Override
    public PcodeBlockBasic getParent() {
		return parent;
	}
	
	/* (non-Javadoc)
	 * @see ghidra.program.model.pcode.PcodeOp#getBasicIter()
	 */
	@Override
    public Iterator<PcodeOp> getBasicIter() {
		return basiciter;
	}
	
	/* (non-Javadoc)
	 * @see ghidra.program.model.pcode.PcodeOp#getInsertIter()
	 */
	@Override
    public Iterator<Object> getInsertIter() {
		return insertiter;
	}
	
//	public Iterator getCodeIter() {
//		return codeiter;
//	}

	/**
	 * Set the parent basic block this pcode is contained within.
	 * 
	 * @param par parent basic block.
	 */
	public void setParent(PcodeBlockBasic par) {
		parent = par;	
	}
	
	/**
	 * Set the iterator being used to iterate the pcode within a basic block.
	 * 
	 * @param iter
	 */
	public void setBasicIter(Iterator<PcodeOp> iter) {
		basiciter = iter;
	}
	
	/**
	 * Set the iterator being used to iterate the pcode to insert within a block.
	 * @param iter
	 */
	public void setInsertIter(Iterator<Object> iter) {
		insertiter = iter;
	}
	
//	public void setCodeIter(Iterator iter) {
//		codeiter = iter;
//	}
}
