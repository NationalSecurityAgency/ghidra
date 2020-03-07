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
import java.util.TreeMap;

import ghidra.program.model.address.Address;
/**
 * 
 *
 * Container for PcodeOpAST's
 */
public class PcodeOpBank {
	private TreeMap<SequenceNumber, PcodeOpAST> opTree;				// All ops sorted by SequenceNumber
	private ListLinked<Object> deadList;			// List of dead ops
	private ListLinked<Object> aliveList;			// LIst of living ops
	private int nextUnique;					// Next unique index for created op

	public PcodeOpBank() {
		opTree = new TreeMap<SequenceNumber, PcodeOpAST>();
		deadList = new ListLinked<Object>();
		aliveList = new ListLinked<Object>();
		nextUnique = 0;
	}

	public int size() {
		return opTree.size();	
	}
	
	public void clear() {
		opTree.clear();
		deadList.clear();
		aliveList.clear();
	}
	
	public PcodeOp create(int opcode,int numinputs,Address pc) {
		PcodeOpAST op;
		op = new PcodeOpAST(pc, nextUnique, opcode, numinputs);
		nextUnique += 1;
		
		opTree.put(op.getSeqnum(),op);
		op.setInsertIter(deadList.add(op));
		return op;
	}

	public PcodeOp create(int opcode, int numinputs, SequenceNumber sq) {
		PcodeOpAST op = new PcodeOpAST(sq,opcode,numinputs);

		if (sq.getTime()>nextUnique)
			nextUnique = sq.getTime()+1;
		
		opTree.put(op.getSeqnum(),op);
		op.setInsertIter(deadList.add(op));
		return op;	
	}
	
	public void destroy(PcodeOp op) {
		PcodeOpAST op_ast = (PcodeOpAST)op;
		if (!op_ast.isDead()) return;				// Should probably throw an exception
		opTree.remove(op.getSeqnum());
		deadList.remove(op.getInsertIter());
	}
	
	public void changeOpcode(PcodeOp op,int newopc) {
		PcodeOpAST op_ast = (PcodeOpAST)op;
		op_ast.setOpcode(newopc);
	}
	
	public void markAlive(PcodeOp op) {
		PcodeOpAST op_ast = (PcodeOpAST)op;
		deadList.remove(op_ast.getInsertIter());
		op_ast.setInsertIter(aliveList.add(op_ast));
	}
	
	public void markDead(PcodeOp op) {
		PcodeOpAST op_ast = (PcodeOpAST)op;
		aliveList.remove(op_ast.getInsertIter());
		op_ast.setInsertIter(deadList.add(op_ast));
	}
	
	public boolean isEmpty() {
		return opTree.isEmpty();
	}
	
	public PcodeOp findOp(SequenceNumber num) {			// Find op with given sequence number
		return opTree.get(num);
	}

	public Iterator<PcodeOpAST> allOrdered() {				// Return all ops in SequenceNumber order
		return opTree.values().iterator();	
	}
	
	public Iterator<PcodeOpAST> allOrdered(Address pc) {		// Return all ops associated with indicated address
		SequenceNumber min = new SequenceNumber(pc,0);
		SequenceNumber max = new SequenceNumber(pc,Integer.MAX_VALUE);
		return opTree.subMap(min,max).values().iterator();
	}
	
	/**
	 * Returns iterator containing both PcodeOpAST and {@literal Iterator<PcodeOp>} objects.
	 */
	public Iterator<Object> allAlive() {
		return aliveList.iterator();
	}
	
	/**
	 * Returns iterator containing both PcodeOpAST and {@literal Iterator<PcodeOp>} objects.
	 */
	public Iterator<Object> allDead() {
		return deadList.iterator();
	}
}
