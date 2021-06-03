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
/*
 * Created on May 18, 2004
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.program.model.pcode;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.ListIterator;

import ghidra.program.model.address.Address;

/**
 * 
 *
 * This type of Varnode is a node in an Abstract Syntax Tree
 * It keeps track of its defining PcodeOp (in-edge) and PcodeOps which use it (out-edges)
 */
public class VarnodeAST extends Varnode {

	private boolean bInput;
	private boolean bAddrTied;
	private boolean bPersistent;
	private boolean bUnaffected;
	private boolean bFree;
	private int uniqId;					// Unique Id for distinguishing otherwise identical varnodes
	private short mergegroup;			// Forced merge group within this varnode's high
	private HighVariable high;			// High-level variable which this varnode is an instance of
	private PcodeOp def;				// Operation which defines this varnode (in-edge)
	private LinkedList<PcodeOp> descend;		// List of operations which use this varnode (out-edges)

	public VarnodeAST(Address a, int sz, int id) {
		super(a, sz);
		bInput = false;
		bAddrTied = false;
		bPersistent = false;
		bUnaffected = false;
		bFree = true;
		uniqId = id;
		def = null;
		mergegroup = 0;
		descend = new LinkedList<PcodeOp>();
	}

	@Override
	public boolean isFree() {
		return bFree;
	}

	@Override
	public boolean isInput() {
		return bInput;
	}

	@Override
	public boolean isPersistent() {
		return bPersistent;
	}

	@Override
	public boolean isAddrTied() {
		return bAddrTied;
	}

	@Override
	public boolean isUnaffected() {
		return bUnaffected;
	}

	@Override
	public PcodeOp getDef() {
		return def;
	}

	@Override
	public Iterator<PcodeOp> getDescendants() {
		return descend.iterator();
	}

	@Override
	public Address getPCAddress() {
		if (bInput) {
			return Address.NO_ADDRESS;
		}
		if (def != null) {
			return def.getSeqnum().getTarget();
		}
		if (descend.size() == 1) {
			return descend.get(0).getSeqnum().getTarget();
		}
		return Address.NO_ADDRESS;
	}

	@Override
	public HighVariable getHigh() {
		return high;
	}

	public int getUniqueId() {
		return uniqId;
	}

	@Override
	public short getMergeGroup() {
		return mergegroup;
	}

	public void setAddrtied(boolean val) {
		bAddrTied = val;
	}

	public void setInput(boolean val) {
		bInput = val;
		bFree = false;
		def = null;
	}

	public void setPersistent(boolean val) {
		bPersistent = val;
	}

	public void setUnaffected(boolean val) {
		bUnaffected = val;
	}

	public void setFree(boolean val) {
		bFree = val;
	}

	public void setDef(PcodeOp op) {
		def = op;
		if (op != null) {
			bFree = false;
			bInput = false;
		}
	}

	public void setMergeGroup(short val) {
		mergegroup = val;
	}

	public void setHigh(HighVariable hi) {
		high = hi;
	}

	public void addDescendant(PcodeOp op) {
		descend.add(op);
	}

	public void removeDescendant(PcodeOp op) {
		ListIterator<PcodeOp> iter = descend.listIterator();
		while (iter.hasNext()) {
			if (op == iter.next()) {
				iter.remove();
			}
		}
	}

	/**
	 * Replace all of parameter vn's references with this
	 * @param vn  Varnode whose references will get replaced
	 */
	public void descendReplace(VarnodeAST vn) {
		ListIterator<PcodeOp> iter = vn.descend.listIterator();
		while (iter.hasNext()) {
			PcodeOp op = iter.next();
			if (op.getOutput() == this)
				continue;		// Cannot be input to your own definition
			int num = op.getNumInputs();
			for (int i = 0; i < num; ++i)
				// Find reference to vn
				if (op.getInput(i) == vn) {
					vn.removeDescendant(op);
					op.setInput(null, i);
					addDescendant(op);
					op.setInput(this, i);
					break;
				}
		}
	}

	// This routine must be consistent with the Comparator classes used for sorting varnodes
	// in the Abstract Syntax Tree.  In particular, for a given location and size, there can
	// be only one varnode defined by input and only one defined by a PcodeOp with a given
	// SequenceNumber.  But there can be multiple Varnodes of the same location and size,
	// which are all free.  Thus in the free case, the equals method must compare the uniqId

	@Override
	public boolean equals(Object o) {
		if (o == this)
			return true;
		if (!(o instanceof VarnodeAST))
			return false;
		VarnodeAST vn = (VarnodeAST) o;

		if (getOffset() != vn.getOffset() || getSize() != vn.getSize() ||
			getSpace() != vn.getSpace())
			return false;
		if (isFree()) {
			if (vn.isFree())
				return (uniqId == vn.uniqId);
			return false;
		}
		else if (vn.isFree())
			return false;
		if (isInput() != vn.isInput())
			return false;
		if (def != null) {
			PcodeOp vnDef = vn.getDef();
			if (vnDef == null)
				return false;
			return (def.getSeqnum().equals(vnDef.getSeqnum()));
		}
		return true;
	}

	@Override
	public int hashCode() {
		return uniqId;
	}
}
