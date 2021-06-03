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
 * Created on May 26, 2004
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.program.model.pcode;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

/**
 * 
 *
 * Container class for VarnodeAST's
 */
public class VarnodeBank {

	public class LocComparator implements Comparator<VarnodeAST> {

		/* 
		 * Compare objects by location, size, then definition
		 */
		@Override
		public int compare(VarnodeAST v1, VarnodeAST v2) {
			int cmp = v1.getAddress().compareTo(v2.getAddress());
			if (cmp!=0) {
				return cmp;
			}
			if (v1.getSize() != v2.getSize()) {
				return (v1.getSize() < v2.getSize() ? -1 : 1);
			}
			if (v1.isInput()) {
				if (v2.isInput()) {
					return 0;
				}
				return -1;
			}
			if (v2.isInput()) {
				return 1;
			}
			if (v1.getDef() != null) {
				if (v2.getDef()==null) {
					return -1;
				}
				return v1.getDef().getSeqnum().compareTo(v2.getDef().getSeqnum());
			}
			if (v2.getDef()!=null) {
				return 1;
			}
			 							// Reaching this point guarantees both Varnodes are free
			if (v1.getUniqueId() == v2.getUniqueId()) {
				return 0;
			}
			return (v1.getUniqueId()<v2.getUniqueId() ? -1 : 1);
		}
	}
	
	public class DefComparator implements Comparator<VarnodeAST> {

		/* 
		 * Compare by definition then location and size
		 */
		@Override
		public int compare(VarnodeAST v1, VarnodeAST v2) {
			int comp;
			if (v1.isInput()) {
				if (!v2.isInput()) {
					return -1;
				}
			}
			else if (v1.getDef() != null) {
				if (v2.isInput()) {
					return 1;
				}
				if (v2.isFree()) {
					return -1;
				}
				comp = v1.getDef().getSeqnum().compareTo(v2.getDef().getSeqnum());
				if (comp != 0) {
					return comp;
				}
			}
			comp = v1.getAddress().compareTo(v2.getAddress());
			if (comp != 0) {
				return comp;
			}
			if (v1.getSize() != v2.getSize()) {
				return (v1.getSize() < v2.getSize() ? -1 : 1);
			}
			if (v1.isFree()) {		// Both Varnodes must be free, compare uniqId
				if (v1.getUniqueId()==v2.getUniqueId()) {
					return 0;
				}
				return (v1.getUniqueId() < v2.getUniqueId() ? -1 : 1);
			}
			return 0;
		}
	}

	private TreeSet<VarnodeAST> locTree;						// Varnodes sorted by location
//	private TreeSet defTree;						// Varnodes sorted by definition
	
	public VarnodeBank() {
		locTree = new TreeSet<VarnodeAST>(new LocComparator());
//		defTree = new TreeSet(new DefComparator());
	}
	
	public void clear() {
		locTree.clear();
//		defTree.clear();
	}

	public int size() {
		return locTree.size();
	}
	
	public boolean isEmpty() {
		return locTree.isEmpty();
	}
	
	public Varnode create(int s,Address addr,int id) {
		VarnodeAST vn = new VarnodeAST(addr,s,id);
		locTree.add(vn);
//		defTree.add(vn);
		return vn;
	}
	
	public void destroy(Varnode vn) {
		locTree.remove(vn);
//		defTree.remove(vn);
	}
	
	private Varnode xref(VarnodeAST vn) {
		SortedSet<VarnodeAST> sset = locTree.tailSet(vn);
		if (!sset.isEmpty()) {
			VarnodeAST oldvn = sset.first();
			if (oldvn.equals(vn)) {			// Set already contains this Varnode
				oldvn.descendReplace(vn);
				return oldvn;
			}
		}
		locTree.add(vn);
//		defTree.add(vn);
		return vn;
	}
	
	public void makeFree(Varnode vn) {
		VarnodeAST vn1 = (VarnodeAST) vn;
		locTree.remove(vn1);
//		defTree.remove(vn1);
		
		vn1.setDef(null);			// Clear things that make vn non-free
		vn1.setInput(false);
		vn1.setFree(true);
		
		locTree.add(vn1);
//		defTree.add(vn1);
	}
	
	public Varnode setInput(Varnode vn) {
		if (!vn.isFree()) {
			return null;
		}
		if (vn.isConstant()) {
			return null;
		}
		
		VarnodeAST vn1 = (VarnodeAST)vn;
		locTree.remove(vn1);
//		defTree.remove(vn1);
		vn1.setInput(true);
		return xref(vn1);
	}
	
	public Varnode setDef(Varnode vn,PcodeOp op) {
		if (!vn.isFree()) {
			return null;
		}
		if (vn.isConstant()) {
			return null;
		}
		
		VarnodeAST vn1 = (VarnodeAST)vn;
		locTree.remove(vn1);
//		defTree.remove(vn1);
		vn1.setDef(op);
		return xref(vn1);
	}

	public Iterator<VarnodeAST> locRange() {
		return locTree.iterator();
	}
	
	public Iterator<VarnodeAST> locRange(AddressSpace spaceid) {
		VarnodeAST searchvn1 = new VarnodeAST(spaceid.getAddress(0),0,0);
		searchvn1.setInput(true);
		VarnodeAST searchvn2 = new VarnodeAST(spaceid.getMaxAddress(), Integer.MAX_VALUE, 0);
		return locTree.subSet(searchvn1, searchvn2).iterator();
	}
	
	public Iterator<VarnodeAST> locRange(Address addr) {
		VarnodeAST searchvn1 = new VarnodeAST(addr,0,0);
		searchvn1.setInput(true);
		VarnodeAST searchvn2 = new VarnodeAST(addr.add(1),0,0);
		searchvn2.setInput(true);
		return locTree.subSet(searchvn1,searchvn2).iterator();
	}
	
	public Iterator<VarnodeAST> locRange(int sz,Address addr) {
		VarnodeAST searchvn1 = new VarnodeAST(addr,sz,0);
		searchvn1.setInput(true);
		VarnodeAST searchvn2 = new VarnodeAST(addr,sz+1,0);
		searchvn2.setInput(true);
		return locTree.subSet(searchvn1,searchvn2).iterator();
	}
	
	public Varnode find(int sz,Address addr,Address pc,int uniq) {
		VarnodeAST searchvn = new VarnodeAST(addr,sz,0);
		int uq = (uniq==-1) ? 0 : uniq;
		PcodeOpAST op = new PcodeOpAST(pc, uq, PcodeOp.COPY, 0);
		searchvn.setDef(op);
		Iterator<VarnodeAST> iter = locTree.tailSet(searchvn).iterator();
		for(;iter.hasNext();) {
			VarnodeAST vn = iter.next();
			if (vn.getSize()!=sz) {
				break;
			}
			if (!vn.getAddress().equals(addr)) {
				break;
			}
			PcodeOp op2 = vn.getDef();
			if ((op2!=null)&&(op2.getSeqnum().getTarget().equals(pc))) {
				if ((uniq==-1)||(op2.getSeqnum().getTime()==uniq)) {
					return vn;
				}
			}
		}
		return null;
	}
	
	public Varnode findInput(int sz,Address addr) {
		VarnodeAST searchvn = new VarnodeAST(addr,sz,0);
		searchvn.setInput(true);
		Iterator<VarnodeAST> iter = locTree.tailSet(searchvn).iterator();
		if (iter.hasNext()) {
			VarnodeAST vn = iter.next();
			if (vn.isInput() && (vn.getSize()==sz) && vn.getAddress().equals(addr)) {
				return vn;
			}
		}
		return null;
	}
}
