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

import java.util.*;

import generic.hash.SimpleCRC32;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

/**
 * A hash utility to uniquely identify a temporary Varnode in data-flow
 *
 * Most Varnodes can be identified within the data-flow graph by their storage address
 * and the address of the PcodeOp that defines them.  For temporary registers,
 * this does not work because the storage address is ephemeral. This class allows
 * Varnodes like temporary registers (and constants) to be robustly identified
 * by hashing details of the local data-flow.
 *
 * This class, when presented with a Varnode (via constructor), calculates a hash (getHash())
 * and an address (getAddress()) of the PcodeOp most closely associated with the Varnode,
 * either the defining op or the op directly reading the Varnode.
 * There are actually four hash variants that can be calculated, labeled 0, 1, 2, or 3,
 * which incrementally hash in a larger portion of data-flow.
 */
public class DynamicHash {

	// Table for how to hash opcodes, lumps certain operators (i.e. AND SUB PTRADD PTRSUB) into one hash
	// zero indicates the operator should be skipped
	public final static int transtable[] = { 0, PcodeOp.COPY, PcodeOp.LOAD, PcodeOp.STORE,
		PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.BRANCHIND,

		PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.CALLOTHER, PcodeOp.RETURN,

		PcodeOp.INT_EQUAL, PcodeOp.INT_EQUAL,	// NOT_EQUAL hashes same as EQUAL
		PcodeOp.INT_SLESS, PcodeOp.INT_SLESS,	// SLESSEQUAL hashes same as SLESS
		PcodeOp.INT_LESS, PcodeOp.INT_LESS,		// LESSEQUAL hashes same as LESS

		PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.INT_ADD, PcodeOp.INT_ADD,		// SUB hashes same as ADD
		PcodeOp.INT_CARRY, PcodeOp.INT_SCARRY, PcodeOp.INT_SBORROW, PcodeOp.INT_2COMP,
		PcodeOp.INT_NEGATE,

		PcodeOp.INT_XOR, PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_MULT,	// LEFT hashes same as MULT
		PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT, PcodeOp.INT_MULT, PcodeOp.INT_DIV, PcodeOp.INT_SDIV,
		PcodeOp.INT_REM, PcodeOp.INT_SREM,

		PcodeOp.BOOL_NEGATE, PcodeOp.BOOL_XOR, PcodeOp.BOOL_AND, PcodeOp.BOOL_OR,

		PcodeOp.FLOAT_EQUAL, PcodeOp.FLOAT_EQUAL,	// NOTEQUAL hashes same as EQUAL
		PcodeOp.FLOAT_LESS, PcodeOp.FLOAT_LESS,		// LESSEQUAL hashes same as EQUAL
		0,						// Unused slot -- skip
		PcodeOp.FLOAT_NAN,

		PcodeOp.FLOAT_ADD, PcodeOp.FLOAT_DIV, PcodeOp.FLOAT_MULT, PcodeOp.FLOAT_ADD,	// SUB hashes same as ADD
		PcodeOp.FLOAT_NEG, PcodeOp.FLOAT_ABS, PcodeOp.FLOAT_SQRT,

		PcodeOp.FLOAT_INT2FLOAT, PcodeOp.FLOAT_FLOAT2FLOAT, PcodeOp.FLOAT_TRUNC, PcodeOp.FLOAT_CEIL,
		PcodeOp.FLOAT_FLOOR, PcodeOp.FLOAT_ROUND,

		PcodeOp.MULTIEQUAL, PcodeOp.INDIRECT, PcodeOp.PIECE, PcodeOp.SUBPIECE,

		0,				// CAST is skipped
		PcodeOp.INT_ADD, PcodeOp.INT_ADD,		// PTRADD and PTRSUB hash same as INT_ADD
		PcodeOp.SEGMENTOP, PcodeOp.CPOOLREF, PcodeOp.NEW, PcodeOp.INSERT, PcodeOp.EXTRACT,
		PcodeOp.POPCOUNT, PcodeOp.LZCOUNT };

	/**
	 * An edge between a Varnode and a PcodeOp
	 * 
	 * A DynamicHash is defined on a sub-graph of the data-flow, and this defines an edge
	 * in the sub-graph.  The edge can either be from an input Varnode to the PcodeOp
	 * that reads it, or from a PcodeOp to the Varnode it defines.
	 */
	private static class ToOpEdge implements Comparable<ToOpEdge> {
		private PcodeOp op;
		private int slot;			// slot containing varnode we are coming from

		public ToOpEdge(PcodeOp o, int s) {
			op = o;
			slot = s;
		}

		public PcodeOp getOp() {
			return op;
		}

		public int getSlot() {
			return slot;
		}

		public int hash(int reg) {
			reg = SimpleCRC32.hashOneByte(reg, slot);
			reg = SimpleCRC32.hashOneByte(reg, transtable[op.getOpcode()]);
			long val = op.getSeqnum().getTarget().getOffset();
			int sz = op.getSeqnum().getTarget().getSize();
			for (int i = 0; i < sz; i += 8) {
				reg = SimpleCRC32.hashOneByte(reg, (int) val);
				val >>= 8;
			}
			return reg;
		}

		@Override
		public int compareTo(ToOpEdge o) {
			Address addr1 = op.getSeqnum().getTarget();
			Address addr2 = o.op.getSeqnum().getTarget();
			int cmp = addr1.compareTo(addr2);
			if (cmp != 0) {
				return cmp;
			}
			int ord1 = op.getSeqnum().getOrder();
			int ord2 = o.op.getSeqnum().getOrder();
			if (ord1 != ord2) {
				return (ord1 < ord2) ? -1 : 1;
			}
			if (slot == o.slot) {
				return 0;
			}
			return (slot < o.slot) ? -1 : 1;
		}
	}

	private int vnproc;			// Number of varnodes processed in the -markvn- list
	private int opproc;			// Number of ops processed in the -markop- list
	private int opedgeproc;		// Number of edges processed in the -opedge- list

	private ArrayList<PcodeOp> markop;
	private ArrayList<Varnode> markvn;
	private ArrayList<Varnode> vnedge;
	private ArrayList<ToOpEdge> opedge;

	private HashSet<Object> markset;

	private Address addrresult;			// Address most closely associated with variable
	private long hash;

	private DynamicHash() {
		markop = new ArrayList<>();
		markvn = new ArrayList<>();
		vnedge = new ArrayList<>();
		opedge = new ArrayList<>();
	}

	/**
	 * Construct a hash of the given Varnode with a specific hash method.
	 * 
	 * @param root is the given Varnode
	 * @param method is the method (0, 1, 2, 3)
	 */
	public DynamicHash(Varnode root, int method) {
		this();
		calcHash(root, method);
	}

	/**
	 * Construct a unique hash for the given Varnode, which must be in
	 * a syntax tree.  The hash method is cycled until a uniquely identifying one is found.
	 * @param root is the given Varnode
	 * @param fd is the PcodeSyntaxTree containing the Varnode
	 */
	public DynamicHash(Varnode root, PcodeSyntaxTree fd) {
		this();
		uniqueHash(root, fd);
	}

	/**
	 * Construct a unique hash that allows recovery of a specific PcodeOp and slot from the
	 * syntax tree.  The hash method is cycled until a uniquely identifying one is found.
	 * @param op is the specific PcodeOp to hash
	 * @param slot is the specific slot (-1 is the output, >=0 is an input)
	 * @param fd is the PcodeSyntaxTree containing the PcodeOp
	 */
	public DynamicHash(PcodeOp op, int slot, PcodeSyntaxTree fd) {
		this();
		uniqueHash(op, slot, fd);
	}

	/**
	 * Construct a level 0 hash on the input Varnode to the given PcodeOp
	 * 
	 * The PcodeOp can be raw, no linked into a PcodeSyntaxTree
	 * @param op is the given PcodeOp
	 * @param inputIndex is the index of the input Varnode to hash
	 */
	public DynamicHash(PcodeOp op, int inputIndex) {
		this();
		VarnodeAST[] vnarray = new VarnodeAST[op.getNumInputs()];
		Varnode vn = op.getInput(inputIndex);
		VarnodeAST vnroot = new VarnodeAST(vn.getAddress(), vn.getSize(), 0);
		vnarray[inputIndex] = vnroot;
		PcodeOp cloneop = new PcodeOp(op.getSeqnum(), op.getOpcode(), vnarray, null);
		vnroot.addDescendant(cloneop);
		calcHash(vnroot, 0);
	}

	public long getHash() {
		return hash;
	}

	public Address getAddress() {
		return addrresult;
	}

	private void clear() {
		markop.clear();
		markvn.clear();
		vnedge.clear();
		opedge.clear();
	}

	/**
	 * For a DynamicHash on a PcodeOp, the op must not be a CAST or other skipped opcode.
	 * Test if the given op is a skip op, and if so follow data-flow indicated by the
	 * slot to another PcodeOp until we find one that isn't a skip op. Return null, if
	 * the initial op is not skipped, otherwise return a ToOpEdge indicating the
	 * new (op,slot) pair.
	 * @param op is the given PcodeOp
	 * @param slot is the slot
	 * @return null or a new (op,slot) pair
	 */
	private static ToOpEdge moveOffSkip(PcodeOp op, int slot) {
		if (transtable[op.getOpcode()] != 0) {
			return null;
		}
		do {
			if (slot >= 0) {
				Varnode vn = op.getOutput();
				op = vn.getLoneDescend();
				if (op == null) {
					return new ToOpEdge(null, 0);	// Indicate the end of the data-flow path
				}
				slot = op.getSlot(vn);
			}
			else {
				Varnode vn = op.getInput(0);
				op = vn.getDef();
				if (op == null) {
					return new ToOpEdge(null, 0);	// Indicate the end of the data-flow path
				}
			}
		}
		while (transtable[op.getOpcode()] == 0);
		return new ToOpEdge(op, slot);
	}

	/**
	 * Encode a particular PcodeOp and slot
	 * @param op is the PcodeOp to preserve
	 * @param slot is the slot to preserve (-1 for output, >=0 for input)
	 * @param method is the method to use for encoding (4, 5, or 6)
	 */
	private void calcHash(PcodeOp op, int slot, int method) {
		Varnode root;
		if (slot < 0) {
			root = op.getOutput();
			if (root == null) {
				hash = 0;
				addrresult = Address.NO_ADDRESS;
				return;
			}
		}
		else {
			if (slot >= op.getNumInputs()) {
				hash = 0;
				addrresult = Address.NO_ADDRESS;
				return;
			}
			root = op.getInput(slot);
		}
		vnproc = 0;
		opproc = 0;
		opedgeproc = 0;
		markset = new HashSet<>();
		opedge.add(new ToOpEdge(op, slot));
		switch (method) {
			case 4:
				break;
			case 5:
				gatherUnmarkedOp();
				for (; opproc < markop.size(); ++opproc) {
					buildOpUp(markop.get(opproc));
				}
				gatherUnmarkedVn();
				break;
			case 6:
				gatherUnmarkedOp();
				for (; opproc < markop.size(); ++opproc) {
					buildOpDown(markop.get(opproc));
				}
				gatherUnmarkedVn();
				break;
			default:
				break;
		}
		pieceTogetherHash(root, method);
	}

	private void calcHash(Varnode root, int method) {
		vnproc = 0;
		opproc = 0;
		opedgeproc = 0;
		markset = new HashSet<>();

		vnedge.add(root);
		gatherUnmarkedVn();
		for (int i = vnproc; i < markvn.size(); ++i) {
			buildVnUp(markvn.get(i));
		}
		for (; vnproc < markvn.size(); ++vnproc) {
			buildVnDown(markvn.get(vnproc));
		}

		switch (method) {
			case 0:
				break;
			case 1:
				gatherUnmarkedOp();
				for (; opproc < markop.size(); ++opproc) {
					buildOpUp(markop.get(opproc));
				}

				gatherUnmarkedVn();
				for (; vnproc < markvn.size(); ++vnproc) {
					buildVnUp(markvn.get(vnproc));
				}
				break;
			case 2:
				gatherUnmarkedOp();
				for (; opproc < markop.size(); ++opproc) {
					buildOpDown(markop.get(opproc));
				}

				gatherUnmarkedVn();
				for (; vnproc < markvn.size(); ++vnproc) {
					buildVnDown(markvn.get(vnproc));
				}
				break;
			case 3:
				gatherUnmarkedOp();
				for (; opproc < markop.size(); ++opproc) {
					buildOpUp(markop.get(opproc));
				}

				gatherUnmarkedVn();
				for (; vnproc < markvn.size(); ++vnproc) {
					buildVnDown(markvn.get(vnproc));
				}
				break;
			default:
				break;
		}

		pieceTogetherHash(root, method);
	}

	private void pieceTogetherHash(Varnode root, int method) {
		if (opedge.size() == 0) {
			hash = 0;
			addrresult = null;
			return;
		}

		int reg = 0x3ba0fe06;		// Calculate the 32-bit hash

		// Hash in information about the root
		reg = SimpleCRC32.hashOneByte(reg, root.getSize());
		if (root.isConstant()) {
			long val = root.getOffset();
			for (int i = 0; i < root.getSize(); ++i) {
				reg = SimpleCRC32.hashOneByte(reg, (int) val);
				val >>>= 8;
			}
		}

		for (ToOpEdge element : opedge) {
			reg = element.hash(reg);
		}

		// Build the final 64-bit hash
		PcodeOp op = null;
		int slot = 0;
		int ct;
		boolean attachedop = true;
		for (ct = 0; ct < opedge.size(); ++ct) {	// Find op that is directly attached to -root- i.e. not a skip op
			op = opedge.get(ct).getOp();
			slot = opedge.get(ct).getSlot();
			if ((slot < 0) && (op.getOutput() == root)) {
				break;
			}
			if ((slot >= 0) && (op.getInput(slot) == root)) {
				break;
			}
		}
		if (ct == opedge.size()) {			// If everything attached to the root was a skip op
			op = opedge.get(0).getOp();		// Return op that is not attached directly
			slot = opedge.get(0).getSlot();
			attachedop = false;
		}

		// 15 bits unused
		hash = attachedop ? 0 : 1;
		hash <<= 4;
		hash |= method;			// 4-bits
		hash <<= 7;
		hash |= transtable[op.getOpcode()];	// 7-bits
		hash <<= 5;
		hash |= slot & 0x1f;	// 5-bits

		hash <<= 32;
		hash |= reg & 0xffffffffL;				// 32-bits for the neighborhood hash
		addrresult = op.getSeqnum().getTarget();
	}

	private void uniqueHash(PcodeOp op, int slot, PcodeSyntaxTree fd) {
		ArrayList<PcodeOp> oplist = new ArrayList<>();
		ArrayList<PcodeOp> oplist2 = new ArrayList<>();
		ArrayList<PcodeOp> champion = new ArrayList<>();
		int method;
		long tmphash = 0;
		Address tmpaddr = null;
		int maxduplicates = 8;

		ToOpEdge move = moveOffSkip(op, slot);
		if (move != null) {
			op = move.getOp();
			slot = move.getSlot();
			if (op == null) {
				hash = 0;
				addrresult = Address.NO_ADDRESS;
				return;
			}
		}
		gatherOpsAtAddress(oplist, fd, op.getSeqnum().getTarget());
		for (method = 4; method < 7; ++method) {
			clear();
			calcHash(op, slot, method);
			if (hash == 0) {
				return;		// Can't get a good hash
			}
			tmphash = hash;
			tmpaddr = addrresult;
			oplist2.clear();
			for (PcodeOp tmpop : oplist) {
				if (slot >= tmpop.getNumInputs()) {
					continue;
				}
				clear();
				calcHash(tmpop, slot, method);
				if (getComparable(hash) == getComparable(tmphash)) {	// Hash collision
					oplist2.add(tmpop);
					if (oplist2.size() > maxduplicates) {
						break;
					}
				}
			}
			if (oplist2.size() <= maxduplicates) {
				if ((champion.size() == 0) || (oplist2.size() < champion.size())) {
					champion = oplist2;
					oplist2 = new ArrayList<>();
					if (champion.size() == 1) {
						break;		// Current hash is unique
					}
				}
			}
		}
		if (champion.size() == 0) {
			hash = 0;
			addrresult = Address.NO_ADDRESS;	// Couldn't find a unique hash
			return;
		}
		int total = champion.size() - 1;	// total is in range [0,maxduplicates-1]
		int pos;
		for (pos = 0; pos <= total; ++pos) {
			if (champion.get(pos) == op) {
				break;
			}
		}
		if (pos > total) {
			hash = 0;
			addrresult = Address.NO_ADDRESS;
			return;
		}
		hash = tmphash | ((long) pos << 49);	// Store three bits for position with list of duplicate hashes
		hash |= ((long) total << 52);	// Store three bits for total number of duplicate hashes
		addrresult = tmpaddr;
	}

	private void uniqueHash(Varnode root, PcodeSyntaxTree fd) {
		ArrayList<Varnode> vnlist = new ArrayList<>();
		ArrayList<Varnode> vnlist2 = new ArrayList<>();
		ArrayList<Varnode> champion = new ArrayList<>();
		int method;
		long tmphash = 0;
		Address tmpaddr = null;
		int maxduplicates = 8;

		for (method = 0; method < 4; ++method) {
			clear();
			calcHash(root, method);
			if (hash == 0) {
				return;				// Can't get a good hash
			}
			tmphash = hash;
			tmpaddr = addrresult;
			vnlist.clear();
			vnlist2.clear();
			gatherFirstLevelVars(vnlist, fd, tmpaddr, tmphash);
			for (int i = 0; i < vnlist.size(); ++i) {
				Varnode tmpvn = vnlist.get(i);
				clear();
				calcHash(tmpvn, method);
				if (getComparable(hash) == getComparable(tmphash)) {		// Hash collision
					vnlist2.add(tmpvn);
					if (vnlist2.size() > maxduplicates) {
						break;
					}
				}
			}
			if (vnlist2.size() <= maxduplicates) {
				if ((champion.size() == 0) || (vnlist2.size() < champion.size())) {
					champion = vnlist2;
					vnlist2 = new ArrayList<>();
					if (champion.size() == 1) {
						break;		// Current hash is unique
					}
				}
			}
		}
		if (champion.size() == 0) {
			hash = 0;
			addrresult = Address.NO_ADDRESS;	// Couldn't find a unique hash
			return;
		}
		int total = champion.size() - 1;	// total is in range [0,maxduplicates-1]
		int pos;
		for (pos = 0; pos <= total; ++pos) {
			if (champion.get(pos) == root) {
				break;
			}
		}
		if (pos > total) {
			hash = 0;
			addrresult = Address.NO_ADDRESS;
			return;
		}
		hash = tmphash | ((long) pos << 49);	// Store three bits for position with list of duplicate hashes
		hash |= ((long) total << 52);	// Store three bits for total number of duplicate hashes
		addrresult = tmpaddr;
	}

	private void buildVnUp(Varnode vn) {		// Follow def edge
		PcodeOp op;
		for (;;) {
			PcodeOp tmpop = vn.getDef();
			if (tmpop == null) {
				return;
			}
			op = tmpop;
			if (transtable[op.getOpcode()] != 0) {
				break;	// Do not ignore this operation
			}
			vn = op.getInput(0);
		}
		opedge.add(new ToOpEdge(op, -1));
	}

	private void buildVnDown(Varnode vn) {	// Follow descendant edges
		Iterator<PcodeOp> iter = vn.getDescendants();
		if (iter == null) {
			return; // no descendants
		}

		ArrayList<ToOpEdge> newedge = new ArrayList<>();

		while (iter.hasNext()) {
			PcodeOp op = iter.next();
			Varnode tmpvn = vn;
			while (transtable[op.getOpcode()] == 0) {
				tmpvn = op.getOutput();
				if (tmpvn == null) {
					op = null;
					break;
				}
				op = tmpvn.getLoneDescend();
				if (op == null) {
					break;
				}
			}
			if (op == null) {
				continue;
			}
			int slot = op.getSlot(tmpvn);
			newedge.add(new ToOpEdge(op, slot));
		}
		if (newedge.size() > 1) {
			Collections.sort(newedge);
		}
		opedge.addAll(newedge);
	}

	private void buildOpUp(PcodeOp op) {
		for (int i = 0; i < op.getNumInputs(); ++i) {
			Varnode vn = op.getInput(i);
			vnedge.add(vn);
		}
	}

	private void buildOpDown(PcodeOp op) {
		Varnode vn = op.getOutput();
		if (vn == null) {
			return;
		}
		vnedge.add(vn);
	}

	private void gatherUnmarkedVn() {
		for (Varnode vn : vnedge) {
			if (markset.contains(vn)) {
				continue;
			}
			markvn.add(vn);
			markset.add(vn);
		}
		vnedge.clear();
	}

	private void gatherUnmarkedOp() {
		for (; opedgeproc < opedge.size(); ++opedgeproc) {
			PcodeOp op = opedge.get(opedgeproc).getOp();
			if (markset.contains(op)) {
				continue;
			}
			markop.add(op);
			markset.add(op);
		}
	}

	public static Varnode findVarnode(PcodeSyntaxTree fd, Address addr, long h) {
		DynamicHash dhash = new DynamicHash();
		int method = getMethodFromHash(h);
		int total = getTotalFromHash(h);
		int pos = getPositionFromHash(h);
		h = clearTotalPosition(h);
		ArrayList<Varnode> vnlist = new ArrayList<>();
		ArrayList<Varnode> vnlist2 = new ArrayList<>();
		gatherFirstLevelVars(vnlist, fd, addr, h);
		for (int i = 0; i < vnlist.size(); ++i) {
			Varnode tmpvn = vnlist.get(i);
			dhash.clear();
			dhash.calcHash(tmpvn, method);
			if (getComparable(dhash.getHash()) == getComparable(h)) {
				vnlist2.add(tmpvn);
			}
		}
		if (total != vnlist2.size()) {
			return null;
		}
		return vnlist2.get(pos);
	}

	public static PcodeOp findOp(PcodeSyntaxTree fd, Address addr, long h) {
		DynamicHash dhash = new DynamicHash();
		int method = getMethodFromHash(h);
		int slot = getSlotFromHash(h);
		int total = getTotalFromHash(h);
		int pos = getPositionFromHash(h);
		h = clearTotalPosition(h);
		ArrayList<PcodeOp> oplist = new ArrayList<>();
		ArrayList<PcodeOp> oplist2 = new ArrayList<>();
		gatherOpsAtAddress(oplist, fd, addr);
		for (PcodeOp tmpop : oplist) {
			if (slot >= tmpop.getNumInputs()) {
				continue;
			}
			dhash.clear();
			dhash.calcHash(tmpop, slot, method);
			if (getComparable(dhash.getHash()) == getComparable(h)) {
				oplist2.add(tmpop);
			}
		}
		if (total != oplist2.size()) {
			return null;
		}
		return oplist2.get(pos);
	}

	public static void gatherOpsAtAddress(ArrayList<PcodeOp> oplist, PcodeSyntaxTree fd,
			Address addr) {
		Iterator<PcodeOpAST> iter = fd.getPcodeOps(addr);
		while (iter.hasNext()) {
			oplist.add(iter.next());
		}
	}

	private static void dedupVarnodes(ArrayList<Varnode> varlist) {
		if (varlist.size() < 2) {
			return;
		}
		ArrayList<Varnode> resList = new ArrayList<>();
		HashSet<Varnode> hashSet = new HashSet<>();
		for (Varnode vn : varlist) {
			if (hashSet.add(vn)) {
				resList.add(vn);
			}
		}
		varlist.clear();
		varlist.addAll(resList);
	}

	public static void gatherFirstLevelVars(ArrayList<Varnode> varlist, PcodeSyntaxTree fd,
			Address addr, long h) {
		int opc = getOpCodeFromHash(h);
		int slot = getSlotFromHash(h);
		boolean isnotattached = getIsNotAttached(h);
		Iterator<PcodeOpAST> iter = fd.getPcodeOps(addr);

		while (iter.hasNext()) {
			PcodeOp op = iter.next();
			if (transtable[op.getOpcode()] != opc) {
				continue;
			}
			if (slot < 0) {
				Varnode vn = op.getOutput();
				if (vn != null) {
					if (isnotattached) {		// If original varnode was not attached to (this) op
						op = vn.getLoneDescend();
						if (op != null) {
							if (transtable[op.getOpcode()] == 0) {	// Check for skip op
								vn = op.getOutput();
								if (vn == null) {
									continue;
								}
							}
						}
					}
					varlist.add(vn);
				}
			}
			else if (slot < op.getNumInputs()) {
				Varnode vn = op.getInput(slot);
				if (isnotattached) {
					op = vn.getDef();
					if ((op != null) && (transtable[op.getOpcode()] == 0)) {
						vn = op.getInput(0);
					}
				}
				varlist.add(vn);
			}
		}
		dedupVarnodes(varlist);
	}

	public static int getSlotFromHash(long h) {
		int res = (int) ((h >> 32) & 0x1f);
		if (res == 31) {
			res = -1;
		}
		return res;
	}

	public static int getMethodFromHash(long h) {
		return (int) ((h >> 44) & 0xf);
	}

	public static int getOpCodeFromHash(long h) {
		return (int) ((h >> 37) & 0x7f);
	}

	public static int getPositionFromHash(long h) {
		return (int) ((h >> 49) & 7);
	}

	public static int getTotalFromHash(long h) {
		return ((int) ((h >> 52) & 7) + 1);
	}

	public static boolean getIsNotAttached(long h) {
		return (((h >> 48) & 1) != 0);
	}

	public static long clearTotalPosition(long h) {
		long val = 0x3f;
		val <<= 49;
		val = ~val;
		h &= val;
		return h;
	}

	public static int getComparable(long h) {
		return (int) h;
	}

	/**
	 * Test that extendval is equal to val1, where extendval may be an extension
	 * @param val1  is the value that needs to be matched
	 * @param size  is the number of bytes in the value to be matched
	 * @param extendval is the possibly extended value
	 * @return true if they are equal
	 */
	private static boolean matchWithPossibleExtension(long val1, int size, long extendval) {
		if (extendval >= 0) {			// If there was an extension, it was a zero extension
			return (val1 == extendval);
		}
		// Possible sign extension
		long mask = -1;
		mask >>>= (8 - size) * 8;
		long maskcomp = ~mask;
		maskcomp >>= 1;			// Add bit that we are extending from
		if ((extendval & maskcomp) != maskcomp) {	// Make sure sign-extension is consistent
			return false;
		}
		return (val1 == (mask & extendval));
	}

	/**
	 * Given a constant value accessed as an operand by a particular instruction,
	 * calculate a (level 0) hash for (any) corresponding constant varnode
	 * @param instr is the instruction referencing the constant
	 * @param value of the constant
	 * @return array of hash values (may be zero length)
	 */
	public static long[] calcConstantHash(Instruction instr, long value) {
		long[] tmp = new long[2];
		int count = 0;
		for (PcodeOp op : instr.getPcode(true)) {
			Varnode[] inputs = op.getInputs();
			for (int i = 0; i < inputs.length; i++) {
				if (inputs[i].isConstant() &&
					matchWithPossibleExtension(inputs[i].getOffset(), inputs[i].getSize(), value)) {
					if (count >= tmp.length) {
						long[] newtmp = new long[count + 10];
						for (int j = 0; j < tmp.length; ++j) {
							newtmp[j] = tmp[j];
						}
						tmp = newtmp;
					}
					DynamicHash dynamicHash = new DynamicHash(op, i);
					tmp[count] = dynamicHash.getHash();
					if (tmp[count] != 0) {
						count += 1;
					}
				}
			}
		}
		long[] res = new long[count];
		for (int i = 0; i < count; ++i) {
			res[i] = tmp[i];
		}
		return res;
	}
}
