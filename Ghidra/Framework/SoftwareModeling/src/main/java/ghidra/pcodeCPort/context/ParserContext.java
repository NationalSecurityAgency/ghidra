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

import generic.stl.IteratorSTL;
import generic.stl.VectorSTL;
import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.pcodeCPort.address.Address;
import ghidra.pcodeCPort.globalcontext.ContextCache;
import ghidra.pcodeCPort.slghsymbol.*;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.pcodeCPort.translate.BadDataError;

public class ParserContext {
	public enum ContextState {
		uninitialized, disassembly, pcode;
	}

	private ContextState parsestate;
	private AddrSpace const_space;
	private byte[] buf = new byte[16]; // Pointer to instruction bit stream
	private int[] context; // Pointer to local context
	private int contextsize; // Number of entries in context array
	private ContextCache contcache; // Interface for getting/setting context
	private VectorSTL<ContextSet> contextcommit = new VectorSTL<ContextSet>();
	private Address addr; // Address of start of instruction
	private Address naddr; // Address of next instruction
	private VectorSTL<ConstructState> state = new VectorSTL<ConstructState>(); // Current resolved
																				// instruction
	ConstructState base_state;
	private ConstructState point; // Current substate
	private boolean outofband;
	private int oob_offset;
	private int alloc; // Number of ConstructState's allocated
	private int delayslot; // delayslot depth

	public void dispose() {
		if (context != null) {
			context = null;
		}
	}

	private ConstructState getState(int index) {
		ConstructState constructState = state.get(index);
		if (constructState == null) {
			constructState = new ConstructState();
			state.set(index, constructState);
		}
		return constructState;
	}

	public void setAddr(Address ad) {
		addr = ad;
	}

	public void setNaddr(Address ad) {
		naddr = ad;
	}

	public void clearCommits() {
		contextcommit.clear();
	}

	public Address getAddr() {
		return addr;
	}

	public Address getNaddr() {
		return naddr;
	}

	public AddrSpace getCurSpace() {
		return addr.getSpace();
	}

	public AddrSpace getConstSpace() {
		return const_space;
	}

	public void setContextWord(int i, int val, int mask) {
		context[i] = (context[i] & (~mask)) | (mask & val);
	}

	public void loadContext() {
		contcache.getContext(addr, context);
	}

	public int getLength() {
		return base_state.length;
	}

	public void setDelaySlot(int val) {
		delayslot = val;
	}

	public int getDelaySlot() {
		return delayslot;
	}

	public ParserContext(ContextCache ccache) {
		parsestate = ContextState.uninitialized;
		contcache = ccache;
		if (ccache != null) {
			contextsize = ccache.getDatabase().getContextSize();
			context = new int[contextsize];
		}
		else {
			contextsize = 0;
			context = null;
		}
	}

	private void resize(VectorSTL<ConstructState> list, int newsize) {
		while (list.size() < newsize) {
			list.push_back(new ConstructState());
		}
		while (list.size() > newsize) {
			list.pop_back();
		}
	}

	public byte[] getBuffer() {
		return buf;
	}

	public void initialize(int maxstate, int maxparam, AddrSpace spc) {
		const_space = spc;
		resize(state, maxstate);
		getState(0).parent = null;
		for (int i = 0; i < maxstate; ++i) {
			resize(getState(i).resolve, maxparam);
		}
		base_state = getState(0);
	}

	public ContextState getParserState() {
		return parsestate;
	}

	public void setParserState(ContextState st) {
		parsestate = st;
	}

	public void deallocateState(ParserWalkerChange walker) {
		alloc = 1;
		walker.context = this;
		walker.baseState();
	}

	public void allocateOperand(int i, ParserWalkerChange walker) {
		ConstructState opstate = state.get(alloc++);
		opstate.parent = walker.point;
		opstate.ct = null;
		walker.point.resolve.set(i, opstate);
		walker.breadcrumb[walker.depth++] += 1;
		walker.point = opstate;
		walker.breadcrumb[walker.depth] = 0;
	}

	public int getInstructionBytes(int bytestart, int size, int off) {
		// Get bytes from the instruction stream into an int
		// (assuming big endian format)
		off += bytestart;
		if (off >= 16) {
			throw new BadDataError("Instruction is using more than 16 bytes");
		}
		int res = 0;
		for (int i = 0; i < size; ++i) {
			res <<= 8;
			res |= buf[i + off];
		}
		return res;
	}

	public int getInstructionBits(int startbit, int size, int off) {
		off += (startbit / 8);
		if (off >= 16) {
			throw new BadDataError("Instruction is using more than 16 bytes");
		}
		startbit = startbit % 8;
		int bytesize = (startbit + size - 1) / 8 + 1;
		int res = 0;
		for (int i = 0; i < bytesize; ++i) {
			res <<= 8;
			res |= buf[i + off];
		}
		res <<= 8 * (4 - bytesize) + startbit; // Move starting bit to highest position
		res >>= 8 * 4 - size;	// Shift to bottom of intm
		return res;
	}

	// Get bytes from context into a intm
	// Assume request is within a intm
	public int getContextBytes(int bytestart, int size) {
		int res = context[bytestart / 4];
		res <<= (bytestart % 4) * 8;
		res >>>= (4 - size) * 8;
		return res;
	}

	public int getContextBits(int startbit, int size) {
		int res = context[startbit / (8 * 4)]; // Get intm containing highest bit
		res <<= (startbit % (8 * 4)); // Shift startbit to highest position
		res >>>= (8 * 4 - size);
		return res;
	}

	// set the offset into instruction bytes (for
	// future calls into getInstructionBytes) without
	// disturbing the tree walk
	public void setOffsetOutOfBand(Constructor c, int index) {
		outofband = true;
		ConstructState pt = point;
		while (pt.ct != c) {
			if (pt == getState(0)) {
				return;
			}
			pt = pt.parent;
		}
		OperandSymbol sym = c.getOperand(index);
		int i = sym.getOffsetBase();
		// if i<0, i.e. the offset of the operand is constructor relative
		// its possible that the branch corresponding to the operand
		// has not been constructed yet. Context expressions are
		// evaluated BEFORE the constructors branches are created.
		// So we have to construct the offset explicitly.
		if (i < 0) {
			oob_offset = pt.offset + sym.getRelativeOffset();
		}
		else {
			oob_offset = pt.resolve.get(index).offset;
		}
	}

	public void addCommit(TripleSymbol sym, int num, int mask, boolean flow, ConstructState point) {
		contextcommit.push_back(new ContextSet());
		ContextSet set = contextcommit.back();

		set.sym = sym;
		set.point = point; // This is the current state
		set.num = num;
		set.mask = mask;
		set.value = context[num] & mask;
		set.flow = flow;
	}

	public void applyCommits() {
		if (contextcommit.empty()) {
			return;
		}
		ParserWalker walker = new ParserWalker(this);
		walker.baseState();

		IteratorSTL<ContextSet> iter;
		for (iter = contextcommit.begin(); !iter.isEnd(); iter.increment()) {
			TripleSymbol sym = iter.get().sym;
			Address addr = null;
			if (sym.getType() == symbol_type.operand_symbol) {
				// The value for an OperandSymbol is probabably already
				// calculated, we just need to find the right
				// tree node of the state
				int i = ((OperandSymbol) sym).getIndex();
				FixedHandle h = (iter.get().point.resolve.get(i).hand);
				addr = new Address(h.space, h.offset_offset);
			}
			else {
				FixedHandle hand = new FixedHandle();
				sym.getFixedHandle(hand, walker);
				addr = new Address(hand.space, hand.offset_offset);
			}
			// Commit context change
			contcache.setContext(addr, iter.get().num, iter.get().mask, iter.get().value);
		}
	}

	/**
	 * Returns primary flow reference destination address for instruction or null
	 */
	public Address getFlowRefAddr() {
		throw new SleighException("Flow reference (inst_ref) is undefined at " + getAddr());
	}

	/**
	 * Returns original flow destination address for instruction or null
	 */
	public Address getFlowDestAddr() {
		throw new SleighException("Flow destination (inst_dest) is undefined at " + getAddr());
	}
}
