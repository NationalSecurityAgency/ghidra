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

import java.util.*;

import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;
import ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.*;

/**
 * 
 *
 * All the recovered context for a single instruction
 * The main data structure is the tree of constructors and operands
 */

public class SleighParserContext implements ParserContext {
	private MemBuffer memBuffer;
	private Address addr; // Address of start of instruction (inst_start)
	private Address nextInstrAddr; // Address of next instruction (inst_next)
	private Address next2InstAddr; // Address of instruction after next instruction (inst_next2)
	private Address refAddr; // corresponds to inst_ref for call-fixup use
	private Address destAddr; // corresponds to inst_dest for call-fixup use
	private SleighInstructionPrototype prototype;
	private AddressSpace constantSpace;
	private HashMap<ConstructState, FixedHandle> handleMap;
	private ArrayList<ContextSet> contextcommit; // Pending changes to context
	private int[] context; // packed context bits

	public SleighParserContext(MemBuffer memBuf, SleighInstructionPrototype prototype,
			ProcessorContextView processorContext) {
		this.handleMap = new HashMap<>();
		this.prototype = prototype;
		this.constantSpace = prototype.getLanguage().getAddressFactory().getConstantSpace();
		this.memBuffer = memBuf;
		this.addr = memBuf.getAddress();

		int contextSize = prototype.getContextCache().getContextSize();
		context = new int[contextSize];

		contextcommit = new ArrayList<>();
		try {
			nextInstrAddr = addr.add(prototype.getLength());
		}
		catch (AddressOutOfBoundsException exc) {
			// no next instruction, last instruction in memory.
			nextInstrAddr = null;
		}
		prototype.getContextCache().getContext(processorContext, context);
	}

	@Override
	public SleighInstructionPrototype getPrototype() {
		return prototype;
	}

	/**
	 * Constructor for building precompiled templates.
	 * NOTE: This form does not support use of {@code inst_next2}.
	 * @param aAddr  = address to which 'inst_start' resolves 
	 * @param nAddr  = address to which 'inst_next' resolves
	 * @param rAddr  = special address associated with original call
	 * @param dAddr  = destination address of original call being replaced
	 */
	public SleighParserContext(Address aAddr, Address nAddr, Address rAddr, Address dAddr) {
		memBuffer = null;
		prototype = null;
		context = null;
		contextcommit = null;
		addr = aAddr;
		nextInstrAddr = nAddr;
		refAddr = rAddr;
		destAddr = dAddr;
		handleMap = new HashMap<>();
	}

	/**
	 * Generate context specifically for an instruction that has a delayslot.
	 * When generating p-code SLEIGH has an alternate interpretation of the "inst_next"
	 * symbol that takes into account the instruction in the delay slot.  This context is
	 * generated at the point when specific instruction(s) in the delay slot are known.
	 * @param origContext is the original context (for the instruction in isolation)
	 * @param delayByteCount is the number of bytes in instruction stream occupied by the delay slot
	 */
	public SleighParserContext(SleighParserContext origContext, int delayByteCount) {
		memBuffer = origContext.memBuffer;
		prototype = origContext.prototype;
		context = origContext.context;
		contextcommit = origContext.contextcommit;
		addr = origContext.addr;
		refAddr = origContext.refAddr;
		destAddr = origContext.destAddr;
		constantSpace = origContext.constantSpace;
		handleMap = origContext.handleMap;
		try {
			nextInstrAddr = addr.add(prototype.getLength() + delayByteCount);
		}
		catch (AddressOutOfBoundsException exc) {
			// no next instruction, last instruction in memory.
			nextInstrAddr = null;
		}
	}

	/**
	 * @return context commits for normal instruction parse.
	 */
	Iterator<ContextSet> getContextCommits() {
		return contextcommit != null ? contextcommit.iterator() : null;
	}

	public void addCommit(ConstructState point, TripleSymbol sym, int num, int mask) {
		ContextSet set = new ContextSet();
		set.sym = sym;
		set.point = point;
		set.num = num;
		set.mask = mask;
		set.value = context[num] & mask;
		contextcommit.add(set);
	}

	public void applyCommits(ProcessorContext ctx) throws MemoryAccessException {
		if (contextcommit.size() == 0) {
			return;
		}
		ContextCache contextCache = prototype.getContextCache();
		ParserWalker walker = new ParserWalker(this);
		walker.baseState();
		for (ContextSet set : contextcommit) {
			FixedHandle hand;
			if (set.sym instanceof OperandSymbol) {		// value of OperandSymbol is already calculated, find right node
				int ind = ((OperandSymbol) set.sym).getIndex();
				hand = getFixedHandle(set.point.getSubState(ind));
			}
			else {
				hand = new FixedHandle();
				set.sym.getFixedHandle(hand, walker);
			}
			// TODO: this is a hack. Addresses that are computed end up in the
			// constant space and we must factor-in the wordsize.
			long offset = hand.offset_offset;
			AddressSpace curSpace = addr.getAddressSpace();
			if (hand.space.getType() == AddressSpace.TYPE_CONSTANT) {
				offset = offset * curSpace.getAddressableUnitSize();
			}
			Address address = curSpace.getAddress(offset);
			contextCache.setContext(ctx, address, set.num, set.mask, set.value);
		}
		contextcommit.clear();
	}

	public FixedHandle getFixedHandle(ConstructState constructState) {
		FixedHandle handle = handleMap.get(constructState);
		if (handle == null) {
			handle = new FixedHandle();
			handleMap.put(constructState, handle);
		}
		return handle;
	}

	/**
	 * get address of current instruction
	 * @return address of current instruction
	 */
	public Address getAddr() {
		return addr;
	}

	/**
	 * Get address of instruction after current instruction.  This may return null if this context 
	 * instance does not support use of {@code inst_next} or next address falls beyond end of
	 * address space.
	 * @return address of next instruction or null
	 */
	public Address getNaddr() {
		return nextInstrAddr;
	}

	/**
	 * Get address of instruction after the next instruction.  This may return {@link #getNaddr()}
	 * if this context instance does not support use of {@code inst_next2} or parse of next 
	 * instruction fails.
	 * @return address of instruction after the next instruction or null
	 */
	public Address getN2addr() {
		if (next2InstAddr != null) {
			return next2InstAddr;
		}
		next2InstAddr = computeNext2Address();
		if (next2InstAddr == null) {
			// unsupported use of inst_next2 or parse failure on next instruction 
			// returns same as inst_next
			next2InstAddr = nextInstrAddr;
		}
		return next2InstAddr;
	}

	/**
	 * Return the address after the next instruction (inst_next2).  The length of next instruction 
	 * based on attempted parse of next instruction and does not consider any delayslot use.
	 * The current instructions context is used during the parse.
	 * @return address after the next instruction or null if unable/failed to determine
	 */
	private Address computeNext2Address() {
		if (memBuffer == null || nextInstrAddr == null) {
			return null; // not supported without memBuffer for parse
		}
		try {
			Address nextAddr = nextInstrAddr;
			Language language = prototype.getLanguage();

			// limitation: assumes same context as current instruction
			ProcessorContextImpl ctx = new ProcessorContextImpl(language);
			RegisterValue ctxVal = getContextRegisterValue();
			if (ctxVal != null) {
				ctx.setRegisterValue(ctxVal);
			}

			int offset = (int) nextAddr.subtract(addr);
			MemBuffer nearbymem = new WrappedMemBuffer(memBuffer, offset);

			SleighInstructionPrototype proto =
				(SleighInstructionPrototype) language.parse(nearbymem, ctx, true);

			return nextAddr.addNoWrap(proto.getLength());
		}
		catch (Exception e) {
			// ignore
		}
		return null;
	}

	/**
	 * Get address space containing current instruction
	 * @return address space containing current instruction
	 */
	public AddressSpace getCurSpace() {
		return addr.getAddressSpace();
	}

	/**
	 * Get constant address space
	 * @return constant address space
	 */
	public AddressSpace getConstSpace() {
		return constantSpace;
	}

	/**
	 * Get memory buffer for current instruction which may also be used to parse next instruction
	 * or delay slot instructions.
	 * @return memory buffer for current instruction
	 */
	public MemBuffer getMemBuffer() {
		return memBuffer;
	}

	/**
	 * Get bytes from the instruction stream into an int
	 * (packed in big endian format).  Uninitialized or 
	 * undefined memory will return zero byte values.
	 * @param offset offset relative start of this context
	 * @param bytestart pattern byte offset relative to specified context offset 
	 * @param size is the number of bytes to fetch
	 * @return requested byte-range value
	 * @throws MemoryAccessException if no bytes are available at first byte when (offset+bytestart==0).
	 */
	public int getInstructionBytes(int offset, int bytestart, int size)
			throws MemoryAccessException {
		offset += bytestart;
		byte[] bytes = new byte[size]; // leave any unavailable bytes as 0 in result
		int readSize = memBuffer.getBytes(bytes, offset);
		if (offset == 0 && readSize == 0) {
			throw new MemoryAccessException("invalid memory");
		}
		int result = 0;
		for (int i = 0; i < size; i++) {
			result <<= 8;
			result |= bytes[i] & 0xff;
		}
		return result;
	}

	/**
	 * Get bits from the instruction stream into an int
	 * (packed in big endian format).  Uninitialized or 
	 * undefined memory will return zero bit values.
	 * @param offset offset relative start of this context
	 * @param startbit is the index of the first bit to fetch
	 * @param size is the number of bits to fetch
	 * @return requested bit-range value
	 * @throws MemoryAccessException if no bytes are available at first byte when (offset+bytestart/8==0).
	 */
	public int getInstructionBits(int offset, int startbit, int size) throws MemoryAccessException {

		offset += (startbit / 8);
		startbit %= 8;
		int bytesize = (startbit + size - 1) / 8 + 1;

		byte[] bytes = new byte[bytesize]; // leave any unavailable bytes as 0 in result
		int readSize = memBuffer.getBytes(bytes, offset);
		if (offset == 0 && readSize == 0) {
			throw new MemoryAccessException("invalid memory");
		}

		int res = 0;
		for (int i = 0; i < bytesize; i++) {
			res <<= 8;
			res |= bytes[i] & 0xff;
		}

		res <<= 8 * (4 - bytesize) + startbit; //Move starting bit to highest position
		res >>>= 32 - size; // Shift to the bottom of int
		return res;
	}

	/**
	 * Get the processor context value as a RegisterValue
	 * @return processor context value
	 */
	public RegisterValue getContextRegisterValue() {

		Register baseContextRegister = prototype.getLanguage().getContextBaseRegister();
		if (baseContextRegister == null) {
			return null;
		}

		// convert context int words to byte array for RegisterValue use
		int ctxByteLen = baseContextRegister.getMinimumByteSize();
		byte[] ctxValueBytes = new byte[ctxByteLen];

		for (int i = 0; i < context.length; i++) {
			int word = context[i];
			for (int n = 3; n >= 0; --n) {
				int byteIndex = (i * 4) + n;
				setByte(ctxValueBytes, byteIndex, (byte) word);
				word >>= 8;
			}
		}

		// append mask to value array for RegisterValue use
		byte[] ctxValueMaskBytes = new byte[2 * ctxByteLen];
		Arrays.fill(ctxValueMaskBytes, 0, ctxByteLen, (byte) 0xff);
		System.arraycopy(ctxValueBytes, 0, ctxValueMaskBytes, ctxByteLen, ctxByteLen);

		return new RegisterValue(baseContextRegister, ctxValueMaskBytes);
	}

	private void setByte(byte[] bytes, int index, byte b) {
		if (index < bytes.length) {
			bytes[index] = b;
		}
	}

	/**
	 * Get bytes from context into an int
	 * @param bytestart is the index of the first byte to fetch
	 * @param bytesize number of bytes (range: 1 - 4)
	 * @return the packed bytes from context
	 */
	public int getContextBytes(int bytestart, int bytesize) {
		int intstart = bytestart / 4;
		int res = context[intstart];
		int byteOffset = bytestart % 4;
		int unusedBytes = 4 - bytesize;
		res <<= byteOffset * 8;
		res >>>= unusedBytes * 8;
		int remaining = bytesize - 4 + byteOffset;
		if (remaining > 0 && ++intstart < context.length) {
			int res2 = context[intstart];
			unusedBytes = 4 - remaining;
			res2 >>>= unusedBytes * 8;
			res |= res2;
		}
		return res;
	}

	/**
	 * Get full set of context bytes.  Sleigh only supports context
	 * which is a multiple of 4-bytes (i.e., size of int)
	 * @return the array of context data
	 */
	public int[] getContextBytes() {
		return context;
	}

	/**
	 * Get bits from context into an int
	 * @param startbit is the index of the first bit to fetch
	 * @param bitsize number of bits (range: 1 - 32)
	 * @return the packed bits
	 */
	public int getContextBits(int startbit, int bitsize) {
		int intstart = startbit / 32;
		int res = context[intstart]; // Get int containing bits
		int bitOffset = startbit % 32;
		int unusedBits = 32 - bitsize;
		res <<= bitOffset; // Shift startbit to highest position
		res >>>= unusedBits;
		int remaining = bitsize - 32 + bitOffset;
		if (remaining > 0 && ++intstart < context.length) {
			int res2 = context[intstart];
			unusedBits = 32 - remaining;
			res2 >>>= unusedBits;
			res |= res2;
		}
		return res;
	}

	public void setContextWord(int i, int val, int mask) {
		context[i] = (context[i] & (~mask)) | (mask & val);
	}

	ConstructState getRootState() {
		return prototype.getRootState();
	}

	static class ContextSet {
		public TripleSymbol sym; // Resolves to address where set takes affect
		public int num; // Context word being affected
		public int mask; // bits being affected
		public int value; // new value being set
		public ConstructState point;
	}

	public boolean isValid(MemBuffer buf) {
		return buf == this.memBuffer && addr.equals(buf.getAddress());
	}

	public Address getFlowRefAddr() {
		if (refAddr == null) {
			throw new SleighException("Flow reference (inst_ref) is undefined at " + getAddr());
		}
		return refAddr;
	}

	public Address getFlowDestAddr() {
		if (destAddr == null) {
			throw new SleighException("Flow destination (inst_dest) is undefined at " + getAddr());
		}
		return destAddr;
	}
}
