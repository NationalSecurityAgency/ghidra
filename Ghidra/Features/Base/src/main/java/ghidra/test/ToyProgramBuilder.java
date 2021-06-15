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
package ghidra.test;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

public class ToyProgramBuilder extends ProgramBuilder {

	private static final String TOY_LANGUAGE_ID_BE = "Toy:BE:32:builder";
	private static final String TOY_LANGUAGE_ID_LE = "Toy:LE:32:builder";
	private static final String TOY_LANGUAGE_ID_BE_ALIGN2 = "Toy:BE:32:builder.align2";
	private static final String TOY_LANGUAGE_ID_LE_ALIGN2 = "Toy:LE:32:builder.align2";

	private AddressFactory addrFactory;
	private AddressSpace defaultSpace;
	private List<Address> definedInstrAddresses;

	/**
	 * Construct toy program builder using specified toy language
	 * @param name program name
	 * @param languageName toy language ID (note: only builder variant supports all instructions)
	 * @param consumer program consumer (if null this builder will be used as consumer and must be disposed to release program)
	 * @throws Exception
	 */
	public ToyProgramBuilder(String name, String languageName, Object consumer) throws Exception {
		super(name, checkLanguageName(languageName), consumer);
		Program program = getProgram();
		addrFactory = program.getAddressFactory();
		defaultSpace = addrFactory.getDefaultAddressSpace();
		definedInstrAddresses = new ArrayList<Address>();
	}

	/**
	 * Construct toy program builder using toy language "builder" variant.
	 * This builder will be the program consumer and must be disposed
	 * @param name program name
	 * @param bigEndian language endianess
	 * @throws Exception
	 */
	public ToyProgramBuilder(String name, boolean bigEndian) throws Exception {
		this(name, bigEndian, false, null);
	}

	/**
	 * Construct toy program builder using toy language "builder" variant.
	 * This builder will be the program consumer and must be disposed
	 * @param name program name
	 * @param bigEndian language endianess
	 * @param consumer program consumer (if null this builder will be used as consumer and must be disposed to release program)
	 * @throws Exception
	 */
	public ToyProgramBuilder(String name, boolean bigEndian, Object consumer) throws Exception {
		this(name, bigEndian, false, consumer);
	}

	/**
	 * Construct toy program builder using toy language "builder" variant.
	 * This builder will be the program consumer and must be disposed
	 * @param name program name
	 * @param bigEndian language endianess
	 * @param consumer program consumer (if null this builder will be used as consumer and must be disposed to release program)
	 * @throws Exception
	 */
	public ToyProgramBuilder(String name, boolean bigEndian, boolean wordAligned, Object consumer)
			throws Exception {
		super(name, getToyLanguageId(bigEndian, wordAligned), consumer);
		Program program = getProgram();
		addrFactory = program.getAddressFactory();
		defaultSpace = addrFactory.getDefaultAddressSpace();
		definedInstrAddresses = new ArrayList<Address>();
	}

	private static String getToyLanguageId(boolean bigEndian, boolean wordAligned) {
		if (wordAligned) {
			return bigEndian ? TOY_LANGUAGE_ID_BE_ALIGN2 : TOY_LANGUAGE_ID_LE_ALIGN2;
		}
		return bigEndian ? TOY_LANGUAGE_ID_BE : TOY_LANGUAGE_ID_LE;
	}

	private static String checkLanguageName(String languageName) {
		if (!languageName.startsWith(_TOY_LANGUAGE_PREFIX)) {
			throw new IllegalArgumentException("Toy language required");
		}
		return languageName;
	}

	/**
	 * Get address in default ram space
	 * @param offset address offset
	 * @return the address
	 */
	public Address getAddress(long offset) {
		return defaultSpace.getAddress(offset);
	}

	private void addInstructionBytes(Address start, byte... instrBytes)
			throws MemoryAccessException {
		Program program = getProgram();
		int txId = program.startTransaction("Add Instruction Bytes");
		try {
			for (int i = 0; i < instrBytes.length; i++) {
				program.getMemory().setByte(start.add(i), instrBytes[i]);
			}
			definedInstrAddresses.add(start);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private void addInstructionWords(Address start, short... instrWords)
			throws MemoryAccessException {
		Program program = getProgram();
		int txId = program.startTransaction("Add Instruction Bytes");
		try {
			for (int i = 0; i < instrWords.length; i++) {
				program.getMemory().setShort(start.add(i * 2), instrWords[i]);
			}
			definedInstrAddresses.add(start);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private short getByteRelativeOffset(Address address, Address dest) {
		if (!address.getAddressSpace().equals(dest.getAddressSpace())) {
			throw new IllegalArgumentException(
				"Instruction addr and targetAddr must be in same address space");
		}
		int relDest = (int) dest.subtract(address);
		if (relDest > Byte.MAX_VALUE || relDest < Byte.MIN_VALUE) {
			throw new IllegalArgumentException("targetAddr is out of range for instruction: " +
				relDest);
		}
		return (short) (relDest & 0xff);
	}

	private short getShortRelativeOffset(Address address, Address dest) {
		if (!address.getAddressSpace().equals(dest.getAddressSpace())) {
			throw new IllegalArgumentException(
				"Instruction addr and targetAddr must be in same address space");
		}
		int relDest = (int) dest.subtract(address);
		if (relDest > Byte.MAX_VALUE || relDest < Byte.MIN_VALUE) {
			throw new IllegalArgumentException("targetAddr is out of range for instruction: " +
				relDest);
		}
		return (short) (relDest & 0xffff);
	}

	private String toHex(long value) {
		return Long.toHexString(value);
	}

	/**
	 * Get locations where instruction bytes have been added
	 * @return instruction start locations
	 */
	public List<Address> getDefinedInstructionAddress() {
		return definedInstrAddresses;
	}

	/**
	 * Reset/clear the list of defined instruction addresses
	 */
	public void resetDefinedInstructionAddresses() {
		definedInstrAddresses.clear();
	}

	/**
	 * Add NOP instruction bytes of specified byte length
	 * @param offset instruction address offset
	 * @param length length of NOP instruction in bytes
	 * @throws MemoryAccessException
	 */
	public void addBytesNOP(long offset, int length) throws MemoryAccessException {
		addBytesNOP(toHex(offset), length);
	}

	/**
	 * Add NOP instruction bytes of specified byte length
	 * @param addr instruction address
	 * @param length length of NOP instruction in bytes
	 * @throws MemoryAccessException
	 */
	public void addBytesNOP(String addr, int length) throws MemoryAccessException {
		if (length == 1) {
			addInstructionBytes(addr(addr), (byte) 0xf7); // nop #1
		}
		else if (length < 18) {
			byte[] bytes = new byte[length];
			bytes[0] = (byte) 0xd9;
			length -= 2;
			bytes[1] = (byte) (length | 0x30);
			for (int i = 0; i < length; i++) {
				bytes[2 + i] = 0;
			}
			addInstructionBytes(addr(addr), bytes); // nop #n
		}
		else {
			throw new IllegalArgumentException("Unsupported NOP length: " + length);
		}
	}

	/**
	 * Add simple fall-through (consumes 2-bytes)
	 * @param offset instruction address offset
	 * @throws MemoryAccessException
	 */
	public void addBytesFallthrough(long offset) throws MemoryAccessException {
		addBytesFallthrough(toHex(offset));
	}

	/**
	 * Add simple fall-through (consumes 2-bytes)
	 * @param addr instruction address
	 * @throws MemoryAccessException
	 */
	public void addBytesFallthrough(String addr) throws MemoryAccessException {
		addInstructionWords(addr(addr), (short) 0xd100); // or r0,r0,r0
	}

	/**
	 * Add store indirect (consumes 2-bytes)
	 * @param offset instruction address offset
	 * @param srcRegIndex source register index (0..15)
	 * @param destRegIndex destination register index (contained indirect memory address)  (0..15)
	 * @throws MemoryAccessException
	 */
	public void addBytesStore(long offset, int srcRegIndex, int destRegIndex)
			throws MemoryAccessException {
		addBytesStore(toHex(offset), srcRegIndex, destRegIndex);
	}

	/**
	 * Add store indirect (consumes 2-bytes)
	 * @param addr instruction address
	 * @param srcRegIndex source register index (0..15)
	 * @param destRegIndex destination register index (contained indirect memory address)  (0..15)
	 * @throws MemoryAccessException
	 */
	public void addBytesStore(String addr, int srcRegIndex, int destRegIndex)
			throws MemoryAccessException {
		addInstructionWords(addr(addr),
			(short) (0xd700 | (srcRegIndex & 0x0f) | ((destRegIndex & 0x0f) << 4))); // store [d],s
	}

	/**
	 * Add load indirect (consumes 2-bytes)
	 * @param offset instruction address offset
	 * @param srcRegIndex source register index (contained indirect memory address) (0..15)
	 * @param destRegIndex destination register index (0..15)
	 * @throws MemoryAccessException
	 */
	public void addBytesLoad(long offset, int srcRegIndex, int destRegIndex)
			throws MemoryAccessException {
		addBytesLoad(toHex(offset), srcRegIndex, destRegIndex);
	}

	/**
	 * Add load indirect (consumes 2-bytes)
	 * @param addr instruction address
	 * @param srcRegIndex source register index (contained indirect memory address) (0..15)
	 * @param destRegIndex destination register index (0..15)
	 * @throws MemoryAccessException
	 */
	public void addBytesLoad(String addr, int srcRegIndex, int destRegIndex)
			throws MemoryAccessException {
		addInstructionWords(addr(addr),
			(short) (0xd600 | (srcRegIndex & 0x0f) | ((destRegIndex & 0x0f) << 4))); // load d,[s]
	}

	/**
	 * Add move immediate instruction (consumes 2-bytes)
	 * @param offset instruction offset
	 * @param imm immediate byte value
	 * @throws MemoryAccessException
	 */
	public void addBytesMoveImmediate(long offset, short imm) throws MemoryAccessException {
		addBytesMoveImmediate(toHex(offset), imm);
	}

	/**
	 * Add move immediate instruction (consumes 2-bytes)
	 * @param addr instruction address
	 * @param imm immediate byte value
	 * @throws MemoryAccessException
	 */
	public void addBytesMoveImmediate(String addr, short imm) throws MemoryAccessException {
		addInstructionWords(addr(addr), (short) ((imm & 0x700) << 4 | (imm & 0xff))); // imm r0,#<imm>
	}

	/**
	 * Add simple fall-through which sets noflow context value on next instruction (consumes 2-bytes)
	 * @param offset instruction address offset
	 * @param ctxVal context value (0-15)
	 * @throws MemoryAccessException
	 */
	public void addBytesFallthroughSetNoFlowContext(long offset, int ctxVal)
			throws MemoryAccessException {
		addBytesFallthroughSetNoFlowContext(toHex(offset), ctxVal);
	}

	/**
	 * Add simple fall-through which sets noflow context value on next instruction (consumes 2-bytes)
	 * @param addr instruction address
	 * @param ctxVal context value (0-15)
	 * @throws MemoryAccessException
	 */
	public void addBytesFallthroughSetNoFlowContext(String addr, int ctxVal)
			throws MemoryAccessException {
		addInstructionWords(addr(addr), (short) (0xd900 | (ctxVal & 0xf) | 0x10)); // nfctx i
	}

	/**
	 * Add simple fall-through which sets noflow context value on target address (consumes 2-bytes)
	 * @param offset instruction address offset
	 * @param ctxVal context value (0-15)
	 * @param target context target address offset
	 * @throws MemoryAccessException
	 */
	public void addBytesFallthroughSetNoFlowContext(long offset, int ctxVal, long target)
			throws MemoryAccessException {
		addBytesFallthroughSetNoFlowContext(toHex(offset), ctxVal, toHex(target));
	}

	/**
	 * Add simple fall-through which sets noflow context value on target address (consumes 2-bytes)
	 * @param addr instruction address
	 * @param ctxVal context value (0-15)
	 * @param targetAddr context target address
	 * @throws MemoryAccessException
	 */
	public void addBytesFallthroughSetNoFlowContext(String addr, int ctxVal, String targetAddr)
			throws MemoryAccessException {
		Address address = addr(addr);
		Address target = addr(targetAddr);
		short relTarget = getByteRelativeOffset(address, target);
		addInstructionWords(address, (short) (0xd900 | (ctxVal & 0xf) | 0x20), relTarget); // nfctx target,i
	}

	/**
	 * Add simple fall-through which sets flowing context value on next instruction (consumes 2-bytes)
	 * @param offset instruction address offset
	 * @param ctxVal context value (0-15)
	 * @throws MemoryAccessException
	 */
	public void addBytesFallthroughSetFlowContext(long offset, int ctxVal)
			throws MemoryAccessException {
		addBytesFallthroughSetFlowContext(toHex(offset), ctxVal);
	}

	/**
	 * Add simple fall-through which sets flowing context value on next instruction (consumes 2-bytes)
	 * @param addr instruction address
	 * @param ctxVal context value (0-15)
	 * @throws MemoryAccessException
	 */
	public void addBytesFallthroughSetFlowContext(String addr, int ctxVal)
			throws MemoryAccessException {
		addInstructionWords(addr(addr), (short) (0xd900 | (ctxVal & 0xf))); // fctx i
	}

	/**
	 * Add call (consumes 2-bytes)
	 * @param offset instruction address offset
	 * @param dest call destination offset
	 * @throws MemoryAccessException
	 */
	public void addBytesCall(long offset, long dest) throws MemoryAccessException {
		addBytesCall(toHex(offset), toHex(dest));
	}

	/**
	 * Add call (consumes 2-bytes)
	 * @param addr instruction address
	 * @param destAddr call destination address
	 * @throws MemoryAccessException
	 */
	public void addBytesCall(String addr, String destAddr) throws MemoryAccessException {
		Address address = addr(addr);
		Address dest = addr(destAddr);
		short relDest = getShortRelativeOffset(address, dest);
		addInstructionWords(address, (short) (0xf800 | (relDest & 0x7f))); // call rel
	}

	/**
	 * Add call w/ delayslot (consumes 4-bytes)
	 * @param offset instruction address offset
	 * @param dest call destination offset
	 * @throws MemoryAccessException
	 */
	public void addBytesCallWithDelaySlot(long offset, long dest) throws MemoryAccessException {
		addBytesCallWithDelaySlot(toHex(offset), toHex(dest));
	}

	/**
	 * Add call w/ delayslot (consumes 4-bytes)
	 * @param addr instruction address
	 * @param destAddr call destination address
	 * @throws MemoryAccessException
	 */
	public void addBytesCallWithDelaySlot(String addr, String destAddr)
			throws MemoryAccessException {
		Address address = addr(addr);
		Address dest = addr(destAddr);
		short relDest = getByteRelativeOffset(address, dest);
		addInstructionWords(address, (short) (0xf500 | relDest)); // callds rel
		addBytesFallthrough(address.getOffset() + 2);
	}

	/**
	 * Add terminal/return (consumes 2-bytes)
	 * @param offset instruction address offset
	 * @throws MemoryAccessException
	 */
	public void addBytesReturn(long offset) throws MemoryAccessException {
		addBytesReturn(toHex(offset));
	}

	/**
	 * Add terminal/return (consumes 2-bytes)
	 * @param addr instruction address
	 * @throws MemoryAccessException
	 */
	public void addBytesReturn(String addr) throws MemoryAccessException {
		addInstructionWords(addr(addr), (short) 0xf400); // ret
	}

	/**
	 * Add branch (consumes 2-bytes)
	 * @param offset address offset
	 * @param dest call destination offset
	 * @throws MemoryAccessException
	 */
	public void addBytesBranch(long offset, long dest) throws MemoryAccessException {
		addBytesBranch(toHex(offset), toHex(dest));
	}

	/**
	 * Add branch (consumes 2-bytes)
	 * @param addr instruction address offset
	 * @param destAddr call destination address
	 * @throws MemoryAccessException
	 */
	public void addBytesBranch(String addr, String destAddr) throws MemoryAccessException {
		Address address = addr(addr);
		Address dest = addr(destAddr);
		short relDest = getByteRelativeOffset(address, dest);
		addInstructionWords(address, (short) (0xe000 | (relDest << 4) | 0x7)); // br rel
	}

	/**
	 * Add branch (consumes 2-bytes)
	 * @param offset instruction address offset
	 * @param dest call destination offset
	 * @throws MemoryAccessException
	 */
	public void addBytesBranchConditional(long offset, long dest) throws MemoryAccessException {
		addBytesBranchConditional(toHex(offset), toHex(dest));
	}

	/**
	 * Add branch (consumes 2-bytes)
	 * @param addr instruction address
	 * @param destAddr call destination address
	 * @throws MemoryAccessException
	 */
	public void addBytesBranchConditional(String addr, String destAddr)
			throws MemoryAccessException {
		Address address = addr(addr);
		Address dest = addr(destAddr);
		short relDest = getByteRelativeOffset(address, dest);
		addInstructionWords(address, (short) (0xe000 | (relDest << 4))); // breq rel
	}

	/**
	 * Add branch w/ delay slot (consumes 4-bytes)
	 * @param offset instruction address offset
	 * @param dest call destination offset
	 * @throws MemoryAccessException
	 */
	public void addBytesBranchWithDelaySlot(long offset, long dest) throws MemoryAccessException {
		addBytesBranchWithDelaySlot(toHex(offset), toHex(dest));
	}

	/**
	 * Add branch w/ delay slot (consumes 4-bytes)
	 * @param addr instruction address
	 * @param destAddr call destination address
	 * @throws MemoryAccessException
	 */
	public void addBytesBranchWithDelaySlot(String addr, String destAddr)
			throws MemoryAccessException {
		Address address = addr(addr);
		Address dest = addr(destAddr);
		short relDest = getByteRelativeOffset(address, dest);
		addInstructionWords(address, (short) (0xe000 | (relDest << 4) | 0xf)); // brds rel
		addBytesFallthrough(address.getOffset() + 2);
	}

	/**
	 * Add COP instruction for exercising nfctx context (consumes 2-bytes).  Location will not be added to
	 * defined instruction address list.
	 * @param offset instruction address offset
	 * @throws MemoryAccessException
	 */
	public void addBytesCopInstruction(long offset) throws MemoryAccessException {
		addBytesCopInstruction(toHex(offset));
	}

	/**
	 * Add COP instruction for exercising nfctx context (consumes 2-bytes).  Location will not be added to
	 * defined instruction address list.
	 * @param addr instruction address
	 * @throws MemoryAccessException
	 */
	public void addBytesCopInstruction(String addr) throws MemoryAccessException {
		addInstructionWords(addr(addr), (short) 0xda00);
	}

	/**
	 * Add BAD instruction (consumes 2-bytes).  Location will not be added to
	 * defined instruction address list.
	 * @param offset bad instruction address offset
	 * @throws MemoryAccessException
	 */
	public void addBytesBadInstruction(long offset) throws MemoryAccessException {
		addBytesBadInstruction(toHex(offset));
	}

	/**
	 * Add BAD instruction (consumes 2-bytes).  Location will not be added to
	 * defined instruction address list.
	 * @param addr bad instruction address
	 * @throws MemoryAccessException
	 */
	public void addBytesBadInstruction(String addr) throws MemoryAccessException {
		// do not add to definedInstrAddresses
		Program program = getProgram();
		int txId = program.startTransaction("Add Instruction Bytes");
		try {
			program.getMemory().setShort(addr(addr), (short) 0xf00f);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	public void createNOPInstruction(String address, int size) throws Exception {
		addBytesNOP(address, size);
		disassemble(address, 1);
	}

	public void createCallInstruction(String address, String callAddress) throws Exception {
		addBytesCall(address, callAddress);
		disassemble(address, 1);

	}

	public void createReturnInstruction(String address) throws Exception {
		addBytesReturn(address);
		disassemble(address, 1);
	}

	public void createJmpInstruction(String address, String destAddress) throws Exception {
		addBytesBranch(address, destAddress);
		disassemble(address, 1);
	}

	public void createConditionalJmpInstruction(String address, String destAddress)
			throws Exception {
		addBytesBranchConditional(address, destAddress);
		disassemble(address, 1);
	}

	public void createJmpWithDelaySlot(String address, String destAddress) throws Exception {
		addBytesBranchWithDelaySlot(address, destAddress);
		disassemble(address, 1);
	}

}
