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
package ghidra.pcode.exec;

import java.util.*;

import generic.ULongSpan;
import generic.ULongSpan.*;
import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.util.Msg;

/**
 * A p-code executor state space for storing and retrieving bytes as arrays
 * 
 * @param <B> if this space is a cache, the type of object backing this space
 */
public class BytesPcodeExecutorStateSpace<B> {
	protected final static byte[] EMPTY = new byte[] {};
	protected final SemisparseByteArray bytes;
	protected final Language language; // for logging diagnostics
	protected final AddressSpace space;
	protected final B backing;

	/**
	 * Construct an internal space for the given address space
	 * 
	 * @param language the language, for logging diagnostics
	 * @param space the address space
	 * @param backing the backing object, possibly {@code null}
	 */
	public BytesPcodeExecutorStateSpace(Language language, AddressSpace space, B backing) {
		this.language = language;
		this.space = space;
		this.backing = backing;
		this.bytes = new SemisparseByteArray();
	}

	protected BytesPcodeExecutorStateSpace(Language language, AddressSpace space, B backing,
			SemisparseByteArray bytes) {
		this.language = language;
		this.space = space;
		this.backing = backing;
		this.bytes = bytes;
	}

	public BytesPcodeExecutorStateSpace<B> fork() {
		return new BytesPcodeExecutorStateSpace<>(language, space, backing, bytes.fork());
	}

	/**
	 * Write a value at the given offset
	 * 
	 * @param offset the offset
	 * @param val the value
	 */
	public void write(long offset, byte[] val, int srcOffset, int length) {
		bytes.putData(offset, val, srcOffset, length);
	}

	/**
	 * Extension point: Read from backing into this space, when acting as a cache.
	 * 
	 * @param uninitialized the ranges which need to be read.
	 * @return the ranges which remain uninitialized
	 */
	protected ULongSpanSet readUninitializedFromBacking(ULongSpanSet uninitialized) {
		return uninitialized;
	}

	/**
	 * Read a value from cache (or raw space if not acting as a cache) at the given offset
	 * 
	 * @param offset the offset
	 * @param size the number of bytes to read (the size of the value)
	 * @return the bytes read
	 */
	protected byte[] readBytes(long offset, int size, Reason reason) {
		byte[] data = new byte[size];
		bytes.getData(offset, data);
		return data;
	}

	protected AddressRange addrRng(ULongSpan span) {
		return new AddressRangeImpl(
			space.getAddress(span.min()),
			space.getAddress(span.max()));
	}

	protected ULongSpan spanRng(AddressRange range) {
		return ULongSpan.span(
			range.getMinAddress().getOffset(),
			range.getMaxAddress().getOffset());
	}

	protected AddressSet addrSet(ULongSpanSet set) {
		AddressSet result = new AddressSet();
		for (ULongSpan span : set.spans()) {
			result.add(addrRng(span));
		}
		return result;
	}

	/**
	 * This assumes without assertion that the set is contained in this space
	 * 
	 * @param set the address set
	 * @return the unsigned long span set
	 */
	protected ULongSpanSet spanSet(AddressSetView set) {
		MutableULongSpanSet result = new DefaultULongSpanSet();
		for (AddressRange range : set) {
			result.add(spanRng(range));
		}
		return result;
	}

	protected Set<Register> getRegs(AddressSetView set) {
		Set<Register> regs = new TreeSet<>();
		for (AddressRange rng : set) {
			Register r = language.getRegister(rng.getMinAddress(), (int) rng.getLength());
			if (r != null) {
				regs.add(r);
			}
			else {
				regs.addAll(Arrays.asList(language.getRegisters(rng.getMinAddress())));
			}
		}
		return regs;
	}

	protected void warnAddressSet(String message, AddressSetView set) {
		Set<Register> regs = getRegs(set);
		if (regs.isEmpty()) {
			Msg.warn(this, message + ": " + set);
		}
		else {
			Msg.warn(this, message + ": " + set + " (registers " + regs + ")");
		}
	}

	protected void warnUninit(ULongSpanSet uninit) {
		AddressSet uninitialized = addrSet(uninit);
		warnAddressSet("Emulator read from uninitialized state", uninitialized);
	}

	/**
	 * Read a value from the space at the given offset
	 * 
	 * <p>
	 * If this space is not acting as a cache, this simply delegates to
	 * {@link #readBytes(long, int)}. Otherwise, it will first ensure the cache covers the requested
	 * value.
	 * 
	 * @param offset the offset
	 * @param size the number of bytes to read (the size of the value)
	 * @param reason the reason for reading state
	 * @return the bytes read
	 */
	public byte[] read(long offset, int size, Reason reason) {
		ULongSpanSet uninitialized = bytes.getUninitialized(offset, offset + size - 1);
		if (uninitialized.isEmpty()) {
			return readBytes(offset, size, reason);
		}
		if (backing != null) {
			uninitialized = readUninitializedFromBacking(uninitialized);
			if (uninitialized.isEmpty()) {
				return readBytes(offset, size, reason);
			}
		}

		/**
		 * The decoder will buffer ahead, so give it as much as we can, but no more than is actually
		 * initialized. If it's a (non-decode) read, give it everything, but invoke the warning.
		 */
		if (reason == Reason.EXECUTE_DECODE) {
			Iterator<ULongSpan> it =
				uninitialized.complement(ULongSpan.extent(offset, size)).iterator();
			if (it.hasNext()) {
				ULongSpan init = it.next();
				if (init.min().longValue() == offset) {
					return readBytes(offset, (int) init.length(), reason);
				}
			}
		}

		if (reason == Reason.EXECUTE_READ) {
			warnUninit(uninitialized);
		}
		else if (reason == Reason.EXECUTE_DECODE) {
			/**
			 * The callers may be reading ahead, so it's not appropriate to throw an exception here.
			 * Instead, communicate there's no more. If the buffer's empty on their end, they'll
			 * handle the error as appropriate. If it's in the emulator, the instruction decoder
			 * should eventually throw the decode exception.
			 */
			return EMPTY;
		}
		return readBytes(offset, size, reason);
	}

	public Map<Register, byte[]> getRegisterValues(List<Register> registers) {
		Map<Register, byte[]> result = new HashMap<>();
		for (Register reg : registers) {
			long min = reg.getAddress().getOffset();
			long max = min + reg.getNumBytes();
			if (!bytes.isInitialized(min, max)) {
				continue;
			}
			byte[] data = new byte[reg.getNumBytes()];
			bytes.getData(min, data);
			result.put(reg, data);
		}
		return result;
	}

	public void clear() {
		bytes.clear();
	}
}
