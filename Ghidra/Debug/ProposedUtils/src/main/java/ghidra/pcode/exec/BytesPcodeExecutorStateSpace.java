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

import com.google.common.collect.*;
import com.google.common.primitives.UnsignedLong;

import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.util.Msg;

/**
 * A p-code executor state space for storing bytes, retrieved and set as arrays.
 * 
 * @param <B> if this space is a cache, the type of object backing this space
 */
public class BytesPcodeExecutorStateSpace<B> {
	protected final SemisparseByteArray bytes = new SemisparseByteArray();
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
	 * Utility for handling uninitialized ranges: Get the lower endpoint
	 * 
	 * @param rng the range
	 * @return the lower endpoint
	 */
	public long lower(Range<UnsignedLong> rng) {
		return rng.lowerBoundType() == BoundType.CLOSED
				? rng.lowerEndpoint().longValue()
				: rng.lowerEndpoint().longValue() + 1;
	}

	/**
	 * Utility for handling uninitialized ranges: Get the upper endpoint
	 * 
	 * @param rng the range
	 * @return the upper endpoint
	 */
	public long upper(Range<UnsignedLong> rng) {
		return rng.upperBoundType() == BoundType.CLOSED
				? rng.upperEndpoint().longValue()
				: rng.upperEndpoint().longValue() - 1;
	}

	/**
	 * Extension point: Read from backing into this space, when acting as a cache.
	 * 
	 * @param uninitialized the ranges which need to be read.
	 */
	protected void readUninitializedFromBacking(RangeSet<UnsignedLong> uninitialized) {
	}

	/**
	 * Read a value from cache (or raw space if not acting as a cache) at the given offset
	 * 
	 * @param offset the offset
	 * @param size the number of bytes to read (the size of the value)
	 * @return the bytes read
	 */
	protected byte[] readBytes(long offset, int size) {
		byte[] data = new byte[size];
		bytes.getData(offset, data);
		return data;
	}

	protected AddressRange addrRng(Range<UnsignedLong> rng) {
		Address start = space.getAddress(lower(rng));
		Address end = space.getAddress(upper(rng));
		return new AddressRangeImpl(start, end);
	}

	protected AddressSet addrSet(RangeSet<UnsignedLong> set) {
		AddressSet result = new AddressSet();
		for (Range<UnsignedLong> rng : set.asRanges()) {
			result.add(addrRng(rng));
		}
		return result;
	}

	protected Set<Register> getRegs(AddressSet set) {
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

	protected void warnAddressSet(String message, AddressSet set) {
		Set<Register> regs = getRegs(set);
		if (regs.isEmpty()) {
			Msg.warn(this, message + ": " + set);
		}
		else {
			Msg.warn(this, message + ": " + set + " (registers " + regs + ")");
		}
	}

	protected void warnUninit(RangeSet<UnsignedLong> uninit) {
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
	 * @return the bytes read
	 */
	public byte[] read(long offset, int size) {
		if (backing != null) {
			readUninitializedFromBacking(bytes.getUninitialized(offset, offset + size - 1));
		}
		RangeSet<UnsignedLong> stillUninit = bytes.getUninitialized(offset, offset + size - 1);
		if (!stillUninit.isEmpty()) {
			warnUninit(stillUninit);
		}
		return readBytes(offset, size);
	}
}
