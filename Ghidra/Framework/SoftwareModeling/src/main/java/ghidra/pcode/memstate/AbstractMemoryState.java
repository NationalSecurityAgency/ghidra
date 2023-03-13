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
package ghidra.pcode.memstate;

import java.math.BigInteger;

import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;

public abstract class AbstractMemoryState implements MemoryState {
	final Language language;

	public AbstractMemoryState(Language language) {
		this.language = language;
	}

	/**
	 * A convenience method for setting a value directly on a varnode rather than breaking out the
	 * components
	 * 
	 * @param vn the varnode location to be written
	 * @param cval the value to write into the varnode location
	 */
	@Override
	public final void setValue(Varnode vn, long cval) {
		Address addr = vn.getAddress();
		setValue(addr.getAddressSpace(), addr.getOffset(), vn.getSize(), cval);
	}

	/**
	 * A convenience method for setting a value directly on a register rather than breaking out the
	 * components
	 * 
	 * @param reg the register location to be written
	 * @param cval the value to write into the register location
	 */
	@Override
	public final void setValue(Register reg, long cval) {
		Address addr = reg.getAddress();
		setValue(addr.getAddressSpace(), addr.getOffset(), reg.getMinimumByteSize(), cval);
	}

	/**
	 * This is a convenience method for setting registers by name. Any register name known to the
	 * language can be used as a write location. The associated address space, offset, and size is
	 * looked up and automatically passed to the main setValue routine.
	 * 
	 * @param nm is the name of the register
	 * @param cval is the value to write to the register
	 */
	@Override
	public final void setValue(String nm, long cval) {
		// Set a "register" value
		setValue(language.getRegister(nm), cval);
	}

	/**
	 * This is the main interface for writing values to the MemoryState. If there is no registered
	 * MemoryBank for the desired address space, or if there is some other error, an exception is
	 * thrown.
	 * 
	 * @param spc is the address space to write to
	 * @param off is the offset where the value should be written
	 * @param size is the number of bytes to be written
	 * @param cval is the value to be written
	 */
	@Override
	public final void setValue(AddressSpace spc, long off, int size, long cval) {
		setChunk(Utils.longToBytes(cval, size, language.isBigEndian()), spc, off, size);
	}

	/**
	 * A convenience method for reading a value directly from a varnode rather than querying for the
	 * offset and space
	 * 
	 * @param vn the varnode location to be read
	 * @return the value read from the varnode location
	 */
	@Override
	public final long getValue(Varnode vn) {
		Address addr = vn.getAddress();
		return getValue(addr.getAddressSpace(), addr.getOffset(), vn.getSize());
	}

	/**
	 * A convenience method for reading a value directly from a register rather than querying for
	 * the offset and space
	 * 
	 * @param reg the register location to be read
	 * @return the value read from the register location
	 */
	@Override
	public final long getValue(Register reg) {
		Address addr = reg.getAddress();
		return getValue(addr.getAddressSpace(), addr.getOffset(), reg.getMinimumByteSize());
	}

	/**
	 * This is a convenience method for reading registers by name. any register name known to the
	 * language can be used as a read location. The associated address space, offset, and size is
	 * looked up and automatically passed to the main getValue routine.
	 * 
	 * @param nm is the name of the register
	 * @return the value associated with that register
	 */
	@Override
	public final long getValue(String nm) {
		// Get a "register" value
		return getValue(language.getRegister(nm));
	}

	/**
	 * This is the main interface for reading values from the MemoryState. If there is no registered
	 * MemoryBank for the desired address space, or if there is some other error, an exception is
	 * thrown.
	 * 
	 * @param spc is the address space being queried
	 * @param off is the offset of the value being queried
	 * @param size is the number of bytes to query
	 * @return the queried value
	 */
	@Override
	public final long getValue(AddressSpace spc, long off, int size) {
		if (spc.isConstantSpace()) {
			return off;
		}
		byte[] bytes = new byte[size];
		getChunk(bytes, spc, off, size, false);
		return Utils.bytesToLong(bytes, size, language.isBigEndian());
	}

	/**
	 * A convenience method for setting a value directly on a varnode rather than breaking out the
	 * components
	 * 
	 * @param vn the varnode location to be written
	 * @param cval the value to write into the varnode location
	 */
	@Override
	public final void setValue(Varnode vn, BigInteger cval) {
		Address addr = vn.getAddress();
		setValue(addr.getAddressSpace(), addr.getOffset(), vn.getSize(), cval);
	}

	/**
	 * A convenience method for setting a value directly on a register rather than breaking out the
	 * components
	 * 
	 * @param reg the register location to be written
	 * @param cval the value to write into the register location
	 */
	@Override
	public final void setValue(Register reg, BigInteger cval) {
		Address addr = reg.getAddress();
		setValue(addr.getAddressSpace(), addr.getOffset(), reg.getMinimumByteSize(), cval);
	}

	/**
	 * This is a convenience method for setting registers by name. Any register name known to the
	 * language can be used as a write location. The associated address space, offset, and size is
	 * looked up and automatically passed to the main setValue routine.
	 * 
	 * @param nm is the name of the register
	 * @param cval is the value to write to the register
	 */
	@Override
	public final void setValue(String nm, BigInteger cval) {
		// Set a "register" value
		setValue(language.getRegister(nm), cval);
	}

	/**
	 * This is the main interface for writing values to the MemoryState. If there is no registered
	 * MemoryBank for the desired address space, or if there is some other error, an exception is
	 * thrown.
	 * 
	 * @param spc is the address space to write to
	 * @param off is the offset where the value should be written
	 * @param size is the number of bytes to be written
	 * @param cval is the value to be written
	 */
	@Override
	public final void setValue(AddressSpace spc, long off, int size, BigInteger cval) {
		setChunk(Utils.bigIntegerToBytes(cval, size, language.isBigEndian()), spc, off, size);
	}

	/**
	 * A convenience method for reading a value directly from a varnode rather than querying for the
	 * offset and space
	 * 
	 * @param vn the varnode location to be read
	 * @param signed true if signed value should be returned, false for unsigned value
	 * @return the unsigned value read from the varnode location
	 */
	@Override
	public final BigInteger getBigInteger(Varnode vn, boolean signed) {
		Address addr = vn.getAddress();
		return getBigInteger(addr.getAddressSpace(), addr.getOffset(), vn.getSize(), signed);
	}

	/**
	 * A convenience method for reading a value directly from a register rather than querying for
	 * the offset and space
	 * 
	 * @param reg the register location to be read
	 * @return the unsigned value read from the register location
	 */
	@Override
	public final BigInteger getBigInteger(Register reg) {
		Address addr = reg.getAddress();
		return getBigInteger(addr.getAddressSpace(), addr.getOffset(), reg.getMinimumByteSize(),
			false);
	}

	/**
	 * This is a convenience method for reading registers by name. any register name known to the
	 * language can be used as a read location. The associated address space, offset, and size is
	 * looked up and automatically passed to the main getValue routine.
	 * 
	 * @param nm is the name of the register
	 * @return the unsigned value associated with that register
	 */
	@Override
	public final BigInteger getBigInteger(String nm) {
		// Get a "register" value
		return getBigInteger(language.getRegister(nm));
	}

	/**
	 * This is the main interface for reading values from the MemoryState. If there is no registered
	 * MemoryBank for the desired address space, or if there is some other error, an exception is
	 * thrown.
	 * 
	 * @param spc is the address space being queried
	 * @param off is the offset of the value being queried
	 * @param size is the number of bytes to query
	 * @param signed true if signed value should be returned, false for unsigned value
	 * @return the queried unsigned value
	 */
	@Override
	public final BigInteger getBigInteger(AddressSpace spc, long off, int size, boolean signed) {
		if (spc.isConstantSpace()) {
			if (!signed && off < 0) {
				return new BigInteger(1, Utils.longToBytes(off, 8, true));
			}
			return BigInteger.valueOf(off);
		}
		byte[] bytes = new byte[size];
		getChunk(bytes, spc, off, size, false);
		return Utils.bytesToBigInteger(bytes, size, language.isBigEndian(), signed);
	}
}
