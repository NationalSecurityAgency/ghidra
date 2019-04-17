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
import java.util.HashMap;
import java.util.Map;

import generic.stl.VectorSTL;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;

/**
 * All storage/state for a pcode emulator machine
 *
 * Every piece of information in a pcode emulator machine is representable as a triple
 * (AddressSpace,offset,size).  This class allows getting and setting
 * of all state information of this form.
 */
public class MemoryState {

	Language language;
	VectorSTL<MemoryBank> memspace = new VectorSTL<MemoryBank>();
	Map<Register, Varnode> regVarnodeCache = new HashMap<Register, Varnode>();

	/**
	 * MemoryState constructor for a specified processor language
	 * @param language
	 */
	public MemoryState(Language language) {
		this.language = language;
	}

	private Varnode getVarnode(Register reg) {
		Varnode varnode = regVarnodeCache.get(reg);
		if (varnode == null) {
			varnode = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
			regVarnodeCache.put(reg, varnode);
		}
		return varnode;
	}

	/**
	 * MemoryBanks associated with specific address spaces must be registers with this MemoryState
	 * via this method.  Each address space that will be used during emulation must be registered
	 * separately.  The MemoryState object does not assume responsibility for freeing the MemoryBank.
	 * @param bank is a pointer to the MemoryBank to be registered
	 */
	public final void setMemoryBank(MemoryBank bank) {
		AddressSpace spc = bank.getSpace();
		int index = spc.getUnique();

		while (index >= memspace.size())
			memspace.push_back(null);

		memspace.set(index, bank);
	}

	/**
	 * Any MemoryBank that has been registered with this MemoryState can be retrieved via this
	 * method if the MemoryBank's associated address space is known.
	 * @param spc is the address space of the desired MemoryBank
	 * @return the MemoryBank or null if no bank is associated with spc.
	 */
	public final MemoryBank getMemoryBank(AddressSpace spc) {
		int index = spc.getUnique();
		if (index >= memspace.size())
			return null;
		return memspace.get(index);
	}

	/**
	 * A convenience method for setting a value directly on a varnode rather than
	 * breaking out the components
	 * @param vn the varnode location to be written
	 * @param cval the value to write into the varnode location
	 */
	public final void setValue(Varnode vn, long cval) {
		Address addr = vn.getAddress();
		setValue(addr.getAddressSpace(), addr.getOffset(), vn.getSize(), cval);
	}

	/**
	 * A convenience method for setting a value directly on a register rather than
	 * breaking out the components
	 * @param reg the register location to be written
	 * @param cval the value to write into the register location
	 */
	public final void setValue(Register reg, long cval) {
		Address addr = reg.getAddress();
		setValue(addr.getAddressSpace(), addr.getOffset(), reg.getMinimumByteSize(), cval);
	}

	/**
	 * This is a convenience method for setting registers by name.
	 * Any register name known to the language can be used as a write location.
	 * The associated address space, offset, and size is looked up and automatically
	 * passed to the main setValue routine.
	 * @param nm is the name of the register
	 * @param cval is the value to write to the register
	 */
	public final void setValue(String nm, long cval) {
		// Set a "register" value
		Varnode vdata = getVarnode(language.getRegister(nm));
		Address addr = vdata.getAddress();
		setValue(addr.getAddressSpace(), addr.getOffset(), vdata.getSize(), cval);
	}

	/**
	 * This is the main interface for writing values to the MemoryState.
	 * If there is no registered MemoryBank for the desired address space, or
	 * if there is some other error, an exception is thrown.
	 * @param spc is the address space to write to
	 * @param off is the offset where the value should be written
	 * @param size is the number of bytes to be written
	 * @param cval is the value to be written
	 */
	public final void setValue(AddressSpace spc, long off, int size, long cval) {
		setChunk(Utils.longToBytes(cval, size, language.isBigEndian()), spc, off, size);
	}

	/**
	 * A convenience method for reading a value directly from a varnode rather
	 * than querying for the offset and space
	 * @param vn the varnode location to be read
	 * @return the value read from the varnode location
	 */
	public final long getValue(Varnode vn) {
		Address addr = vn.getAddress();
		return getValue(addr.getAddressSpace(), addr.getOffset(), vn.getSize());
	}

	/**
	 * A convenience method for reading a value directly from a register rather
	 * than querying for the offset and space
	 * @param reg the register location to be read
	 * @return the value read from the register location
	 */
	public final long getValue(Register reg) {
		Address addr = reg.getAddress();
		return getValue(addr.getAddressSpace(), addr.getOffset(), reg.getMinimumByteSize());
	}

	/**
	 * This is a convenience method for reading registers by name.
	 * any register name known to the language can be used as a read location.
	 * The associated address space, offset, and size is looked up and automatically
	 * passed to the main getValue routine.
	 * @param nm is the name of the register
	 * @return the value associated with that register
	 */
	public final long getValue(String nm) {
		// Get a "register" value
		Varnode vdata = getVarnode(language.getRegister(nm));
		Address addr = vdata.getAddress();
		return getValue(addr.getAddressSpace(), addr.getOffset(), vdata.getSize());
	}

	/**
	 * This is the main interface for reading values from the MemoryState.
	 * If there is no registered MemoryBank for the desired address space, or
	 * if there is some other error, an exception is thrown.
	 * @param spc is the address space being queried
	 * @param off is the offset of the value being queried
	 * @param size is the number of bytes to query
	 * @return the queried value
	 */
	public final long getValue(AddressSpace spc, long off, int size) {
		if (spc.isConstantSpace()) {
			return off;
		}
		byte[] bytes = new byte[size];
		getChunk(bytes, spc, off, size, false);
		return Utils.bytesToLong(bytes, size, language.isBigEndian());
	}

	/**
	 * A convenience method for setting a value directly on a varnode rather than
	 * breaking out the components
	 * @param vn the varnode location to be written
	 * @param cval the value to write into the varnode location
	 */
	public final void setValue(Varnode vn, BigInteger cval) {
		Address addr = vn.getAddress();
		setValue(addr.getAddressSpace(), addr.getOffset(), vn.getSize(), cval);
	}

	/**
	 * A convenience method for setting a value directly on a register rather than
	 * breaking out the components
	 * @param reg the register location to be written
	 * @param cval the value to write into the register location
	 */
	public final void setValue(Register reg, BigInteger cval) {
		Address addr = reg.getAddress();
		setValue(addr.getAddressSpace(), addr.getOffset(), reg.getMinimumByteSize(), cval);
	}

	/**
	 * This is a convenience method for setting registers by name.
	 * Any register name known to the language can be used as a write location.
	 * The associated address space, offset, and size is looked up and automatically
	 * passed to the main setValue routine.
	 * @param nm is the name of the register
	 * @param cval is the value to write to the register
	 */
	public final void setValue(String nm, BigInteger cval) {
		// Set a "register" value
		Varnode vdata = getVarnode(language.getRegister(nm));
		Address addr = vdata.getAddress();
		setValue(addr.getAddressSpace(), addr.getOffset(), vdata.getSize(), cval);
	}

	/**
	 * This is the main interface for writing values to the MemoryState.
	 * If there is no registered MemoryBank for the desired address space, or
	 * if there is some other error, an exception is thrown.
	 * @param spc is the address space to write to
	 * @param off is the offset where the value should be written
	 * @param size is the number of bytes to be written
	 * @param cval is the value to be written
	 */
	public final void setValue(AddressSpace spc, long off, int size, BigInteger cval) {
		setChunk(Utils.bigIntegerToBytes(cval, size, language.isBigEndian()), spc, off, size);
	}

	/**
	 * A convenience method for reading a value directly from a varnode rather
	 * than querying for the offset and space
	 * @param vn the varnode location to be read
	 * @param signed true if signed value should be returned, false for unsigned value
	 * @return the unsigned value read from the varnode location
	 */
	public final BigInteger getBigInteger(Varnode vn, boolean signed) {
		Address addr = vn.getAddress();
		return getBigInteger(addr.getAddressSpace(), addr.getOffset(), vn.getSize(), signed);
	}

	/**
	 * A convenience method for reading a value directly from a register rather
	 * than querying for the offset and space
	 * @param reg the register location to be read
	 * @return the unsigned value read from the register location
	 */
	public final BigInteger getBigInteger(Register reg) {
		Address addr = reg.getAddress();
		return getBigInteger(addr.getAddressSpace(), addr.getOffset(), reg.getMinimumByteSize(),
			false);
	}

	/**
	 * This is a convenience method for reading registers by name.
	 * any register name known to the language can be used as a read location.
	 * The associated address space, offset, and size is looked up and automatically
	 * passed to the main getValue routine.
	 * @param nm is the name of the register
	 * @return the unsigned value associated with that register
	 */
	public final BigInteger getBigInteger(String nm) {
		// Get a "register" value
		Varnode vdata = getVarnode(language.getRegister(nm));
		Address addr = vdata.getAddress();
		return getBigInteger(addr.getAddressSpace(), addr.getOffset(), vdata.getSize(), false);
	}

	/**
	 * This is the main interface for reading values from the MemoryState.
	 * If there is no registered MemoryBank for the desired address space, or
	 * if there is some other error, an exception is thrown.
	 * @param spc is the address space being queried
	 * @param off is the offset of the value being queried
	 * @param size is the number of bytes to query
	 * @param signed true if signed value should be returned, false for unsigned value
	 * @return the queried unsigned value
	 */
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

	/**
	 * This is the main interface for reading a range of bytes from the MemorySate.
	 * The MemoryBank associated with the address space of the query is looked up
	 * and the request is forwarded to the getChunk method on the MemoryBank. If there
	 * is no registered MemoryBank or some other error, an exception is thrown.
	 * All getLongValue methods utilize this method to read the bytes from the
	 * appropriate memory bank. 
	 * @param res the result buffer for storing retrieved bytes
	 * @param spc the desired address space
	 * @param off the starting offset of the byte range being read
	 * @param size the number of bytes being read
	 * @param stopOnUnintialized if true a partial read is permitted and returned size may be 
	 * smaller than size requested
	 * @return number of bytes actually read
	 * @throws LowlevelError if spc has not been mapped within this MemoryState or memory fault
	 * handler generated error
	 */
	public int getChunk(byte[] res, AddressSpace spc, long off, int size,
			boolean stopOnUnintialized) {
		if (spc.isConstantSpace()) {
			System.arraycopy(Utils.longToBytes(off, size, language.isBigEndian()), 0, res, 0, size);
			return size;
		}
		MemoryBank mspace = getMemoryBank(spc);
		if (mspace == null)
			throw new LowlevelError("Getting chunk from unmapped memory space: " + spc.getName());
		return mspace.getChunk(off, size, res, stopOnUnintialized);
	}

	/**
	 * This is the main interface for setting values for a range of bytes in the MemoryState.
	 * The MemoryBank associated with the desired address space is looked up and the
	 * write is forwarded to the setChunk method on the MemoryBank. If there is no
	 * registered MemoryBank or some other error, an exception  is throw.
	 * All setValue methods utilize this method to read the bytes from the
	 * appropriate memory bank. 
	 * @param val the byte values to be written into the MemoryState
	 * @param spc the address space being written
	 * @param off the starting offset of the range being written
	 * @param size the number of bytes to write
	 * @throws LowlevelError if spc has not been mapped within this MemoryState
	 */
	public void setChunk(byte[] val, AddressSpace spc, long off, int size) {
		MemoryBank mspace = getMemoryBank(spc);
		if (mspace == null)
			throw new LowlevelError("Setting chunk of unmapped memory space: " + spc.getName());
		mspace.setChunk(off, size, val);
	}

	/**
	 * This is the main interface for setting the initialization status for a range of bytes
	 * in the MemoryState.
	 * The MemoryBank associated with the desired address space is looked up and the
	 * write is forwarded to the setInitialized method on the MemoryBank. If there is no
	 * registered MemoryBank or some other error, an exception  is throw.
	 * All setValue methods utilize this method to read the bytes from the
	 * appropriate memory bank. 
	 * @param initialized indicates if range should be marked as initialized or not
	 * @param spc the address space being written
	 * @param off the starting offset of the range being written
	 * @param size the number of bytes to write
	 */
	public void setInitialized(boolean initialized, AddressSpace spc, long off, int size) {
		MemoryBank mspace = getMemoryBank(spc);
		if (mspace == null)
			throw new LowlevelError("Setting intialization status of unmapped memory space: " +
				spc.getName());
		mspace.setInitialized(off, size, initialized);
	}

}
