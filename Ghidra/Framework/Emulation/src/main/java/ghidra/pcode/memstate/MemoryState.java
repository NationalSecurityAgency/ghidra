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

import ghidra.pcode.error.LowlevelError;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;

public interface MemoryState {

	/**
	 * MemoryBanks associated with specific address spaces must be registers with this MemoryState
	 * via this method.  Each address space that will be used during emulation must be registered
	 * separately.  The MemoryState object does not assume responsibility for freeing the MemoryBank.
	 * @param bank is a pointer to the MemoryBank to be registered
	 */
	void setMemoryBank(MemoryBank bank);

	/**
	 * Any MemoryBank that has been registered with this MemoryState can be retrieved via this
	 * method if the MemoryBank's associated address space is known.
	 * @param spc is the address space of the desired MemoryBank
	 * @return the MemoryBank or null if no bank is associated with spc.
	 */
	MemoryBank getMemoryBank(AddressSpace spc);

	/**
	 * A convenience method for setting a value directly on a varnode rather than
	 * breaking out the components
	 * @param vn the varnode location to be written
	 * @param cval the value to write into the varnode location
	 */
	void setValue(Varnode vn, long cval);

	/**
	 * A convenience method for setting a value directly on a register rather than
	 * breaking out the components
	 * @param reg the register location to be written
	 * @param cval the value to write into the register location
	 */
	void setValue(Register reg, long cval);

	/**
	 * This is a convenience method for setting registers by name.
	 * Any register name known to the language can be used as a write location.
	 * The associated address space, offset, and size is looked up and automatically
	 * passed to the main setValue routine.
	 * @param nm is the name of the register
	 * @param cval is the value to write to the register
	 */
	void setValue(String nm, long cval);

	/**
	 * This is the main interface for writing values to the MemoryState.
	 * If there is no registered MemoryBank for the desired address space, or
	 * if there is some other error, an exception is thrown.
	 * @param spc is the address space to write to
	 * @param off is the offset where the value should be written
	 * @param size is the number of bytes to be written
	 * @param cval is the value to be written
	 */
	void setValue(AddressSpace spc, long off, int size, long cval);

	/**
	 * A convenience method for reading a value directly from a varnode rather
	 * than querying for the offset and space
	 * @param vn the varnode location to be read
	 * @return the value read from the varnode location
	 */
	long getValue(Varnode vn);

	/**
	 * A convenience method for reading a value directly from a register rather
	 * than querying for the offset and space
	 * @param reg the register location to be read
	 * @return the value read from the register location
	 */
	long getValue(Register reg);

	/**
	 * This is a convenience method for reading registers by name.
	 * any register name known to the language can be used as a read location.
	 * The associated address space, offset, and size is looked up and automatically
	 * passed to the main getValue routine.
	 * @param nm is the name of the register
	 * @return the value associated with that register
	 */
	long getValue(String nm);

	/**
	 * This is the main interface for reading values from the MemoryState.
	 * If there is no registered MemoryBank for the desired address space, or
	 * if there is some other error, an exception is thrown.
	 * @param spc is the address space being queried
	 * @param off is the offset of the value being queried
	 * @param size is the number of bytes to query
	 * @return the queried value
	 */
	long getValue(AddressSpace spc, long off, int size);

	/**
	 * A convenience method for setting a value directly on a varnode rather than
	 * breaking out the components
	 * @param vn the varnode location to be written
	 * @param cval the value to write into the varnode location
	 */
	void setValue(Varnode vn, BigInteger cval);

	/**
	 * A convenience method for setting a value directly on a register rather than
	 * breaking out the components
	 * @param reg the register location to be written
	 * @param cval the value to write into the register location
	 */
	void setValue(Register reg, BigInteger cval);

	/**
	 * This is a convenience method for setting registers by name.
	 * Any register name known to the language can be used as a write location.
	 * The associated address space, offset, and size is looked up and automatically
	 * passed to the main setValue routine.
	 * @param nm is the name of the register
	 * @param cval is the value to write to the register
	 */
	void setValue(String nm, BigInteger cval);

	/**
	 * This is the main interface for writing values to the MemoryState.
	 * If there is no registered MemoryBank for the desired address space, or
	 * if there is some other error, an exception is thrown.
	 * @param spc is the address space to write to
	 * @param off is the offset where the value should be written
	 * @param size is the number of bytes to be written
	 * @param cval is the value to be written
	 */
	void setValue(AddressSpace spc, long off, int size, BigInteger cval);

	/**
	 * A convenience method for reading a value directly from a varnode rather
	 * than querying for the offset and space
	 * @param vn the varnode location to be read
	 * @param signed true if signed value should be returned, false for unsigned value
	 * @return the unsigned value read from the varnode location
	 */
	BigInteger getBigInteger(Varnode vn, boolean signed);

	/**
	 * A convenience method for reading a value directly from a register rather
	 * than querying for the offset and space
	 * @param reg the register location to be read
	 * @return the unsigned value read from the register location
	 */
	BigInteger getBigInteger(Register reg);

	/**
	 * This is a convenience method for reading registers by name.
	 * any register name known to the language can be used as a read location.
	 * The associated address space, offset, and size is looked up and automatically
	 * passed to the main getValue routine.
	 * @param nm is the name of the register
	 * @return the unsigned value associated with that register
	 */
	BigInteger getBigInteger(String nm);

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
	BigInteger getBigInteger(AddressSpace spc, long off, int size, boolean signed);

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
	int getChunk(byte[] res, AddressSpace spc, long off, int size,
			boolean stopOnUnintialized);

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
	void setChunk(byte[] val, AddressSpace spc, long off, int size);

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
	void setInitialized(boolean initialized, AddressSpace spc, long off, int size);

}
