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

import generic.stl.VectorSTL;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;

/**
 * All storage/state for a pcode emulator machine
 *
 * Every piece of information in a pcode emulator machine is representable as a triple
 * (AddressSpace,offset,size). This class allows getting and setting of all state information of
 * this form.
 */
public class DefaultMemoryState extends AbstractMemoryState {

	VectorSTL<MemoryBank> memspace = new VectorSTL<MemoryBank>();

	/**
	 * MemoryState constructor for a specified processor language
	 * 
	 * @param language
	 */
	public DefaultMemoryState(Language language) {
		super(language);
	}

	/**
	 * MemoryBanks associated with specific address spaces must be registers with this MemoryState
	 * via this method. Each address space that will be used during emulation must be registered
	 * separately. The MemoryState object does not assume responsibility for freeing the MemoryBank.
	 * 
	 * @param bank is a pointer to the MemoryBank to be registered
	 */
	@Override
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
	 * 
	 * @param spc is the address space of the desired MemoryBank
	 * @return the MemoryBank or null if no bank is associated with spc.
	 */
	@Override
	public final MemoryBank getMemoryBank(AddressSpace spc) {
		int index = spc.getUnique();
		if (index >= memspace.size())
			return null;
		return memspace.get(index);
	}

	/**
	 * This is the main interface for reading a range of bytes from the MemorySate. The MemoryBank
	 * associated with the address space of the query is looked up and the request is forwarded to
	 * the getChunk method on the MemoryBank. If there is no registered MemoryBank or some other
	 * error, an exception is thrown. All getLongValue methods utilize this method to read the bytes
	 * from the appropriate memory bank.
	 * 
	 * @param res the result buffer for storing retrieved bytes
	 * @param spc the desired address space
	 * @param off the starting offset of the byte range being read
	 * @param size the number of bytes being read
	 * @param stopOnUnintialized if true a partial read is permitted and returned size may be
	 *            smaller than size requested
	 * @return number of bytes actually read
	 * @throws LowlevelError if spc has not been mapped within this MemoryState or memory fault
	 *             handler generated error
	 */
	@Override
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
	 * This is the main interface for setting values for a range of bytes in the MemoryState. The
	 * MemoryBank associated with the desired address space is looked up and the write is forwarded
	 * to the setChunk method on the MemoryBank. If there is no registered MemoryBank or some other
	 * error, an exception is throw. All setValue methods utilize this method to read the bytes from
	 * the appropriate memory bank.
	 * 
	 * @param val the byte values to be written into the MemoryState
	 * @param spc the address space being written
	 * @param off the starting offset of the range being written
	 * @param size the number of bytes to write
	 * @throws LowlevelError if spc has not been mapped within this MemoryState
	 */
	@Override
	public void setChunk(byte[] val, AddressSpace spc, long off, int size) {
		MemoryBank mspace = getMemoryBank(spc);
		if (mspace == null)
			throw new LowlevelError("Setting chunk of unmapped memory space: " + spc.getName());
		mspace.setChunk(off, size, val);
	}

	/**
	 * This is the main interface for setting the initialization status for a range of bytes in the
	 * MemoryState. The MemoryBank associated with the desired address space is looked up and the
	 * write is forwarded to the setInitialized method on the MemoryBank. If there is no registered
	 * MemoryBank or some other error, an exception is throw. All setValue methods utilize this
	 * method to read the bytes from the appropriate memory bank.
	 * 
	 * @param initialized indicates if range should be marked as initialized or not
	 * @param spc the address space being written
	 * @param off the starting offset of the range being written
	 * @param size the number of bytes to write
	 */
	@Override
	public void setInitialized(boolean initialized, AddressSpace spc, long off, int size) {
		MemoryBank mspace = getMemoryBank(spc);
		if (mspace == null)
			throw new LowlevelError("Setting intialization status of unmapped memory space: " +
				spc.getName());
		mspace.setInitialized(off, size, initialized);
	}
}
