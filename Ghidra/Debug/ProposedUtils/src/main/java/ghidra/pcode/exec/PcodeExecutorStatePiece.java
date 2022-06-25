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

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.Varnode;

/**
 * An interface that provides storage for values of type {@code T}, addressed by offsets of type
 * {@code A}.
 *
 * @param <A> the type of offsets
 * @param <T> the type of values
 */
public interface PcodeExecutorStatePiece<A, T> {

	/**
	 * Construct a range, if only to verify the range is valid
	 * 
	 * @param space the address space
	 * @param offset the starting offset
	 * @param size the length (in bytes) of the range
	 */
	default void checkRange(AddressSpace space, long offset, int size) {
		// TODO: Perhaps get/setVar should just take an AddressRange?
		try {
			new AddressRangeImpl(space.getAddress(offset), size);
		}
		catch (AddressOverflowException | AddressOutOfBoundsException e) {
			throw new IllegalArgumentException("Given offset and length exceeds address space");
		}
	}

	/**
	 * Convert the given offset from {@code long} to type {@code A}
	 * 
	 * <p>
	 * Note, is it unlikely (and discouraged) to encode the space in {@code A}. The reason the space
	 * is given is to ensure the result has the correct size.
	 * 
	 * @param space the space where the offset applies
	 * @param l the offset
	 * @return the same offset as type {@code A}
	 */
	A longToOffset(AddressSpace space, long l);

	/**
	 * Set the value of a register variable
	 * 
	 * @param reg the register
	 * @param val the value
	 */
	default void setVar(Register reg, T val) {
		Address address = reg.getAddress();
		setVar(address.getAddressSpace(), address.getOffset(), reg.getMinimumByteSize(), true, val);
	}

	/**
	 * Set the value of a variable
	 * 
	 * @param var the variable
	 * @param val the value
	 */
	default void setVar(Varnode var, T val) {
		Address address = var.getAddress();
		setVar(address.getAddressSpace(), address.getOffset(), var.getSize(), true, val);
	}

	/**
	 * Set the value of a variable
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the size of the variable
	 * @param truncateAddressableUnit true to truncate to the language's "addressable unit"
	 * @param val the value
	 */
	void setVar(AddressSpace space, A offset, int size, boolean truncateAddressableUnit, T val);

	/**
	 * Set the value of a variable
	 * 
	 * <p>
	 * This method is typically used for writing memory variables.
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the size of the variable
	 * @param truncateAddressableUnit true to truncate to the language's "addressable unit"
	 * @param val the value
	 */
	default void setVar(AddressSpace space, long offset, int size, boolean truncateAddressableUnit,
			T val) {
		checkRange(space, offset, size);
		setVar(space, longToOffset(space, offset), size, truncateAddressableUnit, val);
	}

	/**
	 * Get the value of a register variable
	 * 
	 * @param reg the register
	 * @return the value
	 */
	default T getVar(Register reg) {
		Address address = reg.getAddress();
		return getVar(address.getAddressSpace(), address.getOffset(), reg.getMinimumByteSize(),
			true);
	}

	/**
	 * Get the value of a variable
	 * 
	 * @param var the variable
	 * @return the value
	 */
	default T getVar(Varnode var) {
		Address address = var.getAddress();
		return getVar(address.getAddressSpace(), address.getOffset(), var.getSize(), true);
	}

	/**
	 * Get the value of a variable
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the size of the variable
	 * @param truncateAddressableUnit true to truncate to the language's "addressable unit"
	 * @return the value
	 */
	T getVar(AddressSpace space, A offset, int size, boolean truncateAddressableUnit);

	/**
	 * Get the value of a variable
	 * 
	 * <p>
	 * This method is typically used for reading memory variables.
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the size of the variable
	 * @param truncateAddressableUnit true to truncate to the language's "addressalbe unit"
	 * @return the value
	 */
	default T getVar(AddressSpace space, long offset, int size, boolean truncateAddressableUnit) {
		checkRange(space, offset, size);
		return getVar(space, longToOffset(space, offset), size, truncateAddressableUnit);
	}

	/**
	 * Bind a buffer of concrete bytes at the given start address
	 * 
	 * @param address the start address
	 * @return a buffer
	 */
	MemBuffer getConcreteBuffer(Address address);

	/**
	 * Truncate the given offset to the language's "addressable unit"
	 * 
	 * @param space the space where the offset applies
	 * @param offset the offset
	 * @return the truncated offset
	 */
	default long truncateOffset(AddressSpace space, long offset) {
		return space.truncateAddressableWordOffset(offset) * space.getAddressableUnitSize();
	}
}
