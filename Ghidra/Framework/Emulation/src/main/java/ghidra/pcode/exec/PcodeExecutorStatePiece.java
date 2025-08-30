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

import java.math.BigInteger;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Stream;

import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.Varnode;

/**
 * An interface that provides storage for values of type {@code T}, addressed by offsets of type
 * {@code A}
 * 
 * <p>
 * The typical pattern for implementing a state is to compose it from one or more state pieces. Each
 * piece must use the same address type and arithmetic. If more than one piece is needed, they are
 * composed using {@link PairedPcodeExecutorStatePiece}. Once all the pieces are composed, the root
 * piece can be wrapped to make a state using {@link DefaultPcodeExecutorState} or
 * {@link PairedPcodeExecutorState}. The latter corrects the address type to be a pair so it matches
 * the type of values.
 *
 * @param <A> the type of address offsets
 * @param <T> the type of values
 */
public interface PcodeExecutorStatePiece<A, T> {

	/**
	 * Reasons for reading state
	 */
	enum Reason {
		/** The value is needed as the default program counter or disassembly context */
		RE_INIT,
		/** The value is being read by the emulator as data in the course of execution */
		EXECUTE_READ,
		/** The value is being decoded by the emulator as an instruction for execution */
		EXECUTE_DECODE,
		/** The value is being inspected by something other than an emulator */
		INSPECT
	}

	/**
	 * Construct a range, if only to verify the range is valid
	 * 
	 * @param space the address space
	 * @param offset the starting offset
	 * @param size the length (in bytes) of the range
	 */
	default void checkRange(AddressSpace space, long offset, int size) {
		// TODO: Perhaps get/setVar should just take an AddressRange?
		if (space.isConstantSpace()) {
			return;
		}
		try {
			new AddressRangeImpl(space.getAddress(offset), size);
		}
		catch (AddressOverflowException | AddressOutOfBoundsException e) {
			throw new IllegalArgumentException("Given offset and length exceeds address space");
		}
	}

	/**
	 * Get the language defining the address spaces of this state piece
	 * 
	 * @return the language
	 */
	Language getLanguage();

	/**
	 * Get the arithmetic used to manipulate addresses of the type used by this state
	 * 
	 * @return the address (or offset) arithmetic
	 */
	PcodeArithmetic<A> getAddressArithmetic();

	/**
	 * Get the arithmetic used to manipulate values of the type stored by this state
	 * 
	 * @return the arithmetic
	 */
	PcodeArithmetic<T> getArithmetic();

	/**
	 * Stream over the pieces within.
	 * 
	 * <p>
	 * If this piece is not a composition of others, then simply stream this piece in a singleton.
	 * Otherwise, stream the component pieces. (Do not include the composition itself, just the
	 * component pieces.)
	 * 
	 * @return the stream
	 */
	Stream<PcodeExecutorStatePiece<?, ?>> streamPieces();

	/**
	 * Create a deep copy of this state
	 * 
	 * @param cb callbacks to receive emulation events
	 * @return the copy
	 */
	default PcodeExecutorStatePiece<A, T> fork(PcodeStateCallbacks cb) {
		throw new UnsupportedOperationException();
	}

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
	 * @param quantize true to quantize to the language's "addressable unit"
	 * @param val the value
	 */
	void setVar(AddressSpace space, A offset, int size, boolean quantize, T val);

	/**
	 * Set the value of a variable without issuing callbacks
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the size of the variable
	 * @param val the value
	 */
	void setVarInternal(AddressSpace space, A offset, int size, T val);

	/**
	 * Set the value of a variable
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the size of the variable
	 * @param quantize true to quantize to the language's "addressable unit"
	 * @param val the value
	 */
	default void setVar(AddressSpace space, long offset, int size, boolean quantize, T val) {
		checkRange(space, offset, size);
		A aOffset = getAddressArithmetic().fromConst(offset, space.getPointerSize());
		setVar(space, aOffset, size, quantize, val);
	}

	/**
	 * Set the value of a variable without issuing callbacks
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the size of the variable
	 * @param val the value
	 */
	default void setVarInternal(AddressSpace space, long offset, int size, T val) {
		A aOffset = getAddressArithmetic().fromConst(offset, space.getPointerSize());
		setVarInternal(space, aOffset, size, val);
	}

	/**
	 * Set the value of a variable
	 * 
	 * @param address the address in memory
	 * @param size the size of the variable
	 * @param quantize true to quantize to the language's "addressable unit"
	 * @param val the value
	 */
	default void setVar(Address address, int size, boolean quantize, T val) {
		setVar(address.getAddressSpace(), address.getOffset(), size, quantize, val);
	}

	/**
	 * Get the value of a register variable
	 * 
	 * @param reg the register
	 * @param reason the reason for reading the register
	 * @return the value
	 */
	default T getVar(Register reg, Reason reason) {
		Address address = reg.getAddress();
		return getVar(address.getAddressSpace(), address.getOffset(), reg.getMinimumByteSize(),
			true, reason);
	}

	/**
	 * Get the value of a variable
	 * 
	 * @param var the variable
	 * @param reason the reason for reading the variable
	 * @return the value
	 */
	default T getVar(Varnode var, Reason reason) {
		Address address = var.getAddress();
		return getVar(address.getAddressSpace(), address.getOffset(), var.getSize(), true, reason);
	}

	/**
	 * Get the value of a variable
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the size of the variable
	 * @param quantize true to quantize to the language's "addressable unit"
	 * @param reason the reason for reading the variable
	 * @return the value
	 */
	T getVar(AddressSpace space, A offset, int size, boolean quantize, Reason reason);

	/**
	 * Get the value of a variable without issuing callbacks
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the size of the variable
	 * @param reason the reason for reading the variable
	 * @return the value
	 */
	T getVarInternal(AddressSpace space, A offset, int size, Reason reason);

	/**
	 * Get the entry at or after a given offset (without issuing callbacks)
	 *
	 * <p>
	 * (Optional operation) For pieces where each value is effective over a range, it is common to
	 * use an internal map (vice a byte array). When serializing the state, or otherwise seeking a
	 * complete examination, it is useful to retrieve those internal entries.
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @return the entry
	 */
	default Entry<A, T> getNextEntryInternal(AddressSpace space, A offset) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Get the value of a variable
	 * 
	 * <p>
	 * This method is typically used for reading memory variables.
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the size of the variable
	 * @param quantize true to quantize to the language's "addressable unit"
	 * @param reason the reason for reading the variable
	 * @return the value
	 */
	default T getVar(AddressSpace space, long offset, int size, boolean quantize, Reason reason) {
		checkRange(space, offset, size);
		A aOffset = getAddressArithmetic().fromConst(offset, space.getPointerSize());
		return getVar(space, aOffset, size, quantize, reason);
	}

	/**
	 * Get the value of a variable without issuing callbacks
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the size of the variable
	 * @param reason the reason for reading the variable
	 * @return the value
	 */
	default T getVarInternal(AddressSpace space, long offset, int size, Reason reason) {
		A aOffset = getAddressArithmetic().fromConst(offset, space.getPointerSize());
		return getVarInternal(space, aOffset, size, reason);
	}

	/**
	 * Get the entry at a given offset (without issuing callbacks)
	 *
	 * <p>
	 * (Optional operation) For pieces where each value is effective over a range, it is common to
	 * use an internal map (vice a byte array). When serializing the state, or otherwise seeking a
	 * complete examination, it is useful to retrieve those internal entries. This returns the next
	 * entry at or after the given offset within the given space. NOTE the returned entry
	 * <em>must</em> be for the given space. If no such entry exists, return {@code null}.
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @return the entry or null
	 */
	default Entry<Long, T> getNextEntryInternal(AddressSpace space, long offset) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Get the value of a variable
	 * 
	 * <p>
	 * This method is typically used for reading memory variables.
	 * 
	 * @param address the address of the variable
	 * @param size the size of the variable
	 * @param quantize true to quantize to the language's "addressable unit"
	 * @param reason the reason for reading the variable
	 * @return the value
	 */
	default T getVar(Address address, int size, boolean quantize, Reason reason) {
		return getVar(address.getAddressSpace(), address.getOffset(), size, quantize, reason);
	}

	/**
	 * Get all register values known to this state
	 * 
	 * <p>
	 * When the state acts as a cache, it should only return those cached.
	 * 
	 * @return a map of registers and their values
	 */
	Map<Register, T> getRegisterValues();

	/**
	 * Bind a buffer of concrete bytes at the given start address
	 * 
	 * @param address the start address
	 * @param purpose the reason why the emulator needs a concrete value
	 * @return a buffer
	 */
	MemBuffer getConcreteBuffer(Address address, Purpose purpose);

	/**
	 * Quantize the given offset to the language's "addressable unit"
	 * 
	 * @param space the space where the offset applies
	 * @param offset the offset
	 * @return the quantized offset
	 */
	default long quantizeOffset(AddressSpace space, long offset) {
		return space.truncateAddressableWordOffset(offset) * space.getAddressableUnitSize();
	}

	/**
	 * Erase the entire state or piece
	 * 
	 * <p>
	 * This is generally only useful when the state is itself a cache to another object. This will
	 * ensure the state is reading from that object rather than a stale cache. If this is not a
	 * cache, this could in fact clear the whole state, and the machine using it will be left in the
	 * dark.
	 */
	void clear();

	/**
	 * Convenience to set a variable to a concrete value
	 * 
	 * @param address the address in memory
	 * @param value the value
	 */
	default void setConcrete(Address address, byte[] value) {
		setVar(address, value.length, false, getArithmetic().fromConst(value));
	}

	/**
	 * Convenience to inspect the concrete value of a variable
	 * 
	 * @param address the address in memory
	 * @param size the number of bytes to inspect
	 * @return the value
	 * @throws ConcretionError if the value cannot be made concrete
	 */
	default byte[] inspectConcrete(Address address, int size) {
		return getArithmetic().toConcrete(getVar(address, size, false, Reason.INSPECT),
			Purpose.INSPECT);
	}

	/**
	 * Convenience to set a variable to a concrete value as a {@link BigInteger}
	 * 
	 * @param address the address is memory
	 * @param size the size of the variable (in bytes)
	 * @param value the value
	 */
	default void setBigInteger(Address address, int size, BigInteger value) {
		setVar(address, size, false, getArithmetic().fromConst(value, size));
	}

	/**
	 * Convenience to inspect the concrete value of a variable as a {@link BigInteger}
	 * 
	 * @param address the address in memory
	 * @param size the number of bytes to inspect
	 * @return the value
	 * @throws ConcretionError if the value cannot be made concrete
	 */
	default BigInteger inspectBigInteger(Address address, int size) {
		return getArithmetic().toBigInteger(getVar(address, size, false, Reason.INSPECT),
			Purpose.INSPECT);
	}

	/**
	 * Convenience to set a variable to a concrete value as a {@code long}
	 * 
	 * @param address the address is memory
	 * @param value the value
	 */
	default void setLong(Address address, long value) {
		setVar(address, Long.BYTES, false, getArithmetic().fromConst(value, Long.BYTES));
	}

	/**
	 * Convenience to inspect the concrete value of a variable as a {@code long}
	 * 
	 * @param address the address in memory
	 * @return the value
	 * @throws ConcretionError if the value cannot be made concrete
	 */
	default long inspectLong(Address address) {
		return getArithmetic().toLong(getVar(address, Long.BYTES, false, Reason.INSPECT),
			Purpose.INSPECT);
	}

	/**
	 * Convenience to set a variable to a concrete value as an {@code int}
	 * 
	 * @param address the address is memory
	 * @param value the value
	 */
	default void setInt(Address address, int value) {
		setVar(address, Integer.BYTES, false, getArithmetic().fromConst(value, Integer.BYTES));
	}

	/**
	 * Convenience to inspect the concrete value of a variable as an {@code int}
	 * 
	 * @param address the address in memory
	 * @return the value
	 * @throws ConcretionError if the value cannot be made concrete
	 */
	default int inspectInt(Address address) {
		return (int) getArithmetic().toLong(getVar(address, Integer.BYTES, false, Reason.INSPECT),
			Purpose.INSPECT);
	}

	/**
	 * Convenience to set a variable to a concrete value as a {@code short}
	 * 
	 * @param address the address is memory
	 * @param value the value
	 */
	default void setShort(Address address, short value) {
		setVar(address, Short.BYTES, false, getArithmetic().fromConst(value, Short.BYTES));
	}

	/**
	 * Convenience to inspect the concrete value of a variable as a {@code short}
	 * 
	 * @param address the address in memory
	 * @return the value
	 * @throws ConcretionError if the value cannot be made concrete
	 */
	default short inspectShort(Address address) {
		return (short) getArithmetic().toLong(getVar(address, Short.BYTES, false, Reason.INSPECT),
			Purpose.INSPECT);
	}

	/**
	 * Convenience to set a variable to a concrete value as a {@code byte}
	 * 
	 * @param address the address is memory
	 * @param value the value
	 */
	default void setByte(Address address, byte value) {
		setVar(address, Byte.BYTES, false, getArithmetic().fromConst(value, Byte.BYTES));
	}

	/**
	 * Convenience to inspect the concrete value of a variable as a {@code byte}
	 * 
	 * @param address the address in memory
	 * @return the value
	 * @throws ConcretionError if the value cannot be made concrete
	 */
	default byte inspectByte(Address address) {
		return (byte) getArithmetic().toLong(getVar(address, Byte.BYTES, false, Reason.INSPECT),
			Purpose.INSPECT);
	}

	/**
	 * Convenience to set a register variable to a concrete value as a {@link RegisterValue}
	 * 
	 * <p>
	 * <b>NOTE:</b> The register from the given value does not have to match the given register, but
	 * their <em>sizes</em> should at least match. This permits simpler moving of values from one
	 * register to another. If the sizes do not match, the behavior is undefined.
	 * 
	 * @param register the register
	 * @param value the value
	 */
	default void setRegisterValue(Register register, RegisterValue value) {
		setVar(register, getArithmetic().fromConst(value));
	}

	/**
	 * Convenience to set a register variable to a concrete value as a {@link RegisterValue}
	 * 
	 * @param value the value
	 */
	default void setRegisterValue(RegisterValue value) {
		setRegisterValue(value.getRegister(), value);
	}

	/**
	 * Convenience to inspect the concrete value of a register variable as a {@link RegisterValue}
	 * 
	 * @param register the register
	 * @return the value
	 * @throws ConcretionError if the value cannot be made concrete
	 */
	default RegisterValue inspectRegisterValue(Register register) {
		return getArithmetic().toRegisterValue(register, getVar(register, Reason.INSPECT),
			Purpose.INSPECT);
	}
}
