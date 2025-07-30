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

import ghidra.pcode.emu.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.*;

/**
 * A set of callbacks available for state changes during p-code execution.
 * 
 * <p>
 * When dealing with emulation (as opposed to just p-code execution), consider
 * {@link PcodeEmulationCallbacks} instead. See {@link PcodeEmulator} for advice regarding extension
 * versus integration. In particular, these callbacks were introduced to avert the need to extend
 * {@link PcodeExecutorState}s and/or {@link PcodeExecutorStatePiece}s just to introduce
 * integration-driven behaviors. E.g., to lazily load state from an external machine-state snapshot,
 * the client should implement the
 * {@link #readUninitialized(PcodeExecutorStatePiece, AddressSetView)} or
 * {@link PcodeEmulationCallbacks#readUninitialized(PcodeThread, PcodeExecutorStatePiece, AddressSetView)}
 * callback rather than extending {@link BytesPcodeExecutorStatePiece}.
 */
public interface PcodeStateCallbacks {
	/**
	 * A singleton implementation of the callbacks that does nothing.
	 */
	enum NoPcodeStateCallbacks implements PcodeStateCallbacks {
		/** Callbacks that do nothing */
		INSTANCE;
	}

	/** Callbacks that do nothing */
	PcodeStateCallbacks NONE = NoPcodeStateCallbacks.INSTANCE;

	/**
	 * A convenience for constructing an address set from a varnode-like triple
	 * 
	 * @param space the address space
	 * @param offset the offset
	 * @param length the size in bytes, at least 1
	 * @return the address set
	 */
	static AddressSet rngSet(AddressSpace space, long offset, int length) {
		Address min = space.getAddress(offset);
		return new AddressSet(min, min.add(length - 1));
	}

	/**
	 * Check that the given piece has a required value domain
	 * 
	 * @param <A> the piece's address domain
	 * @param <T> the piece's value domain
	 * @param piece the piece
	 * @param domain the required value domain
	 * @return the piece cast to the required value domain if it matched, or null if the piece has a
	 *         different value domain.
	 */
	@SuppressWarnings("unchecked")
	static <A, T> PcodeExecutorStatePiece<A, T> checkValueDomain(
			PcodeExecutorStatePiece<A, ?> piece, Class<T> domain) {
		if (piece.getArithmetic().getDomain() == domain) {
			return (PcodeExecutorStatePiece<A, T>) piece;
		}
		return null;
	}

	/**
	 * Data was written into the given state piece (abstract addressing.)
	 * 
	 * @param <A> the piece's address domain
	 * @param <T> the piece's value domain
	 * @param piece the state piece
	 * @param space the address space of the operand
	 * @param offset the offset of the operand
	 * @param length the size of the operand
	 * @param value the value written
	 */
	default <A, T> void dataWritten(PcodeExecutorStatePiece<A, T> piece, AddressSpace space,
			A offset, int length, T value) {
	}

	/**
	 * Typically used from within
	 * {@link #dataWritten(PcodeExecutorStatePiece, AddressSpace, Object, int, Object)} to forward
	 * the call to the callback for concrete addressing
	 * {@link #dataWritten(PcodeExecutorStatePiece, Address, int, Object)}.
	 * 
	 * @param <A> the piece's address domain
	 * @param <T> the piece's value domain
	 * @param piece the state piece
	 * @param space the address space of the operand
	 * @param offset the offset of the operand
	 * @param length the size of the operand
	 * @param value the value written
	 */
	default <A, T> void delegateDataWritten(PcodeExecutorStatePiece<A, T> piece, AddressSpace space,
			A offset, int length, T value) {
		dataWritten(piece, piece.getAddressArithmetic().toAddress(offset, space, Purpose.STORE),
			length, value);
	}

	/**
	 * Data was written into the given state piece (concrete addressing).
	 * 
	 * @param <A> the piece's address domain
	 * @param <T> the piece's value domain
	 * @param piece the state piece
	 * @param address the address of the operand
	 * @param length the size of the operand
	 * @param value the value written
	 */
	default <A, T> void dataWritten(PcodeExecutorStatePiece<A, T> piece, Address address,
			int length, T value) {
	}

	/**
	 * Typically used from within
	 * {@link #dataWritten(PcodeExecutorStatePiece, Address, int, Object)} to forward the call to
	 * the callback for abstract addressing
	 * {@link #dataWritten(PcodeExecutorStatePiece, AddressSpace, Object, int, Object)}.
	 * 
	 * @param <A> the piece's address domain
	 * @param <T> the piece's value domain
	 * @param piece the state piece
	 * @param address the address of the operand
	 * @param length the size of the operand
	 * @param value the value written
	 */
	default <A, T> void delegateDataWritten(PcodeExecutorStatePiece<A, T> piece, Address address,
			int length, T value) {
		dataWritten(piece, address.getAddressSpace(),
			piece.getAddressArithmetic().fromConst(address), length, value);
	}

	/**
	 * The executor is preparing to read from uninitialized portions of the given state piece
	 * (abstract addressing).
	 * 
	 * <p>
	 * This callback provides an opportunity for something to initialize the required portion
	 * lazily. In most cases, this should either return 0 indicating the requested portion remains
	 * uninitialized, or the full {@code length} indicating the full requested portion is now
	 * initialized. If, for some reason, the requested portion could only be partially initialized,
	 * this can return a smaller length. Partial initializations are only recognized from the
	 * starting offset. Other parts could be initialized; however, there is no mechanism for
	 * communicating that result to the executor.
	 * 
	 * @param <A> the piece's address domain
	 * @param <T> the piece's value domain
	 * @param piece the state piece
	 * @param space the address space of the operand
	 * @param offset the offset of the operand
	 * @param length the size of the operand
	 * @return the length of the operand just initialized, typically 0 or {@code length}
	 */
	default <A, T> int readUninitialized(PcodeExecutorStatePiece<A, T> piece,
			AddressSpace space, A offset, int length) {
		return 0;
	}

	/**
	 * Typically used from within
	 * {@link #readUninitialized(PcodeExecutorStatePiece, AddressSpace, Object, int)} to forward to
	 * the callback for concrete addressing
	 * {@link #readUninitialized(PcodeExecutorStatePiece, AddressSetView)}.
	 * 
	 * @param <A> the piece's address domain
	 * @param <T> the piece's value domain
	 * @param piece the state piece
	 * @param space the address space of the operand
	 * @param offset the offset of the operand
	 * @param length the size of the operand
	 * @return the length of the operand just initialized, typically 0 or {@code length}
	 */
	default <A, T> int delegateReadUninitialized(PcodeExecutorStatePiece<A, T> piece,
			AddressSpace space, A offset, int length) {
		long lOffset = piece.getAddressArithmetic().toLong(offset, Purpose.LOAD);
		AddressSet set = PcodeStateCallbacks.rngSet(space, lOffset, length);
		AddressSetView remains = readUninitialized(piece, set);
		if (set == remains) {
			return 0;
		}
		set.delete(remains);
		AddressRange first = set.getFirstRange();
		return first == null ? 0 : (int) first.getLength();
	}

	/**
	 * The executor is preparing to read from uninitialized portions of the given state piece
	 * (concrete addressing).
	 * 
	 * <p>
	 * This callback provides an opportunity for something to initialize the required portion
	 * lazily. This method must return the address set that remains uninitialized. If no part of the
	 * required portion was initialized, this should return {@code set} identically, so that the
	 * caller can quickly recognize that nothing has changed. Otherwise, this should copy
	 * {@code set}, remove those parts it was able to initialize, and return the copy. <b>DO NOT</b>
	 * modify the given {@code set}.
	 * 
	 * @param <A> the piece's address domain
	 * @param <T> the piece's value domain
	 * @param piece the state piece
	 * @param set the uninitialized portion required
	 * @return the addresses in {@code set} that remain uninitialized
	 */
	default <A, T> AddressSetView readUninitialized(PcodeExecutorStatePiece<A, T> piece,
			AddressSetView set) {
		return set;
	}

	/**
	 * Typically used from within
	 * {@link #readUninitialized(PcodeExecutorStatePiece, AddressSetView)} to forward to the
	 * callback for abstract addressing
	 * {@link #readUninitialized(PcodeExecutorStatePiece, AddressSpace, Object, int)}.
	 * 
	 * @param <A> the piece's address domain
	 * @param <T> the piece's value domain
	 * @param piece the state piece
	 * @param set the uninitialized portion required
	 * @return the addresses in {@code set} that remain uninitialized
	 */
	default <A, T> AddressSetView delegateReadUninitialized(PcodeExecutorStatePiece<A, T> piece,
			AddressSetView set) {
		if (set.isEmpty()) {
			return set;
		}
		AddressSet remains = new AddressSet(set);
		for (AddressRange range : set) {
			int l = readUninitialized(piece, range.getAddressSpace(),
				piece.getAddressArithmetic().fromConst(range.getMinAddress()),
				(int) range.getLength());
			if (l == 0) {
				continue;
			}
			remains.delete(range.getMinAddress(), range.getMinAddress().add(l - 1));
		}
		return remains;
	}
}
