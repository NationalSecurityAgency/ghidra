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
package ghidra.pcode.emu;

import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A set of callbacks available for p-code emulation.
 * 
 * <p>
 * Note that some emulator extensions (notably the JIT-accelerated emulator) may disable and/or
 * slightly change the specification of these callbacks. Read an emulator's documentation carefully.
 * That said, an extension should strive to adhere to this specification as closely as possible.
 * 
 * <p>
 * See {@link PcodeEmulator} for advice regarding extending the emulator versus integrating with an
 * emulator. Use of these callbacks is favored over extending an emulator when possible, as this
 * favors composition of such integrations.
 * 
 * @param <T> the type of values in the emulator
 */
public interface PcodeEmulationCallbacks<T> {
	/**
	 * A singleton implementation of the callbacks that does nothing.
	 */
	enum NoPcodeEmulationCallbacks implements PcodeEmulationCallbacks<Object> {
		/** Callbacks that do nothing */
		INSTANCE;
	}

	/**
	 * Obtain callbacks that do nothing.
	 * 
	 * @param <T> the domain
	 * @return {@link NoPcodeEmulationCallbacks#INSTANCE}
	 */
	@SuppressWarnings("unchecked")
	static <T> PcodeEmulationCallbacks<T> none() {
		return (PcodeEmulationCallbacks<T>) NoPcodeEmulationCallbacks.INSTANCE;
	}

	/**
	 * The emulator has been created, but not yet finished construction.
	 * 
	 * <p>
	 * <b>WARNING:</b> At this point, the emulator has not been fully constructed. The most the
	 * callback ought to do is save a pointer to the machine. Attempting to access the machine or
	 * invoke any of its methods will likely result in a {@link NullPointerException}. Use the
	 * {@link #sharedStateCreated(PcodeMachine)} callback to access the machine after it has been
	 * constructed
	 * 
	 * @param machine the emulator or abstract machine.
	 */
	default void emulatorCreated(PcodeMachine<T> machine) {
	}

	/**
	 * The emulator's shared state has been created.
	 * 
	 * <p>
	 * <b>NOTE:</b> It is possible for clients to interact with other parts of the machine, e.g., to
	 * create a thread, before this callback gets invoked. The shared state is created lazily, i.e.,
	 * the first time {@link PcodeMachine#getSharedState()} gets called, whether by the client or
	 * the machine's internals. If a pointer to the machine is needed early, consider
	 * {@link #emulatorCreated(PcodeMachine)}.
	 * 
	 * @param machine the emulator or abstract machine
	 */
	default void sharedStateCreated(PcodeMachine<T> machine) {
	}

	/**
	 * A new thread has just been created.
	 * 
	 * <p>
	 * The thread is fully constructed. This callback may access it.
	 * 
	 * @param thread the new thread
	 */
	default void threadCreated(PcodeThread<T> thread) {
	}

	/**
	 * The emulator is preparing to decode an instruction, but is checking for injected overrides
	 * first.
	 * 
	 * @see PcodeMachine#inject(Address, String)
	 * @param thread the thread
	 * @param address the thread's program counter
	 * @return null, or a p-code program to override the instruction
	 */
	default PcodeProgram getInject(PcodeThread<T> thread, Address address) {
		return null;
	}

	/**
	 * The emulator is preparing to execute an injected program.
	 *
	 * @see PcodeMachine#inject(Address, String)
	 * @param thread the thread
	 * @param address the thread's program counter
	 * @param program the injected p-code program
	 */
	default void beforeExecuteInject(PcodeThread<T> thread, Address address, PcodeProgram program) {
	}

	/**
	 * The emulator has just finished executing an injected p-code program.
	 * 
	 * <p>
	 * If the program executed a branch, then {@code address} will be the target address. Note that
	 * any sane inject ought to execute a branch, even to effect fall-through, otherwise the program
	 * counter cannot advance.
	 * 
	 * @param thread the thread
	 * @param address the thread's program counter
	 */
	default void afterExecuteInject(PcodeThread<T> thread, Address address) {
	}

	/**
	 * The emulator, having found no injects, is preparing to decode an instruction.
	 * 
	 * @param thread the thread
	 * @param counter the thread's program counter
	 * @param context the decode contextreg value
	 */
	default void beforeDecodeInstruction(PcodeThread<T> thread, Address counter,
			RegisterValue context) {
	}

	/**
	 * The emulator is preparing to execute a decoded instruction.
	 * 
	 * @param thread the thread
	 * @param instruction the decoded instruction
	 * @param program the instruction's p-code program
	 */
	default void beforeExecuteInstruction(PcodeThread<T> thread, Instruction instruction,
			PcodeProgram program) {
	}

	/**
	 * The emulator has finished executing an instruction.
	 * 
	 * @param thread the thread
	 * @param instruction the just-executed instruction
	 */
	default void afterExecuteInstruction(PcodeThread<T> thread, Instruction instruction) {
	}

	/**
	 * The emulator is preparing to execute a p-code op.
	 * 
	 * @param thread the thread
	 * @param op the op
	 * @param frame the frame for the current p-code program
	 */
	default void beforeStepOp(PcodeThread<T> thread, PcodeOp op, PcodeFrame frame) {
	}

	/**
	 * The emulator has just executed a p-code op.
	 * 
	 * @param thread the thread
	 * @param op the op
	 * @param frame the frame for the current p-code program
	 */
	default void afterStepOp(PcodeThread<T> thread, PcodeOp op, PcodeFrame frame) {
	}

	/**
	 * The emulator is preparing to load a value from its execution state.
	 * 
	 * @param thread the thread
	 * @param op the {@link PcodeOp#LOAD} op
	 * @param space the address space of the operand
	 * @param offset the offset of the operand
	 * @param size the size of the operand
	 */
	default void beforeLoad(PcodeThread<T> thread, PcodeOp op, AddressSpace space, T offset,
			int size) {
	}

	/**
	 * The emulator has just loaded a value from its execution state.
	 * 
	 * @param thread the thread
	 * @param op the {@link PcodeOp#LOAD} op
	 * @param space the address space of the operand
	 * @param offset the offset of the operand
	 * @param size the size of the operand
	 * @param value the value loaded
	 */
	default void afterLoad(PcodeThread<T> thread, PcodeOp op, AddressSpace space, T offset,
			int size, T value) {
	}

	/**
	 * The emulator is preparing to store a value into its execution state.
	 * 
	 * @param thread the thread
	 * @param op the {@link PcodeOp#STORE} op
	 * @param space the address space of the operand
	 * @param offset the offset of the operand
	 * @param size the size of the operand
	 * @param value the value to store
	 */
	default void beforeStore(PcodeThread<T> thread, PcodeOp op, AddressSpace space, T offset,
			int size, T value) {
	}

	/**
	 * The emulator has just stored a value into its execution state.
	 * 
	 * @param thread the thread
	 * @param op the {@link PcodeOp#STORE} op
	 * @param space the address space of the operand
	 * @param offset the offset of the operand
	 * @param size the size of the operand
	 * @param value the value stored
	 */
	default void afterStore(PcodeThread<T> thread, PcodeOp op, AddressSpace space, T offset,
			int size, T value) {
	}

	/**
	 * The emulator has just branched to an address.
	 * 
	 * @param thread the thread
	 * @param op the branching op
	 * @param target the new program counter
	 */
	default void afterBranch(PcodeThread<T> thread, PcodeOp op, Address target) {
	}

	/**
	 * The emulator has encountered a userop for which it has no definition.
	 * 
	 * <p>
	 * Emulation has not yet been interrupted at this point. If a callback returns true, indicating
	 * the fault has been handled, then the emulator will proceed. If not, then emulation for this
	 * thread will be interrupted
	 * 
	 * @param thread the thread
	 * @param op the {@link PcodeOp#CALLOTHER} op
	 * @param frame the frame for the current p-code program
	 * @param opName the name of the userop being called
	 * @param library the thread's userop library
	 * @return true if handled, false if not
	 */
	default boolean handleMissingUserop(PcodeThread<T> thread, PcodeOp op, PcodeFrame frame,
			String opName, PcodeUseropLibrary<T> library) {
		return false;
	}

	/**
	 * Data was written into the given state piece (abstract addressing).
	 * 
	 * <p>
	 * <b>NOTE:</b> In contrast to the operation-driven callbacks, e.g.,
	 * {@link #beforeStore(PcodeThread, PcodeOp, AddressSpace, Object, int, Object)}, the
	 * {@code thread} parameter here may be null. It is not necessarily the thread executing the op,
	 * but the thread associated to the state being accessed. In particular, when this is the
	 * <em>shared</em> state, {@code thread} will be null. When this is the <em>local</em> state,
	 * {@code thread} will be the thread of execution. If this behavior poses a serious limitation,
	 * then we may consider changing this to always be the thread of execution.
	 * 
	 * @param <A> the piece's address domain
	 * @param <U> the piece's value domain
	 * @param thread the thread associated to the piece
	 * @param piece the state piece
	 * @param space the address space of the operand
	 * @param offset the offset of the operand
	 * @param length the size of the operand
	 * @param value the value written
	 */
	default <A, U> void dataWritten(PcodeThread<T> thread, PcodeExecutorStatePiece<A, U> piece,
			AddressSpace space, A offset, int length, U value) {
	}

	/**
	 * Typically used from within
	 * {@link #dataWritten(PcodeThread, PcodeExecutorStatePiece, AddressSpace, Object, int, Object)}
	 * to forward the call to the callback for concrete addressing
	 * {@link #dataWritten(PcodeThread, PcodeExecutorStatePiece, Address, int, Object)}.
	 * 
	 * @param <A> the piece's address domain
	 * @param <U> the piece's value domain
	 * @param thread the thread associated to the piece. See
	 *            {@link #dataWritten(PcodeThread, PcodeExecutorStatePiece, AddressSpace, Object, int, Object)}
	 * @param piece the state piece
	 * @param space the address space of the operand
	 * @param offset the offset of the operand
	 * @param length the size of the operand
	 * @param value the value written
	 */
	default <A, U> void delegateDataWritten(PcodeThread<T> thread,
			PcodeExecutorStatePiece<A, U> piece, AddressSpace space, A offset, int length,
			U value) {
		dataWritten(thread, piece,
			piece.getAddressArithmetic().toAddress(offset, space, Purpose.STORE), length, value);
	}

	/**
	 * Data was written into the given state piece (concrete addressing).
	 * 
	 * @param <A> the piece's address domain
	 * @param <U> the piece's value domain
	 * @param thread the thread associated to the piece. See
	 *            {@link #dataWritten(PcodeThread, PcodeExecutorStatePiece, AddressSpace, Object, int, Object)}
	 * @param piece the state piece
	 * @param address the address of the operand
	 * @param length the size of the operand
	 * @param value the value written
	 */
	default <A, U> void dataWritten(PcodeThread<T> thread, PcodeExecutorStatePiece<A, U> piece,
			Address address, int length, U value) {
	}

	/**
	 * Typically used from within
	 * {@link #dataWritten(PcodeThread, PcodeExecutorStatePiece, Address, int, Object)} to forward
	 * the call to the callback for abstract addressing
	 * {@link #dataWritten(PcodeThread, PcodeExecutorStatePiece, AddressSpace, Object, int, Object)}.
	 * 
	 * @param <A> the piece's address domain
	 * @param <U> the piece's value domain
	 * @param thread the thread associated to the piece. See
	 *            {@link #dataWritten(PcodeThread, PcodeExecutorStatePiece, AddressSpace, Object, int, Object)}
	 * @param piece the state piece
	 * @param address the address of the operand
	 * @param length the size of the operand
	 * @param value the value written
	 */
	default <A, U> void delegateDataWritten(PcodeThread<T> thread,
			PcodeExecutorStatePiece<A, U> piece, Address address, int length, U value) {
		dataWritten(thread, piece, address.getAddressSpace(),
			piece.getAddressArithmetic().fromConst(address), length, value);
	}

	/**
	 * The emulator is preparing to read from uninitialized portions of the given state piece
	 * (abstract addressing).
	 * 
	 * <p>
	 * This callback provides an opportunity for something to initialize the required portion
	 * lazily. In most cases, this should either return 0 indicating the requested portion remains
	 * uninitialized, or the full {@code length} indicating the full requested portion is now
	 * initialized. If, for some reason, the requested portion could only be partially initialized,
	 * this can return a smaller length. Partial initializations are only recognized from the
	 * starting offset. Other parts could be initialized; however, there is no mechanism for
	 * communicating that result to the emulator.
	 * 
	 * @param <A> the piece's address domain
	 * @param <U> the piece's value domain
	 * @param thread the thread associated to the piece. See
	 *            {@link #dataWritten(PcodeThread, PcodeExecutorStatePiece, AddressSpace, Object, int, Object)}
	 * @param piece the state piece
	 * @param space the address space of the operand
	 * @param offset the offset of the operand
	 * @param length the size of the operand
	 * @return the length of the operand just initialized, typically 0 or {@code length}
	 */
	default <A, U> int readUninitialized(PcodeThread<T> thread,
			PcodeExecutorStatePiece<A, U> piece, AddressSpace space, A offset, int length) {
		return 0;
	}

	/**
	 * Typically used from within
	 * {@link #readUninitialized(PcodeThread, PcodeExecutorStatePiece, AddressSpace, Object, int)}
	 * to forward to the callback for concrete addressing
	 * {@link #readUninitialized(PcodeThread, PcodeExecutorStatePiece, AddressSetView)}.
	 * 
	 * @param <A> the piece's address domain
	 * @param <U> the piece's value domain
	 * @param thread the thread associated to the piece. See
	 *            {@link #dataWritten(PcodeThread, PcodeExecutorStatePiece, AddressSpace, Object, int, Object)}
	 * @param piece the state piece
	 * @param space the address space of the operand
	 * @param offset the offset of the operand
	 * @param length the size of the operand
	 * @return the length of the operand just initialized, typically 0 or {@code length}
	 */
	default <A, U> int delegateReadUninitialized(PcodeThread<T> thread,
			PcodeExecutorStatePiece<A, U> piece, AddressSpace space, A offset, int length) {
		long lOffset = piece.getAddressArithmetic().toLong(offset, Purpose.LOAD);
		AddressSet set = PcodeStateCallbacks.rngSet(space, lOffset, length);
		AddressSetView remains = readUninitialized(thread, piece, set);
		if (set == remains) {
			return 0;
		}
		set.delete(remains);
		AddressRange first = set.getFirstRange();
		return first == null ? 0 : (int) first.getLength();
	}

	/**
	 * The emulator is preparing to read from uninitialized portions of the given state piece
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
	 * @param <U> the piece's value domain
	 * @param thread the thread associated to the piece. See
	 *            {@link #dataWritten(PcodeThread, PcodeExecutorStatePiece, AddressSpace, Object, int, Object)}
	 * @param piece the state piece
	 * @param set the uninitialized portion required
	 * @return the addresses in {@code set} that remain uninitialized
	 */
	default <A, U> AddressSetView readUninitialized(PcodeThread<T> thread,
			PcodeExecutorStatePiece<A, U> piece, AddressSetView set) {
		return set;
	}

	/**
	 * Typically used from within
	 * {@link #readUninitialized(PcodeThread, PcodeExecutorStatePiece, AddressSetView)} to forward
	 * to the callback for abstract addressing
	 * {@link #readUninitialized(PcodeThread, PcodeExecutorStatePiece, AddressSpace, Object, int)}.
	 * 
	 * @param <A> the piece's address domain
	 * @param <U> the piece's value domain
	 * @param thread the thread associated to the piece. See
	 *            {@link #dataWritten(PcodeThread, PcodeExecutorStatePiece, AddressSpace, Object, int, Object)}
	 * @param piece the state piece
	 * @param set the uninitialized portion required
	 * @return the addresses in {@code set} that remain uninitialized
	 */
	default <A, U> AddressSetView delegateReadUninitialized(PcodeThread<T> thread,
			PcodeExecutorStatePiece<A, U> piece, AddressSetView set) {
		if (set.isEmpty()) {
			return set;
		}
		boolean result = false;
		AddressSet remains = new AddressSet(set);
		for (AddressRange range : set) {
			int l = readUninitialized(thread, piece, range.getAddressSpace(),
				piece.getAddressArithmetic().fromConst(range.getMinAddress()),
				(int) range.getLength());
			if (l == 0) {
				continue;
			}
			remains.delete(range.getMinAddress(), range.getMinAddress().add(l - 1));
			result = true;
		}
		return result ? remains : set;
	}

	/**
	 * A wrapper that can forward callbacks from state pieces to callbacks for the emulator, for a
	 * given thread.
	 * 
	 * @param <T> the emulator's domain
	 * @param thread the thread to include in forwarded callbacks
	 * @param cb the emulator callbacks to receive forwarded calls
	 */
	record Wrapper<T>(PcodeThread<T> thread, PcodeEmulationCallbacks<T> cb)
			implements PcodeStateCallbacks {
		@Override
		public <A, U> void dataWritten(PcodeExecutorStatePiece<A, U> piece, Address address,
				int length, U value) {
			cb.dataWritten(thread, piece, address, length, value);
		}

		@Override
		public <A, U> void dataWritten(PcodeExecutorStatePiece<A, U> piece, AddressSpace space,
				A offset, int length, U value) {
			cb.dataWritten(thread, piece, space, offset, length, value);
		}

		@Override
		public <A, U> int readUninitialized(PcodeExecutorStatePiece<A, U> piece,
				AddressSpace space, A offset, int length) {
			return cb.readUninitialized(thread, piece, space, offset, length);
		}

		@Override
		public <A, U> AddressSetView readUninitialized(PcodeExecutorStatePiece<A, U> piece,
				AddressSetView set) {
			return cb.readUninitialized(thread, piece, set);
		}
	}

	/**
	 * Obtain a callback wrapper suitable for passing into an emulator's execution states
	 * 
	 * <p>
	 * This will forward the calls from the state's pieces to this set of emulator callbacks,
	 * passing the given thread
	 * 
	 * @param thread the thread to include in forwarded callbacks
	 * @return the wrapper
	 */
	default PcodeStateCallbacks wrapFor(PcodeThread<T> thread) {
		return new Wrapper<>(thread, this);
	}
}
