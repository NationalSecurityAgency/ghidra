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
package ghidra.pcode.exec.trace;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.emu.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.trace.data.*;
import ghidra.program.model.address.*;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.MathUtilities;
import ghidra.util.Msg;

/**
 * A collection of static methods for integrating an emulator with a trace.
 */
public enum TraceEmulationIntegration {
	;

	/**
	 * Create a writer (callbacks) that lazily loads data from the given access shim.
	 * 
	 * <p>
	 * Writes are logged, but not written to the trace. Instead, the client should call
	 * {@link Writer#writeDown(PcodeTraceAccess)} to write the logged changes to another given
	 * snapshot. This is used for forking emulation from a chosen snapshot and saving the results
	 * into (usually scratch) snapshots. Scripts might also use this pattern to save a series of
	 * snapshots resulting from an emulation experiment.
	 * 
	 * @param from the access shim for lazy loads
	 * @return the writer
	 */
	public static Writer bytesDelayedWrite(PcodeTraceAccess from) {
		Writer writer = new TraceWriter(from);
		writer.putHandler(new BytesPieceHandler());
		return writer;
	}

	/**
	 * Create a writer (callbacks) that lazily loads data and immediately writes changes to the
	 * given access shim.
	 * 
	 * <p>
	 * Writes are immediately stored into the trace at the same snapshot as state is sourced.
	 * 
	 * @param access the access shim for loads and stores
	 * @return the writer
	 */
	public static Writer bytesImmediateWrite(PcodeTraceAccess access) {
		Writer writer = new TraceWriter(access);
		writer.putHandler(new ImmediateBytesPieceHandler());
		return writer;
	}

	/**
	 * Create state callbacks that lazily load data and immediately write changes to the given
	 * access shim.
	 * 
	 * <p>
	 * Writes are immediately stored into the trace at the same snapshot as state is sourced.
	 *
	 * <p>
	 * Use this instead of {@link #bytesImmediateWrite(PcodeTraceAccess)} when interfacing directly
	 * with a {@link PcodeExecutorState} vice a {@link PcodeEmulator}.
	 * 
	 * @param access the access shim for loads and stores
	 * @param thread the trace thread for register accesses
	 * @param frame the frame for register accesses, usually 0
	 * @return the callbacks
	 */
	public static PcodeStateCallbacks bytesImmediateWrite(PcodeTraceAccess access,
			TraceThread thread, int frame) {
		Writer writer = new TraceWriter(access) {
			@Override
			protected PcodeTraceRegistersAccess getRegAccess(PcodeThread<?> ignored) {
				return access.getDataForLocalState(thread, frame);
			}
		};
		writer.putHandler(new ImmediateBytesPieceHandler());
		return writer.wrapFor(null);
	}

	/**
	 * The key when selecting a handler for a given piece: (address-domain, value-domain)
	 * 
	 * @param <A> the address domain
	 * @param <T> the value domain
	 */
	record PieceType<A, T>(Class<A> addressDomain, Class<T> valueDomain) {
		/**
		 * Get the key for a given piece
		 * 
		 * @param <A> the address domain
		 * @param <T> the value domain
		 * @param piece the piece
		 * @return the key
		 */
		public static <A, T> PieceType<A, T> forPiece(PcodeExecutorStatePiece<A, T> piece) {
			return new PieceType<>(piece.getAddressArithmetic().getDomain(),
				piece.getArithmetic().getDomain());
		}

		/**
		 * Get the key for a given handler
		 * 
		 * @param <A> the address domain
		 * @param <T> the value domain
		 * @param handler the handler
		 * @return the key
		 */
		public static <A, T> PieceType<A, T> forHandler(PieceHandler<A, T> handler) {
			return new PieceType<>(handler.getAddressDomain(), handler.getValueDomain());
		}
	}

	/**
	 * The primary mechanism for integrating emulators and traces
	 * 
	 * <p>
	 * This implements callbacks for the emulator and provides a method for recording logged writes
	 * after some number of emulation steps. The client must pass this writer in as the callbacks
	 * and then later invoke {@link #writeDown(PcodeTraceAccess)}. This also permits the addition of
	 * state piece handlers via {@link #putHandler(PieceHandler)}, should the emulator be operating
	 * on other value domains.
	 */
	public interface Writer extends PcodeEmulationCallbacks<Object> {
		/**
		 * Record state changes into the trace via the given access shim
		 * 
		 * @param into the access shim
		 */
		void writeDown(PcodeTraceAccess into);

		/**
		 * Record state changes into the trace at the given snapshot.
		 * 
		 * <p>
		 * The destination trace is the same as from the source access shim.
		 * 
		 * @param snap the destination snapshot key
		 */
		void writeDown(long snap);

		/**
		 * Add or replace a handler
		 * 
		 * <p>
		 * The handler must identify the address and value domains for which it is applicable. If
		 * there is already a handler for the same domains, the old handler is replaced by this one.
		 * Otherwise, this handler is added without removing any others. The handler is invoked if
		 * and only if the emulator's state contains a piece for the same domains. Otherwise, the
		 * handler may be silently ignored.
		 * 
		 * @param handler the handler
		 */
		void putHandler(PieceHandler<?, ?> handler);

		/**
		 * Cast this writer to fit the emulator's value domain
		 * 
		 * <p>
		 * Use this as the callbacks parameter when constructing the trace-integrated emulator. We
		 * assert this cast is safe, because none of the callbacks actually depend on the emulator's
		 * value domain. Instead, the states are accessed generically and invocations doled out to
		 * respective {@link PieceHandler}s based on their applicable domain types.
		 * 
		 * @param <T> the emulator's value domain
		 * @return this
		 */
		@SuppressWarnings("unchecked")
		default <T> PcodeEmulationCallbacks<T> callbacks() {
			return (PcodeEmulationCallbacks<T>) this;
		}
	}

	/**
	 * The handler for a specific piece within an emulator's (or executor's) state.
	 * 
	 * @see PcodeExecutorStatePiece
	 * @param <A> the address domain of pieces this can handle
	 * @param <T> the value domain of pieces this can handle
	 */
	public interface PieceHandler<A, T> {
		/** A handler that does nothing */
		public static PieceHandler<?, ?> NONE = VoidPieceHandler.INSTANCE;

		/**
		 * Get the address domain this can handle
		 * 
		 * @return the address domain
		 */
		Class<A> getAddressDomain();

		/**
		 * Get the value domain this can handle
		 * 
		 * @return the value domain
		 */
		Class<T> getValueDomain();

		/**
		 * An uninitialized portion of a state piece is being read (concrete addressing).
		 * 
		 * @param acc the trace access shim for the relevant state (shared or local)
		 * @param thread the thread, if applicable. This is null if either the state being accessed
		 *            is the emulator's shared state, or if the state is bound to a plain
		 *            {@link PcodeExecutor}.
		 * @param piece the state piece being handled
		 * @param set the uninitialized portion required
		 * @return the addresses in {@code set} that remain uninitialized
		 * @see PcodeEmulationCallbacks#readUninitialized(PcodeThread, PcodeExecutorStatePiece,
		 *      AddressSetView)
		 */
		AddressSetView readUninitialized(PcodeTraceDataAccess acc, PcodeThread<?> thread,
				PcodeExecutorStatePiece<A, T> piece, AddressSetView set);

		/**
		 * An uninitialized portion of a state piece is being read (abstract addressing).
		 * 
		 * @param acc the trace access shim for the relevant state (shared or local)
		 * @param thread the thread, if applicable. This is null if either the state being accessed
		 *            is the emulator's shared state, or if the state is bound to a plain
		 *            {@link PcodeExecutor}.
		 * @param piece the state piece being handled
		 * @param space the address space
		 * @param offset the offset at the start of the uninitialized portion
		 * @param length the size in bytes of the uninitialized portion
		 * @return the number of bytes just initialized, typically 0 or {@code length}
		 * @see PcodeEmulationCallbacks#readUninitialized(PcodeThread, PcodeExecutorStatePiece,
		 *      AddressSpace, Object, int)
		 */
		default int abstractReadUninit(PcodeTraceDataAccess acc, PcodeThread<?> thread,
				PcodeExecutorStatePiece<A, T> piece, AddressSpace space, A offset, int length) {
			return 0;
		}

		/**
		 * Data was written (concrete addressing).
		 * 
		 * @param acc the trace access shim for the relevant state (shared or local)
		 * @param written the {@link Writer}'s current log of written addresses (mutable).
		 *            Typically, this is not accessed but rather passed to delegate methods.
		 * @param thread the thread, if applicable. This is null if either the state being accessed
		 *            is the emulator's shared state, or if the state is bound to a plain
		 *            {@link PcodeExecutor}.
		 * @param piece the state piece being handled
		 * @param address the start address of the write
		 * @param length the size in bytes of the write
		 * @param value the value written
		 * @return true to prevent the {@link Writer} from updating its log.
		 * @see PcodeEmulationCallbacks#dataWritten(PcodeThread, PcodeExecutorStatePiece, Address,
		 *      int, Object)
		 */
		default boolean dataWritten(PcodeTraceDataAccess acc, AddressSet written,
				PcodeThread<?> thread, PcodeExecutorStatePiece<A, T> piece, Address address,
				int length, T value) {
			return false;
		}

		/**
		 * Data was written (abstract addressing).
		 * 
		 * @param acc the trace access shim for the relevant state (shared or local)
		 * @param written the {@link Writer}'s current log of written addresses (mutable).
		 *            Typically, this is not accessed but rather passed to delegate methods.
		 * @param thread the thread, if applicable. This is null if either the state being accessed
		 *            is the emulator's shared state, or if the state is bound to a plain
		 *            {@link PcodeExecutor}.
		 * @param piece the state piece being handled
		 * @param space the address space
		 * @param offset the offset of the start of the write
		 * @param length the size in bytes of the write
		 * @param value the value written
		 * @see PcodeEmulationCallbacks#dataWritten(PcodeThread, PcodeExecutorStatePiece,
		 *      AddressSpace, Object, int, Object)
		 */
		default void abstractWritten(PcodeTraceDataAccess acc, AddressSet written,
				PcodeThread<?> thread, PcodeExecutorStatePiece<A, T> piece, AddressSpace space,
				A offset, int length, T value) {
		}

		/**
		 * Serialize a given portion of the state to the trace database.
		 * 
		 * <p>
		 * The "given portion" refers to the address set provided in {@code written}. Pieces may
		 * also have state assigned to abstract addresses. In such cases, it is up to the handler to
		 * track what has been written.
		 * 
		 * @param into the destination trace access
		 * @param thread the thread associated with the piece's state
		 * @param piece the source state piece
		 * @param written the portion that is known to have been written
		 */
		void writeDown(PcodeTraceDataAccess into, PcodeThread<?> thread,
				PcodeExecutorStatePiece<A, T> piece, AddressSetView written);
	}

	/**
	 * An implementation of {@link PieceHandler} that does nothing.
	 * 
	 * @implNote This is the object returned when a handler is not found for a given piece. It
	 *           removes the need for a null check.
	 */
	private enum VoidPieceHandler implements PieceHandler<Void, Void> {
		/** The handler that does nothing */
		INSTANCE;

		@Override
		public Class<Void> getAddressDomain() {
			return Void.class;
		}

		@Override
		public Class<Void> getValueDomain() {
			return Void.class;
		}

		@Override
		public AddressSetView readUninitialized(PcodeTraceDataAccess acc, PcodeThread<?> thread,
				PcodeExecutorStatePiece<Void, Void> piece, AddressSetView set) {
			return set;
		}

		@Override
		public void writeDown(PcodeTraceDataAccess into, PcodeThread<?> thread,
				PcodeExecutorStatePiece<Void, Void> piece, AddressSetView written) {
		}
	}

	/**
	 * A handler that implements the lazy-read-writer-later pattern of trace integration for a
	 * concrete emulator's bytes.
	 */
	public static class BytesPieceHandler implements PieceHandler<byte[], byte[]> {
		/**
		 * The maximum number of bytes to buffer at a time
		 */
		public static final int CHUNK_SIZE = 4096;

		@Override
		public Class<byte[]> getAddressDomain() {
			return byte[].class;
		}

		@Override
		public Class<byte[]> getValueDomain() {
			return byte[].class;
		}

		@Override
		public AddressSetView readUninitialized(PcodeTraceDataAccess acc, PcodeThread<?> thread,
				PcodeExecutorStatePiece<byte[], byte[]> piece, AddressSetView set) {
			// NOTE: For simplicity, read without regard to gaps
			// NOTE: We cannot write those gaps, though!!!
			AddressSetView knownButUninit = acc.intersectViewKnown(set, true);
			if (knownButUninit.isEmpty()) {
				return set;
			}
			AddressSet remains = new AddressSet(set);
			AddressRange knownBound = new AddressRangeImpl(
				knownButUninit.getMinAddress(),
				knownButUninit.getMaxAddress());
			ByteBuffer buf = ByteBuffer.allocate((int) knownBound.getLength());
			acc.getBytes(knownBound.getMinAddress(), buf);
			for (AddressRange range : knownButUninit) {
				piece.setVarInternal(range.getAddressSpace(), range.getMinAddress().getOffset(),
					(int) range.getLength(), buf.array());
				remains.delete(range);
			}
			return remains;
		}

		@Override
		public void writeDown(PcodeTraceDataAccess into, PcodeThread<?> thread,
				PcodeExecutorStatePiece<byte[], byte[]> piece, AddressSetView written) {
			for (AddressRange range : written) {
				AddressSpace space = range.getAddressSpace();
				if (space.isUniqueSpace()) {
					continue;
				}
				long lower = range.getMinAddress().getOffset();
				long fullLen = range.getLength();
				while (fullLen > 0) {
					int len = MathUtilities.unsignedMin(CHUNK_SIZE, fullLen);
					// NOTE: Would prefer less copying and less heap garbage....
					byte[] bytes = piece.getVarInternal(space, lower, len, Reason.INSPECT);
					into.putBytes(space.getAddress(lower), ByteBuffer.wrap(bytes));

					lower += bytes.length;
					fullLen -= bytes.length;
				}
			}
		}
	}

	/**
	 * A handler that implements the lazy-read-write-immediately pattern of trace integration for a
	 * concrete emulator's bytes.
	 */
	public static class ImmediateBytesPieceHandler extends BytesPieceHandler {
		@Override
		public boolean dataWritten(PcodeTraceDataAccess acc, AddressSet written,
				PcodeThread<?> thread, PcodeExecutorStatePiece<byte[], byte[]> piece,
				Address address, int length, byte[] value) {
			if (address.isUniqueAddress()) {
				return true;
			}
			acc.putBytes(address, ByteBuffer.wrap(value));
			return true; // Avoid any delayed write
		}
	}

	/**
	 * An abstract implementation of {@link PieceHandler} that seeks to simplify integration of
	 * abstract domains where the state is serialized into a trace's property map.
	 * 
	 * <p>
	 * Generally, such abstract domains should follow a byte-wise access pattern. That is, it should
	 * be capable of reading and writing to overlapping variables. This implementation is aimed at
	 * that pattern. The state piece will need to implement at least
	 * {@link PcodeExecutorStatePiece#getNextEntryInternal(AddressSpace, long)}. Each state entry
	 * should be serialized as an entry at the same address and size in the property map.
	 * Uninitialized reads should search the full range for any applicable entries. Entries may need
	 * to be subpieced, depending on what part of the state is already initialized.
	 * 
	 * <p>
	 * If the address domain is also abstract, the recommended pattern is to attempt to concretize
	 * it (see {@link PcodeArithmetic#toAddress(Object, AddressSpace, Purpose)}) and delegate to the
	 * concrete callback. Failing that, you must choose some other means of storing the state. Our
	 * current recommendation is to use {@link Address#NO_ADDRESS} in a string map, where you can
	 * serialize any number of (address, value) pairs. This will not work for thread-local states,
	 * but it is unlikely you should encounter non-concretizable addresses in a thread-local state.
	 * 
	 * @param <A> the address domain
	 * @param <T> the value domain
	 * @param <P> the type of values in the property map, often {@link String}
	 */
	public static abstract class AbstractPropertyBasedPieceHandler<A, T, P>
			implements PieceHandler<A, T> {

		/**
		 * Get the name of the property map.
		 * 
		 * <p>
		 * This should be unique among all possible domains. Nor should it collide with map names
		 * used for other purposes.
		 */
		protected abstract String getPropertyName();

		/**
		 * Get the type of values in the property map
		 * 
		 * @return the type, often {@link String}{@code .class}
		 */
		protected abstract Class<P> getPropertyType();

		/**
		 * Decode a property entry and set appropriate variable(s) in the piece
		 * <p>
		 * The found property entry may cover more addresses than are actually required, either
		 * because they've not been requested or because the value has already been set. Writing a
		 * value that wasn't requested isn't too bad, but writing one that was already initialized
		 * could be catastrophic.
		 * 
		 * @param piece the piece with uninitialized variables to decode from a property
		 * @param limit the portion that is requested and uninitialized. <b>DO NOT</b> initialize
		 *            any address outside of this set.
		 * @param range the range covered by the found property entry
		 * @param propertyValue the value of the property entry
		 */
		protected abstract void decodeFrom(PcodeExecutorStatePiece<A, T> piece,
				AddressSetView limit, AddressRange range, P propertyValue);

		/**
		 * Encode a variable's value into a property entry
		 * 
		 * @param property the property map (access shim)
		 * @param range the variable's address range (this may optionally be coalesced from several
		 *            variables by the piece's internals)
		 * @param value the variable's value
		 */
		protected abstract void encodeInto(PcodeTracePropertyAccess<P> property, AddressRange range,
				T value);

		@Override
		public AddressSetView readUninitialized(PcodeTraceDataAccess acc, PcodeThread<?> thread,
				PcodeExecutorStatePiece<A, T> piece, AddressSetView set) {
			PcodeTracePropertyAccess<P> property =
				acc.getPropertyAccess(getPropertyName(), getPropertyType());
			AddressSet remains = new AddressSet(set);
			AddressSet cursor = new AddressSet(set);
			boolean result = false;
			while (!cursor.isEmpty()) {
				Address cur = cursor.getMinAddress();
				Entry<AddressRange, P> entry = property.getEntry(cur);
				if (entry == null) {
					// Not the most efficient....
					cursor.delete(cur, cur);
					continue;
				}
				AddressRange physical = new AddressRangeImpl(
					entry.getKey().getMinAddress().getPhysicalAddress(),
					entry.getKey().getMaxAddress().getPhysicalAddress());
				decodeFrom(piece, set, physical, entry.getValue());
				result = true;
				remains.delete(physical);
				cursor.delete(physical);
			}
			return result ? remains : set;
		}

		/**
		 * {@inheritDoc}
		 * <p>
		 * This should be overridden by developers needing to store abstract state into the trace.
		 * Conventionally, if the address cannot be made concrete (see
		 * {@link PcodeArithmetic#toLong(Object, Purpose)}), then it should be stored at
		 * {@link Address#NO_ADDRESS}. It is up to the developer to determine how to (de)serialize
		 * all of the abstract states.
		 */
		@Override
		public int abstractReadUninit(PcodeTraceDataAccess acc, PcodeThread<?> thread,
				PcodeExecutorStatePiece<A, T> piece, AddressSpace space, A offset, int length) {
			throw new UnsupportedOperationException();
		}

		/**
		 * {@inheritDoc}
		 * <p>
		 * This method handles serializing the concrete portion and associating the states to their
		 * respective addresses in the property. Handlers needing to serialize abstracts portions
		 * must both implement the means of tracking what has been written (see
		 * {@link #abstractWritten(PcodeTraceDataAccess, AddressSet, PcodeThread, PcodeExecutorStatePiece, AddressSpace, Object, int, Object)}),
		 * and the placement of that state information into the property. The latter is accomplished
		 * by overriding this method, taking care to invoke the super method for the concrete
		 * portion.
		 */
		@Override
		public void writeDown(PcodeTraceDataAccess into, PcodeThread<?> thread,
				PcodeExecutorStatePiece<A, T> piece, AddressSetView written) {
			PcodeTracePropertyAccess<P> property =
				into.getPropertyAccess(getPropertyName(), getPropertyType());
			AddressSet remains = new AddressSet(written);
			while (!remains.isEmpty()) {
				Address cur = remains.getMinAddress();
				AddressSpace space = cur.getAddressSpace();
				Entry<Long, T> entry = piece.getNextEntryInternal(space, cur.getOffset());
				if (entry == null) {
					remains.delete(space.getMinAddress(), space.getMaxAddress());
					continue;
				}
				if (Long.compareUnsigned(entry.getKey(), cur.getOffset()) < 0) {
					Msg.error(this, "getNextEntryInternal return an incorrect entry.");
					remains.delete(space.getMinAddress(), space.getMaxAddress());
					continue;
				}
				Address min = space.getAddress(entry.getKey());
				AddressRange range = new AddressRangeImpl(min,
					min.add(piece.getArithmetic().sizeOf(entry.getValue()) - 1));
				encodeInto(property, range, entry.getValue());

				// Delete everything preceding and including the range, within the same space
				remains.delete(space.getMinAddress(), range.getMaxAddress());
			}
		}

		@Override
		public void abstractWritten(PcodeTraceDataAccess acc, AddressSet written,
				PcodeThread<?> thread, PcodeExecutorStatePiece<A, T> piece, AddressSpace space,
				A offset, int length, T value) {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * A misguided simplification of {@link AbstractPropertyBasedPieceHandler} that reduces the
	 * requirement to a simple codec.
	 * 
	 * <p>
	 * For cases where subpiecing of variables is not of concern, this simplification may suffice.
	 * This is usually okay for proofs of concept or very simplistic architectures. However, once
	 * you introduce structured/aliased registers (e.g., {@code EAX} is the lower 32 bits of
	 * {@code RAX}), or you're dealing with off-cut memory references, you have to deal with
	 * subpiecing and this simplification is no longer viable.
	 * 
	 * @param <A> the address domain of the piece
	 * @param <T> the value domain of the piece
	 * @param <P> the type of the property map
	 */
	public static abstract class AbstractSimplePropertyBasedPieceHandler<A, T, P>
			extends AbstractPropertyBasedPieceHandler<A, T, P> {

		/**
		 * Decode a state value from the given property value
		 * 
		 * @param propertyValue the property value
		 * @return the decoded state value
		 */
		protected abstract T decode(P propertyValue);

		@Override
		protected void decodeFrom(PcodeExecutorStatePiece<A, T> piece, AddressSetView limit,
				AddressRange range, P propertyValue) {
			piece.setVarInternal(range.getAddressSpace(), range.getMinAddress().getOffset(),
				(int) range.getLength(), decode(propertyValue));
		}

		/**
		 * Encode a state value into a property value
		 * 
		 * @param value the state value
		 * @return the encoded property value
		 */
		protected abstract P encode(T value);

		@Override
		protected void encodeInto(PcodeTracePropertyAccess<P> property, AddressRange range,
				T value) {
			property.put(range, encode(value));
		}
	}

	/**
	 * The implementation of {@link Writer} for traces.
	 * 
	 * <p>
	 * The interface is already somewhat trace-centric in that it requires
	 * {@link Writer#writeDown(PcodeTraceAccess)}, but those may technically do nothing (as is the
	 * case for the write-immediately implementations). NOTE: Perhaps we should replace the
	 * interface with this class (renamed to {@link Writer}).
	 */
	public static class TraceWriter implements Writer {
		protected final PcodeTraceAccess access;
		protected final PcodeTraceMemoryAccess memAccess;
		protected final Map<PcodeThread<?>, PcodeTraceRegistersAccess> regAccess = new HashMap<>();

		/**
		 * An address set to track what has actually been written. It's not enough to just use the
		 * {@link SemisparseByteArray}'s initialized set, as that may be caching bytes from the
		 * trace which are still {@link TraceMemoryState#UNKNOWN}.
		 */
		protected final AddressSet memWritten = new AddressSet();
		protected final Map<PcodeThread<?>, AddressSet> regsWritten = new HashMap<>();

		protected final Map<PieceType<?, ?>, PieceHandler<?, ?>> handlers = new HashMap<>();

		private PcodeMachine<?> emulator;

		/**
		 * Construct a writer which sources state from the given access shim
		 * 
		 * @param access the source access shim
		 */
		public TraceWriter(PcodeTraceAccess access) {
			this.access = access;
			this.memAccess = access.getDataForSharedState();
		}

		@Override
		public void putHandler(PieceHandler<?, ?> handler) {
			handlers.put(PieceType.forHandler(handler), handler);
		}

		@Override
		public void emulatorCreated(PcodeMachine<Object> emulator) {
			this.emulator = emulator;
		}

		@Override
		public void threadCreated(PcodeThread<Object> thread) {
			access.getDataForLocalState(thread, 0).initializeThreadContext(thread);
		}

		@SuppressWarnings("unchecked")
		protected <B, U> PieceHandler<B, U> handlerFor(PcodeExecutorStatePiece<B, U> piece) {
			return (PieceHandler<B, U>) handlers.getOrDefault(PieceType.forPiece(piece),
				PieceHandler.NONE);
		}

		/**
		 * Record the given piece's state into the trace
		 * 
		 * @param <B> the piece's address domain
		 * @param <U> the piece's value domain
		 * @param into the destination trace access shim
		 * @param thread the thread, if applicable
		 * @param piece the piece
		 * @param written the logged portions written
		 */
		protected <B, U> void writePieceDown(PcodeTraceDataAccess into, PcodeThread<?> thread,
				PcodeExecutorStatePiece<B, U> piece, AddressSetView written) {
			PieceHandler<B, U> handler = handlerFor(piece);
			handler.writeDown(into, thread, piece, written);
		}

		@Override
		public void writeDown(PcodeTraceAccess into) {
			PcodeTraceMemoryAccess memInto = into.getDataForSharedState();
			for (PcodeExecutorStatePiece<?, ?> piece : emulator.getSharedState()
					.streamPieces()
					.toList()) {
				writePieceDown(memInto, null, piece, memWritten);
			}
			for (PcodeThread<?> thread : emulator.getAllThreads()) {
				PcodeTraceRegistersAccess regInto = into.getDataForLocalState(thread, 0);
				AddressSetView written = regsWritten.getOrDefault(thread, new AddressSet());
				for (PcodeExecutorStatePiece<?, ?> piece : thread.getState()
						.streamPieces()
						.toList()) {
					writePieceDown(regInto, thread, piece, written);
				}
			}
		}

		@Override
		public void writeDown(long snap) {
			writeDown(access.deriveForWrite(snap));
		}

		protected PcodeTraceRegistersAccess getRegAccess(PcodeThread<?> thread) {
			// Always use frame 0
			return regAccess.computeIfAbsent(thread, t -> access.getDataForLocalState(t, 0));
		}

		@Override
		public <B, U> void dataWritten(PcodeThread<Object> thread,
				PcodeExecutorStatePiece<B, U> piece,
				Address address, int length, U value) {
			PcodeTraceDataAccess acc = address.isRegisterAddress()
					? getRegAccess(thread)
					: memAccess;
			AddressSet written = address.isRegisterAddress()
					? regsWritten.computeIfAbsent(thread, t -> new AddressSet())
					: memWritten;
			if (handlerFor(piece).dataWritten(acc, written, thread, piece, address, length,
				value)) {
				return;
			}
			Address end = address.addWrap(length - 1);
			if (address.compareTo(end) <= 0) {
				written.add(address, end);
			}
			else {
				AddressSpace space = address.getAddressSpace();
				written.add(address, space.getMaxAddress());
				written.add(space.getMinAddress(), end);
			}
		}

		@Override
		public <B, U> void dataWritten(PcodeThread<Object> thread,
				PcodeExecutorStatePiece<B, U> piece, AddressSpace space, B offset, int length,
				U value) {
			PcodeTraceDataAccess acc = space.isRegisterSpace() ? getRegAccess(thread) : memAccess;
			AddressSet written = space.isRegisterSpace()
					? regsWritten.computeIfAbsent(thread, t -> new AddressSet())
					: memWritten;
			handlerFor(piece).abstractWritten(acc, written, thread, piece, space, offset, length,
				value);
		}

		@Override
		public <B, U> int readUninitialized(PcodeThread<Object> thread,
				PcodeExecutorStatePiece<B, U> piece, AddressSpace space, B offset, int length) {
			PcodeTraceDataAccess acc = space.isRegisterSpace() ? getRegAccess(thread) : memAccess;
			return handlerFor(piece).abstractReadUninit(acc, thread, piece, space, offset, length);
		}

		@Override
		public <B, U> AddressSetView readUninitialized(PcodeThread<Object> thread,
				PcodeExecutorStatePiece<B, U> piece, AddressSetView set) {
			if (set.isEmpty()) {
				return set;
			}
			AddressSpace space = set.getMinAddress().getAddressSpace();
			PcodeTraceDataAccess acc = space.isRegisterSpace() ? getRegAccess(thread) : memAccess;
			return handlerFor(piece).readUninitialized(acc, thread, piece, set);
		}
	}
}
