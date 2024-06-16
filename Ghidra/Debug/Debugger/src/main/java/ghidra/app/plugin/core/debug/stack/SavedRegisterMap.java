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
package ghidra.app.plugin.core.debug.stack;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;

import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.async.AsyncFence;
import ghidra.pcode.eval.ArithmeticVarnodeEvaluator;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;
import ghidra.trace.database.DBTraceUtils.AddressRangeMapSetter;
import ghidra.trace.util.TraceRegisterUtils;

/**
 * A map from registers to physical stack addresses
 *
 * <p>
 * This is used by an unwound frame to ensure that register reads are translated to stack reads when
 * the register's value was saved to the stack by some inner frame. If a register is not saved to
 * the stack by such a frame, then its value is read from the register bank.
 */
public class SavedRegisterMap {
	/**
	 * An entry in the map
	 */
	record SavedEntry(AddressRange from, Address to) {
		/**
		 * The range in register space to be redirected to the stack
		 * 
		 * @return the "from" range
		 */
		public AddressRange from() {
			return from;
		}

		/**
		 * The physical address in the stack segment to which the register is redirected
		 * 
		 * <p>
		 * The length of the "to" range is given by the length of the "from" range
		 * 
		 * @return the "to" address
		 */
		public Address to() {
			return to;
		}

		/**
		 * Check if an access should be redirected according to this entry
		 * 
		 * @param address the address to be accessed
		 * @return true to redirect, false otherwise
		 */
		boolean contains(Address address) {
			return from.contains(address);
		}

		/**
		 * Produce an equivalent entry that redirects only the given new "from" range
		 * 
		 * @param range the new "from" range, which must be enclosed by the current "from" range
		 * @return the same or truncated entry
		 */
		public SavedEntry truncate(AddressRange range) {
			int right = (int) from.getMaxAddress().subtract(range.getMaxAddress());
			if (right < 0) {
				throw new AssertionError("Cannot grow");
			}
			int left = (int) from.getMinAddress().subtract(range.getMinAddress());
			if (left < 0) {
				throw new AssertionError("Cannot grow");
			}
			if (left == 0 && right == 0) {
				return this;
			}
			return new SavedEntry(range, to.add(left));
		}

		/**
		 * Produce the same or equivalent entry that redirects at most the given "from" range
		 * 
		 * @param range the "from" range to intersect
		 * @return the same or truncated entry
		 */
		public SavedEntry intersect(AddressRange range) {
			AddressRange intersection = from.intersect(range);
			return intersection == null ? null : truncate(intersection);
		}

		/**
		 * Produce an equivalent entry which excludes any "from" address beyond the given max
		 * 
		 * @param max the max "from" address
		 * @return the same or truncated entry
		 */
		public SavedEntry truncateMax(Address max) {
			if (from.getMaxAddress().compareTo(max) <= 0) {
				return this;
			}
			if (from.getMinAddress().compareTo(max) <= 0) {
				return truncate(new AddressRangeImpl(from.getMinAddress(), max));
			}
			return null;
		}

		/**
		 * Produce an equivalent entry which exclude any "from" address before the given min
		 * 
		 * @param min the min "from" address
		 * @return the same or truncated entry
		 */
		public SavedEntry truncateMin(Address min) {
			if (from.getMinAddress().compareTo(min) >= 0) {
				return this;
			}
			if (from.getMaxAddress().compareTo(min) >= 0) {
				return truncate(new AddressRangeImpl(min, from.getMaxAddress()));
			}
			return null;
		}

		/**
		 * The length of the mapped ranges
		 * 
		 * @return the length
		 */
		public int size() {
			return (int) from.getLength();
		}
	}

	/**
	 * A class which can set values over a range, ensuring no overlapping entries
	 */
	protected class SavedEntrySetter
			extends AddressRangeMapSetter<Map.Entry<Address, SavedEntry>, SavedEntry> {
		@Override
		protected AddressRange getRange(Entry<Address, SavedEntry> entry) {
			return entry.getValue().from;
		}

		@Override
		protected SavedEntry getValue(Entry<Address, SavedEntry> entry) {
			return entry.getValue();
		}

		@Override
		protected void remove(Entry<Address, SavedEntry> entry) {
			saved.remove(entry.getKey());
		}

		@Override
		protected Iterable<Entry<Address, SavedEntry>> getIntersecting(Address lower,
				Address upper) {
			return subMap(lower, upper).entrySet();
		}

		@Override
		protected Entry<Address, SavedEntry> put(AddressRange range, SavedEntry value) {
			saved.put(range.getMinAddress(), value.truncate(range));
			return null;
		}
	}

	private final NavigableMap<Address, SavedEntry> saved;
	private final SavedEntrySetter setter = new SavedEntrySetter();

	/**
	 * Construct an empty (identity) register map
	 */
	public SavedRegisterMap() {
		this.saved = new TreeMap<>();
	}

	/**
	 * Copy a given register map
	 * 
	 * @param saved the map to copy
	 */
	public SavedRegisterMap(TreeMap<Address, SavedEntry> saved) {
		this.saved = new TreeMap<>();
	}

	private NavigableMap<Address, SavedEntry> subMap(Address lower, Address upper) {
		Entry<Address, SavedEntry> adjEnt = saved.floorEntry(lower);
		if (adjEnt != null && adjEnt.getValue().contains(upper)) {
			lower = adjEnt.getKey();
		}
		return saved.subMap(lower, true, upper, true);
	}

	static AddressRange rangeForVarnode(Varnode vn) {
		return new AddressRangeImpl(vn.getAddress(), vn.getAddress().add(vn.getSize() - 1));
	}

	/**
	 * Map a register to a stack varnode
	 * 
	 * @param from the register
	 * @param stackVar the stack varnode
	 */
	public void put(Register from, Varnode stackVar) {
		put(TraceRegisterUtils.rangeForRegister(from), rangeForVarnode(stackVar));
	}

	/**
	 * Map the given ranges, which must have equal lengths
	 * 
	 * @param from the range in register space
	 * @param to the range in the stack segment
	 */
	public void put(AddressRange from, AddressRange to) {
		if (from.getLength() != to.getLength()) {
			throw new IllegalArgumentException("from and to must match in length");
		}
		put(from, to.getMinAddress());
	}

	/**
	 * Map the given range to the given address
	 * 
	 * @param from the range in register space
	 * @param to the address in the stack segment
	 */
	public void put(AddressRange from, Address to) {
		setter.set(from, new SavedEntry(from, to));
	}

	/**
	 * Copy this register map
	 * 
	 * @return the copy
	 */
	public SavedRegisterMap fork() {
		return new SavedRegisterMap(new TreeMap<>(saved));
	}

	private abstract class PieceVisitor<U> {
		public U visitVarnode(Address address, int size, U user) {
			AddressRange range = new AddressRangeImpl(address, address.add(size - 1));
			SavedEntry identity = new SavedEntry(range, address);
			for (SavedEntry se : subMap(range.getMinAddress(), range.getMaxAddress()).values()) {
				Address prev = se.from.getMinAddress().previous();
				if (prev != null) {
					SavedEntry idLeft = identity.truncateMax(prev);
					if (idLeft != null) {
						user = visitPiece(idLeft.to, idLeft.size(), user);
					}
				}
				SavedEntry piece = se.intersect(range);
				user = visitPiece(piece.to, piece.size(), user);
				Address next = se.from.getMaxAddress().next();
				if (next == null) {
					return user;
				}
				identity = identity.truncateMin(next);
			}
			if (identity != null) {
				user = visitPiece(identity.to, identity.size(), user);
			}
			return user;
		}

		abstract U visitPiece(Address address, int size, U user);
	}

	/**
	 * Get a variable from the given state wrt. this mapping
	 * 
	 * <p>
	 * Register reads are redirected to the mapped addresses when applicable.
	 * 
	 * @param <T> the type of values in the state
	 * @param state the state to access
	 * @param address the address of the variable
	 * @param size the size of the variable
	 * @param reason a reason for reading the variable
	 * @return the variable's value
	 */
	public <T> T getVar(PcodeExecutorState<T> state, Address address, int size, Reason reason) {
		PcodeArithmetic<T> arithmetic = state.getArithmetic();
		return new PieceVisitor<T>() {
			@Override
			T visitPiece(Address address, int sz, T value) {
				T piece = state.getVar(address, size, true, reason);
				return ArithmeticVarnodeEvaluator.catenate(arithmetic, size, value, piece, sz);
			}
		}.visitVarnode(address, size, arithmetic.fromConst(0, size));
	}

	/**
	 * Set a variable using the given editor wrt. this mapping
	 * 
	 * @param editor the editor
	 * @param address the address of the variable
	 * @param bytes the bytes (in language-dependent endianness) giving the variable's value
	 * @return a future that completes when all editing commands have completed
	 */
	public CompletableFuture<Void> setVar(StateEditor editor, Address address, byte[] bytes) {
		AsyncFence fence = new AsyncFence();
		new PieceVisitor<ByteBuffer>() {
			@Override
			ByteBuffer visitPiece(Address address, int size, ByteBuffer buf) {
				byte[] sub = new byte[size];
				buf.get(sub);
				fence.include(editor.setVariable(address, sub));
				return buf;
			}
		}.visitVarnode(address, bytes.length, ByteBuffer.wrap(bytes));
		return fence.ready();
	}
}
