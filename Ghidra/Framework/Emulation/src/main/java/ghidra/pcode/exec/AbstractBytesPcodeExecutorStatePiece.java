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

import java.nio.ByteBuffer;
import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.Varnode;

/**
 * An abstract p-code executor state piece for storing and retrieving bytes as arrays
 *
 * @param <S> the type of an executor state space, internally associated with an address space
 */
public abstract class AbstractBytesPcodeExecutorStatePiece<S extends BytesPcodeExecutorStateSpace>
		extends AbstractLongOffsetPcodeExecutorStatePiece<byte[], byte[], S> {

	/**
	 * A memory buffer bound to a given space in this state
	 */
	protected class StateMemBuffer implements MemBufferMixin {
		protected final Address address;
		protected BytesPcodeExecutorStateSpace source;
		protected final Reason reason;

		/**
		 * Construct a buffer bound to the given space, at the given address
		 * 
		 * @param address the address
		 * @param source the space (null will cause readUninit and re-fetch on read attempts)
		 * @param reason the reason this buffer reads from the state, as in
		 *            {@link PcodeExecutorStatePiece#getVar(Varnode, Reason)}
		 */
		public StateMemBuffer(Address address, BytesPcodeExecutorStateSpace source, Reason reason) {
			this.address = address;
			this.source = source;
			this.reason = reason;
		}

		@Override
		public Address getAddress() {
			return address;
		}

		@Override
		public Memory getMemory() {
			return null;
		}

		@Override
		public boolean isBigEndian() {
			return language.isBigEndian();
		}

		@Override
		public int getBytes(ByteBuffer buffer, int addressOffset) {
			if (source == null) {
				Address min = address.add(addressOffset);
				AddressSet set = new AddressSet(min, min.add(buffer.remaining() - 1));
				if (set.equals(
					cb.readUninitialized(AbstractBytesPcodeExecutorStatePiece.this, set))) {
					return 0;
				}
				source = getForSpace(address.getAddressSpace(), false);
				if (source == null) { // still
					return 0;
				}
			}
			byte[] data =
				source.read(address.getOffset() + addressOffset, buffer.remaining(), reason, cb);
			buffer.put(data);
			return data.length;
		}
	}

	protected final Map<AddressSpace, S> spaceMap = new HashMap<>();

	/**
	 * Construct a state for the given language
	 * 
	 * @param language the language, used for its memory model
	 * @param arithmetic the arithmetic
	 * @param cb callbacks to receive emulation events
	 */
	public AbstractBytesPcodeExecutorStatePiece(Language language,
			PcodeArithmetic<byte[]> arithmetic, PcodeStateCallbacks cb) {
		super(language, arithmetic, arithmetic, cb);
	}

	/**
	 * Construct a state for the given language
	 * 
	 * @param language the language, used for its memory model and arithmetic
	 * @param cb callbacks to receive emulation events
	 */
	public AbstractBytesPcodeExecutorStatePiece(Language language, PcodeStateCallbacks cb) {
		this(language, BytesPcodeArithmetic.forLanguage(language), cb);
	}

	protected abstract S newSpace(AddressSpace space);

	@Override
	protected S getForSpace(AddressSpace space, boolean toWrite) {
		if (toWrite) {
			return spaceMap.computeIfAbsent(space, this::newSpace);
		}
		return spaceMap.get(space);
	}

	@Override
	protected void setInSpace(S space, long offset, int size, byte[] val, PcodeStateCallbacks cb) {
		space.write(offset, val, 0, size, cb);
	}

	@Override
	protected byte[] getFromSpace(S space, long offset, int size, Reason reason,
			PcodeStateCallbacks cb) {
		byte[] read = space.read(offset, size, reason, cb);
		if (read.length != size) {
			throw new AccessPcodeExecutionException("Incomplete read (" + read.length +
				" of " + size + " bytes)");
		}
		return read;
	}

	@Override
	protected Map<Register, byte[]> getRegisterValuesFromSpace(S s, List<Register> registers) {
		return s.getRegisterValues(registers);
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, PcodeArithmetic.Purpose purpose) {
		return new StateMemBuffer(address, getForSpace(address.getAddressSpace(), false),
			purpose.reason());
	}

	@Override
	public void clear() {
		for (S space : spaceMap.values()) {
			space.clear();
		}
	}
}
