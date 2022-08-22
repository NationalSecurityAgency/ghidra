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
import java.util.HashMap;
import java.util.Map;

import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;

/**
 * An abstract p-code executor state for storing bytes, retrieved and set as arrays.
 *
 * @param <B> if this state is a cache, the type of object backing each address space
 * @param <S> the type of an execute state space, internally associated with an address space
 */
public abstract class AbstractBytesPcodeExecutorState<B, S extends BytesPcodeExecutorStateSpace<B>>
		extends AbstractLongOffsetPcodeExecutorState<byte[], S> {

	/**
	 * A memory buffer bound to a given space in this state
	 */
	protected class StateMemBuffer implements MemBufferAdapter {
		protected final Address address;
		protected final BytesPcodeExecutorStateSpace<B> source;

		/**
		 * Construct a buffer bound to the given space, at the given address
		 * 
		 * @param address the address
		 * @param source the space
		 */
		public StateMemBuffer(Address address, BytesPcodeExecutorStateSpace<B> source) {
			this.address = address;
			this.source = source;
		}

		@Override
		public Address getAddress() {
			return address;
		}

		@Override
		public Memory getMemory() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean isBigEndian() {
			return language.isBigEndian();
		}

		@Override
		public int getBytes(ByteBuffer buffer, int addressOffset) {
			byte[] data = source.read(address.getOffset() + addressOffset, buffer.remaining());
			buffer.put(data);
			return data.length;
		}
	}

	protected final Map<AddressSpace, S> spaces = new HashMap<>();

	protected final Language language;

	/**
	 * Construct a state for the given language
	 * 
	 * @param language the langauge (used for its memory model)
	 */
	public AbstractBytesPcodeExecutorState(Language language) {
		super(language, BytesPcodeArithmetic.forLanguage(language));
		this.language = language;
	}

	@Override
	protected long offsetToLong(byte[] offset) {
		return Utils.bytesToLong(offset, offset.length, language.isBigEndian());
	}

	@Override
	public byte[] longToOffset(AddressSpace space, long l) {
		return arithmetic.fromConst(l, space.getPointerSize());
	}

	/**
	 * If this state is a cache, get the object backing the given address space
	 * 
	 * @param space the space
	 * @return the backing object
	 */
	protected B getBacking(AddressSpace space) {
		return null;
	}

	/**
	 * Construct a new space internally associated with the given address space, having the given
	 * backing
	 * 
	 * <p>
	 * As the name implies, this often simply wraps {@code S}'s constructor
	 * 
	 * @param space the address space
	 * @param backing the backing, if applicable
	 * @return the new space
	 */
	protected abstract S newSpace(AddressSpace space, B backing);

	@Override
	protected S getForSpace(AddressSpace space, boolean toWrite) {
		return spaces.computeIfAbsent(space, s -> {
			B backing = s.isUniqueSpace() ? null : getBacking(space);
			return newSpace(s, backing);
		});
	}

	@Override
	protected void setInSpace(S space, long offset, int size, byte[] val) {
		if (val.length > size) {
			throw new IllegalArgumentException(
				"Value is larger than variable: " + val.length + " > " + size);
		}
		if (val.length < size) {
			Msg.warn(this, "Value is smaller than variable: " + val.length + " < " + size +
				". Zero extending");
			val = arithmetic.unaryOp(PcodeArithmetic.INT_ZEXT, size, val.length, val);
		}
		space.write(offset, val, 0, size);
	}

	@Override
	protected byte[] getFromSpace(S space, long offset, int size) {
		byte[] read = space.read(offset, size);
		if (read.length != size) {
			throw new AccessPcodeExecutionException("Incomplete read (" + read.length +
				" of " + size + " bytes)");
		}
		return read;
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address) {
		return new StateMemBuffer(address, getForSpace(address.getAddressSpace(), false));
	}
}
