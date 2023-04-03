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
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

/**
 * An abstract p-code executor state piece for storing and retrieving bytes as arrays
 *
 * @param <S> the type of an executor state space, internally associated with an address space
 */
public abstract class AbstractBytesPcodeExecutorStatePiece<S extends BytesPcodeExecutorStateSpace<?>>
		extends AbstractLongOffsetPcodeExecutorStatePiece<byte[], byte[], S> {

	/**
	 * A memory buffer bound to a given space in this state
	 */
	protected class StateMemBuffer implements MemBufferMixin {
		protected final Address address;
		protected final BytesPcodeExecutorStateSpace<?> source;
		protected final Reason reason;

		/**
		 * Construct a buffer bound to the given space, at the given address
		 * 
		 * @param address the address
		 * @param source the space
		 * @param reason the reason this buffer reads from the state, as in
		 *            {@link PcodeExecutorStatePiece#getVar(Varnode, Reason)}
		 */
		public StateMemBuffer(Address address, BytesPcodeExecutorStateSpace<?> source,
				Reason reason) {
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
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean isBigEndian() {
			return language.isBigEndian();
		}

		@Override
		public int getBytes(ByteBuffer buffer, int addressOffset) {
			byte[] data =
				source.read(address.getOffset() + addressOffset, buffer.remaining(), reason);
			buffer.put(data);
			return data.length;
		}
	}

	protected final AbstractSpaceMap<S> spaceMap;

	/**
	 * Construct a state for the given language
	 * 
	 * @param language the language, used for its memory model and arithmetic
	 */
	public AbstractBytesPcodeExecutorStatePiece(Language language) {
		this(language, BytesPcodeArithmetic.forLanguage(language));
	}

	protected AbstractBytesPcodeExecutorStatePiece(Language language,
			AbstractSpaceMap<S> spaceMap) {
		this(language, BytesPcodeArithmetic.forLanguage(language), spaceMap);
	}

	/**
	 * Construct a state for the given language
	 * 
	 * @param language the language, used for its memory model
	 * @param arithmetic the arithmetic
	 */
	public AbstractBytesPcodeExecutorStatePiece(Language language,
			PcodeArithmetic<byte[]> arithmetic) {
		super(language, arithmetic, arithmetic);
		spaceMap = newSpaceMap();
	}

	protected AbstractBytesPcodeExecutorStatePiece(Language language,
			PcodeArithmetic<byte[]> arithmetic, AbstractSpaceMap<S> spaceMap) {
		super(language, arithmetic, arithmetic);
		this.spaceMap = spaceMap;
	}

	/**
	 * A factory method for this state's space map.
	 * 
	 * <p>
	 * Because most of the special logic for extensions is placed in the "state space," i.e., an
	 * object assigned to a particular address space in the state's language, this factory method
	 * must provide the map to create and maintain those spaces. That map will in turn be the
	 * factory of the spaces themselves, allowing extensions to provide additional read/write logic.
	 * 
	 * @return the new space map
	 */
	protected abstract AbstractSpaceMap<S> newSpaceMap();

	@Override
	protected S getForSpace(AddressSpace space, boolean toWrite) {
		return spaceMap.getForSpace(space, toWrite);
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
			val = arithmetic.unaryOp(PcodeOp.INT_ZEXT, size, val.length, val);
		}
		space.write(offset, val, 0, size);
	}

	@Override
	protected byte[] getFromSpace(S space, long offset, int size, Reason reason) {
		byte[] read = space.read(offset, size, reason);
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
