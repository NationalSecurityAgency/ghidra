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
package ghidra.pcode.emu.taint.state;

import java.util.*;
import java.util.Map.Entry;

import ghidra.pcode.emu.taint.TaintPcodeArithmetic;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemBuffer;
import ghidra.taint.model.TaintVec;

/**
 * The taint state piece
 *
 * <p>
 * The framework-provided class from which this derives expects us to implement state for each
 * address space using a separate storage object. We do this by providing {@link TaintSpace}, which
 * is where all the taint storage logic is actually located. We then use a map {@link #spaceMap} to
 * lazily create a keep each of those spaces.
 */
public class TaintPcodeExecutorStatePiece
		extends AbstractLongOffsetPcodeExecutorStatePiece<byte[], TaintVec, TaintSpace> {

	/**
	 * A lazily-populated map of address space to taint storage.
	 */
	protected final Map<AddressSpace, TaintSpace> spaceMap = new HashMap<>();

	/**
	 * Create a state piece
	 * 
	 * @param language the emulator's language
	 * @param addressArithmetic the arithmetic for the address type
	 * @param arithmetic the arithmetic for the value type
	 * @param cb callbacks to receive emulation events
	 */
	public TaintPcodeExecutorStatePiece(Language language,
			PcodeArithmetic<byte[]> addressArithmetic, PcodeArithmetic<TaintVec> arithmetic,
			PcodeStateCallbacks cb) {
		super(language, addressArithmetic, arithmetic, cb);
	}

	/**
	 * Create the taint piece
	 * 
	 * @param language the language of the emulator
	 * @param addressArithmetic the address arithmetic, likely taken from the concrete piece
	 * @param cb callbacks to receive emulation events
	 */
	public TaintPcodeExecutorStatePiece(Language language,
			PcodeArithmetic<byte[]> addressArithmetic, PcodeStateCallbacks cb) {
		super(language, addressArithmetic, TaintPcodeArithmetic.forLanguage(language), cb);
	}

	@Override
	public TaintPcodeExecutorStatePiece fork(PcodeStateCallbacks cb) {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		throw new ConcretionError("Cannot make Taint concrete", purpose);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Here, we just follow the pattern: delegate to the space map.
	 */
	@Override
	protected TaintSpace getForSpace(AddressSpace space, boolean toWrite) {
		if (toWrite) {
			return spaceMap.computeIfAbsent(space, s -> new TaintSpace(space, this));
		}
		return spaceMap.get(space);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Because the super class places no bound on {@code <S>}, we have to provide the delegation to
	 * the storage space.
	 */
	@Override
	protected void setInSpace(TaintSpace space, long offset, int size, TaintVec val,
			PcodeStateCallbacks cb) {
		space.set(offset, val, cb);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Because the super class places no bound on {@code <S>}, we have to provide the delegation to
	 * the storage space.
	 */
	@Override
	protected TaintVec getFromSpace(TaintSpace space, long offset, int size, Reason reason,
			PcodeStateCallbacks cb) {
		return space.get(offset, size, cb);
	}

	@Override
	protected Map<Register, TaintVec> getRegisterValuesFromSpace(TaintSpace space,
			List<Register> registers) {
		return space.getRegisterValues(registers);
	}

	@Override
	public void clear() {
		for (TaintSpace space : spaceMap.values()) {
			space.clear();
		}
	}

	@Override
	public Entry<Long, TaintVec> getNextEntryInternal(AddressSpace space, long offset) {
		TaintSpace s = getForSpace(space, false);
		if (s == null) {
			return null;
		}
		return s.getNextEntry(offset);
	}
}
