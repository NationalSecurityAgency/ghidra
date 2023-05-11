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
package ghidra.pcode.emu.taint;

import java.util.List;
import java.util.Map;

import ghidra.pcode.emu.taint.plain.TaintSpace;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemBuffer;
import ghidra.taint.model.TaintVec;

/**
 * An abstract taint state piece
 *
 * <p>
 * Because we want to reduce code repetition, we use the type hierarchy to increase the capabilities
 * of the state piece as we progress from stand-alone to Debugger-integrated. The framework-provided
 * class from which this derives, however, introduces the idea of a space map, whose values have
 * type {@code <S>}. We'll be using types derived from {@link TaintSpace}, which is where all the
 * taint storage logic is actually located. Because that logic is what we're actually extending with
 * each more capable state piece, we have to ensure that type can be substituted. Thus, we have to
 * create these abstract classes from which the actual state pieces are derived, leaving {@code <S>}
 * bounded, but unspecified.
 *
 * @param <S> the type of spaces
 */
public abstract class AbstractTaintPcodeExecutorStatePiece<S extends TaintSpace>
		extends AbstractLongOffsetPcodeExecutorStatePiece<byte[], TaintVec, S> {

	/**
	 * The map from address space to storage space
	 * 
	 * <p>
	 * While the concept is introduced in the super class, we're not required to actually use one.
	 * We just have to implement {@link #getForSpace(AddressSpace, boolean)}. Nevertheless, the
	 * provided map is probably the best way, so we'll follow the pattern.
	 */
	protected final AbstractSpaceMap<S> spaceMap = newSpaceMap();

	/**
	 * Create a state piece
	 * 
	 * @param language the emulator's language
	 * @param addressArithmetic the arithmetic for the address type
	 * @param arithmetic the arithmetic for the value type
	 */
	public AbstractTaintPcodeExecutorStatePiece(Language language,
			PcodeArithmetic<byte[]> addressArithmetic, PcodeArithmetic<TaintVec> arithmetic) {
		super(language, addressArithmetic, arithmetic);
	}

	/**
	 * Extension point: Create the actual space map
	 * 
	 * <p>
	 * This will need to be implemented by each state piece, i.e., non-abstract derivative class.
	 * The space map will provide instances of {@code <S>}, which will provide the actual (extended)
	 * storage logic.
	 * 
	 * @return the space map
	 */
	protected abstract AbstractSpaceMap<S> newSpaceMap();

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
	protected S getForSpace(AddressSpace space, boolean toWrite) {
		return spaceMap.getForSpace(space, toWrite);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Because the super class places no bound on {@code <S>}, we have to provide the delegation to
	 * the storage space.
	 */
	@Override
	protected void setInSpace(S space, long offset, int size, TaintVec val) {
		space.set(offset, val);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Because the super class places no bound on {@code <S>}, we have to provide the delegation to
	 * the storage space.
	 */
	@Override
	protected TaintVec getFromSpace(S space, long offset, int size, Reason reason) {
		return space.get(offset, size);
	}

	@Override
	protected Map<Register, TaintVec> getRegisterValuesFromSpace(S space,
			List<Register> registers) {
		return space.getRegisterValues(registers);
	}

	@Override
	public void clear() {
		for (S space : spaceMap.values()) {
			space.clear();
		}
	}
}
