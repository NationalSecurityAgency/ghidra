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

import java.util.Map;

import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemBuffer;

/**
 * A p-code executor state formed from a piece whose address and value types are the same
 *
 * <p>
 * This class will also wire in the arithmetic's
 * {@link PcodeArithmetic#modBeforeStore(int, int, Object, int, Object)} and
 * {@link PcodeArithmetic#modAfterLoad(int, int, Object, int, Object)}, which is only possible when
 * the address and value type are guaranteed to match.
 *
 * @param <T> the type of values and addresses in the state
 */
public class DefaultPcodeExecutorState<T> implements PcodeExecutorState<T> {
	protected final PcodeExecutorStatePiece<T, T> piece;
	protected final PcodeArithmetic<T> arithmetic;

	public DefaultPcodeExecutorState(PcodeExecutorStatePiece<T, T> piece,
			PcodeArithmetic<T> arithmetic) {
		this.piece = piece;
		this.arithmetic = arithmetic;
	}

	public DefaultPcodeExecutorState(PcodeExecutorStatePiece<T, T> piece) {
		this(piece, piece.getArithmetic());
	}

	@Override
	public Language getLanguage() {
		return piece.getLanguage();
	}

	@Override
	public PcodeArithmetic<T> getArithmetic() {
		return arithmetic;
	}

	@Override
	public DefaultPcodeExecutorState<T> fork() {
		return new DefaultPcodeExecutorState<>(piece.fork(), arithmetic);
	}

	@Override
	public T getVar(AddressSpace space, T offset, int size, boolean quantize, Reason reason) {
		return piece.getVar(space, offset, size, quantize, reason);
	}

	@Override
	public T getVar(AddressSpace space, long offset, int size, boolean quantize, Reason reason) {
		return piece.getVar(space, offset, size, quantize, reason);
	}

	@Override
	public void setVar(AddressSpace space, T offset, int size, boolean quantize, T val) {
		piece.setVar(space, offset, size, quantize, val);
	}

	@Override
	public void setVar(AddressSpace space, long offset, int size, boolean quantize, T val) {
		piece.setVar(space, offset, size, quantize, val);
	}

	@Override
	public Map<Register, T> getRegisterValues() {
		return piece.getRegisterValues();
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		return piece.getConcreteBuffer(address, purpose);
	}

	@Override
	public void clear() {
		piece.clear();
	}
}
