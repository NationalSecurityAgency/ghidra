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
import java.util.stream.Stream;

import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemBuffer;

public abstract class AbstractPcodeExecutorState<A, T> implements PcodeExecutorState<T> {
	protected final PcodeExecutorStatePiece<A, T> piece;

	public AbstractPcodeExecutorState(PcodeExecutorStatePiece<A, T> piece) {
		this.piece = piece;
	}

	@Override
	public Language getLanguage() {
		return piece.getLanguage();
	}

	@Override
	public PcodeArithmetic<T> getArithmetic() {
		return piece.getArithmetic();
	}

	@Override
	public Stream<PcodeExecutorStatePiece<?, ?>> streamPieces() {
		return piece.streamPieces();
	}

	protected abstract A extractAddress(T value);

	@Override
	public T getVar(AddressSpace space, T offset, int size, boolean quantize, Reason reason) {
		return piece.getVar(space, extractAddress(offset), size, quantize, reason);
	}

	@Override
	public T getVarInternal(AddressSpace space, T offset, int size, Reason reason) {
		return piece.getVarInternal(space, extractAddress(offset), size, reason);
	}

	@Override
	public T getVar(AddressSpace space, long offset, int size, boolean quantize, Reason reason) {
		return piece.getVar(space, offset, size, quantize, reason);
	}

	@Override
	public T getVarInternal(AddressSpace space, long offset, int size, Reason reason) {
		return piece.getVarInternal(space, offset, size, reason);
	}

	@Override
	public void setVar(AddressSpace space, T offset, int size, boolean quantize, T val) {
		piece.setVar(space, extractAddress(offset), size, quantize, val);
	}

	@Override
	public void setVarInternal(AddressSpace space, T offset, int size, T val) {
		piece.setVarInternal(space, extractAddress(offset), size, val);
	}

	@Override
	public void setVar(AddressSpace space, long offset, int size, boolean quantize, T val) {
		piece.setVar(space, offset, size, quantize, val);
	}

	@Override
	public void setVarInternal(AddressSpace space, long offset, int size, T val) {
		piece.setVarInternal(space, offset, size, val);
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
