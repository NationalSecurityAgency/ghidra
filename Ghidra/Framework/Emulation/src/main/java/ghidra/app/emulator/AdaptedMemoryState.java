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
package ghidra.app.emulator;

import javax.help.UnsupportedOperationException;

import ghidra.lifecycle.Transitional;
import ghidra.pcode.emu.ModifiedPcodeThread;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.memstate.AbstractMemoryState;
import ghidra.pcode.memstate.MemoryBank;
import ghidra.program.model.address.AddressSpace;

/**
 * An implementation of {@link MemoryState} which wraps a newer {@link PcodeExecutorState}.
 * 
 * <p>
 * This is a transitional component used internally by the {@link AdaptedEmulator}. It is also used
 * in the {@link ModifiedPcodeThread}, which is part of the newer {@link PcodeEmulator} system, as a
 * means of incorporating {@link EmulateInstructionStateModifier}, which is part of the older
 * {@link EmulatorHelper} system. This class will be removed once both conditions are met:
 * 
 * <ol>
 * <li>An equivalent state modification system is developed for the {@link PcodeEmulator} system,
 * and each {@link EmulateInstructionStateModifier} is ported to it.</li>
 * <li>The {@link AdaptedEmulator} class is removed.</li>
 * </ol>
 * 
 * <p>
 * Guidance for the use of this class is the same as {@link AdaptedEmulator}.
 *
 * @param <T> the type of values in the wrapped state. This matters not to {@link EmulatorHelper},
 *            so long as {@link T} can be made concrete.
 */
@Transitional
public class AdaptedMemoryState<T> extends AbstractMemoryState {
	private final PcodeExecutorState<T> state;
	private final PcodeArithmetic<T> arithmetic;
	private final Reason reason;

	public AdaptedMemoryState(PcodeExecutorState<T> state, Reason reason) {
		super(state.getLanguage());
		this.state = state;
		this.arithmetic = state.getArithmetic();
		this.reason = reason;
	}

	@Override
	public void setMemoryBank(MemoryBank bank) {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBank getMemoryBank(AddressSpace spc) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getChunk(byte[] res, AddressSpace spc, long off, int size,
			boolean stopOnUnintialized) {
		T t = state.getVar(spc, off, size, true, reason);
		byte[] val = arithmetic.toConcrete(t, Purpose.OTHER);
		System.arraycopy(val, 0, res, 0, val.length);
		return val.length;
	}

	@Override
	public void setChunk(byte[] val, AddressSpace spc, long off, int size) {
		T t = arithmetic.fromConst(val);
		state.setVar(spc, off, size, true, t);
	}

	@Override
	public void setInitialized(boolean initialized, AddressSpace spc, long off, int size) {
		// Do nothing
	}
}
