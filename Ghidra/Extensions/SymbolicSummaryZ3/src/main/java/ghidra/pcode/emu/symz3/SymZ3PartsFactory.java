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
package ghidra.pcode.emu.symz3;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.*;
import ghidra.pcode.emu.DefaultPcodeThread.PcodeThreadExecutor;
import ghidra.pcode.emu.auxiliary.AuxEmulatorPartsFactory;
import ghidra.pcode.emu.auxiliary.AuxPcodeEmulator;
import ghidra.pcode.emu.symz3.state.SymZ3PcodeExecutorState;
import ghidra.pcode.exec.*;
import ghidra.program.model.lang.Language;
import ghidra.symz3.model.SymValueZ3;

/**
 * The parts factory for creating emulators with symbolic summaries using Z3
 * 
 * <p>
 * This is probably the most straightforward means of implementing a concrete-plus-auxiliary
 * emulator in Ghidra. For our case, the auxiliary piece is the {@link SymValueZ3}. For an overview
 * of the parts of a p-code emulator, see {@link PcodeEmulator}.
 * 
 * <p>
 * As recommended by the documentation, we've implemented the factory as a singleton. As presented
 * in the source, we'll visit each component in this order:
 * <ul>
 * <li>P-code Arithmetic: {@link SymZ3PcodeArithmetic}</li>
 * <li>Userop Library: {@link SymZ3PcodeUseropLibrary}</li>
 * <li>P-code Executor: {@link SymZ3PcodeThreadExecutor}</li>
 * <li>Machine State: {@link SymZ3PcodeExecutorState}</li>
 * </ul>
 * 
 * <p>
 * If you're following from the {@link ghidra.symz3} package documentation, you'll want to return to
 * {@link ghidra.pcode.emu.symz3.state} before you examine the trace-integrated state. Similarly,
 * you'll want to return to {@link ghidra.pcode.emu.symz3.trace} before you examine the
 * Debugger-integrated state.
 */
public enum SymZ3PartsFactory implements AuxEmulatorPartsFactory<SymValueZ3> {
	/** This singleton factory instance */
	INSTANCE;

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Here we simply return the arithmetic for symbolic values for the emulator's language.
	 */
	@Override
	public PcodeArithmetic<SymValueZ3> getArithmetic(Language language) {
		return SymZ3PcodeArithmetic.forLanguage(language);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We introduce two userops for obtaining symbolic values. Aside from initializing a trace
	 * (assuming a trace-integrated emulator), or writing directly to the state in the script, this
	 * library will allow clients to quickly initialize symbolic values in the machine. Furthermore,
	 * this can permit the placement of symbolic values in intermediate states of the machine during
	 * its execution. We construct and return the library here.
	 */
	@Override
	public PcodeUseropLibrary<Pair<byte[], SymValueZ3>> createSharedUseropLibrary(
			AuxPcodeEmulator<SymValueZ3> emulator) {
		return new SymZ3PcodeUseropLibrary();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We have no thread-specific userops to add, which means we also have no need to stubs, so here
	 * we just return the empty library.
	 */
	@Override
	public PcodeUseropLibrary<Pair<byte[], SymValueZ3>> createLocalUseropStub(
			AuxPcodeEmulator<SymValueZ3> emulator) {
		return PcodeUseropLibrary.nil();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We have no thread-specific userops to add, so here we just return the empty library.
	 */
	@Override
	public PcodeUseropLibrary<Pair<byte[], SymValueZ3>> createLocalUseropLibrary(
			AuxPcodeEmulator<SymValueZ3> emulator, PcodeThread<Pair<byte[], SymValueZ3>> thread) {
		return PcodeUseropLibrary.nil();
	}

	@Override
	public PcodeThread<Pair<byte[], SymValueZ3>> createThread(AuxPcodeEmulator<SymValueZ3> emulator,
			String name) {
		return new SymZ3PcodeThread(name, emulator);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We'd like to instrument conditional branches to record preconditions, so we'll need a custom
	 * executor. We construct it here.
	 */
	@Override
	public PcodeThreadExecutor<Pair<byte[], SymValueZ3>> createExecutor(
			AuxPcodeEmulator<SymValueZ3> emulator,
			DefaultPcodeThread<Pair<byte[], SymValueZ3>> thread) {
		return new SymZ3PcodeThreadExecutor((SymZ3PcodeThread) thread);
	}

	@Override
	public PcodeExecutorState<Pair<byte[], SymValueZ3>> createSharedState(
			AuxPcodeEmulator<SymValueZ3> emulator, BytesPcodeExecutorStatePiece concrete,
			PcodeStateCallbacks cb) {
		return new SymZ3PcodeExecutorState(emulator.getLanguage(), concrete, cb);
	}

	@Override
	public PcodeExecutorState<Pair<byte[], SymValueZ3>> createLocalState(
			AuxPcodeEmulator<SymValueZ3> emulator, PcodeThread<Pair<byte[], SymValueZ3>> thread,
			BytesPcodeExecutorStatePiece concrete, PcodeStateCallbacks cb) {
		return new SymZ3PcodeExecutorState(emulator.getLanguage(), concrete, cb);
	}
}
