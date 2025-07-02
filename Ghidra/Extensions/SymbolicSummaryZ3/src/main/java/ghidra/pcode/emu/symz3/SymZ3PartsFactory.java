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

import ghidra.app.plugin.core.debug.service.emulation.RWTargetMemoryPcodeExecutorStatePiece;
import ghidra.app.plugin.core.debug.service.emulation.RWTargetRegistersPcodeExecutorStatePiece;
import ghidra.pcode.emu.*;
import ghidra.pcode.emu.DefaultPcodeThread.PcodeThreadExecutor;
import ghidra.pcode.emu.auxiliary.AuxPcodeEmulator;
import ghidra.pcode.emu.symz3.plain.SymZ3PcodeExecutorState;
import ghidra.pcode.emu.symz3.trace.SymZ3TracePcodeExecutorState;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.debug.auxiliary.AuxDebuggerEmulatorPartsFactory;
import ghidra.pcode.exec.debug.auxiliary.AuxDebuggerPcodeEmulator;
import ghidra.pcode.exec.trace.BytesTracePcodeExecutorStatePiece;
import ghidra.pcode.exec.trace.TracePcodeExecutorState;
import ghidra.pcode.exec.trace.auxiliary.AuxTracePcodeEmulator;
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
 * <li>Machine State</li>
 * <ul>
 * <li>Stand alone: {@link SymZ3PcodeExecutorState}</li>
 * <li>Trace integrated: {@link SymZ3TracePcodeExecutorState}</li>
 * <li>Debugger integrated: Not applicable. Uses trace integration only.</li>
 * </ul>
 * </ul>
 * 
 * <p>
 * If you're following from the {@link ghidra.symz3} package documentation, you'll want to return to
 * {@link ghidra.pcode.emu.symz3.plain} before you examine the trace-integrated state. Similarly,
 * you'll want to return to {@link ghidra.pcode.emu.symz3.trace} before you examine the
 * Debugger-integrated state.
 */
public enum SymZ3PartsFactory implements AuxDebuggerEmulatorPartsFactory<SymValueZ3> {
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
			AuxPcodeEmulator<SymValueZ3> emulator, BytesPcodeExecutorStatePiece concrete) {
		return new SymZ3PcodeExecutorState(emulator.getLanguage(), concrete);
	}

	@Override
	public PcodeExecutorState<Pair<byte[], SymValueZ3>> createLocalState(
			AuxPcodeEmulator<SymValueZ3> emulator, PcodeThread<Pair<byte[], SymValueZ3>> thread,
			BytesPcodeExecutorStatePiece concrete) {
		return new SymZ3PcodeExecutorState(emulator.getLanguage(), concrete);
	}

	@Override
	public TracePcodeExecutorState<Pair<byte[], SymValueZ3>> createTraceSharedState(
			AuxTracePcodeEmulator<SymValueZ3> emulator,
			BytesTracePcodeExecutorStatePiece concrete) {
		return new SymZ3TracePcodeExecutorState(concrete);
	}

	@Override
	public TracePcodeExecutorState<Pair<byte[], SymValueZ3>> createTraceLocalState(
			AuxTracePcodeEmulator<SymValueZ3> emulator,
			PcodeThread<Pair<byte[], SymValueZ3>> emuThread,
			BytesTracePcodeExecutorStatePiece concrete) {
		return new SymZ3TracePcodeExecutorState(concrete);
	}

	@Override
	public TracePcodeExecutorState<Pair<byte[], SymValueZ3>> createDebuggerSharedState(
			AuxDebuggerPcodeEmulator<SymValueZ3> emulator,
			RWTargetMemoryPcodeExecutorStatePiece concrete) {
		return new SymZ3TracePcodeExecutorState(concrete);
	}

	@Override
	public TracePcodeExecutorState<Pair<byte[], SymValueZ3>> createDebuggerLocalState(
			AuxDebuggerPcodeEmulator<SymValueZ3> emulator,
			PcodeThread<Pair<byte[], SymValueZ3>> emuThread,
			RWTargetRegistersPcodeExecutorStatePiece concrete) {
		return new SymZ3TracePcodeExecutorState(concrete);
	}
}
