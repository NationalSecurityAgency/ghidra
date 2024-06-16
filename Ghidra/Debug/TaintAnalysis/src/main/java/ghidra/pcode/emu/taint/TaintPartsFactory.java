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

import org.apache.commons.lang3.tuple.Pair;

import ghidra.app.plugin.core.debug.service.emulation.RWTargetMemoryPcodeExecutorStatePiece;
import ghidra.app.plugin.core.debug.service.emulation.RWTargetRegistersPcodeExecutorStatePiece;
import ghidra.pcode.emu.*;
import ghidra.pcode.emu.DefaultPcodeThread.PcodeThreadExecutor;
import ghidra.pcode.emu.auxiliary.AuxPcodeEmulator;
import ghidra.pcode.emu.taint.plain.TaintPcodeExecutorState;
import ghidra.pcode.emu.taint.trace.TaintTracePcodeExecutorState;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.debug.auxiliary.AuxDebuggerEmulatorPartsFactory;
import ghidra.pcode.exec.debug.auxiliary.AuxDebuggerPcodeEmulator;
import ghidra.pcode.exec.trace.BytesTracePcodeExecutorStatePiece;
import ghidra.pcode.exec.trace.TracePcodeExecutorState;
import ghidra.pcode.exec.trace.auxiliary.AuxTracePcodeEmulator;
import ghidra.program.model.lang.Language;
import ghidra.taint.model.TaintVec;

/**
 * The parts factory for creating emulators with taint analysis
 * 
 * <p>
 * This is probably the most straightforward means of implementing a concrete-plus-auxiliary
 * emulator in Ghidra. For our case, the auxiliary piece is the {@link TaintVec}. Ideally, the
 * auxiliary piece implements the analog of a byte array, so that each byte in the concrete piece
 * corresponds to an element in the abstract piece. We've done that here by letting each taint set
 * in the vector be the taint on the corresponding byte. Each part we implement must adhere to that
 * rule. For an overview of the parts of a p-code emulator, see {@link PcodeEmulator}.
 * 
 * <p>
 * As recommended by the documentation, we've implemented the factory as a singleton. As presented
 * in the source, we'll visit each component in this order:
 * <ul>
 * <li>P-code Arithmetic: {@link TaintPcodeArithmetic}</li>
 * <li>Userop Library: {@link TaintPcodeUseropLibrary}</li>
 * <li>P-code Executor: {@link TaintPcodeThreadExecutor}</li>
 * <li>Machine State</li>
 * <ul>
 * <li>Stand alone: {@link TaintPcodeExecutorState}</li>
 * <li>Trace integrated: {@link TaintTracePcodeExecutorState}</li>
 * <li>Debugger integrated: {@link TaintTracePcodeExecutorState} (same as Trace integrated)</li>
 * </ul>
 * </ul>
 * 
 * <p>
 * If you're following from the {@link ghidra.taint} package documentation, you'll want to return to
 * {@link ghidra.pcode.emu.taint.plain} before you examine the trace-integrated state. Similarly,
 * you'll want to return to {@link ghidra.pcode.emu.taint.trace} before you examine the
 * Debugger-integrated state.
 */
public enum TaintPartsFactory implements AuxDebuggerEmulatorPartsFactory<TaintVec> {
	/** This singleton factory instance */
	INSTANCE;

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Here we simply return the arithmetic for taint vectors for the emulator's language.
	 */
	@Override
	public PcodeArithmetic<TaintVec> getArithmetic(Language language) {
		return TaintPcodeArithmetic.forLanguage(language);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We introduce two userops for tainting variables. Aside from initializing a trace (assuming a
	 * trace-integrated emulator), or writing directly to the state in the script, this library will
	 * allow clients to quickly initialize taints in the machine. Furthermore, this can permit the
	 * placement of taints in intermediate states of the machine during its execution. We construct
	 * and return the library here.
	 */
	@Override
	public PcodeUseropLibrary<Pair<byte[], TaintVec>> createSharedUseropLibrary(
			AuxPcodeEmulator<TaintVec> emulator) {
		return new TaintPcodeUseropLibrary();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We have no thread-specific userops to add, which means we also have no need for stubs, so
	 * here we just return the empty library.
	 */
	@Override
	public PcodeUseropLibrary<Pair<byte[], TaintVec>> createLocalUseropStub(
			AuxPcodeEmulator<TaintVec> emulator) {
		return PcodeUseropLibrary.nil();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We have no thread-specific userops to add, so here we just return the empty library.
	 */
	@Override
	public PcodeUseropLibrary<Pair<byte[], TaintVec>> createLocalUseropLibrary(
			AuxPcodeEmulator<TaintVec> emulator, PcodeThread<Pair<byte[], TaintVec>> thread) {
		return PcodeUseropLibrary.nil();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We'd like to instrument conditional branches to check for taint, so we'll need a custom
	 * executor. We construct it here.
	 */
	@Override
	public PcodeThreadExecutor<Pair<byte[], TaintVec>> createExecutor(
			AuxPcodeEmulator<TaintVec> emulator,
			DefaultPcodeThread<Pair<byte[], TaintVec>> thread) {
		return new TaintPcodeThreadExecutor(thread);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * To track what variables in the machine state are tainted, we need a taint state. We construct
	 * the part for the machine's memory here.
	 */
	@Override
	public PcodeExecutorState<Pair<byte[], TaintVec>> createSharedState(
			AuxPcodeEmulator<TaintVec> emulator, BytesPcodeExecutorStatePiece concrete) {
		return new TaintPcodeExecutorState(emulator.getLanguage(), concrete);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * To track what variables in the machine state are tainted, we need a taint state. We construct
	 * the part for a thread's registers and temporary (unique) variables here.
	 */
	@Override
	public PcodeExecutorState<Pair<byte[], TaintVec>> createLocalState(
			AuxPcodeEmulator<TaintVec> emulator, PcodeThread<Pair<byte[], TaintVec>> thread,
			BytesPcodeExecutorStatePiece concrete) {
		return new TaintPcodeExecutorState(emulator.getLanguage(), concrete);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * If you're following the {@link ghidra.taint} package documentation, please finish reading
	 * about the stand-alone emulator before proceeding to this trace-integrated part. This part
	 * extends the shared state of the stand-alone emulator so that it can lazily deserialize taint
	 * sets from a trace database. It can also serialize intermediate and/or final taint sets back
	 * into a trace database.
	 */
	@Override
	public TracePcodeExecutorState<Pair<byte[], TaintVec>> createTraceSharedState(
			AuxTracePcodeEmulator<TaintVec> emulator, BytesTracePcodeExecutorStatePiece concrete) {
		return new TaintTracePcodeExecutorState(concrete);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * If you're following the {@link ghidra.taint} package documentation, please finish reading
	 * about the stand-alone emulator before proceeding to this trace-integrated part. This part
	 * extends the local state of the stand-alone emulator so that it can lazily deserialize taint
	 * sets from a trace database. It can also serialize intermediate and/or final taint sets back
	 * into a trace database.
	 */
	@Override
	public TracePcodeExecutorState<Pair<byte[], TaintVec>> createTraceLocalState(
			AuxTracePcodeEmulator<TaintVec> emulator, PcodeThread<Pair<byte[], TaintVec>> emuThread,
			BytesTracePcodeExecutorStatePiece concrete) {
		return new TaintTracePcodeExecutorState(concrete);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * If you're following the {@link ghidra.taint} package documentation, please finish reading
	 * about the stand-alone and trace-integrated emulators before proceeding to this
	 * Debugger-integrated part. This part uses the same shared state as the trace-integrated
	 * emulator but takes a different data access shim, so that it can also deserialize taint sets
	 * from mapped static programs. Since taint is not generally a concept understood by a live
	 * debugger, we need not retrieve anything new from the target. Note that the shim is passed to
	 * us implicitly via the {@code concrete} state.
	 */
	@Override
	public TracePcodeExecutorState<Pair<byte[], TaintVec>> createDebuggerSharedState(
			AuxDebuggerPcodeEmulator<TaintVec> emulator,
			RWTargetMemoryPcodeExecutorStatePiece concrete) {
		return new TaintTracePcodeExecutorState(concrete);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * If you're following the {@link ghidra.taint} package documentation, please finish reading
	 * about the stand-alone and trace-integrated emulators before proceeding to this method. Since
	 * taint is not generally a concept understood by a live debugger, we need not retrieve anything
	 * new from the target. Furthermore, because static program mappings do not apply to registers,
	 * we need not consider them. Thus, we can just re-use the trace-integrated local state. The
	 * concrete piece given to us, which we just pass to our paired state, will handle retrieving
	 * concrete values from the live target, if applicable.
	 */
	@Override
	public TracePcodeExecutorState<Pair<byte[], TaintVec>> createDebuggerLocalState(
			AuxDebuggerPcodeEmulator<TaintVec> emulator,
			PcodeThread<Pair<byte[], TaintVec>> emuThread,
			RWTargetRegistersPcodeExecutorStatePiece concrete) {
		return new TaintTracePcodeExecutorState(concrete);
	}
}
