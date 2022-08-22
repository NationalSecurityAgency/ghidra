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
package ghidra.pcode.emu.auxiliary;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.*;
import ghidra.pcode.emu.DefaultPcodeThread.PcodeThreadExecutor;
import ghidra.pcode.exec.*;
import ghidra.program.model.lang.Language;

/**
 * An auxiliary emulator parts factory for stand-alone emulation
 *
 * <p>
 * This can manufacture all the parts needed for a stand-alone emulator with concrete and some
 * implementation-defined auxiliary state. More capable emulators may also use many of these parts.
 * Usually, the additional capabilities deal with how state is loaded and stored or otherwise made
 * available to the user. The pattern of use for a stand-alone emulator is usually in a script:
 * Create an emulator, initialize its state, write instructions to its memory, create and initialize
 * a thread, point its counter at the instructions, instrument, step/run, inspect, and finally
 * terminate.
 * 
 * <p>
 * This "parts factory" pattern aims to flatten the extension points of the
 * {@link AbstractPcodeMachine} and its components into a single class. Its use is not required, but
 * may make things easier. It also encapsulates some "special knowledge," that might not otherwise
 * be obvious to a developer, e.g., it creates the concrete state pieces, so the developer need not
 * guess (or keep up to date) the concrete state piece classes to instantiate.
 * 
 * <p>
 * The factory itself should be a singleton object. See the Taint Analyzer for a complete solution
 * using this interface.
 *
 * @param <U> the type of auxiliary values
 */
public interface AuxEmulatorPartsFactory<U> {
	/**
	 * Get the arithmetic for the emulator given a target langauge
	 * 
	 * @param language the language
	 * @return the arithmetic
	 */
	PcodeArithmetic<U> getArithmetic(Language language);

	/**
	 * Create the userop library for the emulator (used by all threads)
	 * 
	 * @param emulator the emulator
	 * @return the userop library
	 */
	PcodeUseropLibrary<Pair<byte[], U>> createSharedUseropLibrary(AuxPcodeEmulator<U> emulator);

	/**
	 * Create a stub userop library for the emulator's threads
	 * 
	 * @param emulator the emulator
	 * @return the library of stubs
	 */
	PcodeUseropLibrary<Pair<byte[], U>> createLocalUseropStub(AuxPcodeEmulator<U> emulator);

	/**
	 * Create a userop library for a given thread
	 * 
	 * @param emulator the emulator
	 * @param thread the thread
	 * @return the userop library
	 */
	PcodeUseropLibrary<Pair<byte[], U>> createLocalUseropLibrary(AuxPcodeEmulator<U> emulator,
			PcodeThread<Pair<byte[], U>> thread);

	/**
	 * Create an executor for the given thread
	 * 
	 * <p>
	 * This allows the implementor to override or intercept the logic for individual p-code
	 * operations that would not otherwise be possible in the arithmetic, e.g., to print diagnostics
	 * on a conditional branch.
	 * 
	 * @param emulator the emulator
	 * @param thread the thread
	 * @return the executor
	 */
	default PcodeThreadExecutor<Pair<byte[], U>> createExecutor(
			AuxPcodeEmulator<U> emulator, DefaultPcodeThread<Pair<byte[], U>> thread) {
		return new PcodeThreadExecutor<>(thread);
	}

	/**
	 * Create a thread with the given name
	 * 
	 * @param emulator the emulator
	 * @param name the thread's name
	 * @return the thread
	 */
	default PcodeThread<Pair<byte[], U>> createThread(AuxPcodeEmulator<U> emulator, String name) {
		return new AuxPcodeThread<>(name, emulator);
	}

	/**
	 * Create the shared (memory) state of a new stand-alone emulator
	 * 
	 * <p>
	 * This is usually composed of pieces using {@link PairedPcodeExecutorStatePiece}, but it does
	 * not have to be. It must incorporate the concrete piece provided. It should be self contained
	 * and relatively fast.
	 * 
	 * @param emulator the emulator
	 * @param concrete the concrete piece
	 * @return the composed state
	 */
	PcodeExecutorState<Pair<byte[], U>> createSharedState(AuxPcodeEmulator<U> emulator,
			BytesPcodeExecutorStatePiece concrete);

	/**
	 * Create the local (register) state of a new stand-alone emulator
	 * 
	 * <p>
	 * This is usually composed of pieces using {@link PairedPcodeExecutorStatePiece}, but it does
	 * not have to be. It must incorporate the concrete piece provided. It should be self contained
	 * and relatively fast.
	 * 
	 * @param emulator the emulator
	 * @param thread the thread
	 * @param concrete the concrete piece
	 * @return the composed state
	 */
	PcodeExecutorState<Pair<byte[], U>> createLocalState(AuxPcodeEmulator<U> emulator,
			PcodeThread<Pair<byte[], U>> thread, BytesPcodeExecutorStatePiece concrete);
}
