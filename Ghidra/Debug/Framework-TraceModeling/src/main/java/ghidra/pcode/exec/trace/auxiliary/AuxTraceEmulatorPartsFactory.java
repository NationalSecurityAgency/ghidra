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
package ghidra.pcode.exec.trace.auxiliary;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.auxiliary.AuxEmulatorPartsFactory;
import ghidra.pcode.exec.trace.*;

/**
 * An auxiliary emulator parts factory capable of integrating with a trace
 *
 * <p>
 * This can manufacture parts for an emulator that reads and writes its state (concrete and
 * auxiliary pieces) from and to a trace, as well as all the parts for the less integrated forms of
 * the same emulator. The pattern of use is generally to read from a given "source" snap, execute
 * some stepping schedule, then write the cache to a given "destination" snap.
 *
 * @param <U> the type of auxiliary values
 */
public interface AuxTraceEmulatorPartsFactory<U> extends AuxEmulatorPartsFactory<U> {
	/**
	 * Create the shared (memory) state of a new trace-integrated emulator
	 * 
	 * <p>
	 * This is usually composed of pieces using {@link PairedTracePcodeExecutorStatePiece}, but it
	 * does not have to be. It must incorporate the concrete piece provided. The state must be
	 * capable of lazily loading state from a trace and later writing its cache back into the trace
	 * at another snapshot. The given concrete piece is already capable of doing that for concrete
	 * values. The auxiliary piece should be able to independently load its state from the trace,
	 * since this is one way a user expects to initialize the auxiliary values.
	 * 
	 * @param emulator the emulator
	 * @param concrete the concrete piece
	 * @return the composed state
	 */
	TracePcodeExecutorState<Pair<byte[], U>> createTraceSharedState(
			AuxTracePcodeEmulator<U> emulator, BytesTracePcodeExecutorStatePiece concrete);

	/**
	 * Create the local (register) state of a new trace-integrated thread
	 * 
	 * <p>
	 * This must have the same capabilities as
	 * {@link #createTraceSharedState(AuxTracePcodeEmulator, BytesTracePcodeExecutorStatePiece)}.
	 * 
	 * @param emulator the emulator
	 * @param thread the new thread
	 * @param concrete the concrete piece
	 * @return the composed state
	 */
	TracePcodeExecutorState<Pair<byte[], U>> createTraceLocalState(
			AuxTracePcodeEmulator<U> emulator, PcodeThread<Pair<byte[], U>> thread,
			BytesTracePcodeExecutorStatePiece concrete);
}
