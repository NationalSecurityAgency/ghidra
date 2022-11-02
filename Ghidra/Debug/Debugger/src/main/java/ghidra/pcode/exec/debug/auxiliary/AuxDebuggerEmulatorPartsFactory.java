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
package ghidra.pcode.exec.debug.auxiliary;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.app.plugin.core.debug.service.emulation.*;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.auxiliary.AuxEmulatorPartsFactory;
import ghidra.pcode.emu.auxiliary.AuxPcodeEmulator;
import ghidra.pcode.exec.trace.*;
import ghidra.pcode.exec.trace.auxiliary.AuxTraceEmulatorPartsFactory;
import ghidra.pcode.exec.trace.auxiliary.AuxTracePcodeEmulator;

/**
 * The most capable auxiliary emulator parts factory
 * 
 * <p>
 * This can manufacture parts for an emulator that is fully integrated with the Debugger UI, as well
 * as all the parts for the less integrated forms of the same emulator. The pattern of use is
 * generally to implement {@link DebuggerPcodeEmulatorFactory}, allowing the UI to discover and
 * instantiate the emulator, though they could also be created directly by scripts or plugins.
 *
 * <p>
 * For an example of a fully-integrated solution using this interface, see the Taint Analyzer. Its
 * project serves as an archetype for similar dynamic analysis employing p-code emulation.
 *
 * <p>
 * We recommend implementors start with the methods declared in {@link AuxEmulatorPartsFactory} with
 * the aim of creating a derivative of {@link AuxPcodeEmulator}. Note that one Debugger-integrated
 * emulator parts factory can be used with all three of {@link AuxPcodeEmulator},
 * {@link AuxTracePcodeEmulator}, {@link AuxTraceEmulatorPartsFactory}. Once the stand-alone
 * emulator has been tested, proceed to the methods in {@link AuxTraceEmulatorPartsFactory} with the
 * aim of creating a derivative of {@link AuxTracePcodeEmulator}. Most of the work here is in
 * factoring the state objects and pieces to reduce code duplication among the stand-alone and
 * trace-integrated states. Once the trace-integrated emulator is tested, then proceed to the
 * methods declared here in {@link AuxDebuggerEmulatorPartsFactory} with the aim of creating a
 * derivative of {@link AuxDebuggerPcodeEmulator}. Again, most of the work is in factoring the
 * states to avoid code duplication. Once the Debugger-integrated emulator is tested, the final bit
 * is to implement a {@link DebuggerPcodeEmulatorFactory} so that users can configure and create the
 * emulator. Other UI pieces, e.g., actions, fields, and table columns, may be needed to facilitate
 * user access to the emulator's auxiliary state. Furthermore, a userop library for accessing the
 * auxiliary state is recommended, since Sleigh code can be executed by the user.
 *
 * @param <U> the type of auxiliary values
 */
public interface AuxDebuggerEmulatorPartsFactory<U> extends AuxTraceEmulatorPartsFactory<U> {
	/**
	 * Create the shared (memory) state of a new Debugger-integrated emulator
	 * 
	 * <p>
	 * This state is usually composed of pieces using {@link PairedTracePcodeExecutorStatePiece},
	 * but it does not have to be. It must incorporate the concrete piece provided. The state must
	 * be capable of lazily loading state from a trace, from a live target, and from mapped static
	 * programs. It must also be able to write its cache into the trace at another snapshot. The
	 * given concrete piece is already capable of doing that for concrete values. The auxiliary
	 * piece can, at its discretion, delegate to the concrete piece in order to derive its values.
	 * It should be able to independently load its state from the trace and mapped static program,
	 * since this is one way a user expects to initialize the auxiliary values. It ought to use the
	 * same data-access shim as the given concrete state. See
	 * {@link TracePcodeExecutorStatePiece#getData()}.
	 * 
	 * @param emulator the emulator
	 * @param concrete the concrete piece
	 * @return the composed state
	 */
	TracePcodeExecutorState<Pair<byte[], U>> createDebuggerSharedState(
			AuxDebuggerPcodeEmulator<U> emulator,
			RWTargetMemoryPcodeExecutorStatePiece concrete);

	/**
	 * Create the local (register) state of a new Debugger-integrated thread
	 * 
	 * <p>
	 * Like
	 * {@link #createDebuggerSharedState(AuxDebuggerPcodeEmulator, RWTargetMemoryPcodeExecutorStatePiece)}
	 * this state must also be capable of lazily loading state from a trace and from a live target.
	 * Static programs can't be mapped into register space, so they do not apply here.
	 * 
	 * @param emulator the emulator
	 * @param thread the new thread
	 * @param concrete the concrete piece
	 * @return the composed state
	 */
	TracePcodeExecutorState<Pair<byte[], U>> createDebuggerLocalState(
			AuxDebuggerPcodeEmulator<U> emulator, PcodeThread<Pair<byte[], U>> thread,
			RWTargetRegistersPcodeExecutorStatePiece concrete);
}
