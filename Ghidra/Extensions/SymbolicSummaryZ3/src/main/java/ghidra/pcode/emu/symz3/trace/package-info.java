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
/**
 * The trace-integrated Symbolic Z3 Emulator
 * 
 * <p>
 * This package builds on {@link ghidra.pcode.emu.plain} to construct a trace-integrated emulator.
 * See that package for remarks about this "working solution." Those state components were factored
 * to accommodate the state components introduced by this package.
 * 
 * <p>
 * For this package, I recommend a bottom-up approach, since you should already be familiar with the
 * parts factory and the structure of the stand-alone state part.
 * {@link ghidra.pcode.emu.symz3.trace.SymZ3TraceSpace} adds the ability to read and write symbolic
 * values sets from a trace. {@link ghidra.pcode.emu.symz3.trace.SymZ3TracePcodeExecutorStatePiece}
 * works that into a state piece derived from
 * {@link ghidra.pcode.emu.symz3.plain.SymZ3PcodeExecutorStatePiece}. Then,
 * {@link ghidra.pcode.emu.symz3.trace.SymZ3TracePcodeExecutorState} composes that with a given
 * concrete state piece. The factory creates that state for use by the
 * {@link ghidra.pcode.emu.symz3.trace.SymZ3TracePcodeEmulator}.
 */
package ghidra.pcode.emu.symz3.trace;
