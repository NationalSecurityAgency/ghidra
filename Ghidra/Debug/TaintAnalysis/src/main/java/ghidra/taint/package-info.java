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
 * The Taint Analysis module
 * 
 * <p>
 * This serves as the archetype for custom emulators and the bells and whistles needed to make them
 * accessible and useful. Because this is already a working solution, we won't provide a "tutorial,"
 * as those often require the presentation of intermediate solutions, working from simple to
 * complex. Instead, we'll direct readers to read files in a certain order, as a "tour" working
 * mostly in bottom-up fashion.
 * 
 * <p>
 * Before even starting with the emulator, we must implement the domain of analysis. For some use
 * cases, the domain may already be implemented by a 3rd-party library, so it's only necessary to
 * add it to your module's dependencies. Our Taint Analyzer implements the domain itself, as its
 * fairly simple, and it allows us to tailor it to our needs. For the implementation of the taint
 * domain, see the {@link ghidra.taint.model} package.
 * 
 * <p>
 * Next, we implement the stand-alone emulator using
 * {@link ghidra.pcode.exec.debug.auxiliary.AuxDebuggerEmulatorPartsFactory}. Technically, that interface
 * requires more than necessary for a stand-alone emulator, but because a fully-integrated emulator
 * is the goal, you can start with it and leave its methods stubbed until you actually need them.
 * The implementation of each method will move our attention to each part necessary to construct the
 * emulator. See the {@link ghidra.pcode.emu.taint.plain} package. The emulator itself
 * {@link ghidra.pcode.emu.taint.plain.TaintPcodeEmulator} is trivially derived from
 * {@link ghidra.pcode.emu.auxiliary.AuxPcodeEmulator} and our factory.
 * 
 * <p>
 * Next, we implement the trace-integrated emulator. For this, we just implement two more methods:
 * {@link ghidra.pcode.exec.debug.auxiliary.AuxDebuggerEmulatorPartsFactory#createTraceSharedState(ghidra.pcode.exec.trace.auxiliary.AuxTracePcodeEmulator, ghidra.pcode.exec.trace.BytesTracePcodeExecutorStatePiece)}
 * and
 * {@link ghidra.pcode.exec.debug.auxiliary.AuxDebuggerEmulatorPartsFactory#createTraceLocalState(ghidra.pcode.exec.trace.auxiliary.AuxTracePcodeEmulator, ghidra.pcode.emu.PcodeThread, ghidra.pcode.exec.trace.BytesTracePcodeExecutorStatePiece)}.
 * Then we derive {@link ghidra.pcode.emu.taint.trace.TaintTracePcodeEmulator} trivially from
 * {@link ghidra.pcode.exec.trace.auxiliary.AuxTracePcodeEmulator} and our factory. See the
 * {@link ghidra.pcode.emu.taint.trace} package.
 * 
 * <p>
 * Next, in like fashion, we implement and derive the Debugger-integrated emulator. See the
 * {@link ghidra.pcode.emu.taint.full} package.
 * 
 * <p>
 * Finally, we add some UI components to make the emulator's machine state visible to the user.
 * These are in the {@link ghidra.taint.gui.field} package.
 * 
 * <p>
 * There is a not-yet-integrated user-op library for tainting file reads. See
 * {@link ghidra.pcode.emu.taint.lib}.
 */
package ghidra.taint;
