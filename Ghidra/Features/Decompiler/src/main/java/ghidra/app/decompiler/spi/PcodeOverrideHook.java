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
package ghidra.app.decompiler.spi;

import java.io.IOException;

import ghidra.app.decompiler.DecompileCallback;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PatchEncoder;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.NoValueException;

/**
 * SPI for processor modules to supply per-instruction synthetic pcode
 * to the decompiler.  Implementations are discovered by
 * {@link ClassSearcher} and consulted by {@link DecompileCallback}
 * before falling through to the sleigh-derived prototype pcode.
 *
 * <p>For each instruction the decompiler asks every hook whose
 * {@link #canHandle(Program)} returns true, in discovery order, until
 * one returns true from {@link #emit}.  That hook's pcode is used; the
 * rest of the chain is skipped.  If no hook claims the instruction,
 * the prototype pcode is emitted.
 *
 * <p>The intended use is for architectures whose ISA encodes
 * decompile-time semantics that don't map cleanly onto sleigh (e.g.
 * NDS32 IFC, where one instruction can legally be reached from
 * multiple callers' flows).  A hook can read per-function user
 * {@code PropertyMap}s (typically published by an analyzer in the
 * same module) and emit replacement pcode shaped to the specific
 * flow being decompiled.
 *
 * <h2>Implementation guidance</h2>
 *
 * <p>Hooks are constructed once per JVM at discovery and reused
 * across decompile calls.  They must be thread-safe; in practice
 * holding only immutable configuration is the simplest approach.
 *
 * <p>{@link #canHandle(Program)} should be cheap (a processor name
 * comparison plus a register-presence check is typical) and is
 * invoked once per cached function.
 *
 * <p>To emit pcode use
 * {@link DecompileCallback#encodeInstruction(ghidra.program.model.pcode.Encoder, Address, ghidra.program.model.pcode.PcodeOp[], int, int, ghidra.program.model.address.AddressFactory)
 * DecompileCallback.encodeInstruction}.
 *
 * <p>Class names must end in {@code "PcodeOverrideHook"} so the
 * {@link ClassSearcher} indexes them.
 */
public interface PcodeOverrideHook extends ExtensionPoint {

	/**
	 * Whether this hook can process {@code program}.  Called once per
	 * cached function; if it returns false, {@link #emit} will not be
	 * called for any instruction in that function.
	 */
	boolean canHandle(Program program);

	/**
	 * Attempt to emit synthetic pcode for {@code instr} at {@code addr}.
	 *
	 * @param program          program being decompiled
	 * @param cachedFunction   function whose decompile triggered this call;
	 *                         {@code instr} may lie in this function's
	 *                         extended body rather than its primary body
	 * @param addr             address of the instruction
	 * @param instr            the instruction at {@code addr}
	 * @param resultEncoder    encoder to write pcode into via
	 *                         {@code DecompileCallback.encodeInstruction}
	 * @return true if pcode was emitted (decompiler skips the prototype);
	 *         false to defer to the next hook or the prototype pcode
	 * @throws IOException if writing to {@code resultEncoder} fails
	 * @throws NoValueException if a user PropertyMap entry the hook
	 *                          consulted disappeared between
	 *                          {@code hasProperty} and the read
	 */
	boolean emit(Program program, Function cachedFunction, Address addr,
			Instruction instr, PatchEncoder resultEncoder)
			throws IOException, NoValueException;
}
