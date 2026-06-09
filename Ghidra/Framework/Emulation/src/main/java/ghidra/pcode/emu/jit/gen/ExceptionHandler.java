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
package ghidra.pcode.emu.jit.gen;

import ghidra.pcode.emu.jit.JitPassage.DecodedPcodeOp;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator.PcGen;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A requested exception handler
 * 
 * <p>
 * When an exception occurs, we must retire all of the variables before we pop the
 * {@link JitCompiledPassage#run(int) run} method's frame. We also write out the program counter and
 * disassembly context so that the emulator can resume appropriately. After that, we re-throw the
 * exception.
 * 
 * <p>
 * When the code generator knows the code it's emitting can cause a user exception, e.g., the Direct
 * invocation of a userop, and there are live variables in scope, then it should request a handler
 * (via {@link JitCodeGenerator#requestExceptionHandler(DecodedPcodeOp, JitBlock)}) and surround the
 * code in a {@code try-catch} on {@link Throwable} directing it to this handler.
 * 
 * @param op the op which may cause an exception
 * @param block the block containing the op
 * @param lbl the label at the start of the handler
 */
public record ExceptionHandler(PcodeOp op, JitBlock block, Lbl<Ent<Bot, TRef<Throwable>>> lbl) {
	/**
	 * Construct a handler, generating a new label
	 * 
	 * @param op the op which may cause an exception
	 * @param block the block containing the op
	 */
	public ExceptionHandler(PcodeOp op, JitBlock block) {
		this(op, block, Lbl.create());
	}

	/**
	 * Emit the handler's code into the {@link JitCompiledPassage#run(int) run} method.
	 * 
	 * @param <THIS> the type of the compiled passage
	 * @param em the dead emitter
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @return the dead emitter
	 */
	public <THIS extends JitCompiledPassage> Emitter<Dead> genRun(Emitter<Dead> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen) {
		var emLive = em.emit(Lbl::placeDead, lbl);
		if (gen.context.getConfiguration().logStackTraces()) {
			emLive = emLive
					.emit(Op::dup)
					.emit(Op::invokevirtual, GenConsts.T_THROWABLE, "printStackTrace",
						GenConsts.MDESC_THROWABLE__PRINT_STACK_TRACE, false)
					.step(Inv::takeObjRef)
					.step(Inv::retVoid);
		}
		return emLive
				.emit(gen::genExit, localThis, block, PcGen.loadOffset(gen.getAddressForOp(op)),
					gen.getExitContext(op))
				.emit(Op::athrow);
	}
}
