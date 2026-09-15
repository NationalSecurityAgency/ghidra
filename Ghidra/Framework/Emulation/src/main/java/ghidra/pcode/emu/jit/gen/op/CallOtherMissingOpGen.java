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
package ghidra.pcode.emu.jit.gen.op;

import static ghidra.pcode.emu.jit.gen.GenConsts.MDESC_SLEIGH_LINK_EXCEPTION__$INIT;
import static ghidra.pcode.emu.jit.gen.GenConsts.T_SLEIGH_LINK_EXCEPTION;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator.PcGen;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Bot;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Methods.RetReq;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.pcode.emu.jit.op.JitCallOtherMissingOp;
import ghidra.pcode.exec.SleighLinkException;

/**
 * The generator for a {@link JitCallOtherMissingOp callother-missing}.
 * 
 * <p>
 * This emits code to retire the program counter, context, and live variables, then throw a
 * {@link SleighLinkException}.
 */
public enum CallOtherMissingOpGen implements OpGen<JitCallOtherMissingOp> {
	/** The generator singleton */
	GEN;

	@Override
	public <THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, JitCallOtherMissingOp op, JitBlock block, Scope scope) {
		String message = gen.getErrorMessage(op.op());
		PcGen pcGen = PcGen.loadOffset(gen.getAddressForOp(op.op()));
		return new DeadOpResult(em
				.emit(gen::genExit, localThis, block, pcGen, gen.getExitContext(op.op()))
				.emit(Op::new_, T_SLEIGH_LINK_EXCEPTION)
				.emit(Op::dup)
				.emit(Op::ldc__a, message)
				.emit(Op::invokespecial, T_SLEIGH_LINK_EXCEPTION, "<init>",
					MDESC_SLEIGH_LINK_EXCEPTION__$INIT, false)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::retVoid)
				.emit(Op::athrow));
	}
}
