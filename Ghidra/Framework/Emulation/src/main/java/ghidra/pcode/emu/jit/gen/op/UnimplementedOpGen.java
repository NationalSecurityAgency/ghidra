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

import static ghidra.pcode.emu.jit.gen.GenConsts.*;

import ghidra.pcode.emu.jit.JitPassage.DecodeErrorPcodeOp;
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
import ghidra.pcode.emu.jit.op.JitUnimplementedOp;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.exec.DecodePcodeExecutionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;

/**
 * The generator for a {@link JitUnimplementedOp unimplemented}.
 * 
 * <p>
 * This emits code to retire the program counter, context, and live variables, then throw a
 * {@link DecodePcodeExecutionException} or {@link LowlevelError}. The former case is constructed by
 * {@link JitCompiledPassage#createDecodeError(String, long)}.
 */
public enum UnimplementedOpGen implements OpGen<JitUnimplementedOp> {
	/** The generator singleton */
	GEN;

	@Override
	public <THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, JitUnimplementedOp op, JitBlock block, Scope scope) {
		Address counter = gen.getAddressForOp(op.op());
		PcGen pcGen = PcGen.loadOffset(counter);
		RegisterValue ctx = gen.getExitContext(op.op());
		String message = gen.getErrorMessage(op.op());

		if (op.op() instanceof DecodeErrorPcodeOp) {
			return new DeadOpResult(em
					.emit(gen::genExit, localThis, block, pcGen, ctx)
					.emit(Op::aload, localThis)
					.emit(Op::ldc__a, message)
					.emit(Op::ldc__l, counter.getOffset())
					.emit(Op::invokeinterface, T_JIT_COMPILED_PASSAGE, "createDecodeError",
						MDESC_JIT_COMPILED_PASSAGE__CREATE_DECODE_ERROR)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::takeObjRef)
					.step(Inv::ret)
					.emit(Op::athrow));
		}
		return new DeadOpResult(em
				.emit(gen::genExit, localThis, block, pcGen, ctx)
				.emit(Op::new_, T_LOWLEVEL_ERROR)
				.emit(Op::dup)
				.emit(Op::ldc__a, message)
				.emit(Op::invokespecial, T_LOWLEVEL_ERROR, "<init>", MDESC_LOWLEVEL_ERROR__$INIT,
					false)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::retVoid)
				.emit(Op::athrow));
	}
}
