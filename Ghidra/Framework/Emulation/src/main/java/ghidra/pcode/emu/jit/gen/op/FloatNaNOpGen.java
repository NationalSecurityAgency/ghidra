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

import static ghidra.lifecycle.Unfinished.TODO;
import static ghidra.pcode.emu.jit.gen.GenConsts.*;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Bot;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Methods.RetReq;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.pcode.emu.jit.op.JitFloatNaNOp;

/**
 * The generator for a {@link JitFloatNaNOp float_nan}.
 * 
 * <p>
 * This uses the unary operator generator and emits an invocation of {@link Float#isNaN(float)} or
 * {@link Double#isNaN(double)}, depending on the type.
 */
public enum FloatNaNOpGen implements UnOpGen<JitFloatNaNOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false;
	}

	@Override
	public <THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, JitFloatNaNOp op, JitBlock block, Scope scope) {
		JitType uType = gen.resolveType(op.u(), op.uType());
		return new LiveOpResult(switch (uType) {
			case FloatJitType t -> em
					.emit(gen::genReadToStack, localThis, op.u(), t, ext())
					.emit(Op::invokestatic, TR_FLOAT, "isNaN", MDESC_FLOAT__IS_NAN, false)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(gen::genWriteFromStack, localThis, op.out(), IntJitType.I4, ext(), scope);
			case DoubleJitType t -> em
					.emit(gen::genReadToStack, localThis, op.u(), t, ext())
					.emit(Op::invokestatic, TR_DOUBLE, "isNaN", MDESC_DOUBLE__IS_NAN, false)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(gen::genWriteFromStack, localThis, op.out(), IntJitType.I4, ext(), scope);
			case MpFloatJitType t -> TODO("MpFloat");
			default -> throw new AssertionError();
		});
	}
}
