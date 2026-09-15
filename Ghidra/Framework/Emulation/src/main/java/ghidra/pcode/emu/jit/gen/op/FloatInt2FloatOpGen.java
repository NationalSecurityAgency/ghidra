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

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Bot;
import ghidra.pcode.emu.jit.gen.util.Methods.RetReq;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.pcode.emu.jit.op.JitFloatInt2FloatOp;

/**
 * The generator for a {@link JitFloatInt2FloatOp float_int2float}.
 * 
 * <p>
 * This uses the unary operator generator and emits {@link Op#i2f(Emitter) i2f},
 * {@link Op#i2d(Emitter) i2d}, {@link Op#l2f(Emitter) l2f}, or {@link Op#l2d(Emitter) l2d}.
 */
public enum FloatInt2FloatOpGen implements FloatConvertUnOpGen<JitFloatInt2FloatOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false; // TODO: Is it signed? Test to figure it out.
	}

	@Override
	public <THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, JitFloatInt2FloatOp op, JitBlock block, Scope scope) {
		JitType uType = gen.resolveType(op.u(), op.uType());
		JitType outType = gen.resolveType(op.out(), op.type());
		return new LiveOpResult(switch (uType) {
			case IntJitType ut -> switch (outType) {
				case FloatJitType ot -> gen(em, localThis, gen, op, ut, ot, Op::i2f, scope);
				case DoubleJitType ot -> gen(em, localThis, gen, op, ut, ot, Op::i2d, scope);
				case MpFloatJitType ot -> TODO("MpFloat");
				default -> throw new AssertionError();
			};
			case LongJitType ut -> switch (outType) {
				case FloatJitType ot -> gen(em, localThis, gen, op, ut, ot, Op::l2f, scope);
				case DoubleJitType ot -> gen(em, localThis, gen, op, ut, ot, Op::l2d, scope);
				case MpFloatJitType ot -> TODO("MpFloat");
				default -> throw new AssertionError();
			};
			case MpIntJitType ut -> TODO("MpInt->Float");
			default -> throw new AssertionError();
		});
	}
}
