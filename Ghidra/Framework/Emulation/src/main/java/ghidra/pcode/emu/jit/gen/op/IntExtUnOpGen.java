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
import ghidra.pcode.emu.jit.op.JitUnOp;

/**
 * An extension for unary integer extension operators
 * <p>
 * The strategy here is to do nothing more than invoke the readers and writers. Because those are
 * responsible for converting between the types, with the appropriate signedness, the work of
 * extension is already done. We need only to know whether or not the operators should be treated as
 * signed or unsigned. Thankfully, that method is already required by a super interface.
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface IntExtUnOpGen<T extends JitUnOp> extends UnOpGen<T> {

	@Override
	default <THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, T op, JitBlock block, Scope scope) {
		JitType uType = gen.resolveType(op.u(), op.uType());
		JitType oType = gen.resolveType(op.out(), op.type());
		JitType minType = JitType.unifyLeast(uType, oType);
		return new LiveOpResult(switch (minType) {
			case IntJitType t -> em
					.emit(gen::genReadToStack, localThis, op.u(), t, ext())
					.emit(gen::genWriteFromStack, localThis, op.out(), t, ext(), scope);
			case LongJitType t -> em
					.emit(gen::genReadToStack, localThis, op.u(), t, ext())
					.emit(gen::genWriteFromStack, localThis, op.out(), t, ext(), scope);
			// Need floats for COPY
			case FloatJitType t -> em
					.emit(gen::genReadToStack, localThis, op.u(), t, ext())
					.emit(gen::genWriteFromStack, localThis, op.out(), t, ext(), scope);
			case DoubleJitType t -> em
					.emit(gen::genReadToStack, localThis, op.u(), t, ext())
					.emit(gen::genWriteFromStack, localThis, op.out(), t, ext(), scope);
			case MpIntJitType t -> {
				var result = em
						.emit(gen::genReadToOpnd, localThis, op.u(), t, ext(), scope);
				yield result.em()
						.emit(gen::genWriteFromOpnd, localThis, op.out(), result.opnd(), ext(),
							scope);
			}
			default -> throw new AssertionError();
		});
	}
}
