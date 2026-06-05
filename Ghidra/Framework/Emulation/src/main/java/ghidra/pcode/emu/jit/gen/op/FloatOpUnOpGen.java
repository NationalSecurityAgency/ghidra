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

import ghidra.lifecycle.Unfinished;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.RetReq;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitFloatUnOp;

/**
 * An extension for floating-point unary operators
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface FloatOpUnOpGen<T extends JitFloatUnOp> extends UnOpGen<T> {
	@Override
	default boolean isSigned() {
		return false;
	}

	/**
	 * Emit the JVM bytecode to perform the operator with float operands on the stack.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with the input operand on top
	 * @param em the emitter typed with the incoming stack
	 * @return the emitter typed with the resulting stack, i.e., the tail with the result pushed
	 */
	<N1 extends Next, N0 extends Ent<N1, TFloat>> Emitter<Ent<N1, TFloat>>
			opForFloat(Emitter<N0> em);

	/**
	 * Emit the JVM bytecode to perform the operator with double operands on the stack.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with the input operand on top
	 * @param em the emitter typed with the incoming stack
	 * @return the emitter typed with the resulting stack, i.e., the tail with the result pushed
	 */
	<N1 extends Next, N0 extends Ent<N1, TDouble>> Emitter<Ent<N1, TDouble>>
			opForDouble(Emitter<N0> em);

	@Override
	default <THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, T op, JitBlock block, Scope scope) {
		JitType uType = gen.resolveType(op.u(), op.uType());
		return new LiveOpResult(switch (uType) {
			case FloatJitType t -> em
					.emit(gen::genReadToStack, localThis, op.u(), t, ext())
					.emit(this::opForFloat)
					.emit(gen::genWriteFromStack, localThis, op.out(), t, Ext.ZERO, scope);
			case DoubleJitType t -> em
					.emit(gen::genReadToStack, localThis, op.u(), t, ext())
					.emit(this::opForDouble)
					.emit(gen::genWriteFromStack, localThis, op.out(), t, Ext.ZERO, scope);
			case MpFloatJitType t -> Unfinished.TODO("MpFloat");
			default -> throw new AssertionError();
		});
	}
}
