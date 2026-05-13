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
import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Bot;
import ghidra.pcode.emu.jit.gen.util.Methods.RetReq;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.pcode.emu.jit.gen.var.ValGen;
import ghidra.pcode.emu.jit.op.JitSubPieceOp;
import ghidra.pcode.emu.jit.var.JitVal;

/**
 * The generator for a {@link JitSubPieceOp subpiece}.
 * <p>
 * This is not quite like a normal binary operator, because the second operand is always a constant.
 * It behaves more like a class of unary operators, if you ask me. Thus, we do not extend
 * {@link BinOpGen}. We first emit code to load the operand. Then, because the shift amount is
 * constant, we can deal with it at <em>generation time</em>. We emit code to shift right by that
 * constant amount, accounting for bits and bytes. The masking, if required, is taken care of by the
 * variable writing code, given the resulting type.
 * <p>
 * To avoid loading parts of the (left) operand that will just get dropped by this operator, we
 * instead provide the subpiecing arguments (namely the offset and destination operand size) to the
 * value-loading logic. This is done via the {@link ValGen#subpiece(int, int)} method. We can then
 * load only those parts that are actually needed.
 */
public enum SubPieceOpGen implements OpGen<JitSubPieceOp> {
	/** The generator singleton */
	GEN;

	@Override
	public <THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, JitSubPieceOp op, JitBlock block, Scope scope) {
		JitType uType = gen.resolveType(op.u(), op.uType());
		JitType outType = gen.resolveType(op.out(), op.type());
		ValGen<JitVal> uGen = ValGen.lookup(op.u()).subpiece(op.offset(), op.out().size());

		int pieceSize = Math.min(uType.size() - op.offset(), outType.size());
		JitType pType = JitTypeBehavior.INTEGER.type(pieceSize);

		return new LiveOpResult(switch (pType) {
			case IntJitType t -> em
					.emit(uGen::genReadToStack, localThis, gen, op.u(), t, Ext.ZERO)
					.emit(gen::genWriteFromStack, localThis, op.out(), t, Ext.ZERO, scope);
			case LongJitType t -> em
					.emit(uGen::genReadToStack, localThis, gen, op.u(), t, Ext.ZERO)
					.emit(gen::genWriteFromStack, localThis, op.out(), t, Ext.ZERO, scope);
			case MpIntJitType t -> {
				var result = em
						.emit(uGen::genReadToOpnd, localThis, gen, op.u(), t, Ext.ZERO, scope);
				yield result.em()
						.emit(gen::genWriteFromOpnd, localThis, op.out(), result.opnd(),
							Ext.ZERO, scope);
			}
			default -> throw new AssertionError();
		});
	}
}
