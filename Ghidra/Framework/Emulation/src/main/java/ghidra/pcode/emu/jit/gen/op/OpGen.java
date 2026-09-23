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

import java.lang.classfile.CodeBuilder;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.pcode.emu.jit.analysis.*;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Methods.RetReq;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.pcode.emu.jit.gen.var.VarGen;
import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.JitOutVar;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.pcode.exec.PcodeExecutor;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The bytecode generator for a specific p-code op
 * <p>
 * The {@link JitCodeGenerator} selects the correct generator for each {@link PcodeOp} using
 * {@link JitDataFlowModel#getJitOp(PcodeOp)} and {@link #lookup(JitOp)}. The following table lists
 * each p-code op, its use-def class, its generator class, and a brief strategy for its bytecode
 * implementation.
 * <table border="1">
 * <tr>
 * <th>P-code Op</th>
 * <th>Use-Def Type</th>
 * <th>Generator Type</th>
 * <th>Bytecodes / Methods</th>
 * </tr>
 * <tr>
 * <td colspan="4"><em>Misc Data</em></td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#UNIMPLEMENTED unimplemented}</td>
 * <td>{@link JitUnimplementedOp}</td>
 * <td>{@link UnimplementedOpGen}</td>
 * <td>{@link CodeBuilder#new_ new}, {@link CodeBuilder#athrow athrow}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#COPY copy}</td>
 * <td>{@link JitCopyOp}</td>
 * <td>{@link CopyOpGen}</td>
 * <td>none; defers to {@link VarGen}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#LOAD load}</td>
 * <td>{@link JitLoadOp}</td>
 * <td>{@link LoadOpGen}</td>
 * <td>{@link JitCompiledPassage#readIntLE4(byte[], int)}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#STORE store}</td>
 * <td>{@link JitStoreOp}</td>
 * <td>{@link StoreOpGen}</td>
 * <td>{@link JitCompiledPassage#writeIntLE4(int, byte[], int)}, etc.</td>
 * </tr>
 * <tr>
 * <td colspan="4"><em>Control Flow</em></td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#BRANCH branch},<br/>
 * {@link PcodeOp#CALL call}</td>
 * <td>{@link JitBranchOp}</td>
 * <td>{@link BranchOpGen}</td>
 * <td>{@link CodeBuilder#goto_ goto}, {@link CodeBuilder#areturn areturn}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#CBRANCH cbranch}</td>
 * <td>{@link JitCBranchOp}</td>
 * <td>{@link CBranchOpGen}</td>
 * <td>{@link CodeBuilder#ifeq ifeq}, {@link CodeBuilder#ifne ifne}, {@link CodeBuilder#goto_ goto},
 * {@link CodeBuilder#areturn areturn}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#BRANCHIND branchind},<br/>
 * {@link PcodeOp#CALLIND callind},<br/>
 * {@link PcodeOp#RETURN return}</td>
 * <td>{@link JitBranchIndOp}</td>
 * <td>{@link BranchIndOpGen}</td>
 * <td>{@link CodeBuilder#areturn areturn}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#CALLOTHER callother}</td>
 * <td>{@link JitCallOtherOp},<br/>
 * {@link JitCallOtherDefOp},<br/>
 * {@link JitCallOtherMissingOp},<br/>
 * {@link JitNopOp}</td>
 * <td>{@link CallOtherOpGen},<br/>
 * {@link CallOtherMissingOpGen},<br/>
 * {@link NopOpGen}</td>
 * <td>See {@link JitDataFlowUseropLibrary}:
 * <ul>
 * <li><b>Standard</b>:
 * {@link PcodeUseropDefinition#execute(PcodeExecutor, PcodeUseropLibrary, PcodeOp)}</li>
 * <li><b>Inlining</b>: userop's p-code</li>
 * <li><b>Direct</b>: {@link CodeBuilder#invokevirtual invokevirtual}</li>
 * <li><b>Missing</b>: {@link CodeBuilder#new_ new}, {@link CodeBuilder#athrow athrow}</li>
 * </ul>
 * </td>
 * </tr>
 * <tr>
 * <td colspan="4"><em>Integer Comparison</em></td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_EQUAL int_equal}</td>
 * <td>{@link JitIntEqualOp}</td>
 * <td>{@link IntEqualOpGen}</td>
 * <td>{@link CodeBuilder#if_icmpeq if_icmpeq}, {@link CodeBuilder#ifeq ifeq}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_NOTEQUAL int_notequal}</td>
 * <td>{@link JitIntNotEqualOp}</td>
 * <td>{@link IntNotEqualOpGen}</td>
 * <td>{@link CodeBuilder#if_icmpne if_icmpne}, {@link CodeBuilder#ifne ifne}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SLESS int_sless}</td>
 * <td>{@link JitIntSLessOp}</td>
 * <td>{@link IntSLessOpGen}</td>
 * <td>{@link CodeBuilder#if_icmplt if_icmplt}, {@link CodeBuilder#iflt iflt}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SLESSEQUAL int_slessequal}</td>
 * <td>{@link JitIntSLessEqualOp}</td>
 * <td>{@link IntSLessEqualOpGen}</td>
 * <td>{@link CodeBuilder#if_icmple if_icmple}, {@link CodeBuilder#ifle ifle}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_LESS int_less}</td>
 * <td>{@link JitIntLessOp}</td>
 * <td>{@link IntLessOpGen}</td>
 * <td>{@link Integer#compareUnsigned(int, int)}, {@link CodeBuilder#iflt iflt}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_LESSEQUAL int_lessequal}</td>
 * <td>{@link JitIntLessEqualOp}</td>
 * <td>{@link IntLessEqualOpGen}</td>
 * <td>{@link Integer#compareUnsigned(int, int)}, {@link CodeBuilder#ifle ifle}, etc.</td>
 * </tr>
 * <tr>
 * <td colspan="4"><em>Integer Arithmetic</em></td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_ZEXT int_zext}</td>
 * <td>{@link JitIntZExtOp}</td>
 * <td>{@link IntZExtOpGen}</td>
 * <td>none; defers to {@link VarGen} and {@link Opnd}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SEXT int_sext}</td>
 * <td>{@link JitIntSExtOp}</td>
 * <td>{@link IntSExtOpGen}</td>
 * <td>none; defers to {@link VarGen} and {@link Opnd}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_ADD int_add}</td>
 * <td>{@link JitIntAddOp}</td>
 * <td>{@link IntAddOpGen}</td>
 * <td>{@link CodeBuilder#iadd iadd}, {@link CodeBuilder#ladd ladd}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SUB int_sub}</td>
 * <td>{@link JitIntSubOp}</td>
 * <td>{@link IntSubOpGen}</td>
 * <td>{@link CodeBuilder#isub isub}, {@link CodeBuilder#lsub lsub}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_CARRY int_carry}</td>
 * <td>{@link JitIntCarryOp}</td>
 * <td>{@link IntCarryOpGen}</td>
 * <td>{@link Integer#compareUnsigned(int, int)}, {@link CodeBuilder#iadd iadd},
 * {@link CodeBuilder#ishr ishr}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SCARRY int_scarry}</td>
 * <td>{@link JitIntSCarryOp}</td>
 * <td>{@link IntSCarryOpGen}</td>
 * <td>{@link JitCompiledPassage#sCarryIntRaw(int, int)}, {@link CodeBuilder#ishr ishr}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SBORROW int_sborrow}</td>
 * <td>{@link JitIntSBorrowOp}</td>
 * <td>{@link IntSBorrowOpGen}</td>
 * <td>{@link JitCompiledPassage#sBorrowIntRaw(int, int)}, {@link CodeBuilder#ishr ishr}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_2COMP int_2comp}</td>
 * <td>{@link JitInt2CompOp}</td>
 * <td>{@link Int2CompOpGen}</td>
 * <td>{@link CodeBuilder#ineg ineg}, {@link CodeBuilder#lneg lneg}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_NEGATE int_negate}</td>
 * <td>{@link JitIntNegateOp}</td>
 * <td>{@link IntNegateOpGen}</td>
 * <td>{@link CodeBuilder#iconst_m1 iconst_m1}, {@link CodeBuilder#ixor ixor}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_XOR int_xor}</td>
 * <td>{@link JitIntXorOp}</td>
 * <td>{@link IntXorOpGen}</td>
 * <td>{@link CodeBuilder#ixor ixor}, {@link CodeBuilder#lxor lxor}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_AND int_and}</td>
 * <td>{@link JitIntAndOp}</td>
 * <td>{@link IntAndOpGen}</td>
 * <td>{@link CodeBuilder#iand iand}, {@link CodeBuilder#land land}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_OR int_or}</td>
 * <td>{@link JitIntOrOp}</td>
 * <td>{@link IntOrOpGen}</td>
 * <td>{@link CodeBuilder#ior ior}, {@link CodeBuilder#lor lor}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_LEFT int_left}</td>
 * <td>{@link JitIntLeftOp}</td>
 * <td>{@link IntLeftOpGen}</td>
 * <td>{@link JitCompiledPassage#intLeft(int, int)}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_RIGHT int_right}</td>
 * <td>{@link JitIntRightOp}</td>
 * <td>{@link IntRightOpGen}</td>
 * <td>{@link JitCompiledPassage#intRight(int, int)}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SRIGHT int_sright}</td>
 * <td>{@link JitIntSRightOp}</td>
 * <td>{@link IntSRightOpGen}</td>
 * <td>{@link JitCompiledPassage#intSRight(int, int)}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_MULT int_mult}</td>
 * <td>{@link JitIntMultOp}</td>
 * <td>{@link IntMultOpGen}</td>
 * <td>{@link CodeBuilder#imul imul}, {@link CodeBuilder#lmul lmul}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_DIV int_div}</td>
 * <td>{@link JitIntDivOp}</td>
 * <td>{@link IntDivOpGen}</td>
 * <td>{@link Integer#divideUnsigned(int, int)}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SDIV int_sdiv}</td>
 * <td>{@link JitIntSDivOp}</td>
 * <td>{@link IntSDivOpGen}</td>
 * <td>{@link CodeBuilder#idiv idiv}, {@link CodeBuilder#ldiv ldiv}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_REM int_rem}</td>
 * <td>{@link JitIntRemOp}</td>
 * <td>{@link IntRemOpGen}</td>
 * <td>{@link Integer#remainderUnsigned(int, int)}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SREM int_srem}</td>
 * <td>{@link JitIntSRemOp}</td>
 * <td>{@link IntSRemOpGen}</td>
 * <td>{@link CodeBuilder#irem irem}, {@link CodeBuilder#lrem lrem}</td>
 * </tr>
 * <tr>
 * <td colspan="4"><em>Boolean Logic</em></td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#BOOL_NEGATE bool_negate}</td>
 * <td>{@link JitBoolNegateOp}</td>
 * <td>{@link BoolNegateOpGen}</td>
 * <td>Conditional jumps to {@link CodeBuilder#ldc ldc} 0 or 1</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#BOOL_XOR bool_xor}</td>
 * <td>{@link JitBoolXorOp}</td>
 * <td>{@link BoolXorOpGen}</td>
 * <td>Conditional jumps to {@link CodeBuilder#ldc ldc} 0 or 1</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#BOOL_AND bool_and}</td>
 * <td>{@link JitBoolAndOp}</td>
 * <td>{@link BoolAndOpGen}</td>
 * <td>Conditional jumps to {@link CodeBuilder#ldc ldc} 0 or 1</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#BOOL_OR bool_or}</td>
 * <td>{@link JitBoolOrOp}</td>
 * <td>{@link BoolOrOpGen}</td>
 * <td>Conditional jumps to {@link CodeBuilder#ldc ldc} 0 or 1</td>
 * </tr>
 * <tr>
 * <td colspan="4"><em>Float Comparison</em></td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_EQUAL float_equal}</td>
 * <td>{@link JitFloatEqualOp}</td>
 * <td>{@link FloatEqualOpGen}</td>
 * <td>{@link CodeBuilder#fcmpl fcmpl}, {@link CodeBuilder#dcmpl dcmpl}, {@link CodeBuilder#ifne
 * ifeq}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_NOTEQUAL float_notequal}</td>
 * <td>{@link JitFloatNotEqualOp}</td>
 * <td>{@link FloatNotEqualOpGen}</td>
 * <td>{@link CodeBuilder#fcmpl fcmpl}, {@link CodeBuilder#dcmpl dcmpl}, {@link CodeBuilder#ifne
 * ifne}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_LESS float_less}</td>
 * <td>{@link JitFloatLessOp}</td>
 * <td>{@link FloatLessOpGen}</td>
 * <td>{@link CodeBuilder#fcmpg fcmpg}, {@link CodeBuilder#dcmpl dcmpg}, {@link CodeBuilder#iflt
 * iflt}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_LESSEQUAL float_lessequal}</td>
 * <td>{@link JitFloatLessEqualOp}</td>
 * <td>{@link FloatLessEqualOpGen}</td>
 * <td>{@link CodeBuilder#fcmpg fcmpg}, {@link CodeBuilder#dcmpg dcmpg}, {@link CodeBuilder#ifle
 * ifle}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_NAN float_nan}</td>
 * <td>{@link JitFloatNaNOp}</td>
 * <td>{@link FloatNaNOpGen}</td>
 * <td>{@link Float#isNaN(float)}, {@link Double#isNaN(double)}</td>
 * </tr>
 * <tr>
 * <td colspan="4"><em>Float Arithmetic</em></td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_ADD float_add}</td>
 * <td>{@link JitFloatAddOp}</td>
 * <td>{@link FloatAddOpGen}</td>
 * <td>{@link CodeBuilder#fadd fadd}, {@link CodeBuilder#dadd dadd}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_DIV float_div}</td>
 * <td>{@link JitFloatDivOp}</td>
 * <td>{@link FloatDivOpGen}</td>
 * <td>{@link CodeBuilder#fdiv fdiv}, {@link CodeBuilder#ddiv ddiv}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_MULT float_mult}</td>
 * <td>{@link JitFloatMultOp}</td>
 * <td>{@link FloatMultOpGen}</td>
 * <td>{@link CodeBuilder#fmul fmul}, {@link CodeBuilder#dmul dmul}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_SUB float_sub}</td>
 * <td>{@link JitFloatSubOp}</td>
 * <td>{@link FloatSubOpGen}</td>
 * <td>{@link CodeBuilder#fsub fsub}, {@link CodeBuilder#dsub dsub}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_NEG float_neg}</td>
 * <td>{@link JitFloatNegOp}</td>
 * <td>{@link FloatNegOpGen}</td>
 * <td>{@link CodeBuilder#fneg fneg}, {@link CodeBuilder#dneg dneg}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_ABS float_abs}</td>
 * <td>{@link JitFloatAbsOp}</td>
 * <td>{@link FloatAbsOpGen}</td>
 * <td>{@link Math#abs(float)}, {@link Math#abs(double)}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_SQRT float_sqrt}</td>
 * <td>{@link JitFloatSqrtOp}</td>
 * <td>{@link FloatSqrtOpGen}</td>
 * <td>{@link Math#sqrt(double)}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_INT2FLOAT float_int2float}</td>
 * <td>{@link JitFloatInt2FloatOp}</td>
 * <td>{@link FloatInt2FloatOpGen}</td>
 * <td>{@link CodeBuilder#i2f i2f}, {@link CodeBuilder#i2d i2d}, {@link CodeBuilder#l2f l2f},
 * {@link CodeBuilder#l2d l2d}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_FLOAT2FLOAT float_float2float}</td>
 * <td>{@link JitFloatFloat2FloatOp}</td>
 * <td>{@link FloatFloat2FloatOpGen}</td>
 * <td>{@link CodeBuilder#f2d f2d}, {@link CodeBuilder#d2f d2f}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_TRUNC float_trunc}</td>
 * <td>{@link JitFloatTruncOp}</td>
 * <td>{@link FloatTruncOpGen}</td>
 * <td>{@link CodeBuilder#f2i f2i}, {@link CodeBuilder#f2l f2l}, {@link CodeBuilder#d2i d2i},
 * {@link CodeBuilder#d2l d2l}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_CEIL float_ceil}</td>
 * <td>{@link JitFloatCeilOp}</td>
 * <td>{@link FloatCeilOpGen}</td>
 * <td>{@link Math#ceil(double)}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_FLOOR float_floor}</td>
 * <td>{@link JitFloatFloorOp}</td>
 * <td>{@link FloatFloorOpGen}</td>
 * <td>{@link Math#floor(double)}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_ROUND float_round}</td>
 * <td>{@link JitFloatRoundOp}</td>
 * <td>{@link FloatRoundOpGen}</td>
 * <td>+0.5 then {@link Math#floor(double)}</td>
 * </tr>
 * <tr>
 * <td colspan="4"><em>Miscellaneous</em></td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#SUBPIECE subpiece}</td>
 * <td>{@link JitSubPieceOp}</td>
 * <td>{@link SubPieceOpGen}</td>
 * <td>{@link CodeBuilder#iushr iushr}, {@link CodeBuilder#lushr lushr}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#POPCOUNT popcount}</td>
 * <td>{@link JitPopCountOp}</td>
 * <td>{@link PopCountOpGen}</td>
 * <td>{@link Integer#bitCount(int)}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#LZCOUNT lzcount}</td>
 * <td>{@link JitLzCountOp}</td>
 * <td>{@link LzCountOpGen}</td>
 * <td>{@link Integer#numberOfLeadingZeros(int)}, etc.</td>
 * </tr>
 * <tr>
 * <td colspan="4"><em>Synthetic</em></td>
 * </tr>
 * <tr>
 * <td>(none)</td>
 * <td>{@link JitCatenateOp}</td>
 * <td>{@link CatenateOpGen}</td>
 * </tr>
 * <tr>
 * <td>(none)</td>
 * <td>{@link JitSynthSubPieceOp}</td>
 * <td>{@link SynthSubPieceOpGen}</td>
 * </tr>
 * <tr>
 * <td>(none)</td>
 * <td>{@link JitPhiOp}</td>
 * <td>{@link PhiOpGen}</td>
 * </tr>
 * </table>
 * <p>
 * There are other p-code ops. Some are only used in "high" p-code, and so we need not implement
 * them here. Others are used in abstract virtual machines, e.g., {@link PcodeOp#NEW} or are just
 * not yet implemented, e.g., {@link PcodeOp#SEGMENTOP}.
 * <p>
 * The mapping from {@link PcodeOp} opcode to {@link JitOp} is done in, e.g.,
 * {@link JitOp#binOp(PcodeOp, JitOutVar, JitVal, JitVal)}, and the mapping from {@link JitOp} to
 * {@link OpGen} is done in {@link #lookup(JitOp)}.
 * <p>
 * The synthetic use-def nodes do not correspond to any p-code op. They are synthesized based on
 * access patterns to the {@link JitDataFlowState}. Their generators do not emit any bytecode. See
 * {@link JitVarScopeModel} regarding coalescing and allocating variables.
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface OpGen<T extends JitOp> {
	/**
	 * Lookup the generator for a given p-code op use-def node
	 * 
	 * @param <T> the class of the op
	 * @param op the {@link JitOp} whose generator to look up
	 * @return the generator
	 */
	@SuppressWarnings("unchecked")
	static <T extends JitOp> OpGen<T> lookup(T op) {
		return (OpGen<T>) switch (op) {
			case JitBoolAndOp _ -> BoolAndOpGen.GEN;
			case JitBoolNegateOp _ -> BoolNegateOpGen.GEN;
			case JitBoolOrOp _ -> BoolOrOpGen.GEN;
			case JitBoolXorOp _ -> BoolXorOpGen.GEN;
			case JitBranchIndOp _ -> BranchIndOpGen.GEN;
			case JitBranchOp _ -> BranchOpGen.GEN;
			case JitCallOtherOp _ -> CallOtherOpGen.GEN;
			case JitCallOtherDefOp _ -> CallOtherOpGen.GEN;
			case JitCallOtherMissingOp _ -> CallOtherMissingOpGen.GEN;
			case JitCatenateOp _ -> CatenateOpGen.GEN;
			case JitCBranchOp _ -> CBranchOpGen.GEN;
			case JitCopyOp _ -> CopyOpGen.GEN;
			case JitFloatAbsOp _ -> FloatAbsOpGen.GEN;
			case JitFloatAddOp _ -> FloatAddOpGen.GEN;
			case JitFloatCeilOp _ -> FloatCeilOpGen.GEN;
			case JitFloatDivOp _ -> FloatDivOpGen.GEN;
			case JitFloatEqualOp _ -> FloatEqualOpGen.GEN;
			case JitFloatFloat2FloatOp _ -> FloatFloat2FloatOpGen.GEN;
			case JitFloatFloorOp _ -> FloatFloorOpGen.GEN;
			case JitFloatInt2FloatOp _ -> FloatInt2FloatOpGen.GEN;
			case JitFloatLessEqualOp _ -> FloatLessEqualOpGen.GEN;
			case JitFloatLessOp _ -> FloatLessOpGen.GEN;
			case JitFloatMultOp _ -> FloatMultOpGen.GEN;
			case JitFloatNaNOp _ -> FloatNaNOpGen.GEN;
			case JitFloatNegOp _ -> FloatNegOpGen.GEN;
			case JitFloatNotEqualOp _ -> FloatNotEqualOpGen.GEN;
			case JitFloatRoundOp _ -> FloatRoundOpGen.GEN;
			case JitFloatSqrtOp _ -> FloatSqrtOpGen.GEN;
			case JitFloatSubOp _ -> FloatSubOpGen.GEN;
			case JitFloatTruncOp _ -> FloatTruncOpGen.GEN;
			case JitInt2CompOp _ -> Int2CompOpGen.GEN;
			case JitIntAddOp _ -> IntAddOpGen.GEN;
			case JitIntAndOp _ -> IntAndOpGen.GEN;
			case JitIntCarryOp _ -> IntCarryOpGen.GEN;
			case JitIntDivOp _ -> IntDivOpGen.GEN;
			case JitIntEqualOp _ -> IntEqualOpGen.GEN;
			case JitIntNegateOp _ -> IntNegateOpGen.GEN;
			case JitIntLeftOp _ -> IntLeftOpGen.GEN;
			case JitIntLessEqualOp _ -> IntLessEqualOpGen.GEN;
			case JitIntLessOp _ -> IntLessOpGen.GEN;
			case JitIntMultOp _ -> IntMultOpGen.GEN;
			case JitIntNotEqualOp _ -> IntNotEqualOpGen.GEN;
			case JitIntOrOp _ -> IntOrOpGen.GEN;
			case JitIntRemOp _ -> IntRemOpGen.GEN;
			case JitIntRightOp _ -> IntRightOpGen.GEN;
			case JitIntSBorrowOp _ -> IntSBorrowOpGen.GEN;
			case JitIntSCarryOp _ -> IntSCarryOpGen.GEN;
			case JitIntSExtOp _ -> IntSExtOpGen.GEN;
			case JitIntSLessEqualOp _ -> IntSLessEqualOpGen.GEN;
			case JitIntSLessOp _ -> IntSLessOpGen.GEN;
			case JitIntSDivOp _ -> IntSDivOpGen.GEN;
			case JitIntSRemOp _ -> IntSRemOpGen.GEN;
			case JitIntSRightOp _ -> IntSRightOpGen.GEN;
			case JitIntSubOp _ -> IntSubOpGen.GEN;
			case JitIntXorOp _ -> IntXorOpGen.GEN;
			case JitIntZExtOp _ -> IntZExtOpGen.GEN;
			case JitLoadOp _ -> LoadOpGen.GEN;
			case JitLzCountOp _ -> LzCountOpGen.GEN;
			case JitPhiOp _ -> PhiOpGen.GEN;
			case JitPopCountOp _ -> PopCountOpGen.GEN;
			case JitNopOp _ -> NopOpGen.GEN;
			case JitStoreOp _ -> StoreOpGen.GEN;
			case JitSubPieceOp _ -> SubPieceOpGen.GEN;
			case JitSynthSubPieceOp _ -> SynthSubPieceOpGen.GEN;
			case JitUnimplementedOp _ -> UnimplementedOpGen.GEN;
			default -> throw new AssertionError("Unrecognized op: " + op);
		};
	}

	/**
	 * For debugging: emit code to print the values of the given operand to stderr.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param opnd the operand whose values to print
	 * @return the emitter typed with the incoming stack
	 */
	static <N extends Next> Emitter<N> generateSyserrInts(Emitter<N> em, Opnd<MpIntJitType> opnd) {
		List<SimpleOpnd<TInt, IntJitType>> legs = opnd.type().castLegsLE(opnd);
		String fmt = legs.stream().map(_ -> "%08x").collect(Collectors.joining(":"));
		var emArr = em
				.emit(Op::getstatic, T_SYSTEM, "err", T_PRINT_STREAM)
				.emit(Op::ldc__a, fmt)
				.emit(Op::ldc__i, legs.size())
				.emit(Op::anewarray, T_OBJECT);
		for (int i = 0; i < legs.size(); i++) {
			SimpleOpnd<TInt, IntJitType> leg = legs.get(i);
			emArr = emArr
					.emit(Op::dup)
					.emit(Op::ldc__i, i)
					.emit(leg::read)
					.emit(Op::invokestatic, TR_INTEGER, "valueOf", MDESC_INTEGER__VALUE_OF,
						false)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(Op::aastore);
		}
		return emArr
				.emit(Op::invokevirtual, T_STRING, "formatted", MDESC_STRING__FORMATTED, false)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::ret)
				.emit(Op::invokevirtual, T_PRINT_STREAM, "println", MDESC_PRINT_STREAM__PRINTLN,
					false)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::retVoid);
	}

	/**
	 * The result of emitting code for a p-code op
	 */
	sealed interface OpResult {
		/**
		 * {@return the emitter with unknown stack}
		 * <p>
		 * Switch on the actual type to ascertain the stack's actual contents.
		 */
		Emitter<?> em();
	}

	/**
	 * The result when bytecode after that emitted is reachable
	 * 
	 * @param em the emitter typed with the empty stack
	 */
	record LiveOpResult(Emitter<Bot> em) implements OpResult {}

	/**
	 * The result when bytecode after that emitted is not reachable
	 * 
	 * @param em the dead emitter
	 */
	record DeadOpResult(Emitter<Dead> em) implements OpResult {}

	/**
	 * Emit bytecode into the {@link JitCompiledPassage#run run} method.
	 * <p>
	 * This method must emit the code needed to load any input operands, convert them to the
	 * appropriate type, perform the actual operation, and then if applicable, store the output
	 * operand. The implementations should delegate to {@link JitCodeGenerator#genReadToStack},
	 * {@link JitCodeGenerator#genWriteFromStack} or similar for mp-int types.
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param em the emitter typed with the empty stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param localCtxmod a handle to the local holding {@code ctxmod}
	 * @param retReq an indication of what must be returned by this {@link JitCompiledPassage#run}
	 *            method.
	 * @param gen the code generator
	 * @param op the p-code op (use-def node) to translate
	 * @param block the basic block containing the p-code op
	 * @param scope a scope for generating temporary local storage
	 * @return the result of emitting the p-code op's bytecode
	 */
	<THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, T op, JitBlock block, Scope scope);
}
