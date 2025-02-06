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

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import ghidra.pcode.emu.jit.analysis.*;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.gen.var.VarGen;
import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.*;
import ghidra.pcode.exec.PcodeExecutor;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The bytecode generator for a specific p-code op
 * 
 * <p>
 * The {@link JitCodeGenerator} selects the correct generator for each {@link PcodeOp} using
 * {@link JitDataFlowModel#getJitOp(PcodeOp)} and {@link #lookup(JitOp)}. The following table lists
 * each p-code op, its use-def class, its generator class, and a brief strategy for its bytecode
 * implementation.
 * 
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
 * <td>{@link Opcodes#NEW new}, {@link Opcodes#ATHROW athrow}</td>
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
 * <td>{@link Opcodes#GOTO goto}, {@link Opcodes#ARETURN areturn}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#CBRANCH cbranch}</td>
 * <td>{@link JitCBranchOp}</td>
 * <td>{@link CBranchOpGen}</td>
 * <td>{@link Opcodes#IFEQ ifeq}, {@link Opcodes#IFEQ ifne}, {@link Opcodes#GOTO goto},
 * {@link Opcodes#ARETURN areturn}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#BRANCHIND branchind},<br/>
 * {@link PcodeOp#CALLIND callind},<br/>
 * {@link PcodeOp#RETURN return}</td>
 * <td>{@link JitBranchIndOp}</td>
 * <td>{@link BranchIndOpGen}</td>
 * <td>{@link Opcodes#ARETURN areturn}</td>
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
 * <li><b>Direct</b>: {@link Opcodes#INVOKEVIRTUAL invokevirtual}</li>
 * <li><b>Missing</b>: {@link Opcodes#NEW new}, {@link Opcodes#ATHROW athrow}</li>
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
 * <td>{@link Opcodes#IF_ICMPEQ if_icmpeq}, {@link Opcodes#IFEQ ifeq}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_NOTEQUAL int_notequal}</td>
 * <td>{@link JitIntNotEqualOp}</td>
 * <td>{@link IntNotEqualOpGen}</td>
 * <td>{@link Opcodes#IF_ICMPNE if_icmpne}, {@link Opcodes#IFNE ifne}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SLESS int_sless}</td>
 * <td>{@link JitIntSLessOp}</td>
 * <td>{@link IntSLessOpGen}</td>
 * <td>{@link Opcodes#IF_ICMPLT if_icmplt}, {@link Opcodes#IFLT iflt}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SLESSEQUAL int_slessequal}</td>
 * <td>{@link JitIntSLessEqualOp}</td>
 * <td>{@link IntSLessEqualOpGen}</td>
 * <td>{@link Opcodes#IF_ICMPLE if_icmple}, {@link Opcodes#IFLE ifle}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_LESS int_less}</td>
 * <td>{@link JitIntLessOp}</td>
 * <td>{@link IntLessOpGen}</td>
 * <td>{@link Integer#compareUnsigned(int, int)}, {@link Opcodes#IFLT iflt}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_LESSEQUAL int_lessequal}</td>
 * <td>{@link JitIntLessEqualOp}</td>
 * <td>{@link IntLessEqualOpGen}</td>
 * <td>{@link Integer#compareUnsigned(int, int)}, {@link Opcodes#IFLE ifle}, etc.</td>
 * </tr>
 * <tr>
 * <td colspan="4"><em>Integer Arithmetic</em></td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_ZEXT int_zext}</td>
 * <td>{@link JitIntZExtOp}</td>
 * <td>{@link IntZExtOpGen}</td>
 * <td>none; defers to {@link VarGen} and {@link TypeConversions}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SEXT int_sext}</td>
 * <td>{@link JitIntSExtOp}</td>
 * <td>{@link IntSExtOpGen}</td>
 * <td>{@link Opcodes#ISHL ishl}, {@link Opcodes#ISHR ishr}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_ADD int_add}</td>
 * <td>{@link JitIntAddOp}</td>
 * <td>{@link IntAddOpGen}</td>
 * <td>{@link Opcodes#IADD iadd}, {@link Opcodes#LADD ladd}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SUB int_sub}</td>
 * <td>{@link JitIntSubOp}</td>
 * <td>{@link IntSubOpGen}</td>
 * <td>{@link Opcodes#ISUB isub}, {@link Opcodes#LSUB lsub}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_CARRY int_carry}</td>
 * <td>{@link JitIntCarryOp}</td>
 * <td>{@link IntCarryOpGen}</td>
 * <td>{@link Integer#compareUnsigned(int, int)}, {@link Opcodes#IADD iadd}, {@link Opcodes#ISHR
 * ishr}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SCARRY int_scarry}</td>
 * <td>{@link JitIntSCarryOp}</td>
 * <td>{@link IntSCarryOpGen}</td>
 * <td>{@link JitCompiledPassage#sCarryIntRaw(int, int)}, {@link Opcodes#ISHR ishr}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_SBORROW int_sborrow}</td>
 * <td>{@link JitIntSBorrowOp}</td>
 * <td>{@link IntSBorrowOpGen}</td>
 * <td>{@link JitCompiledPassage#sBorrowIntRaw(int, int)}, {@link Opcodes#ISHR ishr}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_2COMP int_2comp}</td>
 * <td>{@link JitInt2CompOp}</td>
 * <td>{@link Int2CompOpGen}</td>
 * <td>{@link Opcodes#INEG ineg}, {@link Opcodes#LNEG lneg}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_NEGATE int_negate}</td>
 * <td>{@link JitIntNegateOp}</td>
 * <td>{@link IntNegateOpGen}</td>
 * <td>{@link Opcodes#ICONST_M1 iconst_m1}, {@link Opcodes#IXOR ixor}, etc.</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_XOR int_xor}</td>
 * <td>{@link JitIntXorOp}</td>
 * <td>{@link IntXorOpGen}</td>
 * <td>{@link Opcodes#IXOR ixor}, {@link Opcodes#LXOR lxor}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_AND int_and}</td>
 * <td>{@link JitIntAndOp}</td>
 * <td>{@link IntAndOpGen}</td>
 * <td>{@link Opcodes#IAND iand}, {@link Opcodes#LAND land}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#INT_OR int_or}</td>
 * <td>{@link JitIntOrOp}</td>
 * <td>{@link IntOrOpGen}</td>
 * <td>{@link Opcodes#IOR ior}, {@link Opcodes#LOR lor}</td>
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
 * <td>{@link Opcodes#IMUL imul}, {@link Opcodes#LMUL lmul}</td>
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
 * <td>{@link Opcodes#IDIV idiv}, {@link Opcodes#LDIV ldiv}</td>
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
 * <td>{@link Opcodes#IREM irem}, {@link Opcodes#LREM lrem}</td>
 * </tr>
 * <tr>
 * <td colspan="4"><em>Boolean Logic</em></td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#BOOL_NEGATE bool_negate}</td>
 * <td>{@link JitBoolNegateOp}</td>
 * <td>{@link BoolNegateOpGen}</td>
 * <td>Conditional jumps to {@link Opcodes#LDC ldc} 0 or 1</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#BOOL_XOR bool_xor}</td>
 * <td>{@link JitBoolXorOp}</td>
 * <td>{@link BoolXorOpGen}</td>
 * <td>Conditional jumps to {@link Opcodes#LDC ldc} 0 or 1</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#BOOL_AND bool_and}</td>
 * <td>{@link JitBoolAndOp}</td>
 * <td>{@link BoolAndOpGen}</td>
 * <td>Conditional jumps to {@link Opcodes#LDC ldc} 0 or 1</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#BOOL_OR bool_or}</td>
 * <td>{@link JitBoolOrOp}</td>
 * <td>{@link BoolOrOpGen}</td>
 * <td>Conditional jumps to {@link Opcodes#LDC ldc} 0 or 1</td>
 * </tr>
 * <tr>
 * <td colspan="4"><em>Float Comparison</em></td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_EQUAL float_equal}</td>
 * <td>{@link JitFloatEqualOp}</td>
 * <td>{@link FloatEqualOpGen}</td>
 * <td>{@link Opcodes#FCMPL fcmpl}, {@link Opcodes#FCMPL dcmpl}, {@link Opcodes#IFNE ifeq}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_NOTEQUAL float_notequal}</td>
 * <td>{@link JitFloatNotEqualOp}</td>
 * <td>{@link FloatNotEqualOpGen}</td>
 * <td>{@link Opcodes#FCMPL fcmpl}, {@link Opcodes#FCMPL dcmpl}, {@link Opcodes#IFEQ ifne}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_LESS float_less}</td>
 * <td>{@link JitFloatLessOp}</td>
 * <td>{@link FloatLessOpGen}</td>
 * <td>{@link Opcodes#FCMPG fcmpg}, {@link Opcodes#FCMPL dcmpg}, {@link Opcodes#IFGE iflt}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_LESSEQUAL float_lessequal}</td>
 * <td>{@link JitFloatLessEqualOp}</td>
 * <td>{@link FloatLessEqualOpGen}</td>
 * <td>{@link Opcodes#FCMPG fcmpg}, {@link Opcodes#FCMPL dcmpg}, {@link Opcodes#IFGT ifle}</td>
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
 * <td>{@link Opcodes#FADD fadd}, {@link Opcodes#DADD dadd}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_DIV float_div}</td>
 * <td>{@link JitFloatDivOp}</td>
 * <td>{@link FloatDivOpGen}</td>
 * <td>{@link Opcodes#FDIV fdiv}, {@link Opcodes#DDIV ddiv}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_MULT float_mult}</td>
 * <td>{@link JitFloatMultOp}</td>
 * <td>{@link FloatMultOpGen}</td>
 * <td>{@link Opcodes#FMUL fmul}, {@link Opcodes#DMUL dmul}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_SUB float_sub}</td>
 * <td>{@link JitFloatSubOp}</td>
 * <td>{@link FloatSubOpGen}</td>
 * <td>{@link Opcodes#FSUB fsub}, {@link Opcodes#DSUB dsub}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_NEG float_neg}</td>
 * <td>{@link JitFloatNegOp}</td>
 * <td>{@link FloatNegOpGen}</td>
 * <td>{@link Opcodes#FNEG fneg}, {@link Opcodes#DNEG dneg}</td>
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
 * <td>{@link Opcodes#I2F i2f}, {@link Opcodes#I2D i2d}, {@link Opcodes#L2F l2f}, {@link Opcodes#L2D
 * l2d}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_FLOAT2FLOAT float_float2float}</td>
 * <td>{@link JitFloatFloat2FloatOp}</td>
 * <td>{@link FloatFloat2FloatOpGen}</td>
 * <td>{@link Opcodes#F2D f2d}, {@link Opcodes#D2F d2f}</td>
 * </tr>
 * <tr>
 * <td>{@link PcodeOp#FLOAT_TRUNC float_trunc}</td>
 * <td>{@link JitFloatTruncOp}</td>
 * <td>{@link FloatTruncOpGen}</td>
 * <td>{@link Opcodes#F2I f2i}, {@link Opcodes#F2L f2l}, {@link Opcodes#D2I d2i}, {@link Opcodes#D2L
 * d2l}</td>
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
 * <td>{@link Opcodes#IUSHR iushr}, {@link Opcodes#LUSHR lushr}</td>
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
 * 
 * <p>
 * There are other p-code ops. Some are only used in "high" p-code, and so we need not implement
 * them here. Others are used in abstract virtual machines, e.g., {@link PcodeOp#NEW} or are just
 * not yet implemented, e.g., {@link PcodeOp#SEGMENTOP}.
 * 
 * <p>
 * The mapping from {@link PcodeOp} opcode to {@link JitOp} is done in, e.g.,
 * {@link JitOp#binOp(PcodeOp, JitOutVar, JitVal, JitVal)}, and the mapping from {@link JitOp} to
 * {@link OpGen} is done in {@link #lookup(JitOp)}.
 * 
 * <p>
 * The synthetic use-def nodes do not correspond to any p-code op. They are synthesized based on
 * access patterns to the {@link JitDataFlowState}. Their generators do not emit any bytecode. See
 * {@link JitVarScopeModel} regarding coalescing and allocating variables.
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface OpGen<T extends JitOp> extends Opcodes {
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
			case JitBoolAndOp andOp -> BoolAndOpGen.GEN;
			case JitBoolNegateOp negOp -> BoolNegateOpGen.GEN;
			case JitBoolOrOp andOp -> BoolOrOpGen.GEN;
			case JitBoolXorOp andOp -> BoolXorOpGen.GEN;
			case JitBranchIndOp branchIndOp -> BranchIndOpGen.GEN;
			case JitBranchOp branchOp -> BranchOpGen.GEN;
			case JitCallOtherOp callOtherOp -> CallOtherOpGen.GEN;
			case JitCallOtherDefOp callOtherOp -> CallOtherOpGen.GEN;
			case JitCallOtherMissingOp callOtherOp -> CallOtherMissingOpGen.GEN;
			case JitCatenateOp catenateOp -> CatenateOpGen.GEN;
			case JitCBranchOp cBranchOp -> CBranchOpGen.GEN;
			case JitCopyOp copyOp -> CopyOpGen.GEN;
			case JitFloatAbsOp absOp -> FloatAbsOpGen.GEN;
			case JitFloatAddOp addOp -> FloatAddOpGen.GEN;
			case JitFloatCeilOp ceilOp -> FloatCeilOpGen.GEN;
			case JitFloatDivOp divOp -> FloatDivOpGen.GEN;
			case JitFloatEqualOp eqOp -> FloatEqualOpGen.GEN;
			case JitFloatFloat2FloatOp f2fOp -> FloatFloat2FloatOpGen.GEN;
			case JitFloatFloorOp floorOp -> FloatFloorOpGen.GEN;
			case JitFloatInt2FloatOp int2FloatOp -> FloatInt2FloatOpGen.GEN;
			case JitFloatLessEqualOp leqOp -> FloatLessEqualOpGen.GEN;
			case JitFloatLessOp lessOp -> FloatLessOpGen.GEN;
			case JitFloatMultOp multOp -> FloatMultOpGen.GEN;
			case JitFloatNaNOp nanOp -> FloatNaNOpGen.GEN;
			case JitFloatNegOp negOp -> FloatNegOpGen.GEN;
			case JitFloatNotEqualOp neqOp -> FloatNotEqualOpGen.GEN;
			case JitFloatRoundOp roundOp -> FloatRoundOpGen.GEN;
			case JitFloatSqrtOp sqrtOp -> FloatSqrtOpGen.GEN;
			case JitFloatSubOp subOp -> FloatSubOpGen.GEN;
			case JitFloatTruncOp truccOp -> FloatTruncOpGen.GEN;
			case JitInt2CompOp twoCompOp -> Int2CompOpGen.GEN;
			case JitIntAddOp addOp -> IntAddOpGen.GEN;
			case JitIntAndOp andOp -> IntAndOpGen.GEN;
			case JitIntCarryOp carryOp -> IntCarryOpGen.GEN;
			case JitIntDivOp divOp -> IntDivOpGen.GEN;
			case JitIntEqualOp eqOp -> IntEqualOpGen.GEN;
			case JitIntNegateOp negOp -> IntNegateOpGen.GEN;
			case JitIntLeftOp leftOp -> IntLeftOpGen.GEN;
			case JitIntLessEqualOp leqOp -> IntLessEqualOpGen.GEN;
			case JitIntLessOp lessOp -> IntLessOpGen.GEN;
			case JitIntMultOp multOp -> IntMultOpGen.GEN;
			case JitIntNotEqualOp neqOp -> IntNotEqualOpGen.GEN;
			case JitIntOrOp orOp -> IntOrOpGen.GEN;
			case JitIntRemOp remOp -> IntRemOpGen.GEN;
			case JitIntRightOp rightOp -> IntRightOpGen.GEN;
			case JitIntSBorrowOp sborrowOp -> IntSBorrowOpGen.GEN;
			case JitIntSCarryOp scarryOp -> IntSCarryOpGen.GEN;
			case JitIntSExtOp sExtOp -> IntSExtOpGen.GEN;
			case JitIntSLessEqualOp sleqOp -> IntSLessEqualOpGen.GEN;
			case JitIntSLessOp sleqOp -> IntSLessOpGen.GEN;
			case JitIntSDivOp sdivOp -> IntSDivOpGen.GEN;
			case JitIntSRemOp sremOp -> IntSRemOpGen.GEN;
			case JitIntSRightOp srightOp -> IntSRightOpGen.GEN;
			case JitIntSubOp subOp -> IntSubOpGen.GEN;
			case JitIntXorOp xorOp -> IntXorOpGen.GEN;
			case JitIntZExtOp sExtOp -> IntZExtOpGen.GEN;
			case JitLoadOp loadOp -> LoadOpGen.GEN;
			case JitLzCountOp lzCountOp -> LzCountOpGen.GEN;
			case JitPhiOp phiOp -> PhiOpGen.GEN;
			case JitPopCountOp popCountOp -> PopCountOpGen.GEN;
			case JitNopOp nopOp -> NopOpGen.GEN;
			case JitStoreOp storeOp -> StoreOpGen.GEN;
			case JitSubPieceOp spOp -> SubPieceOpGen.GEN;
			case JitSynthSubPieceOp subPieceOp -> SynthSubPieceOpGen.GEN;
			case JitUnimplementedOp unimplOp -> UnimplementedOpGen.GEN;
			default -> throw new AssertionError("Unrecognized op: " + op);
		};
	}

	/**
	 * Emit bytecode into the class constructor.
	 * 
	 * @param gen the code generator
	 * @param op the p-code op (use-def node) to translate
	 * @param iv the visitor for the class constructor
	 */
	default void generateInitCode(JitCodeGenerator gen, T op, MethodVisitor iv) {
	}

	/**
	 * Emit bytecode into the {@link JitCompiledPassage#run(int) run} method.
	 * 
	 * <p>
	 * This method must emit the code needed to load any input operands, convert them to the
	 * appropriate type, perform the actual operation, and then if applicable, store the output
	 * operand. The implementations should delegate to
	 * {@link JitCodeGenerator#generateValReadCode(JitVal, JitTypeBehavior)},
	 * {@link JitCodeGenerator#generateVarWriteCode(JitVar, JitType)}, and {@link TypeConversions}
	 * appropriately.
	 * 
	 * @param gen the code generator
	 * @param op the p-code op (use-def node) to translate
	 * @param block the basic block containing the p-code op
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method.
	 */
	void generateRunCode(JitCodeGenerator gen, T op, JitBlock block, MethodVisitor rv);
}
