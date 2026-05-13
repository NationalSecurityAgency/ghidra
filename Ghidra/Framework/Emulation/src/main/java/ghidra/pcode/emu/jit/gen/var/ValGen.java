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
package ghidra.pcode.emu.jit.gen.var;

import ghidra.pcode.emu.jit.JitConfiguration;
import ghidra.pcode.emu.jit.analysis.JitDataFlowModel;
import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * The bytecode generator for a specific value (operand) access.
 * 
 * <p>
 * The {@link JitCodeGenerator} selects the correct generator for each input operand using
 * {@link #lookup(JitVal)} and each output operand {@link VarGen#lookup(JitVar)}. The op generator
 * has already retrieved the {@link JitOp} whose operands are of the {@link JitVal} class.
 * 
 * <table border="1">
 * <tr>
 * <th>Varnode Type</th>
 * <th>Use-Def Type</th>
 * <th>Generator Type</th>
 * <th>Read Bytecodes / Methods</th>
 * <th>Write Bytecodes / Methods</th>
 * </tr>
 * <tr>
 * <td>{@link Varnode#isConstant() constant}</td>
 * <td>{@link JitConstVal}</td>
 * <td>{@link ConstValGen}</td>
 * <td>{@link Op#ldc__i(Emitter, int) ldc}</td>
 * </tr>
 * <tr>
 * <td>{@link Varnode#isUnique() unique},<br/>
 * {@link Varnode#isRegister() register}<br/>
 * </td>
 * <td>{@link JitInputVar},<br/>
 * {@link JitLocalOutVar},<br/>
 * {@link JitMissingVar}</td>
 * <td>{@link InputVarGen},<br/>
 * {@link LocalOutVarGen}</td>
 * <td>{@link Op#iload(Emitter, Local) iload}, {@link Op#lload(Emitter, Local) lload},
 * {@link Op#fload(Emitter, Local) fload}, {@link Op#dload(Emitter, Local) dload}</td>
 * <td>{@link Op#istore(Emitter, Local) istore}, {@link Op#lstore(Emitter, Local) lstore},
 * {@link Op#fstore(Emitter, Local) fstore}, {@link Op#dstore(Emitter, Local) dstore}</td>
 * </tr>
 * <tr>
 * <td>{@link Varnode#isAddress() memory}</td>
 * <td>{@link JitDirectMemoryVar},<br/>
 * {@link JitMemoryOutVar}</td>
 * <td>{@link DirectMemoryVarGen},<br/>
 * {@link MemoryOutVarGen}</td>
 * <td>{@link JitCompiledPassage#readInt1(byte[], int) readInt*},
 * {@link JitCompiledPassage#readLong1(byte[], int) readLong*}, etc.</td>
 * <td>{@link JitCompiledPassage#writeInt1(int, byte[], int) writeInt*},
 * {@link JitCompiledPassage#writeLong1(long, byte[], int) writeLong*}, etc.</td>
 * </tr>
 * <tr>
 * <td>*indirect</td>
 * <td>{@link JitIndirectMemoryVar}</td>
 * <td>None</td>
 * </tr>
 * </table>
 * 
 * @implNote Memory-mapped registers are treated as {@code memory} varnodes, not {@code register},
 *           because they are shared by all threads. <b>TODO</b>: A {@link JitConfiguration} flag
 *           that says "the machine is single threaded!" so we can optimize memory accesses in the
 *           same manner we do registers and uniques.
 * @implNote The memory variables are all generally handled as if ints, and then {@link Opnd type
 *           conversions} are applied if necessary to access them as floating point.
 * @implNote {@link JitMissingVar} is a special case of {@code unique} and {@code register} variable
 *           where the definition could not be found. It is used as an intermediate result in the
 *           {@link JitDataFlowModel}, but should be converted to a {@link JitOutVar} defined by a
 *           {@link JitPhiOp} before it enters the use-def graph.
 * @implNote {@link JitIndirectMemoryVar} is a singleton dummy used in the {@link JitDataFlowModel}.
 *           It is immediately thrown away, as indirect memory access is instead modeled by
 *           {@link JitLoadOp} and {@link JitStoreOp}.
 * 
 * @see VarGen
 * @param <V> the class op p-code value node in the use-def graph
 */
public interface ValGen<V extends JitVal> {
	/**
	 * Lookup the generator for a given p-code value use-def node
	 * 
	 * @param <V> the class of the value
	 * @param v the {@link JitVal} whose generator to look up
	 * @return the generator
	 */
	@SuppressWarnings("unchecked")
	static <V extends JitVal> ValGen<V> lookup(V v) {
		return (ValGen<V>) switch (v) {
			case JitConstVal c -> ConstValGen.GEN;
			case JitFailVal m -> FailValGen.GEN;
			case JitVar vv -> VarGen.lookup(vv);
			default -> throw new AssertionError();
		};
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	static <FT extends BPrim<?>, TT extends BPrim<?>, N1 extends Next, N0 extends Ent<N1, FT>>
			Emitter<Ent<N1, TT>>
			castBack(Emitter<N0> em, SimpleJitType<TT, ?> to, SimpleJitType<FT, ?> from) {
		return (Emitter) em;
	}

	/**
	 * Emit code to prepare any class-level items required to use this variable
	 * <p>
	 * For example, if this represents a direct memory variable, then this can prepare a reference
	 * to the portion of the state involved, allowing it to access it readily.
	 * <p>
	 * This should be used to emit code into the constructor.
	 * 
	 * @param <THIS> the type of the generated class
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param v the value
	 * @return the emitter with ...
	 */
	<THIS extends JitCompiledPassage, N extends Next> Emitter<N> genValInit(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v);

	/**
	 * Emit code to read the value onto the stack
	 * 
	 * @param <THIS> the type of the generated class
	 * @param <T> the desired JVM type
	 * @param <JT> the desired p-code type
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param v the value
	 * @param type the desired p-code type
	 * @param ext the kind of extension to apply
	 * @return the emitter with ..., result
	 */
	<THIS extends JitCompiledPassage, T extends BPrim<?>, JT extends SimpleJitType<T, JT>,
		N extends Next> Emitter<Ent<N, T>> genReadToStack(Emitter<N> em,
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v, JT type, Ext ext);

	/**
	 * Emit code to read the value into local variables
	 * <p>
	 * NOTE: In some cases, this may not emit any code at all. It may simple compose the operand
	 * from locals already allocated for a variable being "read."
	 * 
	 * @param <THIS> the type of the generated class
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param v the value
	 * @param type the desired p-code type
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generated temporary variables
	 * @return the operand and emitter with ...
	 */
	<THIS extends JitCompiledPassage, N extends Next> OpndEm<MpIntJitType, N> genReadToOpnd(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v,
			MpIntJitType type, Ext ext, Scope scope);

	/**
	 * Emit code to read a leg of the value onto the stack
	 * 
	 * @param <THIS> the type of the generated class
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param v the value
	 * @param type the desired p-code type
	 * @param leg the leg index, 0 being the least significant
	 * @param ext the kind of extension to apply
	 * @return the emitter with ..., result
	 */
	<THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>> genReadLegToStack(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v,
			MpIntJitType type, int leg, Ext ext);

	/**
	 * Emit code to read the value into an array
	 * 
	 * @param <THIS> the type of the generated class
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param v the value
	 * @param type the desired p-code type
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generated temporary variables
	 * @param slack the number of extra (more significant) elements to allocate in the array
	 * @return the operand and emitter with ..., arrayref
	 */
	<THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TRef<int[]>>> genReadToArray(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v,
			MpIntJitType type, Ext ext, Scope scope, int slack);

	/**
	 * Emit code to read the value onto the stack as a boolean
	 * 
	 * @param <THIS> the type of the generated class
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param v the value
	 * @return the emitter with ..., result
	 */
	<THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>> genReadToBool(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v);

	/**
	 * Create a generator for a {@link PcodeOp#SUBPIECE} of a value.
	 * 
	 * @param byteOffset the number of least-significant bytes to remove
	 * @param maxByteSize the maximum size of the resulting variable. In general, a subpiece should
	 *            never exceed the size of the parent varnode, but if it does, this will truncate
	 *            that excess.
	 * @return the resulting subpiece generator
	 */
	ValGen<V> subpiece(int byteOffset, int maxByteSize);
}
