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

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import ghidra.pcode.emu.jit.JitConfiguration;
import ghidra.pcode.emu.jit.analysis.*;
import ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.*;
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
 * <td>{@link Opcodes#LDC ldc}</td>
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
 * <td>See {@link SimpleJitType#opcodeLoad()}:<br/>
 * {@link Opcodes#ILOAD iload}, {@link Opcodes#LLOAD lload}, {@link Opcodes#FLOAD fload},
 * {@link Opcodes#DLOAD dload}</td>
 * <td>See {@link SimpleJitType#opcodeStore()}:<br/>
 * {@link Opcodes#ISTORE istore}, {@link Opcodes#LSTORE lstore}, {@link Opcodes#FSTORE fstore},
 * {@link Opcodes#DSTORE dstore}</td>
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
 * @implNote There are remnants of experiments and fragments in anticipation of multi-precision
 *           integer variables. These are not supported yet, but some of the components for mp-int
 *           support are used in degenerate form to support normal ints. Many of these components
 *           have "{@code Mp}" in the name.
 * @implNote The memory variables are all generally handled as if ints, and then
 *           {@link TypeConversions type conversions} are applied if necessary to access them as
 *           floating point.
 * @implNote {@link JitMissingVar} is a special case of {@code unique} and {@code register} variable
 *           where the definition could not be found. It is used as an intermediate result the
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
			case JitVar vv -> VarGen.lookup(vv);
			default -> throw new AssertionError();
		};
	}

	/**
	 * Prepare any class-level items required to use this variable
	 * 
	 * <p>
	 * For example, if this represents a direct memory variable, then this can prepare a reference
	 * to the portion of the state involved, allowing it to access it readily.
	 * 
	 * @param gen the code generator
	 * @param v the value
	 * @param iv the constructor visitor
	 */
	void generateValInitCode(JitCodeGenerator gen, V v, MethodVisitor iv);

	/**
	 * Read the value onto the stack
	 * 
	 * @param gen the code generator
	 * @param v the value to read
	 * @param typeReq the required type of the value
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 * @return the actual p-code type (which determines the JVM type) of the value on the stack
	 */
	JitType generateValReadCode(JitCodeGenerator gen, V v, JitTypeBehavior typeReq,
			MethodVisitor rv);
}
