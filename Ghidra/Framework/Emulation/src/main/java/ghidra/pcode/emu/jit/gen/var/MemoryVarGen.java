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

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.type.TypedAccessGen;
import ghidra.pcode.emu.jit.var.JitVarnodeVar;

/**
 * The generator for memory variables.
 * 
 * <p>
 * These variables affect the {@link JitBytesPcodeExecutorState state} immediately, i.e., they are
 * not birthed or retired as local JVM variables. The generator delegates to the appropriate
 * {@link TypedAccessGen} for this variable's varnode and assigned type.
 * 
 * @param <V> the class of p-code variable node in the use-def graph
 */
public interface MemoryVarGen<V extends JitVarnodeVar> extends VarGen<V> {
	@Override
	default void generateValInitCode(JitCodeGenerator gen, V v, MethodVisitor iv) {
		VarGen.generateValInitCode(gen, v.varnode());
	}

	@Override
	default JitType generateValReadCode(JitCodeGenerator gen, V v, JitTypeBehavior typeReq,
			MethodVisitor rv) {
		return VarGen.generateValReadCodeDirect(gen, v, typeReq, rv);
	}
}
