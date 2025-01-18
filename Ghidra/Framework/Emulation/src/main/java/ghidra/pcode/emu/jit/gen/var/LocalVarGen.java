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

import ghidra.pcode.emu.jit.analysis.JitAllocationModel.VarHandler;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.var.JitVarnodeVar;

/**
 * The generator for local variable access.
 * 
 * <p>
 * These variables are presumed to be allocated as JVM locals. The generator emits
 * {@link Opcodes#ILOAD iload} and {@link Opcodes#ISTORE istore} and or depending on the assigned
 * type.
 * 
 * @param <V> the class of p-code variable node in the use-def graph
 */
public interface LocalVarGen<V extends JitVarnodeVar> extends VarGen<V> {
	@Override
	default void generateValInitCode(JitCodeGenerator gen, V v, MethodVisitor iv) {
		gen.getAllocationModel().getHandler(v).generateInitCode(gen, iv);
	}

	@Override
	default JitType generateValReadCode(JitCodeGenerator gen, V v, JitTypeBehavior typeReq,
			MethodVisitor rv) {
		VarHandler handler = gen.getAllocationModel().getHandler(v);
		JitType type = typeReq.resolve(gen.getTypeModel().typeOf(v));
		handler.generateLoadCode(gen, type, rv);
		return type;
	}
}
