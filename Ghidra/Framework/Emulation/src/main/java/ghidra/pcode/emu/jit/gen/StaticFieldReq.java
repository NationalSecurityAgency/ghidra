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
package ghidra.pcode.emu.jit.gen;

import org.objectweb.asm.ClassVisitor;

import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.BNonVoid;

/**
 * A static field request initialized in the class initializer
 * 
 * @param <T> the JVM type of the field
 */
public interface StaticFieldReq<T extends BNonVoid> extends FieldReq<T> {

	/**
	 * Emit the field declaration and its initialization bytecode
	 * 
	 * <p>
	 * The declaration is emitted into the class definition, and the initialization code is emitted
	 * into the class initializer.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param cv the visitor for the class definition
	 * @return the emitter typed with the incoming stack
	 */
	<N extends Next> Emitter<N> genClInitCode(Emitter<N> em, JitCodeGenerator<?> gen,
			ClassVisitor cv);

	/**
	 * Emit code to load the field onto the JVM stack
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @return the emitter typed with the resulting stack, i.e., having pushed the value
	 */
	<N extends Next> Emitter<Ent<N, T>> genLoad(Emitter<N> em, JitCodeGenerator<?> gen);
}
