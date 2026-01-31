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
package ghidra.pcode.emu.jit.alloc;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.BPrim;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.pcode.emu.jit.gen.var.VarGen;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.Varnode;

/**
 * An allocated JVM local
 * 
 * @param <T> the JVM type of this local
 * @param <JT> the p-code type of this local
 * @param local the declared local this wraps
 * @param type a type for this local
 * @param vn the varnode whose value this local holds
 * @param opnd this local as an operand
 */
public record JvmLocal<T extends BPrim<?>, JT extends SimpleJitType<T, JT>>(Local<T> local,
		JT type, Varnode vn, SimpleOpnd<T, JT> opnd) {

	/**
	 * Create a {@link JvmLocal} with the given local, type, and varnode
	 * 
	 * @param <T> the JVM type of the local
	 * @param <JT> the p-code type of the local
	 * @param local the local
	 * @param type the p-code type of the local
	 * @param vn the varnode to assign to the local
	 * @return the new local (wrapper)
	 */
	public static <T extends BPrim<?>, JT extends SimpleJitType<T, JT>> JvmLocal<T, JT>
			of(Local<T> local, JT type, Varnode vn) {
		SimpleOpnd<T, JT> opnd = SimpleOpnd.of(type, local);
		return new JvmLocal<>(local, type, vn, opnd);
	}

	/**
	 * Get the name of the wrapped local
	 * 
	 * @return the name
	 */
	public String name() {
		return local.name();
	}

	/**
	 * Cast this local to satisfy checkers when a type variable is known to be of a given type
	 * <p>
	 * This will verify at runtime that the types are in fact identical.
	 * 
	 * @param <TT> the "to" JVM type
	 * @param <TJT> the "to" p-code type
	 * @param type the "to" p-code type
	 * @return this local as the given type
	 */
	@SuppressWarnings("unchecked")
	public <TT extends BPrim<?>, TJT extends SimpleJitType<TT, TJT>> JvmLocal<TT, TJT>
			castOf(TJT type) {
		if (this.type != type) {
			throw new ClassCastException(
				"JvmLocal is not of the given type: this is %s. Requested is %s."
						.formatted(this.type, type));
		}
		return (JvmLocal<TT, TJT>) this;
	}

	/**
	 * Emit bytecode into the class constructor needed to access the varnode's actual value from the
	 * underlying {@link PcodeExecutorState}.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @return the emitter typed with the incoming stack
	 */
	public <N extends Next> Emitter<N> genInit(Emitter<N> em, JitCodeGenerator<?> gen) {
		return VarGen.genVarnodeInit(em, gen, vn);
	}

	/**
	 * Emit bytecode to load this local's value onto the JVM stack as the given type
	 * 
	 * @param <TT> the desired JVM type
	 * @param <TJT> the desired p-code type
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param type the desired p-code type
	 * @param ext the kind of extension to apply
	 * @return the emitter typed with the resulting stack, i.e., having pushed the value
	 */
	public <TT extends BPrim<?>, TJT extends SimpleJitType<TT, TJT>, N extends Next>
			Emitter<Ent<N, TT>>
			genLoadToStack(Emitter<N> em, JitCodeGenerator<?> gen, TJT type, Ext ext) {
		return em
				.emit(opnd::read)
				.emit(Opnd::convert, this.type, type, ext);
	}

	/**
	 * Emit bytecode to store the value on the JVM stack into the local
	 * 
	 * @param <FT> the JVM type of the value on the stack
	 * @param <FJT> the p-code type of the value on the stack
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with the value on top
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param type the p-code type of the value on the stack
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the resulting stack, i.e., having popped the value
	 */
	public <FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>, N1 extends Next,
		N0 extends Ent<N1, FT>> Emitter<N1> genStoreFromStack(Emitter<N0> em,
				JitCodeGenerator<?> gen, FJT type, Ext ext, Scope scope) {
		return em
				.emit(Opnd::convert, type, this.type, ext)
				.emit(opnd::writeDirect);
	}

	/**
	 * Emit bytecode to bring this varnode into scope.
	 * 
	 * <p>
	 * This will copy the value from the {@link JitBytesPcodeExecutorState state} into the local
	 * variable.
	 * 
	 * @param <THIS> the type of the compiled passage
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @return the emitter typed with the incoming stack
	 */
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genBirthCode(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen) {
		return em
				.emit(VarGen::genReadValDirectToStack, localThis, gen, type, vn)
				.emit(opnd::writeDirect);
	}

	/**
	 * Emit bytecode to take this varnode out of scope.
	 * 
	 * <p>
	 * This will copy the value from the local variable into the {@link JitBytesPcodeExecutorState
	 * state}.
	 * 
	 * @param <THIS> the type of the compiled passage
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @return the emitter typed with the incoming stack
	 */
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genRetireCode(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen) {
		return em
				.emit(opnd::read)
				.emit(VarGen::genWriteValDirectFromStack, localThis, gen, type, vn);
	}

	/**
	 * {@return the maximum address that would be occupied by the full primitive type}
	 */
	public Address maxPrimAddr() {
		return vn.getAddress().add(type.ext().size() - 1);
	}
}
