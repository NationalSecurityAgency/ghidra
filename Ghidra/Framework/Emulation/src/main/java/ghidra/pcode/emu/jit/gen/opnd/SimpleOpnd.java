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
package ghidra.pcode.emu.jit.gen.opnd;

import java.util.List;

import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.*;

/**
 * An operand stored in a single JVM local variable
 * 
 * @param <T> the JVM type
 * @param <JT> the p-code type
 */
public interface SimpleOpnd<T extends BPrim<?>, JT extends SimpleJitType<T, JT>> extends Opnd<JT> {

	/**
	 * Create a simple local operand
	 * 
	 * @param <T> the JVM type
	 * @param <JT> the p-code type
	 * @param type the p-code type
	 * @param local the JVM local
	 * @return the operand
	 */
	@SuppressWarnings("unchecked")
	static <T extends BPrim<?>, JT extends SimpleJitType<T, JT>> SimpleOpnd<T, JT> of(
			JT type, Local<T> local) {
		return (SimpleOpnd<T, JT>) switch (type) {
			case IntJitType t -> IntLocalOpnd.of(t, (Local<TInt>) local);
			case LongJitType t -> LongLocalOpnd.of(t, (Local<TLong>) local);
			case FloatJitType t -> FloatLocalOpnd.of(t, (Local<TFloat>) local);
			case DoubleJitType t -> DoubleLocalOpnd.of(t, (Local<TDouble>) local);
			default -> throw new AssertionError();
		};
	}

	/**
	 * Create a read-only {@code int} local operand
	 * <p>
	 * Multi-precision integer operators work by composing several locals into a single p-code
	 * variable. Some of these operators need temporary variables. To avoid generating tons of
	 * those, we generally allow the temporary locals to be mutated. However, the local variables
	 * allocated to hold p-code variables cannot be mutated until the full output value has been
	 * successfully computed. Furthermore, we certainly cannot mutate any input operand by mistake.
	 * Using a read-only local for input operands ensures this does not happen. An attempt to write
	 * to one of these will instead generate a new temporary local, assign the value to it, and
	 * return the new operand. An attempt to write directly to this operand will result in an
	 * exception being thrown at generation time.
	 * 
	 * @param type the p-code type
	 * @param local the local handle
	 * @return the read-only operand
	 */
	static SimpleOpnd<TInt, IntJitType> ofIntReadOnly(IntJitType type, Local<TInt> local) {
		return IntReadOnlyLocalOpnd.of(type, local);
	}

	/**
	 * An operand-emitter tuple
	 * 
	 * @param <T> the JVM type of the operand
	 * @param <JT> the p-code type of the operand
	 * @param <N> the emitter's stack
	 */
	record SimpleOpndEm<T extends BPrim<?>, JT extends SimpleJitType<T, JT>, N extends Next>(
			SimpleOpnd<T, JT> opnd, Emitter<N> em) {

		/**
		 * Cast the operand safely between generic and concrete type
		 * <p>
		 * The given types are checked for equality at runtime, if assertions are enabled
		 * 
		 * @param <TT> the "to" JVM type
		 * @param <TJT> the "to" p-code type
		 * @param to the destination p-code type
		 * @return this cast to the same type, but expressed generically
		 */
		@SuppressWarnings({ "unchecked", "rawtypes" })
		public <TT extends BPrim<?>, TJT extends SimpleJitType<TT, TJT>> SimpleOpndEm<TT, TJT, N>
				castBack(TJT to) {
			assert to == this.opnd.type();
			return (SimpleOpndEm) this;
		}
	}

	/**
	 * Emit code to read the operand onto the stack
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @return the emitter with ..., value
	 */
	<N extends Next> Emitter<Ent<N, T>> read(Emitter<N> em);

	/**
	 * Emit code to write the operand from the stack
	 * <p>
	 * This will generate a new operand if this operand is read-only. Callers must therefore be
	 * prepared to take the result in place of this operand.
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param scope a scope for generated temporary variables
	 * @return the resulting operand and emitter with ...
	 */
	default <N1 extends Next, N0 extends Ent<N1, T>> SimpleOpndEm<T, JT, N1> write(Emitter<N0> em,
			Scope scope) {
		return new SimpleOpndEm<>(this, writeDirect(em));
	}

	/**
	 * Emit code to write the operand, without generating a new operand
	 * <p>
	 * This will throw an exception during generation if this operand is read-only. This should only
	 * be used when the caller is certain the operand can be written and when a scope is not
	 * available.
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	<N1 extends Next, N0 extends Ent<N1, T>> Emitter<N1> writeDirect(Emitter<N0> em);

	@Override
	default List<? extends SimpleOpnd<?, ?>> legsLE() {
		return List.of(this);
	}
}
