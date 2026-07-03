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

import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;

/**
 * A constant {@code int}
 * 
 * @param value the value
 * @param type the p-code type
 */
public record IntConstOpnd(int value, IntJitType type)
		implements ConstSimpleOpnd<TInt, IntJitType> {

	/** 0 of type {@link IntJitType#I1 int1} */
	public static final IntConstOpnd ZERO_I1 = new IntConstOpnd(0, IntJitType.I1);
	/** 0 of type {@link IntJitType#I2 int2} */
	public static final IntConstOpnd ZERO_I2 = new IntConstOpnd(0, IntJitType.I2);
	/** 0 of type {@link IntJitType#I3 int3} */
	public static final IntConstOpnd ZERO_I3 = new IntConstOpnd(0, IntJitType.I3);
	/** 0 of type {@link IntJitType#I4 int4} */
	public static final IntConstOpnd ZERO_I4 = new IntConstOpnd(0, IntJitType.I4);

	/**
	 * Get a constant 0 of the given p-code {@link IntJitType int} type.
	 * 
	 * @param type the type
	 * @return the constant 0
	 */
	public static IntConstOpnd zero(IntJitType type) {
		return switch (type.size()) {
			case 1 -> ZERO_I1;
			case 2 -> ZERO_I2;
			case 3 -> ZERO_I3;
			case 4 -> ZERO_I4;
			default -> throw new AssertionError();
		};
	}

	@Override
	public String name() {
		return "const_int_0x%x".formatted(value);
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> read(Emitter<N> em) {
		return em.emit(Op::ldc__i, value);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TInt>> SimpleOpndEm<TInt, IntJitType, N1>
			write(Emitter<N0> em, Scope scope) {
		return IntLocalOpnd.temp(type(), tempName(), scope).write(em, scope);
	}
}
