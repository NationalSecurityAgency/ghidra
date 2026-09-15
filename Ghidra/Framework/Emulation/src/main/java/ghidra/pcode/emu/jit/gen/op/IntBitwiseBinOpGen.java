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

import java.util.ArrayList;
import java.util.List;

import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.MpIntLocalOpnd;
import ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Bot;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.pcode.emu.jit.op.JitBinOp;

/**
 * An extension for bitwise binary operators
 * <p>
 * This provides a simple strategy for multi-precision integer implementation. Since all bit
 * positions are considered independently, we just apply the same
 * {@link #opForInt(Emitter, IntJitType)} operator to each pair of corresponding legs independently
 * to compute each corresponding output leg.
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface IntBitwiseBinOpGen<T extends JitBinOp> extends IntOpBinOpGen<T> {
	@Override
	default boolean isSigned() {
		return false;
	}

	@Override
	default <THIS extends JitCompiledPassage> Emitter<Bot> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, T op, MpIntJitType type,
			Scope scope) {
		var left = gen.genReadToOpnd(em, localThis, op.l(), type, ext(), scope);
		var right = gen.genReadToOpnd(left.em(), localThis, op.r(), type, rExt(), scope);
		em = right.em();
		var lLegs = left.opnd().type().castLegsLE(left.opnd());
		var rLegs = right.opnd().type().castLegsLE(right.opnd());

		List<SimpleOpnd<TInt, IntJitType>> outLegs = new ArrayList<>();
		int legCount = type.legsAlloc();
		for (int i = 0; i < legCount; i++) {
			var result = em
					.emit(lLegs.get(i)::read)
					.emit(rLegs.get(i)::read)
					.emit(this::opForInt, IntJitType.I4)
					.emit(lLegs.get(i)::write, scope);
			em = result.em();
			outLegs.add(result.opnd());
		}
		var out = MpIntLocalOpnd.of(type, "out", outLegs);
		return gen.genWriteFromOpnd(em, localThis, op.out(), out, ext(), scope);
	}
}
