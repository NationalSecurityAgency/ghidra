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

import ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType;
import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.BPrim;

/**
 * A constant that can be pushed onto the JVM stack
 * 
 * @param <T> the JVM type of the constant
 * @param <JT> the p-code type of the constant
 */
interface ConstSimpleOpnd<T extends BPrim<?>, JT extends SimpleJitType<T, JT>>
		extends SimpleOpnd<T, JT> {

	/**
	 * Generate a name should this need conversion into a temporary variable
	 * 
	 * @return the name
	 */
	default String tempName() {
		return "%d_tempFromRo".formatted(name());
	}

	@Override
	default <N1 extends Next, N0 extends Ent<N1, T>> Emitter<N1> writeDirect(Emitter<N0> em) {
		throw new UnsupportedOperationException();
	}
}
