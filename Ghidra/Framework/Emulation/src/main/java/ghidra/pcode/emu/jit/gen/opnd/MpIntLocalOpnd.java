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

import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;

/**
 * A (usually mutable) multi-precision integer operand
 * <p>
 * This may be composed of simple mutable and constant operands. The most common cause of constant
 * operands is zero extension. It is also possible the same mutable (local) operand may appear more
 * than once. The most common cause of such duplication is sign extension.
 * 
 * @param type the p-code type
 * @param name a name (prefix) to use for generated temporary legs
 * @param legsLE the legs in little-endian order
 */
public record MpIntLocalOpnd(MpIntJitType type, String name,
		List<? extends SimpleOpnd<TInt, IntJitType>> legsLE)
		implements Opnd<MpIntJitType> {

	/**
	 * Create a multi-precision integer operand from the given legs
	 * 
	 * @param type the p-code type
	 * @param name the name (prefix) to use for generate temporary legs
	 * @param legsLE the legs in little-endian order
	 * @return the operand
	 */
	public static MpIntLocalOpnd of(MpIntJitType type, String name,
			List<? extends SimpleOpnd<TInt, IntJitType>> legsLE) {
		return new MpIntLocalOpnd(type, name, legsLE);
	}

	public MpIntLocalOpnd {
		legsLE = List.copyOf(legsLE);
		// Assert leg types match?
	}
}
