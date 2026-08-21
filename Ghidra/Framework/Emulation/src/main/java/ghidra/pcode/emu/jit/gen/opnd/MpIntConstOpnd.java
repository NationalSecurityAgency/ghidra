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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;

/**
 * A constant multi-precision integer operand
 */
record MpIntConstOpnd(MpIntJitType type, String name, List<IntConstOpnd> legsLE)
		implements Opnd<MpIntJitType> {

	static List<IntConstOpnd> computeLegs(BigInteger value, MpIntJitType type) {
		List<IntConstOpnd> legs = new ArrayList<>();
		int count = type.legsAlloc();
		for (int i = 0; i < count; i++) {
			IntJitType t = type.legTypesLE().get(i);
			legs.add(new IntConstOpnd(value.intValue(), t));
			value = value.shiftRight(Integer.SIZE);
		}
		return List.copyOf(legs);
	}

	public MpIntConstOpnd(BigInteger value, MpIntJitType type) {
		this(type, "const_mpint_0x%s".formatted(value.toString(16)), computeLegs(value, type));
	}
}
