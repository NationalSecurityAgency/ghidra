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
package ghidra.program.emulation;

import java.util.function.Function;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeUseropLibraryFactory.UseropLibrary;
import ghidra.program.model.pcode.Varnode;

@UseropLibrary("hexagon")
public class HexagonPcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {
	@Override
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		return new HexagonPcodeUseropLibrary<T>(language);
	}

	public static class HexagonPcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		private static final int FP_ZERO_CLASS_MASK = 0x01;
		private static final int FP_NORMAL_CLASS_MASK = 0x02;
		private static final int FP_SUBNORMAL_CLASS_MASK = 0x04;
		private static final int FP_INFINITE_CLASS_MASK = 0x08;
		private static final int FP_NAN_CLASS_MASK = 0x10;

		public HexagonPcodeUseropLibrary(SleighLanguage language) {
			SleighPcodeUseropDefinition.Factory factory =
				new SleighPcodeUseropDefinition.Factory(language);

			putOp(factory.define("min").params("a", "b").body(args -> """
					if (a s<= b) goto <take_a>;
					  __op_output = b;
					goto <done>;
					<take_a>
					  __op_output = a;
					<done>
					""").build());

			putOp(factory.define("vlslh")
					.params("source", "shift")
					.body(args -> genVecShift(args.get(0), 16, "<<", ">>"))
					.build());
			putOp(factory.define("vlsrh")
					.params("source", "shift")
					.body(args -> genVecShift(args.get(0), 16, ">>", "<<"))
					.build());
			putOp(factory.define("vlslw")
					.params("source", "shift")
					.body(args -> genVecShift(args.get(0), 32, "<<", ">>"))
					.build());
			putOp(factory.define("vlsrw")
					.params("source", "shift")
					.body(args -> genVecShift(args.get(0), 32, ">>", "<<"))
					.build());

			putOp(factory.define("vmux").params("sel", "a", "b").body(args -> """
					local s:1;
					local result:8;
					""" + genVec(0, 8, 1, i -> """
					s = ((sel >> %d) & 1) * 0xff;
					result[%d,8] = (a[%d,8] & s) | (b[%d,8] & ~s);
					""".formatted(i, 8 * i, 8 * i, 8 * i)) + """
					__op_output = result;
					""").build());

			putOp(factory.define("vabsh").params("n").body(args -> genVecAbs(16)).build());
			putOp(factory.define("vabsw").params("n").body(args -> genVecAbs(32)).build());

			putOp(factory.define("dfmpylh").params("rdd", "rss", "rtt").body(args -> """
					rss_lo:8 = rss & 0xffffffff;
					rtt_hi:8 = rtt >> 32;
					prod:8 = (rss_lo * (0x00100000 | (rtt_hi & 0xfffff))) << 1;
					__op_output = rdd + prod;
					""").build());
			putOp(factory.define("dfmpyll").params("rss", "rtt").body(args -> """
					rss_lo:8 = rss & 0xffffffff;
					rtt_lo:8 = rtt & 0xffffffff;
					prod:8 = rss_lo * rtt_lo;
					result:8 = (prod >> 32) << 1;
					if ((prod & 0xffffffff) == 0) goto <done>;
					  result = result + 1;
					<done>
					__op_output = result;
					""").build());

			putOp(factory.define("isClassifiedFloat")
					.params("bits", "cls")
					.body(args -> switch (args.get(1).getSize()) {
						case 4 -> "__op_output = __isClassifiedFloat32(bits, cls);";
						case 8 -> "__op_output = __isClassifiedFloat64(bits, cls);";
						default -> throw new LowlevelError(
							"isClassifiedFloat: invalid float size of " + args.get(0).getSize());
					})
					.build());
		}

		protected String genVec(int start, int stop, int step, Function<Integer, String> slot) {
			StringBuffer buf = new StringBuffer();
			for (int i = start; i < stop; i += step) {
				buf.append(slot.apply(i));
			}
			return buf.toString();
		}

		protected String genVecShift(Varnode source, int slotSize, String posOp, String negOp) {
			int regSize = source.getSize() * 8;
			return """
					s:1 = (shift[0,8] << 1) s>> 1;
					if (s s< 0) goto <shift_neg>;
					""" + genVec(0, regSize, slotSize, slot -> """
					  __op_output[%d,%d] = source[%d,%d] %s s;
					""".formatted(slot, slotSize, slot, slotSize, posOp)) + """
					goto <done>;
					<shift_neg>
					""" + genVec(0, regSize, slotSize, slot -> """
					  __op_output[%d,%d] = source[%d,%d] %s s;
					""".formatted(slot, slotSize, slot, slotSize, negOp)) + """
					<done>
					""";
		}

		protected String genVecAbs(int slotSize) {
			long signMask = Long.MIN_VALUE;
			for (int i = 32; i >= slotSize; i >>>= 1) {
				signMask |= (signMask >>> i);
			}
			long sm = signMask;
			long mult = -1L >>> (64 - slotSize);
			return """
					s = n & 0x%x;
					ones = s >> %d;
					mask = ones * 0x%x;
					inv = n ^ mask;
					""".formatted(sm, slotSize - 1, mult) + genVec(0, 64, slotSize, slot -> """
					__op_output[%d,%d] = inv[%d,%d] + ones[%d,%d];
					""".formatted(slot, slotSize, slot, slotSize, slot, slotSize));
		}

		@PcodeUserop(functional = true)
		public static int __isClassifiedFloat32(int valueBits, int cls) {
			int exp = HexagonFp32.maskFp32Exponent(valueBits);
			int frac = HexagonFp32.maskFp32Fraction(valueBits);
			if ((cls & FP_ZERO_CLASS_MASK) != 0 && HexagonFp32.isFp32Zero(exp, frac)) {
				return 0xff;
			}
			if ((cls & FP_NORMAL_CLASS_MASK) != 0 && HexagonFp32.isFp32Normal(exp, frac)) {
				return 0xff;
			}
			if ((cls & FP_SUBNORMAL_CLASS_MASK) != 0 && HexagonFp32.isFp32Subnormal(exp, frac)) {
				return 0xff;
			}
			if ((cls & FP_INFINITE_CLASS_MASK) != 0 && HexagonFp32.isFp32Infinite(exp, frac)) {
				return 0xff;
			}
			if ((cls & FP_NAN_CLASS_MASK) != 0 && HexagonFp32.isFp32Nan(exp, frac)) {
				return 0xff;
			}
			return 0;
		}

		@PcodeUserop(functional = true)
		public static int __isClassifiedFloat64(long valueBits, int cls) {
			long exp = HexagonFp64.maskFp64Exponent(valueBits);
			long frac = HexagonFp64.maskFp64Fraction(valueBits);
			if ((cls & FP_ZERO_CLASS_MASK) != 0 && HexagonFp64.isFp64Zero(exp, frac)) {
				return 0xff;
			}
			if ((cls & FP_NORMAL_CLASS_MASK) != 0 && HexagonFp64.isFp64Normal(exp, frac)) {
				return 0xff;
			}
			if ((cls & FP_SUBNORMAL_CLASS_MASK) != 0 && HexagonFp64.isFp64Subnormal(exp, frac)) {
				return 0xff;
			}
			if ((cls & FP_INFINITE_CLASS_MASK) != 0 && HexagonFp64.isFp64Infinite(exp, frac)) {
				return 0xff;
			}
			if ((cls & FP_NAN_CLASS_MASK) != 0 && HexagonFp64.isFp64Nan(exp, frac)) {
				return 0xff;
			}
			return 0;
		}

		// LATER: Could/should this be done in Sleigh instead?
		@PcodeUserop(functional = true)
		public static long dfmpyfix(long rss, long rtt) {
			return HexagonFp64.dfmpyfix(rss, rtt);
		}

		// LATER: Could/should this be done in Sleigh instead?
		@PcodeUserop(functional = true)
		public static long dfmpyhh(long rdd, long rss, long rtt) {
			return HexagonFp64.dfmpyhh(rdd, rss, rtt);
		}
	}
}
