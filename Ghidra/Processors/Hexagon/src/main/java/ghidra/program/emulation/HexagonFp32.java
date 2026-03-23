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

public enum HexagonFp32 {
	;
	public static final int FP32_FRAC_POS = 0;
	public static final int FP32_FRAC_SIZE = 23;
	public static final int FP32_FRAC_MASK = ((1 << FP32_FRAC_SIZE) - 1) << FP32_FRAC_POS;
	public static final int FP32_EXP_POS = FP32_FRAC_POS + FP32_FRAC_SIZE;
	public static final int FP32_EXP_SIZE = 8;
	public static final int FP32_EXP_MASK = ((1 << FP32_EXP_SIZE) - 1) << FP32_EXP_POS;
	public static final int FP32_SIGN_POS = FP32_EXP_POS + FP32_EXP_SIZE;
	public static final int FP32_BIAS = (1 << FP32_EXP_SIZE - 1) - 1;

	static int maskFp32Exponent(int valueBits) {
		return FP32_EXP_MASK & valueBits;
	}

	static int maskFp32Fraction(int valueBits) {
		return FP32_FRAC_MASK & valueBits;
	}

	static boolean isFp32Zero(int exp, int frac) {
		return exp == 0 && frac == 0;
	}

	static boolean isFp32Normal(int exp, int frac) {
		return exp != 0 && exp != FP32_EXP_MASK;
	}

	static boolean isFp32Subnormal(int exp, int frac) {
		return exp == 0 && frac != 0;
	}

	static boolean isFp32Infinite(int exp, int frac) {
		return exp == FP32_EXP_MASK && frac == 0;
	}

	static boolean isFp32Nan(int exp, int frac) {
		return exp == FP32_EXP_MASK && frac != 0;
	}
}
