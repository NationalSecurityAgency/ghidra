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
package ghidra.util.database.spatial.hyper;

import java.math.BigInteger;
import java.util.Objects;

public interface StringDimension<P extends HyperPoint, B extends HyperBox<P, B>>
		extends Dimension<String, P, B> {

	@Override
	default int compare(String a, String b) {
		if (a == null && b == null) {
			return 0;
		}
		// Treat null as the absolute max value
		if (a == null) {
			return 1;
		}
		if (b == null) {
			return -1;
		}
		return a.compareTo(b);
	}

	static int charAt(String s, int i) {
		if (s == null) {
			if (i == 0) {
				return 128;
			}
			return 0;
		}
		if (i < s.length()) {
			return Math.min(127, s.charAt(i));
		}
		return 0;
	}

	static int lenStrings(String a, String b) {
		if (a == null) {
			return b.length();
		}
		if (b == null) {
			return a.length();
		}
		return Math.max(a.length(), b.length());
	}

	@Override
	default double distance(String a, String b) {
		if (Objects.equals(a, b)) {
			return 0;
		}
		// TODO: May revisit the starting place value, to scale this dimension down in importance.
		double result = 0;
		double placeVal = Double.MAX_VALUE / 128;
		int len = lenStrings(a, b);
		for (int i = 0; i < len; i++) {
			int ca = charAt(a, i);
			int cb = charAt(b, i);
			double oldResult = result;
			result += placeVal * (cb - ca);
			if (oldResult == result) {
				// Can't capture any more precision, so we're done
				return result;
			}
			if (placeVal == Double.MIN_VALUE || placeVal == 0) {
				return result;
			}
			placeVal /= 128;
		}
		return result;
	}

	static BigInteger subtractExact(String a, String b) {
		int len = lenStrings(a, b);
		BigInteger result = BigInteger.ZERO;
		for (int i = 0; i < len; i++) {
			int ca = charAt(a, i);
			int cb = charAt(b, i);
			result = result.shiftLeft(7).add(BigInteger.valueOf(ca - cb));
		}
		return result;
	}

	static String add(String a, BigInteger d, int len) {
		char[] cb = new char[len];
		boolean carry = false;
		for (int i = len - 1; i >= 0; i--) {
			int tc = charAt(a, i) + (d.intValue() % 128) + (carry ? 1 : 0);
			d = d.shiftRight(7);
			carry = tc >= 128;
			cb[i] = (char) (tc % 128);
		}
		return new String(cb);
	}

	@Override
	default String mid(String a, String b) {
		if (Objects.equals(a, b)) {
			return a;
		}
		if (a == null && b.isEmpty()) {
			return "" + ((char) 64);
		}
		if (b == null && a.isEmpty()) {
			return "" + ((char) 64);
		}
		if (a.compareTo(b) > 0) {
			// I'll cheat a bit here to avoid carries with negative operand
			String c = a;
			a = b;
			b = c;
		}
		BigInteger diff = subtractExact(b, a);
		String maybeTrunc = add(a, diff.shiftRight(1), lenStrings(a, b));
		if (diff.testBit(0)) {
			return maybeTrunc + ((char) 64);
		}
		return maybeTrunc;
	}

	@Override
	default String absoluteMin() {
		return "";
	}

	@Override
	default String absoluteMax() {
		return null;
	}
}
