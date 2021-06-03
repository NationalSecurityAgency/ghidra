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
package ghidra.util;

public class MathUtilities {

	private MathUtilities() {
	}

	/**
	 * Perform unsigned division. Provides proper handling of all 64-bit unsigned values.
	 * 
	 * @param numerator unsigned numerator
	 * @param denominator positive divisor
	 * @return result of unsigned division
	 * @throws IllegalArgumentException if negative denominator is specified
	 */
	public static long unsignedDivide(long numerator, long denominator) {
		if (denominator < 0) {
			throw new IllegalArgumentException("denomintor too big");
		}
		if (numerator >= 0) {
			return numerator / denominator;
		}
		// handle negative numerator value
		long numeratorDiv2 = numerator >>> 1;
		long result = (numeratorDiv2 / denominator) << 1;
		long remainder = (numeratorDiv2 % denominator) << 1;
		remainder += (numerator & 1);
		if (remainder >= denominator) {
			++result;
		}
		return result;
	}

	/**
	 * Perform unsigned modulo. Provides proper handling of all 64-bit unsigned values.
	 * 
	 * @param numerator unsigned numerator
	 * @param denominator positive divisor
	 * @return result of unsigned modulo (i.e., remainder)
	 * @throws IllegalArgumentException if negative denominator is specified
	 */
	public static long unsignedModulo(long numerator, long denominator) {
		if (denominator < 0) {
			throw new IllegalArgumentException("denomintor too big");
		}
		if (numerator >= 0) {
			return numerator % denominator;
		}
		// handle negative numerator value
		long numeratorDiv2 = numerator >>> 1;
		long remainder = (numeratorDiv2 % denominator) << 1;
		remainder += (numerator & 1);
		return remainder % denominator;
	}

	/**
	 * Ensures that the given value is within the given range.
	 * 
	 * @param value the value to check
	 * @param min the minimum value allowed
	 * @param max the maximum value allowed
	 * @return the clamped value
	 */
	public static int clamp(int value, int min, int max) {
		if (value < min) {
			return min;
		}
		if (value > max) {
			return max;
		}
		return value;
	}

	public static void main(String[] args) {
		long d = 4;
		for (long i = 27; i > -27; --i) {
			long result = unsignedDivide(i, d);
			long mod = unsignedModulo(i, d);
			long v = (result * d) + mod;
			System.out.println("0x" + Long.toHexString(i) + " -> 0x" + Long.toHexString(result) +
				":0x" + Long.toHexString(mod) + " -> 0x" + Long.toHexString(v));
		}
	}

	/**
	 * Compute the minimum, treating the inputs as unsigned
	 * 
	 * @param a the first value to consider
	 * @param b the second value to consider
	 * @return the minimum
	 */
	public static long unsignedMin(long a, long b) {
		return (Long.compareUnsigned(a, b) < 0) ? a : b;
	}

	/**
	 * Compute the minimum, treating the inputs as unsigned
	 * 
	 * @param a the first value to consider
	 * @param b the second value to consider
	 * @return the minimum
	 */
	public static int unsignedMin(int a, int b) {
		return (Integer.compareUnsigned(a, b) < 0) ? a : b;
	}

	/**
	 * Compute the minimum, treating the inputs as unsigned
	 * 
	 * <p>
	 * This method is overloaded to prevent accidental signed-extension on one of the inputs. This
	 * method will correctly zero-extend the {@code int} parameter before performing any comparison.
	 * Also note the return type is {@code int}, since b would never be selected if it overflows an
	 * {@code int}.
	 * 
	 * @param a the first value to consider
	 * @param b the second value to consider
	 * @return the minimum
	 */
	public static int unsignedMin(int a, long b) {
		return (Long.compareUnsigned(a & 0x0ffffffffL, b) < 0) ? a : (int) b;
	}

	/**
	 * Compute the minimum, treating the inputs as unsigned
	 * 
	 * <p>
	 * This method is overloaded to prevent accidental signed-extension on one of the inputs. This
	 * method will correctly zero-extend the {@code int} parameter before performing any comparison.
	 * Also note the return type is {@code int}, since b would never be selected if it overflows an
	 * {@code int}.
	 * 
	 * @param a the first value to consider
	 * @param b the second value to consider
	 * @return the minimum
	 */
	public static int unsignedMin(long a, int b) {
		return (Long.compareUnsigned(a, b & 0x0ffffffffL) < 0) ? (int) a : b;
	}

	/**
	 * Compute the maximum, treating the inputs as unsigned
	 * 
	 * @param a the first value to consider
	 * @param b the second value to consider
	 * @return the maximum
	 */
	public static long unsignedMax(long a, long b) {
		return (Long.compareUnsigned(a, b) > 0) ? a : b;
	}

	/**
	 * Compute the maximum, treating the inputs as unsigned
	 * 
	 * @param a the first value to consider
	 * @param b the second value to consider
	 * @return the maximum
	 */
	public static int unsignedMax(int a, int b) {
		return (Integer.compareUnsigned(a, b) > 0) ? a : b;
	}

	/**
	 * Compute the maximum, treating the inputs as unsigned
	 * 
	 * <p>
	 * This method is overloaded to prevent accidental signed-extension on one of the inputs. This
	 * method will correctly zero-extend the {@code int} parameter before performing any comparison.
	 * 
	 * @param a the first value to consider
	 * @param b the second value to consider
	 * @return the maximum
	 */
	public static long unsignedMax(int a, long b) {
		return (Long.compareUnsigned(a & 0x0ffffffffL, b) > 0) ? a : b;
	}

	/**
	 * Compute the maximum, treating the inputs as unsigned
	 * 
	 * <p>
	 * This method is overloaded to prevent accidental signed-extension on one of the inputs. This
	 * method will correctly zero-extend the {@code int} parameter before performing any comparison.
	 * 
	 * @param a the first value to consider
	 * @param b the second value to consider
	 * @return the maximum
	 */
	public static long unsignedMax(long a, int b) {
		return (Long.compareUnsigned(a, b & 0x0ffffffffL) > 0) ? a : b;
	}
}
